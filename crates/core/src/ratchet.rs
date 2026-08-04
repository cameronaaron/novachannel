//! An additive, opt-in ratchet layered on top of [`crate::handshake`] and
//! [`crate::transport`], seeded from [`crate::handshake::EstablishedSession::ratchet_root`].
//! It gives two properties the plain session does not have on its own:
//!
//! - **Per-message forward secrecy.** Every record is sealed under a
//!   fresh, single-use AEAD key pulled off a one-way hash chain
//!   (`ChainKey::advance`, HMAC-SHA256) and discarded the instant it's
//!   used. Recovering the chain's *current* state does not recover any
//!   *past* message key, unlike the plain transport, where one static key
//!   covers every record in the session.
//! - **Post-compromise security.** Either party can call
//!   [`RatchetedSession::initiate_ratchet`] to mix a fresh hybrid
//!   X25519 + ML-KEM-768 exchange (reusing [`crate::kex`]) into an
//!   HKDF-derived root key, advancing to a new "epoch" with fresh chains.
//!   A session compromised at some point recovers confidentiality once a
//!   ratchet step completes and both sides adopt the new epoch.
//!
//! # Honest scope, relative to Signal's actual production ratchet
//! Signal's Double Ratchet now depends on
//! [`signalapp/SparsePostQuantumRatchet`](https://github.com/signalapp/SparsePostQuantumRatchet)
//! ("SPQR"). Having read its real source (`src/v1/unchunked/send_ek.rs`
//! et al., not just the README): SPQR's ratchet step is not "do an
//! ML-KEM exchange" — it's a from-scratch **incremental** re-encoding of
//! ML-KEM-768 (`incremental_mlkem768`, its own module, not the standard
//! one-shot KEM API) that splits the ~1.1KB encapsulation key and ~1KB
//! ciphertext into a `header`/`ek`/`ct1`/`ct2`-style sequence sent across
//! *multiple* round trips via an explicit `KeysUnsampled -> HeaderSent ->
//! EkSent -> EkSentCt1Received` state machine (mirrored in
//! `src/v1/chunked/` with Reed-Solomon erasure coding on top, for
//! tolerance to dropped chunks), so no single message need carry a full
//! KEM payload. The whole thing is machine-verified: `hax_lib` refinement
//! types checked with F*, plus separate ProVerif security models.
//!
//! This module does not attempt any of that. It does a **synchronous,
//! one-shot** hybrid re-key: one full X25519 public key + one full
//! ML-KEM-768 encapsulation key in the initiating message, one full
//! ciphertext in the reply — the same shapes [`crate::kex`] already uses
//! for the initial handshake, just re-run mid-session. That means:
//!
//! - No chunking/erasure coding: a ratchet step costs one ~1.2KB message
//!   each way, all at once, not spread thin. SPQR's entire reason to
//!   exist is avoiding exactly that bandwidth spike; this module accepts
//!   it in exchange for being small enough to have actually been checked
//!   here, by hand, rather than trusted on the strength of the name.
//! - **In-order delivery is required.** The base [`crate::transport`]
//!   module tolerates reordering via its replay window; this module does
//!   not attempt that on top of chain-key ratcheting (out-of-order
//!   handling is most of why SPQR's design and Signal's classical ratchet
//!   are as involved as they are) — build it on a reliable, ordered
//!   stream (e.g. TCP), not raw UDP/QUIC.
//! - **Ratchet initiation must not race.** Both sides calling
//!   [`RatchetedSession::initiate_ratchet`] concurrently, before either
//!   has seen the other's step, is rejected with
//!   [`Error::RatchetInProgress`] rather than silently producing
//!   divergent epoch state — callers that want concurrent-initiation
//!   safety need to add their own coordination (e.g. only the original
//!   handshake initiator ever calls it) or a retry-on-error policy.
//! - **No formal verification.** SPQR is hax/F*-checked and has ProVerif
//!   models. This module has the same test discipline as the rest of
//!   this workspace (adversarial unit tests, `ENGINEERING-STANDARDS.md`)
//!   and nothing more.
//!
//! It gives real forward secrecy and real, hybrid PQ-safe
//! post-compromise security — just via a much smaller, fully-understood
//! mechanism instead of a faithful reimplementation of SPQR.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use kem::KeyExport;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::handshake::EstablishedSession;
use crate::kex::{self, InitiatorKex};
use crate::wire::{Reader, Writer};

type HmacSha256 = Hmac<Sha256>;

const MSG_APPLICATION: u8 = 0;
const MSG_RATCHET_STEP1: u8 = 1;
const MSG_RATCHET_STEP2: u8 = 2;

const LABEL_MESSAGE_KEY: &[u8] = &[0x01];
const LABEL_NEXT_CHAIN: &[u8] = &[0x02];

const LABEL_INIT_SEND: &[u8] = b"novachannel ratchet v1 epoch0 initiator->responder";
const LABEL_INIT_RECV: &[u8] = b"novachannel ratchet v1 epoch0 responder->initiator";
const LABEL_STEP_ROOT: &[u8] = b"novachannel ratchet v1 step root";
const LABEL_STEP_I2R: &[u8] = b"novachannel ratchet v1 step initiator->responder";
const LABEL_STEP_R2I: &[u8] = b"novachannel ratchet v1 step responder->initiator";

/// One position in a one-way hash chain: `advance` yields the next chain
/// state and a one-time message key, and irreversibly consumes `self` in
/// the process, so a compromised chain key can walk *forward* but never
/// *backward*.
#[derive(Clone)]
struct ChainKey([u8; 32]);

impl Drop for ChainKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ChainKey {
    fn advance(&self) -> (ChainKey, [u8; 32]) {
        (
            ChainKey(hmac32(&self.0, LABEL_NEXT_CHAIN)),
            hmac32(&self.0, LABEL_MESSAGE_KEY),
        )
    }
}

fn hmac32(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

/// Seals `plaintext` (already including the leading message-type byte)
/// under a single-use key with an all-zero nonce. Reusing a zero nonce is
/// safe here specifically *because* the key is single-use: AEAD security
/// only requires the (key, nonce) pair be unique per encryption, and a
/// fresh, never-reused key makes that trivially true regardless of nonce.
fn seal_with_message_key(message_key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, Payload},
        ChaCha20Poly1305, Key, KeyInit, Nonce,
    };
    let cipher = ChaCha20Poly1305::new(&Key::from(*message_key));
    cipher
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn open_with_message_key(message_key: &[u8; 32], aad: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, Payload},
        ChaCha20Poly1305, Key, KeyInit, Nonce,
    };
    let cipher = ChaCha20Poly1305::new(&Key::from(*message_key));
    cipher
        .decrypt(&Nonce::from([0u8; 12]), Payload { msg: record, aad })
        .map_err(|_| Error::Decrypt)
}

/// One receive-side chain, tagged with the epoch it belongs to and the
/// sequence number it expects next (strict in-order, per epoch).
struct RecvChain {
    epoch: u32,
    chain: ChainKey,
    expected_seq: u64,
}

/// A [`crate::handshake::EstablishedSession`] upgraded with per-message
/// forward secrecy and an explicit, coordinated hybrid-PQ ratchet step.
/// See the module docs for exactly what this does and does not match
/// from Signal's SPQR.
pub struct RatchetedSession {
    root_key: [u8; 32],
    send_epoch: u32,
    send_chain: ChainKey,
    send_seq: u64,
    recv_current: RecvChain,
    recv_previous: Option<RecvChain>,
    pending: Option<InitiatorKex>,
    pending_epoch: u32,
}

/// A message decoded by [`RatchetedSession::open`]: either application
/// data the caller should deliver upward, or an internal ratchet-control
/// message this call already fully processed (nothing further to do).
pub enum Opened {
    Application(Vec<u8>),
    /// A ratchet-control message was fully processed internally
    /// (including switching to the new epoch). `reply` is `Some` when
    /// this was the peer's step 1 and a step-2 reply was generated and
    /// sealed under the *old* epoch — the caller must send it back —
    /// and `None` when this was the peer's step 2, which needs no reply.
    RatchetAdvanced {
        reply: Option<Vec<u8>>,
    },
}

impl RatchetedSession {
    /// Builds epoch-0 chains directly from the handshake's `ratchet_root`
    /// — no KEX needed yet, since the handshake itself already did one.
    pub fn new(session: &EstablishedSession, is_initiator: bool) -> Self {
        let (send_label, recv_label) = if is_initiator {
            (LABEL_INIT_SEND, LABEL_INIT_RECV)
        } else {
            (LABEL_INIT_RECV, LABEL_INIT_SEND)
        };
        let send_chain = ChainKey(hmac32(&session.ratchet_root, send_label));
        let recv_chain = ChainKey(hmac32(&session.ratchet_root, recv_label));

        RatchetedSession {
            root_key: session.ratchet_root,
            send_epoch: 0,
            send_chain,
            send_seq: 0,
            recv_current: RecvChain {
                epoch: 0,
                chain: recv_chain,
                expected_seq: 0,
            },
            recv_previous: None,
            pending: None,
            pending_epoch: 0,
        }
    }

    /// Seals one application-data record. Safe to call at any time,
    /// including while a ratchet step is pending — see the module docs
    /// on why that doesn't race with epoch transitions.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(1 + plaintext.len());
        payload.push(MSG_APPLICATION);
        payload.extend_from_slice(plaintext);
        self.seal_payload(&payload)
    }

    /// Starts a ratchet step: generates fresh hybrid KEX material, seals
    /// it as a control message under the *current* send chain, and
    /// leaves the epoch transition pending until the peer's reply is
    /// processed by [`Self::open`].
    pub fn initiate_ratchet(&mut self) -> Result<Vec<u8>> {
        if self.pending.is_some() {
            return Err(Error::RatchetInProgress);
        }
        let kex = InitiatorKex::generate();

        let mut w = Writer::new();
        w.put_fixed(kex.x25519_public().as_bytes());
        w.put_var(&kex.ml_kem_public().to_bytes());

        let mut payload = Vec::with_capacity(1 + w.0.len());
        payload.push(MSG_RATCHET_STEP1);
        payload.extend_from_slice(&w.0);

        let record = self.seal_payload(&payload)?;
        self.pending = Some(kex);
        self.pending_epoch = self.send_epoch;
        Ok(record)
    }

    fn seal_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let (next_chain, message_key) = self.send_chain.advance();
        let epoch = self.send_epoch;
        let seq = self.send_seq;
        self.send_seq = self
            .send_seq
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;

        let aad = header_bytes(epoch, seq);
        let ciphertext = seal_with_message_key(&message_key, &aad, payload)?;
        self.send_chain = next_chain;

        let mut out = Vec::with_capacity(aad.len() + ciphertext.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens one record. Ratchet-control messages (steps 1 and 2) are
    /// fully handled internally — including switching to the new epoch —
    /// and reported back as [`Opened::RatchetAdvanced`] rather than
    /// handed to the caller.
    pub fn open(&mut self, record: &[u8]) -> Result<Opened> {
        if record.len() < 12 {
            return Err(Error::Malformed("ratchet record shorter than header"));
        }
        let epoch = u32::from_be_bytes(
            record[..4]
                .try_into()
                .expect("length already checked above"),
        );
        let seq = u64::from_be_bytes(
            record[4..12]
                .try_into()
                .expect("length already checked above"),
        );
        let aad = &record[..12];
        let ciphertext = &record[12..];

        let plaintext = if epoch == self.recv_current.epoch {
            self.open_on(RecvSlot::Current, seq, aad, ciphertext)?
        } else if self
            .recv_previous
            .as_ref()
            .is_some_and(|p| p.epoch == epoch)
        {
            self.open_on(RecvSlot::Previous, seq, aad, ciphertext)?
        } else {
            return Err(Error::UnknownEpoch);
        };

        if plaintext.is_empty() {
            return Err(Error::Malformed("empty ratchet payload"));
        }
        match plaintext[0] {
            MSG_APPLICATION => Ok(Opened::Application(plaintext[1..].to_vec())),
            MSG_RATCHET_STEP1 => {
                let reply = self.handle_step1(epoch, &plaintext[1..])?;
                Ok(Opened::RatchetAdvanced { reply: Some(reply) })
            }
            MSG_RATCHET_STEP2 => {
                self.handle_step2(epoch, &plaintext[1..])?;
                Ok(Opened::RatchetAdvanced { reply: None })
            }
            _ => Err(Error::Malformed("unknown ratchet message type")),
        }
    }

    fn open_on(
        &mut self,
        slot: RecvSlot,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let recv = match slot {
            RecvSlot::Current => &self.recv_current,
            RecvSlot::Previous => self
                .recv_previous
                .as_ref()
                .expect("caller only reaches Previous when recv_previous is Some"),
        };
        if seq != recv.expected_seq {
            return Err(Error::Replay);
        }
        let (next_chain, message_key) = recv.chain.advance();
        let plaintext = open_with_message_key(&message_key, aad, ciphertext)?;

        // Only commit the chain advance once decryption actually
        // succeeded — a forged or corrupted record must not be able to
        // desync the real receive chain.
        let recv = match slot {
            RecvSlot::Current => &mut self.recv_current,
            RecvSlot::Previous => self
                .recv_previous
                .as_mut()
                .expect("caller only reaches Previous when recv_previous is Some"),
        };
        recv.chain = next_chain;
        recv.expected_seq += 1;
        Ok(plaintext)
    }

    fn handle_step1(&mut self, epoch: u32, payload: &[u8]) -> Result<Vec<u8>> {
        if self.pending.is_some() {
            return Err(Error::RatchetInProgress);
        }
        let mut r = Reader::new(payload);
        let peer_x25519 = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let peer_ml_kem = kex::ml_kem_public_from_bytes(r.get_var()?)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in ratchet step1"));
        }

        let kex_out = kex::responder_exchange(&peer_x25519, &peer_ml_kem)?;

        let mut w = Writer::new();
        w.put_fixed(kex_out.x25519_public.as_bytes());
        w.put_var(&kex_out.ml_kem_ciphertext);
        let mut reply_payload = Vec::with_capacity(1 + w.0.len());
        reply_payload.push(MSG_RATCHET_STEP2);
        reply_payload.extend_from_slice(&w.0);

        // The reply itself must still go out under the *old* send chain —
        // the epoch only switches once it's on the wire.
        let reply = self.seal_payload(&reply_payload)?;

        let (new_root, new_send, new_recv) =
            derive_next_epoch(&self.root_key, &kex_out.shared_secret, false);
        self.advance_epoch(epoch, new_root, new_send, new_recv);

        Ok(reply)
    }

    fn handle_step2(&mut self, epoch: u32, payload: &[u8]) -> Result<()> {
        let kex = match self.pending.take() {
            Some(kex) if self.pending_epoch == epoch => kex,
            Some(kex) => {
                self.pending = Some(kex);
                return Err(Error::WrongState);
            }
            None => return Err(Error::WrongState),
        };

        let mut r = Reader::new(payload);
        let peer_x25519 = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let ml_kem_ct = kex::ml_kem_ciphertext_from_bytes(r.get_var()?)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in ratchet step2"));
        }

        let shared_secret = kex.finish(&peer_x25519, &ml_kem_ct)?;
        let (new_root, new_send, new_recv) =
            derive_next_epoch(&self.root_key, &shared_secret, true);
        self.advance_epoch(epoch, new_root, new_send, new_recv);
        Ok(())
    }

    fn advance_epoch(
        &mut self,
        old_epoch: u32,
        new_root: [u8; 32],
        new_send: [u8; 32],
        new_recv: [u8; 32],
    ) {
        let new_epoch = old_epoch + 1;
        self.root_key = new_root;
        self.send_epoch = new_epoch;
        self.send_chain = ChainKey(new_send);
        self.send_seq = 0;

        let old_current = std::mem::replace(
            &mut self.recv_current,
            RecvChain {
                epoch: new_epoch,
                chain: ChainKey(new_recv),
                expected_seq: 0,
            },
        );
        self.recv_previous = Some(old_current);
    }
}

enum RecvSlot {
    Current,
    Previous,
}

fn header_bytes(epoch: u32, seq: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&epoch.to_be_bytes());
    out[4..].copy_from_slice(&seq.to_be_bytes());
    out
}

/// Derives the next epoch's root key and both directional chain keys from
/// the previous root key and a fresh shared secret, mirroring
/// `handshake::finalize_keys`'s shape.
fn derive_next_epoch(
    root_key: &[u8; 32],
    shared_secret: &kex::SharedSecret,
    is_initiator: bool,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(root_key.as_slice()), &shared_secret.0);
    let hk = Hkdf::<Sha256>::from_prk(&prk).expect("HKDF PRK is always the SHA-256 output length");

    let mut new_root = [0u8; 32];
    hk.expand(LABEL_STEP_ROOT, &mut new_root)
        .expect("32-byte output is within HKDF-SHA256's expand limit");
    let mut i2r = [0u8; 32];
    hk.expand(LABEL_STEP_I2R, &mut i2r)
        .expect("32-byte output is within HKDF-SHA256's expand limit");
    let mut r2i = [0u8; 32];
    hk.expand(LABEL_STEP_R2I, &mut r2i)
        .expect("32-byte output is within HKDF-SHA256's expand limit");

    if is_initiator {
        (new_root, i2r, r2i)
    } else {
        (new_root, r2i, i2r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{initiator_start, responder_respond};
    use crate::identity::Identity;

    fn pair() -> (RatchetedSession, RatchetedSession) {
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let (init_state, msg1) = initiator_start(None);
        let (resp_state, msg2) = responder_respond(&server_identity, None, &msg1).unwrap();
        let (msg3, client_session) = init_state.complete(&client_identity, &msg2).unwrap();
        let server_session = resp_state.complete(&msg3).unwrap();

        (
            RatchetedSession::new(&client_session, true),
            RatchetedSession::new(&server_session, false),
        )
    }

    // The four tests below reach internal error branches (a too-short
    // ratchet record, an empty decrypted payload, an unrecognized message
    // type, trailing bytes inside a ratchet-control payload) that the
    // public API in `crates/core/tests/ratchet.rs` never produces on its
    // own — every real caller of `seal`/`initiate_ratchet` always writes a
    // well-formed payload. Reaching them needs the same private
    // `seal_payload` the public methods use internally, which is only
    // available from inside this module.

    #[test]
    fn a_record_shorter_than_the_header_is_rejected() {
        let (_client, mut server) = pair();
        assert!(matches!(server.open(&[0u8; 4]), Err(Error::Malformed(_))));
    }

    #[test]
    fn an_empty_decrypted_payload_is_rejected() {
        let (mut client, mut server) = pair();
        let record = client.seal_payload(&[]).unwrap();
        assert!(matches!(server.open(&record), Err(Error::Malformed(_))));
    }

    #[test]
    fn an_unrecognized_message_type_is_rejected() {
        let (mut client, mut server) = pair();
        let record = client.seal_payload(&[99u8]).unwrap();
        assert!(matches!(server.open(&record), Err(Error::Malformed(_))));
    }

    #[test]
    fn trailing_bytes_in_a_ratchet_step1_payload_are_rejected() {
        let (mut client, mut server) = pair();

        let kex = InitiatorKex::generate();
        let mut w = Writer::new();
        w.put_fixed(kex.x25519_public().as_bytes());
        w.put_var(&kex.ml_kem_public().to_bytes());
        let mut payload = Vec::new();
        payload.push(MSG_RATCHET_STEP1);
        payload.extend_from_slice(&w.0);
        payload.push(0xFF); // trailing garbage

        let record = client.seal_payload(&payload).unwrap();
        assert!(matches!(server.open(&record), Err(Error::Malformed(_))));
    }

    #[test]
    fn trailing_bytes_in_a_ratchet_step2_payload_are_rejected() {
        let (mut client, mut server) = pair();
        // Client has a real pending ratchet at epoch 0, matching the forged
        // reply's epoch tag below.
        client.initiate_ratchet().unwrap();

        let decoy_initiator = InitiatorKex::generate();
        let responder_kex_out = kex::responder_exchange(
            decoy_initiator.x25519_public(),
            decoy_initiator.ml_kem_public(),
        )
        .unwrap();
        let mut w = Writer::new();
        w.put_fixed(responder_kex_out.x25519_public.as_bytes());
        w.put_var(&responder_kex_out.ml_kem_ciphertext);
        let mut payload = Vec::new();
        payload.push(MSG_RATCHET_STEP2);
        payload.extend_from_slice(&w.0);
        payload.push(0xFF); // trailing garbage

        // Sealed under the server's still-current epoch-0 send chain, which
        // the client's epoch-0 recv chain can decrypt.
        let record = server.seal_payload(&payload).unwrap();
        assert!(matches!(client.open(&record), Err(Error::Malformed(_))));
    }

    #[test]
    fn a_step2_reply_at_an_epoch_other_than_the_pending_one_is_rejected_and_pending_survives() {
        let (mut client, _server) = pair();
        client.initiate_ratchet().unwrap();
        assert_eq!(client.pending_epoch, 0);

        let result = client.handle_step2(1, &[0u8; 32]);
        assert!(matches!(result, Err(Error::WrongState)));
        // The mismatched reply must not have consumed the real pending
        // ratchet — a later, correctly-tagged reply should still work.
        assert!(client.pending.is_some());
    }

    #[test]
    fn a_step2_reply_with_no_pending_ratchet_is_rejected() {
        let (_client, mut server) = pair();
        assert!(server.pending.is_none());
        let result = server.handle_step2(0, &[0u8; 32]);
        assert!(matches!(result, Err(Error::WrongState)));
    }
}
