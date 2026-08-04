//! The 3-message mutually authenticated handshake.
//!
//! ```text
//! Initiator                                            Responder
//! ----------                                            ----------
//! eph_x25519_pub, eph_kyber_pub          -- msg1 -->
//!                                        <-- msg2 --   eph_x25519_pub, kyber_ct,
//!                                                       responder_identity,
//!                                                       sign(transcript_1)
//! initiator_identity, sign(transcript_2) -- msg3 -->
//! ```
//!
//! `transcript_1` covers msg1 and the unsigned fields of msg2; `transcript_2`
//! covers msg1, all of msg2, and the unsigned fields of msg3. Signing the
//! transcript rather than a fixed challenge binds each party's identity to
//! *this specific exchange* — the ephemeral keys, the peer's identity, and
//! (transitively) everything each side has committed to so far — which is
//! what rules out a handshake being spliced together from pieces of two
//! different sessions.
//!
//! Traffic keys are derived only after both signatures verify, from a hash
//! covering the *entire* transcript including both signatures. This gives
//! the resulting channel a binding to the full handshake ("channel
//! binding"): the traffic keys themselves are evidence that both parties
//! saw and authenticated the same exchange.
//!
//! Peer authentication is by explicit pinning: callers pass the
//! [`crate::identity::PublicIdentity`] they expect to talk to. There is no
//! CA hierarchy here — that's a deliberate scope boundary, not an oversight.
//! Trust provisioning (how you learn a peer's identity out of band) is left
//! to the application, the same way SSH leaves host-key provisioning to the
//! operator.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use kem::KeyExport;

use crate::error::{Error, Result};
use crate::identity::{HybridSignature, Identity, PublicIdentity};
use crate::kex::{self, InitiatorKex};
use crate::transport::{DirectionalKey, Receiver, Sender};
use crate::wire::{Reader, Writer};

const CONTEXT: &[u8] = b"novachannel v1";
const LABEL_I2R: &[u8] = b"novachannel v1 initiator->responder";
const LABEL_R2I: &[u8] = b"novachannel v1 responder->initiator";
const LABEL_RATCHET_ROOT: &[u8] = b"novachannel v1 ratchet root";

/// Confirmed identity of the peer, returned once the handshake completes.
pub struct PeerInfo {
    pub identity: PublicIdentity,
}

pub struct EstablishedSession {
    pub peer: PeerInfo,
    pub sender: Sender,
    pub receiver: Receiver,
    /// Seeds [`crate::ratchet::RatchetedSession`] for callers who want
    /// per-message forward secrecy and periodic post-compromise re-keying
    /// on top of this session, instead of the fixed directional keys in
    /// `sender`/`receiver`. Derived from the same handshake transcript
    /// hash via a distinct HKDF label, so it's cryptographically
    /// independent of the transport keys above.
    pub ratchet_root: [u8; 32],
}

fn derive_directional_key(prk: &Hkdf<Sha256>, label: &[u8]) -> Result<DirectionalKey> {
    let mut okm = [0u8; 44];
    prk.expand(label, &mut okm)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    let key: [u8; 32] = okm[..32]
        .try_into()
        .expect("okm is a fixed-size [u8; 44] array");
    let iv: [u8; 12] = okm[32..]
        .try_into()
        .expect("okm is a fixed-size [u8; 44] array");
    Ok(DirectionalKey::new(&key, &iv))
}

fn finalize_keys(
    shared_secret: &kex::SharedSecret,
    transcript_final: &[u8],
    is_initiator: bool,
) -> Result<(Sender, Receiver, [u8; 32])> {
    let transcript_hash = Sha256::digest(transcript_final);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(transcript_hash.as_slice()), &shared_secret.0);
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;

    let i2r = derive_directional_key(&hk, LABEL_I2R)?;
    let r2i = derive_directional_key(&hk, LABEL_R2I)?;

    let mut ratchet_root = [0u8; 32];
    hk.expand(LABEL_RATCHET_ROOT, &mut ratchet_root)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;

    Ok(if is_initiator {
        (Sender::new(i2r), Receiver::new(r2i), ratchet_root)
    } else {
        (Sender::new(r2i), Receiver::new(i2r), ratchet_root)
    })
}

/// Initiator-side handshake state, holding only what's needed to validate
/// msg2 and build msg3. The caller's long-term [`Identity`] is passed by
/// reference into [`InitiatorHandshakeState::complete`] rather than stored
/// here, since it's only needed once, at the very end.
pub struct InitiatorHandshakeState {
    kex: InitiatorKex,
    msg1_bytes: Vec<u8>,
    expected_responder: Option<PublicIdentity>,
}

pub fn initiator_start(
    expected_responder: Option<PublicIdentity>,
) -> (InitiatorHandshakeState, Vec<u8>) {
    let kex = InitiatorKex::generate();

    let mut w = Writer::new();
    w.put_fixed(kex.x25519_public().as_bytes());
    w.put_var(&kex.ml_kem_public().to_bytes());
    let msg1_bytes = w.into_bytes();

    (
        InitiatorHandshakeState {
            kex,
            msg1_bytes: msg1_bytes.clone(),
            expected_responder,
        },
        msg1_bytes,
    )
}

impl InitiatorHandshakeState {
    /// Consume msg2, verify the responder's proof of identity, and produce
    /// msg3 plus the fully established session.
    pub fn complete(
        self,
        local_identity: &Identity,
        msg2_bytes: &[u8],
    ) -> Result<(Vec<u8>, EstablishedSession)> {
        let mut r = Reader::new(msg2_bytes);
        let responder_x25519 = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let ml_kem_ct = kex::ml_kem_ciphertext_from_bytes(r.get_var()?)?;
        let responder_identity = PublicIdentity::read(&mut r)?;
        let signed_len = r.consumed();
        let sig = HybridSignature::read(&mut r)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in msg2"));
        }

        if let Some(expected) = &self.expected_responder {
            if expected != &responder_identity {
                return Err(Error::IdentityMismatch);
            }
        }

        let mut transcript_1 =
            Vec::with_capacity(CONTEXT.len() + self.msg1_bytes.len() + signed_len);
        transcript_1.extend_from_slice(CONTEXT);
        transcript_1.extend_from_slice(&self.msg1_bytes);
        transcript_1.extend_from_slice(&msg2_bytes[..signed_len]);
        responder_identity.verify(&transcript_1, &sig)?;

        let shared_secret = self.kex.finish(&responder_x25519, &ml_kem_ct)?;

        let mut msg2_full = Vec::with_capacity(msg2_bytes.len());
        msg2_full.extend_from_slice(msg2_bytes);

        let mut w3 = Writer::new();
        local_identity.public().write(&mut w3);
        let msg3_signed_bytes = w3.0.clone();

        let mut transcript_2 = Vec::with_capacity(
            CONTEXT.len() + self.msg1_bytes.len() + msg2_full.len() + msg3_signed_bytes.len(),
        );
        transcript_2.extend_from_slice(CONTEXT);
        transcript_2.extend_from_slice(&self.msg1_bytes);
        transcript_2.extend_from_slice(&msg2_full);
        transcript_2.extend_from_slice(&msg3_signed_bytes);
        let sig3 = local_identity.sign(&transcript_2);
        sig3.write(&mut w3);
        let msg3_bytes = w3.into_bytes();

        let mut transcript_final = transcript_2;
        transcript_final.extend_from_slice(&msg3_bytes[msg3_signed_bytes.len()..]);

        let (sender, receiver, ratchet_root) =
            finalize_keys(&shared_secret, &transcript_final, true)?;

        Ok((
            msg3_bytes,
            EstablishedSession {
                peer: PeerInfo {
                    identity: responder_identity,
                },
                sender,
                receiver,
                ratchet_root,
            },
        ))
    }
}

pub struct ResponderHandshakeState {
    msg1_bytes: Vec<u8>,
    msg2_full: Vec<u8>,
    shared_secret: kex::SharedSecret,
    expected_initiator: Option<PublicIdentity>,
}

pub fn responder_respond(
    local_identity: &Identity,
    expected_initiator: Option<PublicIdentity>,
    msg1_bytes: &[u8],
) -> Result<(ResponderHandshakeState, Vec<u8>)> {
    let mut r = Reader::new(msg1_bytes);
    let initiator_x25519 = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
    let initiator_ml_kem = kex::ml_kem_public_from_bytes(r.get_var()?)?;
    if !r.finished() {
        return Err(Error::Malformed("trailing bytes in msg1"));
    }

    let kex_out = kex::responder_exchange(&initiator_x25519, &initiator_ml_kem)?;

    let mut w = Writer::new();
    w.put_fixed(kex_out.x25519_public.as_bytes());
    w.put_var(&kex_out.ml_kem_ciphertext);
    local_identity.public().write(&mut w);
    let msg2_signed_bytes = w.0.clone();

    let mut transcript_1 =
        Vec::with_capacity(CONTEXT.len() + msg1_bytes.len() + msg2_signed_bytes.len());
    transcript_1.extend_from_slice(CONTEXT);
    transcript_1.extend_from_slice(msg1_bytes);
    transcript_1.extend_from_slice(&msg2_signed_bytes);
    let sig = local_identity.sign(&transcript_1);
    sig.write(&mut w);
    let msg2_bytes = w.into_bytes();

    Ok((
        ResponderHandshakeState {
            msg1_bytes: msg1_bytes.to_vec(),
            msg2_full: msg2_bytes.clone(),
            shared_secret: kex_out.shared_secret,
            expected_initiator,
        },
        msg2_bytes,
    ))
}

impl ResponderHandshakeState {
    pub fn complete(self, msg3_bytes: &[u8]) -> Result<EstablishedSession> {
        let mut r = Reader::new(msg3_bytes);
        let initiator_identity = PublicIdentity::read(&mut r)?;
        let signed_len = r.consumed();
        let sig = HybridSignature::read(&mut r)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in msg3"));
        }

        if let Some(expected) = &self.expected_initiator {
            if expected != &initiator_identity {
                return Err(Error::IdentityMismatch);
            }
        }

        let mut transcript_2 = Vec::with_capacity(
            CONTEXT.len() + self.msg1_bytes.len() + self.msg2_full.len() + signed_len,
        );
        transcript_2.extend_from_slice(CONTEXT);
        transcript_2.extend_from_slice(&self.msg1_bytes);
        transcript_2.extend_from_slice(&self.msg2_full);
        transcript_2.extend_from_slice(&msg3_bytes[..signed_len]);
        initiator_identity.verify(&transcript_2, &sig)?;

        let mut transcript_final = transcript_2;
        transcript_final.extend_from_slice(&msg3_bytes[signed_len..]);

        let (sender, receiver, ratchet_root) =
            finalize_keys(&self.shared_secret, &transcript_final, false)?;

        Ok(EstablishedSession {
            peer: PeerInfo {
                identity: initiator_identity,
            },
            sender,
            receiver,
            ratchet_root,
        })
    }
}
