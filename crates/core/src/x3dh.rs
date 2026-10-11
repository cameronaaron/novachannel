//! Asynchronous, deniable session establishment: X3DH (Signal's original
//! design) with a hybrid ML-KEM-1024 leg, as Signal's PQXDH extends it.
//!
//! # Why this exists alongside [`crate::handshake`]
//! `crate::handshake`'s 3-message protocol needs both peers online and
//! authenticates by *signing the transcript* with each long-term
//! [`crate::identity::Identity`]. That makes it non-repudiable: a completed
//! transcript proves to third parties that an identity key took part.
//! Useful for an audit trail, but a cost for private messaging, where a
//! leaked or subpoenaed transcript shouldn't prove who said what.
//!
//! This module yields the same [`crate::handshake::EstablishedSession`],
//! which plugs into [`crate::ratchet`] and [`crate::transport`] unchanged,
//! with two differences:
//!
//! - **Asynchronous.** The initiator needs only the responder's published
//!   [`crate::prekey::PreKeyBundle`], no live round trip.
//! - **Deniable.** The only signature is the bundle's
//!   [`crate::prekey::SignedPreKey`] signature over a medium-term key shared
//!   by many sessions. Authentication comes from combining DH/KEM values
//!   (`DH1..DH4` below), each computable by either party *alone* from its
//!   own private keys and the other's public keys. So either party could
//!   have fabricated a transcript, and it proves nothing about the other's
//!   participation.
//!
//! # The combination
//! Initiator A (ephemeral `EK_a`, DH identity `IK_a`) against responder
//! B's bundle (DH identity `IK_b`, signed prekey `SPK_b` with DH and ML-KEM
//! halves, optional one-time prekey `OPK_b`):
//!
//! ```text
//! DH1 = DH(IK_a,  SPK_b)   -- binds A's long-term identity
//! DH2 = DH(EK_a,  IK_b)    -- binds B's long-term identity
//! DH3 = DH(EK_a,  SPK_b)   -- fresh per session (EK_a is ephemeral)
//! DH4 = DH(EK_a,  OPK_b)   -- only with an OPK; its secret is deleted after
//!                             one use, so it survives a later full
//!                             compromise of IK_b and SPK_b
//! SS_pq  = ML-KEM-1024 encapsulated to SPK_b's KEM key
//! SS_pq' = ML-KEM-1024 encapsulated to OPK_b's KEM key -- only with DH4,
//!                             deleted after one use, so it survives a later
//!                             compromise of SPK_b's ML-KEM secret
//! SK = HKDF(DH1 || DH2 || DH3 || [DH4] || SS_pq || [SS_pq'])
//! ```
//!
//! DH2 and DH3 alone give forward secrecy but no authentication: anyone
//! could play A. DH1 authenticates A, since only A (or B, from its SPK
//! secret and `IK_a`) can compute it. Likewise B could have produced DH2
//! unilaterally, so B can't prove it to a third party: that symmetry is the
//! deniability.
//!
//! # What this scheme does not give you
//! - **Forward secrecy against compromise of `SPK_b`'s secret** for sessions
//!   that used no one-time prekey (or ran after they were exhausted).
//!   `SPK_b` is reused by design (that's what makes the scheme
//!   asynchronous), so a live compromise plus a recorded transcript
//!   recovers `SK` for every session without a since-deleted OPK. Real
//!   X3DH makes the same tradeoff; `crate::ratchet`'s re-key is the layer
//!   that recovers from it.
//! - **Liveness confirmation or init-message replay tracking.** The
//!   responder may process the message long after it was sent. Once
//!   established, `crate::transport`'s replay protection applies, but
//!   replaying the init message itself establishes the same `SK` again;
//!   callers who care should track init-message hashes.

use hkdf::Hkdf;
use kem::Encapsulate;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::handshake::{EstablishedSession, PeerInfo};
use crate::identity::PublicIdentity;
use crate::kex;
use crate::prekey::{DhIdentity, OneTimePreKeyStore, PreKeyBundle, SignedPreKey};
use crate::rng::csprng;
use crate::transport::{DirectionalKey, Receiver, Sender};
use crate::wire::{Reader, Writer};

const LABEL_I2R: &[u8] = b"novachannel x3dh v1 initiator->responder";
const LABEL_R2I: &[u8] = b"novachannel x3dh v1 responder->initiator";
const LABEL_RATCHET_ROOT: &[u8] = b"novachannel x3dh v1 ratchet root";
const LABEL_INIT_PAYLOAD: &[u8] = b"novachannel x3dh v1 init payload key";
/// AAD for the init message's sealed payload: all public fields before it,
/// so the payload can't be spliced onto another message's header.
const PAYLOAD_AAD_CONTEXT: &[u8] = b"novachannel x3dh v1 init payload";

/// The combined DH/KEM input keying material, zeroized on drop. Never
/// leaves this module.
struct CombinedSecret(Vec<u8>);

impl Drop for CombinedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Everything derived from one X3DH combination: both directional
/// transport keys, the ratchet seed, and a single-use key for the init
/// payload (sealed before either `Sender` exists, so it can't share their
/// sequence spaces). `i2r`/`r2i` are `Option` only so the `Drop` impl can
/// coexist with [`SessionKeys::take_directional_keys`] moving them out; they
/// are `Some` until that single call.
struct SessionKeys {
    i2r: Option<DirectionalKey>,
    r2i: Option<DirectionalKey>,
    ratchet_root: [u8; 32],
    init_payload_key: [u8; 32],
}

impl SessionKeys {
    /// Takes both directional keys, leaving `self` to zeroize the two raw
    /// arrays it still owns when it drops at the end of the caller's scope.
    fn take_directional_keys(&mut self) -> (DirectionalKey, DirectionalKey) {
        (
            self.i2r
                .take()
                .expect("taken exactly once, right after derive()"),
            self.r2i
                .take()
                .expect("taken exactly once, right after derive()"),
        )
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        // `i2r`/`r2i` zeroize their AEAD state on drop (chacha20poly1305's
        // `zeroize` feature) wherever they are; the two raw arrays held here get
        // the same treatment as `CombinedSecret`'s keying material.
        self.ratchet_root.zeroize();
        self.init_payload_key.zeroize();
    }
}

fn derive(combined: &CombinedSecret) -> Result<SessionKeys> {
    let (prk, _) = Hkdf::<Sha256>::extract(None, &combined.0);
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;

    let mut okm_i2r = [0u8; 44];
    hk.expand(LABEL_I2R, &mut okm_i2r)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    let mut okm_r2i = [0u8; 44];
    hk.expand(LABEL_R2I, &mut okm_r2i)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    let mut ratchet_root = [0u8; 32];
    hk.expand(LABEL_RATCHET_ROOT, &mut ratchet_root)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    let mut init_payload_key = [0u8; 32];
    hk.expand(LABEL_INIT_PAYLOAD, &mut init_payload_key)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;

    let keys = SessionKeys {
        i2r: Some(DirectionalKey::new(
            okm_i2r[..32].try_into().expect("okm_i2r is 44 bytes"),
            okm_i2r[32..].try_into().expect("okm_i2r is 44 bytes"),
        )),
        r2i: Some(DirectionalKey::new(
            okm_r2i[..32].try_into().expect("okm_r2i is 44 bytes"),
            okm_r2i[32..].try_into().expect("okm_r2i is 44 bytes"),
        )),
        ratchet_root,
        init_payload_key,
    };
    okm_i2r.zeroize();
    okm_r2i.zeroize();
    Ok(keys)
}

/// Single-use key with an all-zero nonce, safe for the reason
/// `crate::ratchet::seal_with_message_key` gives: `init_payload_key` is
/// fresh per session and used once.
fn seal_init_payload(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Key, Nonce,
    };
    ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn open_init_payload(key: &[u8; 32], aad: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Key, Nonce,
    };
    ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&Nonce::from([0u8; 12]), Payload { msg: record, aad })
        .map_err(|_| Error::Decrypt)
}

/// The one message an initiator sends to start a session; nothing more is
/// needed until the responder, whenever online, replies over the
/// transport.
pub struct InitMessage {
    pub bytes: Vec<u8>,
}

/// What the initiator gets from [`initiate`]: the wire message to send and
/// the session, already established locally (X3DH completes for the
/// initiator in one step, with no msg2 to wait for).
pub struct InitiatedSession {
    pub message: InitMessage,
    pub session: EstablishedSession,
}

/// Starts a session against `peer_bundle`. `my_signing_identity` is
/// embedded, not signed (module docs), so the responder learns who is
/// talking; `initial_payload` travels with it. Both are protected by the
/// session's AEAD key.
///
/// Call [`PreKeyBundle::verify`] on `peer_bundle` first (or otherwise trust
/// its transport); this function doesn't, matching [`crate::handshake`]:
/// peer trust provisioning is the caller's job.
pub fn initiate(
    my_signing_identity: &PublicIdentity,
    my_dh_identity: &DhIdentity,
    peer_bundle: &PreKeyBundle,
    initial_payload: &[u8],
) -> Result<InitiatedSession> {
    let mut rng = csprng();
    // `ReusableSecret`, not `EphemeralSecret`: this key is DH'd with up to
    // three peer keys (`IK_b`, `SPK_b`, maybe `OPK_b`), and
    // `EphemeralSecret::diffie_hellman` consumes `self`. It still serves one
    // handshake and is dropped at the end of this function.
    let ephemeral_secret = x25519_dalek::ReusableSecret::random_from_rng(&mut rng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    // Each is checked against small-order peer keys (`kex::checked_dh`): a DH
    // term contributing nothing must not slip into the combined secret.
    let dh1 = my_dh_identity.diffie_hellman(peer_bundle.spk_dh_public())?;
    let dh2 = kex::checked_dh(ephemeral_secret.diffie_hellman(&peer_bundle.dh_identity))?;
    let dh3 = kex::checked_dh(ephemeral_secret.diffie_hellman(peer_bundle.spk_dh_public()))?;
    let dh4 = peer_bundle
        .one_time_prekey
        .as_ref()
        .map(|(_, opk_pub, _)| kex::checked_dh(ephemeral_secret.diffie_hellman(opk_pub)))
        .transpose()?;

    let (ml_kem_ct, ml_kem_ss) = peer_bundle.spk_kem_public().encapsulate_with_rng(&mut rng);
    // Only with an OPK: like DH4, its secret is deleted once the responder
    // consumes it, giving the ML-KEM leg the same single-use forward secrecy
    // (see `OneTimePreKey`).
    let ml_kem_opk = peer_bundle
        .one_time_prekey
        .as_ref()
        .map(|(_, _, opk_kem_pub)| opk_kem_pub.encapsulate_with_rng(&mut rng));

    let mut combined_bytes = Vec::with_capacity(32 * 4 + 32 * 2);
    combined_bytes.extend_from_slice(dh1.as_bytes());
    combined_bytes.extend_from_slice(dh2.as_bytes());
    combined_bytes.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = &dh4 {
        combined_bytes.extend_from_slice(dh4.as_bytes());
    }
    combined_bytes.extend_from_slice(&ml_kem_ss);
    if let Some((_, opk_ss)) = &ml_kem_opk {
        combined_bytes.extend_from_slice(opk_ss);
    }
    let combined = CombinedSecret(combined_bytes);
    let mut keys = derive(&combined)?;

    let mut w = Writer::new();
    w.put_fixed(my_dh_identity.public().as_bytes());
    w.put_fixed(ephemeral_public.as_bytes());
    w.put_var(&ml_kem_ct);
    match &peer_bundle.one_time_prekey {
        Some((id, _, _)) => {
            w.put_fixed(&[1]);
            w.put_fixed(&id.to_be_bytes());
            let (opk_ct, _) = ml_kem_opk.as_ref().expect("set together with dh4 above");
            w.put_var(opk_ct);
        }
        None => w.put_fixed(&[0]),
    }
    let header_bytes = w.0.clone();

    let mut payload_w = Writer::new();
    my_signing_identity.write(&mut payload_w);
    payload_w.put_var(initial_payload);
    let payload_plaintext = payload_w.into_bytes();

    let mut aad = Vec::with_capacity(PAYLOAD_AAD_CONTEXT.len() + header_bytes.len());
    aad.extend_from_slice(PAYLOAD_AAD_CONTEXT);
    aad.extend_from_slice(&header_bytes);
    let sealed_payload = seal_init_payload(&keys.init_payload_key, &aad, &payload_plaintext)?;
    w.put_var(&sealed_payload);

    let (i2r, r2i) = keys.take_directional_keys();
    Ok(InitiatedSession {
        message: InitMessage {
            bytes: w.into_bytes(),
        },
        session: EstablishedSession {
            peer: PeerInfo {
                identity: peer_bundle.identity.clone(),
            },
            sender: Sender::new(i2r),
            receiver: Receiver::new(r2i),
            ratchet_root: keys.ratchet_root,
        },
    })
}

/// What the responder gets from [`respond`]: the initiator's signing
/// identity (embedded in the message and not verified here; pinning it is
/// the caller's job, as in `crate::handshake`), the initial payload, and
/// the session.
pub struct RespondedSession {
    pub initiator_identity: PublicIdentity,
    pub initial_payload: Vec<u8>,
    pub session: EstablishedSession,
}

/// Processes an [`InitMessage`] with this responder's [`DhIdentity`],
/// [`SignedPreKey`] and, if referenced, a one-time prekey from `opks`,
/// which is permanently removed there: a second message naming the same
/// id fails with [`Error::UnknownOneTimePreKey`].
pub fn respond(
    my_dh_identity: &DhIdentity,
    my_spk: &SignedPreKey,
    opks: &mut OneTimePreKeyStore,
    init_message_bytes: &[u8],
) -> Result<RespondedSession> {
    let mut r = Reader::new(init_message_bytes);
    let initiator_dh_identity = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
    let initiator_ephemeral = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
    let ml_kem_ct = kex::ml_kem_ciphertext_from_bytes(r.get_var()?)?;
    let has_opk = r.get_fixed(1)?[0];
    let opk_id_and_ct = match has_opk {
        0 => None,
        1 => {
            let id = u32::from_be_bytes(
                r.get_fixed(4)?
                    .try_into()
                    .expect("get_fixed(4) already guarantees the length"),
            );
            let opk_ct = kex::ml_kem_ciphertext_from_bytes(r.get_var()?)?;
            Some((id, opk_ct))
        }
        _ => return Err(Error::Malformed("invalid one-time-prekey presence flag")),
    };
    let header_len = r.consumed();
    let header_bytes = &init_message_bytes[..header_len];
    let sealed_payload = r.get_var()?;
    if !r.finished() {
        return Err(Error::Malformed("trailing bytes in x3dh init message"));
    }

    // Borrow, don't consume yet: deleting it before the AEAD below proves the
    // sender could encrypt to this responder would let anyone burn the whole
    // prekey supply with garbage. See `OneTimePreKeyStore::peek`.
    let one_time_secret = opk_id_and_ct
        .as_ref()
        .map(|(id, _)| opks.peek(*id))
        .transpose()?;

    let dh1 = my_spk.diffie_hellman(&initiator_dh_identity)?;
    let dh2 = my_dh_identity.diffie_hellman(&initiator_ephemeral)?;
    let dh3 = my_spk.diffie_hellman(&initiator_ephemeral)?;
    let dh4 = one_time_secret
        .as_ref()
        .map(|opk| opk.diffie_hellman(&initiator_ephemeral))
        .transpose()?;
    let ml_kem_ss = my_spk.decapsulate(&ml_kem_ct);
    let ml_kem_opk_ss = one_time_secret
        .as_ref()
        .zip(opk_id_and_ct.as_ref())
        .map(|(opk, (_, opk_ct))| opk.decapsulate(opk_ct));

    let mut combined_bytes = Vec::with_capacity(32 * 4 + 32 * 2);
    combined_bytes.extend_from_slice(dh1.as_bytes());
    combined_bytes.extend_from_slice(dh2.as_bytes());
    combined_bytes.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = &dh4 {
        combined_bytes.extend_from_slice(dh4.as_bytes());
    }
    combined_bytes.extend_from_slice(&ml_kem_ss);
    if let Some(opk_ss) = &ml_kem_opk_ss {
        combined_bytes.extend_from_slice(opk_ss);
    }
    let combined = CombinedSecret(combined_bytes);
    let mut keys = derive(&combined)?;

    let mut aad = Vec::with_capacity(PAYLOAD_AAD_CONTEXT.len() + header_bytes.len());
    aad.extend_from_slice(PAYLOAD_AAD_CONTEXT);
    aad.extend_from_slice(header_bytes);
    let payload_plaintext = open_init_payload(&keys.init_payload_key, &aad, sealed_payload)?;

    // Authenticated: the prekey has genuinely been used for a session and
    // must never be used for another.
    if let Some((id, _)) = &opk_id_and_ct {
        opks.consume(*id);
    }

    let mut pr = Reader::new(&payload_plaintext);
    let initiator_identity = PublicIdentity::read(&mut pr)?;
    let initial_payload = pr.get_var()?.to_vec();
    if !pr.finished() {
        return Err(Error::Malformed("trailing bytes in x3dh init payload"));
    }

    let (i2r, r2i) = keys.take_directional_keys();
    let session = EstablishedSession {
        peer: PeerInfo {
            identity: initiator_identity.clone(),
        },
        sender: Sender::new(r2i),
        receiver: Receiver::new(i2r),
        ratchet_root: keys.ratchet_root,
    };

    Ok(RespondedSession {
        initiator_identity,
        initial_payload,
        session,
    })
}
