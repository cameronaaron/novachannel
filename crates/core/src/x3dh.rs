//! Asynchronous, deniable session establishment — X3DH (Signal's original
//! design), extended with a hybrid ML-KEM-1024 leg the way Signal's own
//! PQXDH extends it.
//!
//! # Why this exists alongside [`crate::handshake`]
//! `crate::handshake`'s 3-message protocol needs both peers online at once
//! and authenticates by *signing the transcript* with each party's
//! long-term [`crate::identity::Identity`]. That signature is exactly what
//! makes the resulting proof non-repudiable: anyone holding a completed
//! transcript can show it to a third party as evidence "this identity key
//! authenticated this specific exchange." That's a feature for use cases
//! that want an audit trail (§ its own module docs), and a real cost for
//! private messaging, where a transcript leak or subpoena shouldn't be able
//! to prove who said what.
//!
//! This module produces the same [`crate::handshake::EstablishedSession`]
//! type — it plugs into [`crate::ratchet`] and [`crate::transport`]
//! unmodified — but two things differ:
//!
//! - **Asynchronous.** The initiator needs only the responder's published
//!   [`crate::prekey::PreKeyBundle`], not a live round trip.
//! - **Deniable.** The only signature involved anywhere in this exchange is
//!   the bundle's own [`crate::prekey::SignedPreKey`] signature — over a
//!   medium-term key reused across many sessions, not this one. Session
//!   authentication instead comes from Diffie-Hellman/KEM combination
//!   (`DH1..DH4` below): each party can compute every one of those values
//!   *alone*, given only their own private keys and the other party's
//!   public keys, with no cooperation or proof from the other side. That's
//!   the actual definition of deniability this scheme relies on: a
//!   transcript this module produces could have been fabricated end-to-end
//!   by either party alone, so it is not evidence the other party
//!   participated.
//!
//! # The combination, and why each term is there
//! For initiator A (ephemeral `EK_a`, DH identity `IK_a`) against
//! responder B's bundle (DH identity `IK_b`, signed prekey `SPK_b` with its
//! DH and ML-KEM halves, optional one-time prekey `OPK_b`):
//!
//! ```text
//! DH1 = DH(IK_a,  SPK_b)   -- binds A's long-term identity in
//! DH2 = DH(EK_a,  IK_b)    -- binds B's long-term identity in
//! DH3 = DH(EK_a,  SPK_b)   -- fresh per session (EK_a is ephemeral)
//! DH4 = DH(EK_a,  OPK_b)   -- present only if an OPK was available; the
//!                             one DH term whose secret is deleted after
//!                             one use, so it survives even a later,
//!                             full compromise of IK_b and SPK_b's secrets
//! SS_pq  = ML-KEM-1024 encapsulated against SPK_b's KEM public key
//! SS_pq' = ML-KEM-1024 encapsulated against OPK_b's KEM public key --
//!                             present only alongside DH4; deleted after one
//!                             use the same way, so it survives a later
//!                             compromise of SPK_b's ML-KEM secret too
//! SK = HKDF(DH1 || DH2 || DH3 || [DH4] || SS_pq || [SS_pq'])
//! ```
//!
//! Two DH terms alone (just DH2/DH3, "ephemeral-only") would give forward
//! secrecy but no authentication — anyone could run the protocol as A.
//! DH1 is what actually authenticates A to B: producing it requires A's
//! long-term secret, so only A (or B, who can compute the same value from
//! their own SPK secret and A's public `IK_a`) could have derived `SK`.
//! Symmetrically, DH2 is what a real X3DH gives B no way to *prove* to a
//! third party, because B could have produced it unilaterally too — that
//! symmetry is deniability, not a bug.
//!
//! # What this scheme does not give you
//! - **No forward secrecy against a compromise of `SPK_b`'s secret before
//!   the one-time prekey is exhausted or if none was available** — `SPK_b`
//!   is reused across many sessions by design (that's what makes the
//!   scheme asynchronous), so a live compromise of it plus a recorded
//!   transcript recovers `SK` for every session that didn't also consume a
//!   since-deleted one-time prekey. This is the exact tradeoff real X3DH
//!   makes, not a defect specific to this implementation; it's why
//!   `crate::ratchet`'s post-compromise re-key exists as the layer on top.
//! - **No explicit mutual "I am online and responding now" confirmation**
//!   — being asynchronous means the responder might process this message
//!   long after it was sent; ordinary AEAD replay protection in
//!   `crate::transport` still applies once the session is established, but
//!   the *handshake* message itself is a one-shot value, not something
//!   this crate tracks for replay on its own (an application resending the
//!   same init message would establish the same `SK` twice — callers that
//!   care should track init-message hashes at the application layer).

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
/// AAD binding for the init message's AEAD-sealed payload: everything
/// public in the message that precedes it, so a network attacker can't
/// splice the payload from one init message onto another's public header.
const PAYLOAD_AAD_CONTEXT: &[u8] = b"novachannel x3dh v1 init payload";

/// The combined DH/KEM input keying material, zeroized on drop. Never
/// leaves this module.
struct CombinedSecret(Vec<u8>);

impl Drop for CombinedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Everything derived from one X3DH combination: the two directional
/// transport keys, the ratchet seed, and a single-use key for the init
/// message's own payload (sealed before either directional `Sender` exists
/// to send anything, so it can't reuse either of their sequence spaces).
struct SessionKeys {
    i2r: DirectionalKey,
    r2i: DirectionalKey,
    ratchet_root: [u8; 32],
    init_payload_key: [u8; 32],
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

    Ok(SessionKeys {
        i2r: DirectionalKey::new(
            okm_i2r[..32].try_into().expect("okm_i2r is 44 bytes"),
            okm_i2r[32..].try_into().expect("okm_i2r is 44 bytes"),
        ),
        r2i: DirectionalKey::new(
            okm_r2i[..32].try_into().expect("okm_r2i is 44 bytes"),
            okm_r2i[32..].try_into().expect("okm_r2i is 44 bytes"),
        ),
        ratchet_root,
        init_payload_key,
    })
}

/// Seals under a single-use key with an all-zero nonce — safe here for the
/// same reason `crate::ratchet::seal_with_message_key` documents: AEAD
/// security only needs the (key, nonce) pair to be unique per encryption,
/// and `init_payload_key` is derived fresh per session and used exactly
/// once, ever.
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

/// The single, self-contained message an initiator sends to start a
/// session — nothing further is needed from them until the responder
/// (whenever they come online) replies over the established transport.
pub struct InitMessage {
    pub bytes: Vec<u8>,
}

/// Everything an initiator needs to know once [`initiate`] succeeds: the
/// wire message to send, and the session it already established locally
/// (X3DH, unlike `crate::handshake`, completes for the initiator in one
/// step — there is no msg2 to wait for).
pub struct InitiatedSession {
    pub message: InitMessage,
    pub session: EstablishedSession,
}

/// Starts a session against `peer_bundle`. `my_signing_identity` is
/// embedded (not signed — see module docs) so the responder learns who
/// they're talking to; `initial_payload` is application data delivered
/// alongside it, both protected by the session's own AEAD key derived
/// below.
///
/// Callers must call [`PreKeyBundle::verify`] on `peer_bundle` themselves
/// before this (or otherwise already trust its transport) — this function
/// does not verify it implicitly, matching [`crate::handshake`]'s existing
/// stance that peer trust provisioning is the caller's job.
pub fn initiate(
    my_signing_identity: &PublicIdentity,
    my_dh_identity: &DhIdentity,
    peer_bundle: &PreKeyBundle,
    initial_payload: &[u8],
) -> Result<InitiatedSession> {
    let mut rng = csprng();
    // A `ReusableSecret`, not `EphemeralSecret`: this key is DH'd against
    // up to three different peer public keys below (`IK_b`, `SPK_b`,
    // optionally `OPK_b`), which `EphemeralSecret::diffie_hellman`'s
    // by-value `self` can't do more than once. It's still used for exactly
    // one handshake and dropped at the end of this function either way.
    let ephemeral_secret = x25519_dalek::ReusableSecret::random_from_rng(&mut rng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let dh1 = my_dh_identity.diffie_hellman(peer_bundle.spk_dh_public());
    let dh2 = ephemeral_secret.diffie_hellman(&peer_bundle.dh_identity);
    let dh3 = ephemeral_secret.diffie_hellman(peer_bundle.spk_dh_public());
    let dh4 = peer_bundle
        .one_time_prekey
        .as_ref()
        .map(|(_, opk_pub, _)| ephemeral_secret.diffie_hellman(opk_pub));

    let (ml_kem_ct, ml_kem_ss) = peer_bundle.spk_kem_public().encapsulate_with_rng(&mut rng);
    // Encapsulated only if the bundle carried an OPK: like DH4, this term's
    // secret is deleted the moment the responder consumes it, so it gives
    // the ML-KEM leg the same single-use forward secrecy DH4 gives the
    // classical leg (see `OneTimePreKey`'s docs).
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
    let keys = derive(&combined)?;

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

    Ok(InitiatedSession {
        message: InitMessage {
            bytes: w.into_bytes(),
        },
        session: EstablishedSession {
            peer: PeerInfo {
                identity: peer_bundle.identity.clone(),
            },
            sender: Sender::new(keys.i2r),
            receiver: Receiver::new(keys.r2i),
            ratchet_root: keys.ratchet_root,
        },
    })
}

/// What a responder learns once [`respond`] succeeds: the initiator's
/// signing identity (embedded in the init message, not verified against
/// any external source here — pinning it is the caller's job, same as
/// `crate::handshake`), the initial application payload, and the
/// established session.
pub struct RespondedSession {
    pub initiator_identity: PublicIdentity,
    pub initial_payload: Vec<u8>,
    pub session: EstablishedSession,
}

/// Processes one initiator's [`InitMessage`] using this responder's own
/// long-term [`DhIdentity`], [`SignedPreKey`], and (if the message
/// references one) a one-time prekey drawn from `opks` — which is where
/// that prekey gets permanently removed, so a second init message
/// referencing the same id fails with [`Error::UnknownOneTimePreKey`]
/// rather than silently reusing it.
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

    let one_time_secret = opk_id_and_ct
        .as_ref()
        .map(|(id, _)| opks.take(*id))
        .transpose()?;

    let dh1 = my_spk.diffie_hellman(&initiator_dh_identity);
    let dh2 = my_dh_identity.diffie_hellman(&initiator_ephemeral);
    let dh3 = my_spk.diffie_hellman(&initiator_ephemeral);
    let dh4 = one_time_secret
        .as_ref()
        .map(|opk| opk.diffie_hellman(&initiator_ephemeral));
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
    let keys = derive(&combined)?;

    let mut aad = Vec::with_capacity(PAYLOAD_AAD_CONTEXT.len() + header_bytes.len());
    aad.extend_from_slice(PAYLOAD_AAD_CONTEXT);
    aad.extend_from_slice(header_bytes);
    let payload_plaintext = open_init_payload(&keys.init_payload_key, &aad, sealed_payload)?;

    let mut pr = Reader::new(&payload_plaintext);
    let initiator_identity = PublicIdentity::read(&mut pr)?;
    let initial_payload = pr.get_var()?.to_vec();
    if !pr.finished() {
        return Err(Error::Malformed("trailing bytes in x3dh init payload"));
    }

    let session = EstablishedSession {
        peer: PeerInfo {
            identity: initiator_identity.clone(),
        },
        sender: Sender::new(keys.r2i),
        receiver: Receiver::new(keys.i2r),
        ratchet_root: keys.ratchet_root,
    };

    Ok(RespondedSession {
        initiator_identity,
        initial_payload,
        session,
    })
}
