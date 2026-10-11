//! Sealed sender: hides *who sent a message* from anything relaying it (a
//! server, a mixnode, a passive observer) while the recipient still learns
//! and authenticates the sender.
//!
//! # The problem
//! `crate::handshake` and `crate::x3dh` authenticate a session to the peer
//! but don't hide the sender from whatever routes the bytes. A relay
//! routing by recipient address doesn't need to see who the sender is, and
//! a metadata-resistant system shouldn't require it to. In a
//! [`SealedEnvelope`], nothing identifies the sender to anyone but the
//! recipient who can decrypt it.
//!
//! # Mechanism
//! The only thing an observer sees is a fresh single-use ephemeral hybrid
//! public key (X25519 + ML-KEM-1024), made for this message alone. It is
//! DH'd / encapsulated against the recipient's long-term
//! [`crate::prekey::SealingPublicKey`] to derive a one-time AEAD key that
//! seals a [`SenderCertificate`] (the sender's `PublicIdentity`, signed by a
//! trusted issuer, with an expiry) together with the plaintext. No
//! sender-side long-term key appears on the wire.
//!
//! # Authentication happens at the recipient
//! Unlike `crate::x3dh`, no DH term ties in the sender's long-term key;
//! there is none to tie in without losing anonymity. Authentication rests on
//! the [`SenderCertificate`] signature, which only the recipient can see.
//! So relays cannot check a sender's legitimacy before delivery, and
//! spam/abuse filtering of sealed traffic must happen after unsealing: the
//! same tradeoff Signal's sealed sender makes.
//!
//! # What this module does not do
//! - **Delivery confirmation or replies.** One envelope, one direction; a
//!   reply is a new envelope (or a normal `crate::x3dh`/`crate::handshake`
//!   session), unrelated here.
//! - **Revocation or clocks.** [`SenderCertificate::verify`] takes `now`
//!   from the caller (this crate has no wall clock), and revoking a
//!   certificate before expiry is the caller's problem.
//! - **Envelope replay protection.** Opening the same bytes twice yields
//!   the same plaintext twice; track envelope hashes at the application
//!   layer if that matters, as for `crate::x3dh`'s init message.

use hkdf::Hkdf;
use kem::Encapsulate;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::identity::{HybridSignature, Identity, PublicIdentity};
use crate::kex;
use crate::prekey::{SealingPublicKey, SignedPreKey};
use crate::rng::csprng;
use crate::wire::{Reader, Writer};

const CERT_CONTEXT: &[u8] = b"novachannel sealed-sender v1 certificate";
const LABEL_ENVELOPE_KEY: &[u8] = b"novachannel sealed-sender v1 envelope key";
const AAD_CONTEXT: &[u8] = b"novachannel sealed-sender v1 envelope";

fn cert_signed_bytes(sender_identity: &PublicIdentity, expires_at: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_fixed(CERT_CONTEXT);
    sender_identity.write(&mut w);
    w.put_fixed(&expires_at.to_be_bytes());
    w.into_bytes()
}

/// A sender's `PublicIdentity`, attested by a trusted issuer until
/// `expires_at`. Like Signal's server-issued sender certificate, but with
/// no built-in server: `issuer` is whatever `Identity` the application
/// makes its authority (trust provisioning is the caller's job, as in
/// `crate::handshake`).
pub struct SenderCertificate {
    pub sender_identity: PublicIdentity,
    pub expires_at: u64,
    signature: HybridSignature,
}

impl SenderCertificate {
    pub fn issue(issuer: &Identity, sender_identity: PublicIdentity, expires_at: u64) -> Self {
        let signature = issuer.sign(&cert_signed_bytes(&sender_identity, expires_at));
        SenderCertificate {
            sender_identity,
            expires_at,
            signature,
        }
    }

    /// Checks the signature against `issuer` and expiry against `now`, both
    /// chosen by the caller; nothing is verified implicitly.
    pub fn verify(&self, issuer: &PublicIdentity, now: u64) -> Result<()> {
        if now >= self.expires_at {
            return Err(Error::CertificateExpired);
        }
        issuer.verify(
            &cert_signed_bytes(&self.sender_identity, self.expires_at),
            &self.signature,
        )
    }

    fn write(&self, w: &mut Writer) {
        self.sender_identity.write(w);
        w.put_fixed(&self.expires_at.to_be_bytes());
        self.signature.write(w);
    }

    fn read(r: &mut Reader) -> Result<Self> {
        let sender_identity = PublicIdentity::read(r)?;
        let expires_at = u64::from_be_bytes(
            r.get_fixed(8)?
                .try_into()
                .expect("get_fixed(8) already guarantees the length"),
        );
        let signature = HybridSignature::read(r)?;
        Ok(SenderCertificate {
            sender_identity,
            expires_at,
            signature,
        })
    }
}

/// One sealed, self-contained, single-use envelope.
pub struct SealedEnvelope {
    pub bytes: Vec<u8>,
}

/// The single-use AEAD key an envelope's ephemeral exchange derives,
/// zeroized on drop.
struct EnvelopeKey([u8; 32]);

impl Drop for EnvelopeKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn derive_envelope_key(dh: &x25519_dalek::SharedSecret, ml_kem_ss: &[u8]) -> Result<EnvelopeKey> {
    let mut ikm = Vec::with_capacity(32 + ml_kem_ss.len());
    ikm.extend_from_slice(dh.as_bytes());
    ikm.extend_from_slice(ml_kem_ss);
    let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
    ikm.zeroize();
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;
    let mut key = [0u8; 32];
    hk.expand(LABEL_ENVELOPE_KEY, &mut key)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    Ok(EnvelopeKey(key))
}

/// Seals `plaintext` to `recipient` with `certificate`, so only the
/// recipient can learn and authenticate the sender. The certificate isn't
/// checked here; the recipient checks it after opening.
pub fn seal(
    recipient: &SealingPublicKey,
    certificate: &SenderCertificate,
    plaintext: &[u8],
) -> Result<SealedEnvelope> {
    let mut rng = csprng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = X25519Public::from(&ephemeral_secret);
    let dh = kex::checked_dh(ephemeral_secret.diffie_hellman(&recipient.dh_public))?;
    let (ml_kem_ct, ml_kem_ss) = recipient.kem_public.encapsulate_with_rng(&mut rng);

    let key = derive_envelope_key(&dh, &ml_kem_ss)?;

    let mut w = Writer::new();
    w.put_fixed(ephemeral_public.as_bytes());
    w.put_var(&ml_kem_ct);
    let header_bytes = w.0.clone();

    let mut payload_w = Writer::new();
    certificate.write(&mut payload_w);
    payload_w.put_var(plaintext);
    let payload_plaintext = payload_w.into_bytes();

    let mut aad = Vec::with_capacity(AAD_CONTEXT.len() + header_bytes.len());
    aad.extend_from_slice(AAD_CONTEXT);
    aad.extend_from_slice(&header_bytes);
    let sealed_payload = seal_with_key(&key.0, &aad, &payload_plaintext)?;
    w.put_var(&sealed_payload);

    Ok(SealedEnvelope {
        bytes: w.into_bytes(),
    })
}

/// What [`open`] recovers: the sender's certificate (unchecked; call
/// [`SenderCertificate::verify`] before trusting `sender_identity`) and the
/// plaintext.
pub struct UnsealedMessage {
    pub certificate: SenderCertificate,
    pub plaintext: Vec<u8>,
}

/// Opens an envelope sealed to `recipient_key`'s public half. The embedded
/// certificate isn't verified: the caller picks trusted issuers and calls
/// [`SenderCertificate::verify`], as with `crate::x3dh`'s embedded
/// `PublicIdentity`.
pub fn open(recipient_key: &SignedPreKey, envelope: &SealedEnvelope) -> Result<UnsealedMessage> {
    let mut r = Reader::new(&envelope.bytes);
    let ephemeral_public = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
    let ml_kem_ct = kex::ml_kem_ciphertext_from_bytes(r.get_var()?)?;
    let header_len = r.consumed();
    let header_bytes = &envelope.bytes[..header_len];
    let sealed_payload = r.get_var()?;
    if !r.finished() {
        return Err(Error::Malformed("trailing bytes in sealed envelope"));
    }

    let dh = recipient_key.diffie_hellman(&ephemeral_public)?;
    let ml_kem_ss = recipient_key.decapsulate(&ml_kem_ct);
    let key = derive_envelope_key(&dh, &ml_kem_ss)?;

    let mut aad = Vec::with_capacity(AAD_CONTEXT.len() + header_bytes.len());
    aad.extend_from_slice(AAD_CONTEXT);
    aad.extend_from_slice(header_bytes);
    let payload_plaintext = open_with_key(&key.0, &aad, sealed_payload)?;

    let mut pr = Reader::new(&payload_plaintext);
    let certificate = SenderCertificate::read(&mut pr)?;
    let plaintext = pr.get_var()?.to_vec();
    if !pr.finished() {
        return Err(Error::Malformed("trailing bytes in sealed payload"));
    }

    Ok(UnsealedMessage {
        certificate,
        plaintext,
    })
}

/// Single-use key with an all-zero nonce, safe for the reason
/// `crate::ratchet::seal_with_message_key` gives: `key` is fresh per
/// envelope and used once.
fn seal_with_key(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
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

fn open_with_key(key: &[u8; 32], aad: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305, Key, Nonce,
    };
    ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&Nonce::from([0u8; 12]), Payload { msg: record, aad })
        .map_err(|_| Error::Decrypt)
}
