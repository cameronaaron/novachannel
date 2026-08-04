//! Sealed sender: hides *who sent a message* from anything relaying it —
//! a server, a mixnode, a passive network observer — while still letting
//! the eventual recipient learn and authenticate the sender.
//!
//! # The problem this solves
//! `crate::handshake` and `crate::x3dh` both authenticate a session to its
//! *peer*, but neither hides the sender's identity from whatever routes
//! the bytes between them: `crate::x3dh`'s init message puts the sender's
//! `PublicIdentity` inside an AEAD payload the *recipient* can open, but a
//! server relaying messages by (say) a recipient-address field doesn't
//! need to see that payload to do its job, and a metadata-resistant
//! system should not require it to. This module is a distinct, one-shot
//! envelope built for exactly the relay's-eye view: nothing in a
//! [`SealedEnvelope`] identifies the sender to anyone except the one
//! recipient who can decrypt it.
//!
//! # Mechanism
//! An envelope carries exactly one thing an outside observer can see: a
//! fresh, single-use ephemeral hybrid public key (X25519 + ML-KEM-768),
//! generated new for this one message and never reused. That key is
//! Diffie-Hellman'd / encapsulated against the *recipient's* long-term
//! [`crate::prekey::SealingPublicKey`] to derive a one-time AEAD key, which
//! seals a [`SenderCertificate`] (the sender's `PublicIdentity`, signed by
//! some trusted issuer, with an expiry) together with the actual
//! plaintext. No sender-side long-term key of any kind appears on the
//! wire, signed or otherwise — an observer sees only "a message, to this
//! recipient's sealing key, from some fresh key that reveals nothing about
//! who generated it."
//!
//! # Where authentication happens, and why the server can't do it
//! Unlike `crate::x3dh`, this module has no DH term tying the *sender's*
//! long-term key into the derived secret — there's no sender-side static
//! key to tie in without giving up the anonymity property. Authentication
//! instead comes entirely from [`SenderCertificate`]'s signature, which
//! only the *recipient* can check, because only the recipient can decrypt
//! far enough to see it. This is a deliberate, real limitation, not an
//! oversight: whatever relays this envelope cannot verify the sender is
//! legitimate before delivering it (it cannot see the certificate at all)
//! — spam/abuse filtering on sealed traffic has to happen after the
//! recipient unseals it, the same tradeoff Signal's own sealed sender
//! makes.
//!
//! # What this module deliberately does not do
//! - **No delivery confirmation or reply channel.** This is one envelope,
//!   one direction. A reply is a new, independent sealed envelope (or an
//!   ordinary `crate::x3dh`/`crate::handshake` session) — nothing here
//!   tracks the two as related.
//! - **No certificate revocation or clock.** [`SenderCertificate::verify`]
//!   takes `now` as a caller-supplied value; this crate has no notion of
//!   wall-clock time anywhere, consistent with the rest of it, and
//!   revocation (an issuer un-trusting one certificate before its expiry)
//!   is entirely the caller's problem to solve out of band.
//! - **No replay protection of the envelope itself.** A recipient who
//!   processes the same envelope bytes twice recovers the same plaintext
//!   twice; callers that care should track envelope hashes at the
//!   application layer, the same caveat `crate::x3dh`'s init message
//!   already documents.

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

/// A sender's `PublicIdentity`, attested by some trusted issuer as
/// legitimate until `expires_at` — analogous to Signal's server-issued
/// sender certificate, except this crate has no built-in notion of "the
/// server": `issuer` is whatever `Identity` the deploying application
/// designates as its own certificate authority, the same "trust
/// provisioning is the caller's job" stance `crate::handshake` already
/// takes for peer-identity pinning.
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

    /// Checks the certificate's signature against `issuer` and that it
    /// hasn't expired as of `now`. Callers choose `issuer` (which trusted
    /// authority they expect) and `now` themselves — this function
    /// verifies nothing implicitly.
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

/// Seals `plaintext` to `recipient`, attaching `certificate` so the
/// recipient (and only the recipient) can learn and authenticate who sent
/// it. `certificate` is not checked for validity here — sealing a message
/// under an expired or unsigned-by-anyone-trusted certificate is not this
/// function's job to catch; the recipient checks it after opening.
pub fn seal(
    recipient: &SealingPublicKey,
    certificate: &SenderCertificate,
    plaintext: &[u8],
) -> Result<SealedEnvelope> {
    let mut rng = csprng();
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = X25519Public::from(&ephemeral_secret);
    let dh = ephemeral_secret.diffie_hellman(&recipient.dh_public);
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

/// What [`open`] recovers: the sender's certificate (not yet checked for
/// trust or expiry — call [`SenderCertificate::verify`] before relying on
/// `sender_identity`) and the plaintext.
pub struct UnsealedMessage {
    pub certificate: SenderCertificate,
    pub plaintext: Vec<u8>,
}

/// Opens an envelope sealed to `recipient_key`'s public half. Does not
/// verify the embedded certificate — the caller decides which issuer(s) it
/// trusts and calls [`SenderCertificate::verify`] itself, the same
/// separation `crate::x3dh`'s embedded `PublicIdentity` already leaves to
/// its caller.
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

    let dh = recipient_key.diffie_hellman(&ephemeral_public);
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

/// Seals under a single-use key with an all-zero nonce — safe here for the
/// same reason `crate::ratchet::seal_with_message_key` documents: AEAD
/// security only needs the (key, nonce) pair to be unique per encryption,
/// and `key` is derived fresh per envelope and used exactly once, ever.
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
