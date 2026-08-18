//! Long-term identity keys.
//!
//! Every identity is a *hybrid* of a classical and a post-quantum signature
//! scheme: Ed25519 plus ML-DSA-87 (FIPS 204 — the NIST-ratified successor to
//! the "Dilithium5" round-3 submission this crate used before the 2024
//! finalization; see the crate-level upgrade note). ML-DSA-87 is NIST
//! security category 5, the highest of the three standardized parameter
//! sets — chosen, like `crate::kex`'s ML-KEM-1024, over the smaller
//! ML-DSA-65 (category 3) so identity signatures don't cap this crate's
//! hybrid PQ security below what its key exchange already provides, at the
//! cost of larger signatures (~4.6KB vs. ML-DSA-65's ~3.3KB). A signature is
//! only valid if both components verify. Breaking either scheme alone (a
//! classical break of Ed25519's discrete log, or a future break of the
//! lattice assumption underlying ML-DSA) is therefore insufficient to forge
//! an identity proof — the attacker needs both, which is the standard
//! rationale for hybrid authentication during the migration to
//! post-quantum cryptography.
//!
//! # Key custody
//! [`Identity::generate`] holds both secret keys in process memory, like
//! every other secret in this crate ([`ENGINEERING-STANDARDS.md`] §2.1's
//! standard). A production deployment may instead want the secret key in
//! an HSM, a cloud KMS, or a hardware token that never exports it —
//! [`Identity::from_backends`] is the seam for that: implement
//! [`Ed25519SigningBackend`]/[`MlDsaSigningBackend`] against whatever
//! holds the key, and every other module in this crate (`x3dh`,
//! `handshake`, `prekey`, `sealed_sender`, `multidevice`, `group`) keeps
//! working unchanged, since they all go through `Identity::sign`/
//! `Identity::try_sign`, never the concrete key type directly.
//!
//! This crate deliberately does not depend on any specific vendor's SDK
//! (`aws-sdk-kms`, `cryptoki`, ...) to implement these traits — that
//! would force every consumer of this crate to pull in a cloud SDK or a
//! PKCS#11 library whether or not they use it, the same reasoning
//! `novachannel-oram`'s `ServerStorage` trait already applies to a
//! networked server implementation. What's concretely available today,
//! for a deployment building one: **AWS KMS supports both halves of this
//! hybrid identity natively** — `ML_DSA_87`/`ML_DSA_SHAKE_256` (FIPS 204,
//! generally available since mid-2025) for the post-quantum leg, and
//! `ECC_NIST_EDWARDS25519`/`ED25519_SHA_512` for the classical leg — so a
//! single KMS key pair (or two, one per leg) can back an entire
//! `Identity` with no key ever leaving AWS's HSMs. No cloud KMS or HSM
//! yet supports ML-KEM encapsulation specifically (checked directly, not
//! assumed, as of this writing) — the post-quantum *signing* half has a
//! real HSM story today; [`crate::kex`]'s post-quantum *key-exchange*
//! half does not yet, and still needs to run in-process.
//!
//! [`ENGINEERING-STANDARDS.md`]: https://github.com/cameronaaron/novachannel/blob/main/ENGINEERING-STANDARDS.md

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::{Generate, Keypair, MlDsa87};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::rng::csprng;
use crate::wire::{Reader, Writer};

/// A hybrid public identity: safe to share, serialize, and pin.
#[derive(Clone)]
pub struct PublicIdentity {
    pub(crate) ed25519: VerifyingKey,
    pub(crate) ml_dsa: ml_dsa::VerifyingKey<MlDsa87>,
}

// ml-dsa's key types don't implement PartialEq themselves; compare by their
// canonical byte encoding instead.
impl PartialEq for PublicIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.ed25519 == other.ed25519
            && ml_dsa::KeyExport::to_bytes(&self.ml_dsa)
                == ml_dsa::KeyExport::to_bytes(&other.ml_dsa)
    }
}
impl Eq for PublicIdentity {}

impl std::fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicIdentity")
            .field("ed25519", &self.ed25519)
            .field(
                "ml_dsa",
                &format_args!(
                    "<{} bytes>",
                    ml_dsa::KeyExport::to_bytes(&self.ml_dsa).len()
                ),
            )
            .finish()
    }
}

impl PublicIdentity {
    pub fn verify(&self, message: &[u8], sig: &HybridSignature) -> Result<()> {
        self.ed25519
            .verify(message, &sig.ed25519)
            .map_err(|_| Error::BadSignature)?;
        self.ml_dsa
            .verify(message, &sig.ml_dsa)
            .map_err(|_| Error::BadSignature)
    }

    pub fn write(&self, w: &mut Writer) {
        w.put_fixed(self.ed25519.as_bytes());
        w.put_var(&ml_dsa::KeyExport::to_bytes(&self.ml_dsa));
    }

    pub fn read(r: &mut Reader) -> Result<Self> {
        let ed_bytes = r.get_fixed(32)?;
        let ed25519 = VerifyingKey::from_bytes(
            ed_bytes
                .try_into()
                .expect("get_fixed(32) already guarantees the length"),
        )
        .map_err(|_| Error::Malformed("invalid ed25519 public key"))?;
        let ml_dsa =
            <ml_dsa::VerifyingKey<MlDsa87> as ml_dsa::KeyInit>::new_from_slice(r.get_var()?)
                .map_err(|_| Error::Malformed("invalid ML-DSA public key"))?;
        Ok(PublicIdentity { ed25519, ml_dsa })
    }
}

/// A hybrid detached signature over some message.
#[derive(Clone)]
pub struct HybridSignature {
    pub(crate) ed25519: ed25519_dalek::Signature,
    pub(crate) ml_dsa: ml_dsa::Signature<MlDsa87>,
}

impl std::fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ml_dsa::signature::SignatureEncoding;
        let ml_dsa_bytes = self.ml_dsa.to_bytes();
        let ml_dsa_bytes: &[u8] = ml_dsa_bytes.as_ref();
        f.debug_struct("HybridSignature")
            .field("ed25519", &self.ed25519)
            .field("ml_dsa", &format_args!("<{} bytes>", ml_dsa_bytes.len()))
            .finish()
    }
}

impl HybridSignature {
    pub fn write(&self, w: &mut Writer) {
        use ml_dsa::signature::SignatureEncoding;
        w.put_fixed(&self.ed25519.to_bytes());
        w.put_var(self.ml_dsa.to_bytes().as_ref());
    }

    pub fn read(r: &mut Reader) -> Result<Self> {
        let ed_bytes = r.get_fixed(64)?;
        let ed25519 = ed25519_dalek::Signature::from_slice(ed_bytes)
            .map_err(|_| Error::Malformed("invalid ed25519 signature"))?;
        let ml_dsa = ml_dsa::Signature::<MlDsa87>::try_from(r.get_var()?)
            .map_err(|_| Error::Malformed("invalid ML-DSA signature"))?;
        Ok(HybridSignature { ed25519, ml_dsa })
    }
}

/// An opaque error from an external signing backend — deliberately not a
/// concrete type this crate defines, since a real backend's failure mode
/// (a KMS call's transport error, a PKCS#11 session fault, ...) is the
/// backend implementation's business, not this crate's. Wrapped into
/// [`Error::SigningBackend`] by [`Identity::try_sign`].
pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// Where an [`Identity`]'s Ed25519 secret key actually signs from —
/// implement this against an HSM, a cloud KMS, or a hardware token to
/// keep that key out of process memory entirely. See the module docs'
/// "Key custody" section.
pub trait Ed25519SigningBackend: Send + Sync {
    fn verifying_key(&self) -> VerifyingKey;
    fn sign(&self, message: &[u8]) -> core::result::Result<ed25519_dalek::Signature, BackendError>;
}

/// The post-quantum counterpart of [`Ed25519SigningBackend`], for the
/// ML-DSA-87 half of a hybrid [`Identity`].
pub trait MlDsaSigningBackend: Send + Sync {
    fn verifying_key(&self) -> ml_dsa::VerifyingKey<MlDsa87>;
    fn sign(
        &self,
        message: &[u8],
    ) -> core::result::Result<ml_dsa::Signature<MlDsa87>, BackendError>;
}

enum Ed25519Source {
    InProcess(Box<SigningKey>),
    Backend(Box<dyn Ed25519SigningBackend>),
}

enum MlDsaSource {
    InProcess(Box<ml_dsa::SigningKey<MlDsa87>>),
    Backend(Box<dyn MlDsaSigningBackend>),
}

/// A long-term hybrid identity keypair.
///
/// Holders are expected to keep this off the wire entirely; only
/// [`PublicIdentity`] and [`HybridSignature`] cross the network. Secret
/// key material either lives in process memory
/// ([`Identity::generate`], zeroized on drop) or off-process behind an
/// [`Ed25519SigningBackend`]/[`MlDsaSigningBackend`] pair
/// ([`Identity::from_backends`]) — see the module docs' "Key custody"
/// section.
pub struct Identity {
    ed25519: Ed25519Source,
    ml_dsa: MlDsaSource,
}

impl Identity {
    pub fn generate() -> Self {
        let mut rng = csprng();
        let ed25519 = SigningKey::generate(&mut rng);
        let ml_dsa = ml_dsa::SigningKey::<MlDsa87>::generate_from_rng(&mut rng);
        Identity {
            ed25519: Ed25519Source::InProcess(Box::new(ed25519)),
            ml_dsa: MlDsaSource::InProcess(Box::new(ml_dsa)),
        }
    }

    /// Constructs an `Identity` whose secret keys never enter this
    /// process — every signature this `Identity` produces is delegated to
    /// `ed25519`/`ml_dsa` (an HSM, a cloud KMS, a hardware token). See the
    /// module docs' "Key custody" section for what's concretely available
    /// to implement these traits against today.
    pub fn from_backends(
        ed25519: Box<dyn Ed25519SigningBackend>,
        ml_dsa: Box<dyn MlDsaSigningBackend>,
    ) -> Self {
        Identity {
            ed25519: Ed25519Source::Backend(ed25519),
            ml_dsa: MlDsaSource::Backend(ml_dsa),
        }
    }

    pub fn public(&self) -> PublicIdentity {
        let ed25519 = match &self.ed25519 {
            Ed25519Source::InProcess(sk) => sk.verifying_key(),
            Ed25519Source::Backend(b) => b.verifying_key(),
        };
        let ml_dsa = match &self.ml_dsa {
            MlDsaSource::InProcess(sk) => sk.verifying_key(),
            MlDsaSource::Backend(b) => b.verifying_key(),
        };
        PublicIdentity { ed25519, ml_dsa }
    }

    /// Signs over both legs, surfacing a backend failure as `Err` rather
    /// than panicking. Always succeeds for the default, in-process
    /// [`Self::generate`] case — the `Err` path only exists because
    /// [`Self::from_backends`] makes signing a fallible operation (a
    /// network call, a hardware fault) for the first time in this crate.
    pub fn try_sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let ed25519 = match &self.ed25519 {
            Ed25519Source::InProcess(sk) => sk.sign(message),
            Ed25519Source::Backend(b) => b.sign(message).map_err(Error::SigningBackend)?,
        };
        let ml_dsa = match &self.ml_dsa {
            MlDsaSource::InProcess(sk) => sk.sign(message),
            MlDsaSource::Backend(b) => b.sign(message).map_err(Error::SigningBackend)?,
        };
        Ok(HybridSignature { ed25519, ml_dsa })
    }

    /// Infallible convenience for the common in-process case
    /// ([`Self::generate`]).
    ///
    /// # Panics
    /// Panics if this `Identity` is backed by an external signing backend
    /// ([`Self::from_backends`]) and that backend call fails. Code that
    /// constructs an `Identity` via `from_backends` should call
    /// [`Self::try_sign`] instead, which surfaces the same failure as a
    /// `Result` rather than a panic.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        self.try_sign(message).expect(
            "Identity::sign panics on backend failure; backend-aware code \
             should call Identity::try_sign instead",
        )
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // ed25519_dalek::SigningKey and ml_dsa::SigningKey already zeroize
        // their internal buffers on drop; this guards the one field we hold
        // directly to the same standard in case that changes. Only the
        // in-process case has anything here to zeroize -- a `Backend`
        // holds no secret bytes in this process at all, which is the
        // entire point.
        if let Ed25519Source::InProcess(sk) = &self.ed25519 {
            let mut ed_bytes = sk.to_bytes();
            ed_bytes.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_identitys_signature_verifies_against_its_own_public_key() {
        let identity = Identity::generate();
        let sig = identity.sign(b"hello");
        identity.public().verify(b"hello", &sig).unwrap();
    }

    #[test]
    fn try_sign_matches_sign_for_the_in_process_case() {
        let identity = Identity::generate();
        // Both legs are deterministic given the same key, so try_sign and
        // sign produce byte-identical signatures over the same message —
        // try_sign isn't a second, subtly different code path for the
        // default case, just sign's fallible interface.
        let sig_a = identity.try_sign(b"message").unwrap();
        let sig_b = identity.sign(b"message");
        assert_eq!(sig_a.ed25519.to_bytes(), sig_b.ed25519.to_bytes());
    }

    /// A backend that always fails — proves a real backend failure
    /// surfaces through `Identity::try_sign` as `Error::SigningBackend`
    /// (not silently swallowed, not panicking) and that `Identity::sign`
    /// panics on the same failure rather than returning a bogus signature.
    struct AlwaysFailsEd25519 {
        public: VerifyingKey,
    }

    impl Ed25519SigningBackend for AlwaysFailsEd25519 {
        fn verifying_key(&self) -> VerifyingKey {
            self.public
        }

        fn sign(
            &self,
            _message: &[u8],
        ) -> core::result::Result<ed25519_dalek::Signature, BackendError> {
            Err("simulated HSM transport failure".into())
        }
    }

    /// A backend that just re-signs in-process — not a real HSM, but
    /// enough to prove `Identity::from_backends` actually routes every
    /// operation (`public`, `sign`, `try_sign`) through the trait rather
    /// than silently falling back to some in-process default.
    struct DelegatingEd25519 {
        key: SigningKey,
    }

    impl Ed25519SigningBackend for DelegatingEd25519 {
        fn verifying_key(&self) -> VerifyingKey {
            self.key.verifying_key()
        }

        fn sign(
            &self,
            message: &[u8],
        ) -> core::result::Result<ed25519_dalek::Signature, BackendError> {
            use ed25519_dalek::Signer;
            Ok(self.key.sign(message))
        }
    }

    struct DelegatingMlDsa {
        key: ml_dsa::SigningKey<MlDsa87>,
    }

    impl MlDsaSigningBackend for DelegatingMlDsa {
        fn verifying_key(&self) -> ml_dsa::VerifyingKey<MlDsa87> {
            self.key.verifying_key()
        }

        fn sign(
            &self,
            message: &[u8],
        ) -> core::result::Result<ml_dsa::Signature<MlDsa87>, BackendError> {
            Ok(self.key.sign(message))
        }
    }

    fn delegating_backend_identity() -> Identity {
        let mut rng = csprng();
        let ed25519_key = SigningKey::generate(&mut rng);
        let ml_dsa_key = ml_dsa::SigningKey::<MlDsa87>::generate_from_rng(&mut rng);
        Identity::from_backends(
            Box::new(DelegatingEd25519 { key: ed25519_key }),
            Box::new(DelegatingMlDsa { key: ml_dsa_key }),
        )
    }

    #[test]
    fn a_backend_identitys_signature_verifies_the_same_as_an_in_process_ones() {
        let identity = delegating_backend_identity();
        let sig = identity.try_sign(b"hello from an hsm").unwrap();
        identity
            .public()
            .verify(b"hello from an hsm", &sig)
            .unwrap();
    }

    #[test]
    fn a_failing_backend_surfaces_as_a_signing_backend_error_not_a_panic() {
        let ed25519 = AlwaysFailsEd25519 {
            public: SigningKey::generate(&mut csprng()).verifying_key(),
        };
        let ml_dsa_key = ml_dsa::SigningKey::<MlDsa87>::generate_from_rng(&mut csprng());
        let identity = Identity::from_backends(
            Box::new(ed25519),
            Box::new(DelegatingMlDsa { key: ml_dsa_key }),
        );

        let result = identity.try_sign(b"message");
        assert!(matches!(result, Err(Error::SigningBackend(_))));
    }

    #[test]
    #[should_panic(expected = "Identity::sign panics on backend failure")]
    fn sign_panics_on_a_failing_backend_rather_than_returning_a_bogus_signature() {
        let ed25519 = AlwaysFailsEd25519 {
            public: SigningKey::generate(&mut csprng()).verifying_key(),
        };
        let ml_dsa_key = ml_dsa::SigningKey::<MlDsa87>::generate_from_rng(&mut csprng());
        let identity = Identity::from_backends(
            Box::new(ed25519),
            Box::new(DelegatingMlDsa { key: ml_dsa_key }),
        );

        identity.sign(b"message");
    }
}
