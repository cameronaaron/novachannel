//! Long-term identity keys.
//!
//! Every identity is a *hybrid* of Ed25519 and ML-DSA-87 (FIPS 204, the
//! ratified successor to the round-3 "Dilithium5" this crate used before
//! 2024). ML-DSA-87 is NIST category 5, chosen over ML-DSA-65 (category 3),
//! as ML-KEM-1024 is in `crate::kex`, so signatures don't cap hybrid PQ
//! security below the key exchange's, at the cost of larger signatures
//! (~4.6KB vs ~3.3KB). A signature is valid only if both components
//! verify, so forging needs both a classical break of Ed25519 and a break of
//! ML-DSA's lattice assumption: the standard rationale for hybrid
//! authentication during the PQ migration.
//!
//! # Key custody
//! [`Identity::generate`] keeps both secret keys in process memory, like
//! every secret in this crate ([`ENGINEERING-STANDARDS.md`] §2.1). To keep
//! them in an HSM, cloud KMS or hardware token instead, use
//! [`Identity::from_backends`] with implementations of
//! [`Ed25519SigningBackend`]/[`MlDsaSigningBackend`]. Every other module
//! (`x3dh`, `handshake`, `prekey`, `sealed_sender`, `multidevice`, `group`)
//! signs through `Identity::sign`/`Identity::try_sign`, so they work
//! unchanged.
//!
//! No vendor SDK (`aws-sdk-kms`, `cryptoki`, ...) is a dependency, so
//! consumers don't pull in a cloud SDK or PKCS#11 they don't use (the same
//! reasoning as `novachannel-oram`'s `ServerStorage` trait). For a
//! deployment building one: **AWS KMS supports both legs natively**,
//! `ML_DSA_87`/`ML_DSA_SHAKE_256` (FIPS 204, GA since mid-2025) and
//! `ECC_NIST_EDWARDS25519`/`ED25519_SHA_512`, so one or two KMS key pairs can
//! back an `Identity` without keys leaving AWS's HSMs. When this was
//! written no cloud KMS or HSM offered ML-KEM encapsulation, so
//! [`crate::kex`]'s PQ key exchange still runs in-process.
//!
//! [`ENGINEERING-STANDARDS.md`]: https://github.com/cameronaaron/novachannel/blob/main/ENGINEERING-STANDARDS.md

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ml_dsa::signature::Verifier;
use ml_dsa::{Generate, Keypair, MlDsa87};

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
    /// Both legs must verify; either failing is [`Error::BadSignature`].
    ///
    /// Ed25519 uses `verify_strict`, not permissive `Verifier::verify`. The
    /// permissive (batch-compatible) equation accepts small-order public keys
    /// and non-canonical `R` encodings, admitting signatures valid under more
    /// than one key or valid only to some implementations. Callers here
    /// ([`crate::sealed_sender::SenderCertificate`],
    /// [`crate::multidevice::SignedDeviceList`], [`crate::group::LeafKeyPackage`])
    /// read "verifies under this identity" as *which* identity vouched, and
    /// `verify_strict` makes that true; RFC 8032 §8.4 and libsignal point the
    /// same way.
    pub fn verify(&self, message: &[u8], sig: &HybridSignature) -> Result<()> {
        self.ed25519
            .verify_strict(message, &sig.ed25519)
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

/// An opaque error from an external signing backend. Its failure modes (KMS
/// transport errors, PKCS#11 faults, ...) belong to the backend, so this
/// crate defines no concrete type. [`Identity::try_sign`] wraps it in
/// [`Error::SigningBackend`].
pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// Where an [`Identity`]'s Ed25519 key signs from. Implement it over an HSM,
/// cloud KMS or hardware token to keep the key out of process memory (see
/// "Key custody" in the module docs).
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
/// Keep it off the wire; only [`PublicIdentity`] and [`HybridSignature`]
/// cross the network. Secrets live in process memory
/// ([`Identity::generate`], zeroized on drop) or behind an
/// [`Ed25519SigningBackend`]/[`MlDsaSigningBackend`] pair
/// ([`Identity::from_backends`]); see "Key custody".
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

    /// An `Identity` whose secret keys never enter this process: all signing
    /// is delegated to `ed25519`/`ml_dsa` (HSM, cloud KMS, hardware token). See
    /// "Key custody" for what is available to implement them against.
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

    /// Signs with both legs, returning a backend failure as `Err` instead of
    /// panicking. Always succeeds for [`Self::generate`]; the `Err` path exists
    /// because [`Self::from_backends`] makes signing fallible (a network call,
    /// a hardware fault).
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

    /// Infallible convenience for the in-process case ([`Self::generate`]).
    ///
    /// # Panics
    /// Panics if this `Identity` uses an external backend
    /// ([`Self::from_backends`]) and the call fails. Use [`Self::try_sign`] with
    /// `from_backends` to get a `Result` instead.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        self.try_sign(message).expect(
            "Identity::sign panics on backend failure; backend-aware code \
             should call Identity::try_sign instead",
        )
    }
}

// No `Drop` impl, deliberately.
//
// The old one called `sk.to_bytes()`, which *copies* the secret, and
// zeroized the copy, leaving the key untouched: it cost a copy of the
// secret on every drop, cleared nothing, and read as though it did, which
// is worse than nothing (`ENGINEERING-STANDARDS.md` §0.4).
//
// The key types do the zeroizing: `ed25519_dalek::SigningKey` and
// `ml_dsa::SigningKey` implement `ZeroizeOnDrop` under the `zeroize`
// features enabled in §6.19, and drop as fields normally. The static
// assertions below make that executable: if either dependency stops
// zeroizing on drop, this stops compiling.
//
// A `Backend`-sourced `Identity` holds no secret bytes in this process at
// all.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SigningKey>();
    assert_zeroize_on_drop::<ml_dsa::SigningKey<MlDsa87>>();
};

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
        // Both legs are deterministic per key, so try_sign and sign produce
        // identical bytes: try_sign is sign's fallible interface, not a different
        // path.
        let sig_a = identity.try_sign(b"message").unwrap();
        let sig_b = identity.sign(b"message");
        assert_eq!(sig_a.ed25519.to_bytes(), sig_b.ed25519.to_bytes());
    }

    /// A backend that always fails: a real failure must surface from
    /// `Identity::try_sign` as `Error::SigningBackend` (not swallowed, not a
    /// panic), and `Identity::sign` must panic rather than return a bogus
    /// signature.
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

    /// A backend that re-signs in-process: not an HSM, but enough to show
    /// `Identity::from_backends` routes `public`, `sign` and `try_sign` through
    /// the trait rather than falling back to an in-process key.
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
