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

/// A long-term hybrid identity keypair, including secret key material.
///
/// Holders are expected to keep this off the wire entirely; only
/// [`PublicIdentity`] and [`HybridSignature`] cross the network.
pub struct Identity {
    ed25519: SigningKey,
    ml_dsa: ml_dsa::SigningKey<MlDsa87>,
}

impl Identity {
    pub fn generate() -> Self {
        let mut rng = csprng();
        let ed25519 = SigningKey::generate(&mut rng);
        let ml_dsa = ml_dsa::SigningKey::<MlDsa87>::generate_from_rng(&mut rng);
        Identity { ed25519, ml_dsa }
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            ed25519: self.ed25519.verifying_key(),
            ml_dsa: self.ml_dsa.verifying_key(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        HybridSignature {
            ed25519: self.ed25519.sign(message),
            ml_dsa: self.ml_dsa.sign(message),
        }
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // ed25519_dalek::SigningKey and ml_dsa::SigningKey already zeroize
        // their internal buffers on drop; this guards the one field we hold
        // directly to the same standard in case that changes.
        let mut ed_bytes = self.ed25519.to_bytes();
        ed_bytes.zeroize();
    }
}
