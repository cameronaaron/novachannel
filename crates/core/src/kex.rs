//! Ephemeral hybrid key exchange: X25519 (classical Diffie-Hellman) combined
//! with ML-KEM-1024 (FIPS 203, the NIST-ratified post-quantum KEM formerly
//! known during standardization as "Kyber1024") — NIST security category 5,
//! the highest of the three standardized parameter sets, chosen over the
//! smaller ML-KEM-768 (category 3) for the largest available classical- and
//! quantum-security margin at the cost of larger public keys and
//! ciphertexts (~1568/1568 bytes vs. 768's ~1184/1088).
//!
//! The two shared secrets are concatenated, never mixed by anything cleverer
//! than that, and fed into HKDF by the caller. This is the standard hybrid
//! KEX combiner: an attacker needs to break *both* the discrete-log problem
//! on Curve25519 and the module-LWE problem underlying ML-KEM to recover the
//! session key, so a future quantum break of one leg alone still leaves the
//! session secret. Both keys are ephemeral and used exactly once, which is
//! what gives the channel forward secrecy.

use kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::MlKem1024;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::rng::csprng;

pub type MlKemEncapsulationKey = kem::EncapsulationKey<MlKem1024>;
pub type MlKemDecapsulationKey = kem::DecapsulationKey<MlKem1024>;
pub type MlKemCiphertext = kem::Ciphertext<MlKem1024>;

/// The combined, HKDF-ready shared secret from one hybrid exchange.
pub struct SharedSecret(pub Vec<u8>);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The initiator's ephemeral key material for one handshake attempt.
pub struct InitiatorKex {
    x25519_secret: EphemeralSecret,
    x25519_public: X25519Public,
    ml_kem_public: MlKemEncapsulationKey,
    ml_kem_secret: MlKemDecapsulationKey,
}

impl InitiatorKex {
    pub fn generate() -> Self {
        let mut rng = csprng();
        let x25519_secret = EphemeralSecret::random_from_rng(&mut rng);
        let x25519_public = X25519Public::from(&x25519_secret);
        let (ml_kem_secret, ml_kem_public) = MlKem1024::generate_keypair_from_rng(&mut rng);
        InitiatorKex {
            x25519_secret,
            x25519_public,
            ml_kem_public,
            ml_kem_secret,
        }
    }

    pub fn x25519_public(&self) -> &X25519Public {
        &self.x25519_public
    }

    pub fn ml_kem_public(&self) -> &MlKemEncapsulationKey {
        &self.ml_kem_public
    }

    /// Consumes the ephemeral secret, as it must never be reused.
    pub fn finish(
        self,
        responder_x25519_public: &X25519Public,
        ml_kem_ciphertext: &MlKemCiphertext,
    ) -> Result<SharedSecret> {
        let dh = self.x25519_secret.diffie_hellman(responder_x25519_public);
        let ml_kem_ss = self.ml_kem_secret.decapsulate(ml_kem_ciphertext);
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(dh.as_bytes());
        combined.extend_from_slice(&ml_kem_ss);
        Ok(SharedSecret(combined))
    }
}

/// Output of the responder's half of the exchange.
pub struct ResponderKex {
    pub x25519_public: X25519Public,
    pub ml_kem_ciphertext: MlKemCiphertext,
    pub shared_secret: SharedSecret,
}

pub fn responder_exchange(
    initiator_x25519_public: &X25519Public,
    initiator_ml_kem_public: &MlKemEncapsulationKey,
) -> Result<ResponderKex> {
    let mut rng = csprng();
    let x25519_secret = EphemeralSecret::random_from_rng(&mut rng);
    let x25519_public = X25519Public::from(&x25519_secret);
    let dh = x25519_secret.diffie_hellman(initiator_x25519_public);

    let (ml_kem_ciphertext, ml_kem_ss) = initiator_ml_kem_public.encapsulate_with_rng(&mut rng);

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(dh.as_bytes());
    combined.extend_from_slice(&ml_kem_ss);

    Ok(ResponderKex {
        x25519_public,
        ml_kem_ciphertext,
        shared_secret: SharedSecret(combined),
    })
}

pub fn x25519_public_from_bytes(bytes: &[u8]) -> Result<X25519Public> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Malformed("invalid x25519 public key length"))?;
    Ok(X25519Public::from(arr))
}

pub fn ml_kem_public_from_bytes(bytes: &[u8]) -> Result<MlKemEncapsulationKey> {
    use kem::TryKeyInit;
    MlKemEncapsulationKey::new_from_slice(bytes)
        .map_err(|_| Error::Malformed("invalid ML-KEM public key"))
}

pub fn ml_kem_ciphertext_from_bytes(bytes: &[u8]) -> Result<MlKemCiphertext> {
    MlKemCiphertext::try_from(bytes).map_err(|_| Error::Malformed("invalid ML-KEM ciphertext"))
}
