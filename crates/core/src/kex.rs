//! Ephemeral hybrid key exchange: X25519 plus ML-KEM-1024 (FIPS 203, called
//! "Kyber1024" during standardization). ML-KEM-1024 is NIST category 5,
//! chosen over ML-KEM-768 (category 3) for the largest margin, at the cost
//! of larger keys and ciphertexts (~1568/1568 bytes vs ~1184/1088).
//!
//! The two shared secrets are concatenated and fed to HKDF by the caller,
//! the standard hybrid combiner: recovering the session key needs breaking
//! both Curve25519 discrete log and ML-KEM's module-LWE, so a future quantum
//! break of one leg leaves the secret intact. Both keys are ephemeral and
//! used once, which gives forward secrecy.

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
        let dh = checked_dh(self.x25519_secret.diffie_hellman(responder_x25519_public))?;
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
    let dh = checked_dh(x25519_secret.diffie_hellman(initiator_x25519_public))?;

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

/// Rejects an X25519 exchange whose output is the all-zero point.
///
/// That happens exactly when the peer's public key has small order, forcing
/// a publicly known shared secret whatever this side's key: the peer
/// contributed nothing. RFC 7748 §6.1 recommends this check; it is applied
/// at every X25519 exchange in this crate.
///
/// It inspects the output instead of blacklisting small-order encodings.
/// The blacklist is twelve hand-transcribed constants where one wrong byte
/// silently weakens the check; one comparison on the output can't be
/// mistranscribed and catches every case the table would.
///
/// No known attack on the current constructions depends on this: every
/// exchange is hybrid, so ML-KEM still carries the session, and the party
/// supplying such a key only degrades its own session. It is here because no
/// protocol in this crate has reason to accept a zero-entropy contribution,
/// and accepting it silently would turn a future composition mistake into a
/// real one.
pub(crate) fn checked_dh(shared: x25519_dalek::SharedSecret) -> Result<x25519_dalek::SharedSecret> {
    if shared.was_contributory() {
        Ok(shared)
    } else {
        Err(Error::Malformed(
            "peer's X25519 public key has small order: the exchange contributed no entropy",
        ))
    }
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
