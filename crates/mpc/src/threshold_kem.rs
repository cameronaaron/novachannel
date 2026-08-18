//! Post-quantum threshold decryption: `t`-of-`n` mixnode operators, each
//! holding their own independent ML-KEM-1024 keypair, jointly recover a
//! sender's ephemeral payload key without any single operator — or any
//! coalition smaller than `t` — ever holding it alone.
//!
//! # Why this exists alongside [`crate::Dealer`]/[`crate::frost`]
//! [`crate::Dealer`]'s Feldman DKG and [`crate::frost`]'s FROST signatures
//! are entirely classical elliptic-curve (Ristretto255) constructions:
//! whatever secrecy or unforgeability they provide collapses the moment a
//! cryptographically relevant quantum computer breaks the discrete-log
//! problem those primitives sit on. This module gives the mixnode-operator
//! use case those two exist to serve — "no single operator can decrypt
//! traffic alone" — a path that survives that break, by reframing the
//! problem: operators don't need to *sign* anything jointly, they need to
//! jointly *hold a decryption capability*. That's built here from two
//! primitives already vetted elsewhere in this workspace and composed, not
//! invented:
//! - **ML-KEM-1024** (the same FIPS 203, module-LWE-hard KEM
//!   `novachannel::kex` already uses for the main channel's own PQ leg) as
//!   each operator's own, independent encryption key. No group DKG is
//!   needed at all — there is no shared EC point to jointly commit to, so
//!   the classic bias/rushing attacks [`crate::Dealer`]'s commit-then-reveal
//!   round exists to prevent don't apply here either.
//! - **Shamir secret sharing** of a per-message ephemeral master secret,
//!   reusing this crate's own polynomial-evaluation / Lagrange-interpolation
//!   machinery ([`crate::evaluate`]/[`crate::lagrange_coefficient_at_zero`])
//!   that [`crate::Dealer`]/[`crate::combine_partials`] already rely on.
//!   Shamir's secrecy guarantee (fewer than `t` shares reveal nothing about
//!   the secret) is information-theoretic and does not depend on the field
//!   being cryptographically hard — reusing `curve25519-dalek`'s `Scalar`
//!   field here is purely convenient polynomial arithmetic, not an EC
//!   hardness assumption. The shared value is never used as an EC scalar
//!   multiplier against any public point, so this costs nothing in
//!   post-quantum security even if Ristretto's discrete log were broken
//!   outright.
//!
//! # Protocol
//! 1. **Setup** ([`OperatorKeyPair::generate`]): each operator generates
//!    their own ML-KEM-1024 keypair independently and publishes their
//!    encapsulation key. No coordination round at all.
//! 2. **Sender encapsulation** ([`encrypt_to_group`]): the sender draws a
//!    random master secret `M` (a [`Scalar`]), Shamir-shares it `(t, n)`,
//!    then for each operator does a *fresh* ML-KEM encapsulation to that
//!    operator's own public key and uses the resulting per-operator shared
//!    secret (via HKDF) to AEAD-wrap that operator's share of `M`. `M`
//!    itself (via a separate HKDF) becomes the AEAD key for the actual
//!    payload.
//! 3. **Operator partial decryption** ([`partial_decrypt`]): operator `i`
//!    decapsulates their own ML-KEM ciphertext and AEAD-unwraps their share
//!    of `M`.
//! 4. **Combine** ([`combine_and_decrypt`]): any `t` operators' shares
//!    reconstruct `M` via Lagrange interpolation at zero — the same
//!    technique [`crate::combine_partials`] uses in the exponent, used here
//!    directly on the shared scalar instead — and decrypt the payload.
//!
//! An adversary needs to recover `t` operators' ML-KEM secret keys — an
//! independent module-LWE problem for each — to reconstruct `M`; a full
//! quantum break of Ristretto's discrete log (which would fully break
//! [`crate::Dealer`]/[`crate::frost`]) gains an attacker nothing here, since
//! no EC point ever gates access to `M`.
//!
//! # This module does not do networking
//! Same convention as the rest of this crate (see the crate-level module
//! docs): every function here is a pure computation over caller-supplied
//! bytes. Transporting [`OperatorShare`]/[`GroupCiphertext`] between sender
//! and operators is the caller's job.

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate, Kem};
use ml_kem::MlKem1024;
use rand_core::Rng;
use sha2::Sha256;

use crate::{csprng, evaluate, lagrange_coefficient_at_zero, scalar_from_id, ParticipantId};

pub type OperatorEncapsulationKey = kem::EncapsulationKey<MlKem1024>;
pub type OperatorDecapsulationKey = kem::DecapsulationKey<MlKem1024>;
pub type OperatorCiphertext = kem::Ciphertext<MlKem1024>;

const SHARE_WRAP_INFO: &[u8] = b"novachannel-mpc threshold-kem share-wrap v1";
const PAYLOAD_KEY_INFO: &[u8] = b"novachannel-mpc threshold-kem payload-key v1";

/// One operator's independent ML-KEM-1024 keypair. Unlike [`crate::Dealer`],
/// generating this needs no coordination with any other operator at all.
pub struct OperatorKeyPair {
    id: ParticipantId,
    public: OperatorEncapsulationKey,
    secret: OperatorDecapsulationKey,
}

impl OperatorKeyPair {
    pub fn generate(id: ParticipantId) -> Self {
        let mut rng = csprng();
        let (secret, public) = MlKem1024::generate_keypair_from_rng(&mut rng);
        OperatorKeyPair { id, public, secret }
    }

    pub fn id(&self) -> ParticipantId {
        self.id
    }

    pub fn public(&self) -> &OperatorEncapsulationKey {
        &self.public
    }
}

fn hkdf_expand_32(shared_secret_bytes: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret_bytes);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 is a valid HKDF-SHA256 output length");
    out
}

fn aead_seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut rng = csprng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let mut out = nonce.to_vec();
    out.extend_from_slice(
        &cipher
            .encrypt(&nonce, plaintext)
            .expect("ChaCha20Poly1305 encryption over a bounded plaintext cannot fail"),
    );
    out
}

fn aead_open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 12 {
        return Err("ciphertext too short to contain a nonce".into());
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(12);
    let nonce = Nonce::try_from(nonce_bytes).expect("split_at(12) guarantees the length");
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "AEAD authentication failed".to_string())
}

/// One operator's slice of the sender's encapsulation: an ML-KEM
/// ciphertext only that operator can decapsulate, plus their Shamir share
/// of the master secret, AEAD-wrapped under the resulting shared secret.
pub struct OperatorShare {
    pub ciphertext: OperatorCiphertext,
    pub wrapped_share: Vec<u8>,
}

/// A sender's full encapsulation to the operator group: one
/// [`OperatorShare`] per operator, plus the actual payload, AEAD-encrypted
/// under a key derived from the master secret those shares reconstruct.
pub struct GroupCiphertext {
    pub shares: BTreeMap<ParticipantId, OperatorShare>,
    pub threshold: u32,
    pub payload: Vec<u8>,
}

/// Encrypts `plaintext` to the operator group named by `operators`: any
/// `threshold` of them can later decrypt it via [`partial_decrypt`] +
/// [`combine_and_decrypt`]; fewer cannot, even in collusion.
///
/// # Panics
/// Panics if `threshold` is zero or exceeds `operators.len()` — a
/// caller-side configuration error, not something adversarial input can
/// trigger (`operators` is the sender's own trusted view of the group).
pub fn encrypt_to_group(
    operators: &BTreeMap<ParticipantId, OperatorEncapsulationKey>,
    threshold: u32,
    plaintext: &[u8],
) -> GroupCiphertext {
    assert!(threshold >= 1 && (threshold as usize) <= operators.len());

    let mut rng = csprng();
    let master_secret = Scalar::random(&mut rng);

    // Shamir-share the master secret: same random-polynomial-evaluation
    // technique `Dealer::new`/`Dealer::reveal` use, just for a
    // plain (non-Feldman-committed) secret -- no public commitments are
    // needed here since there is no group public key for anyone to verify
    // a share against; an operator who gets a wrong share simply fails
    // AEAD authentication on `combine_and_decrypt`, which is itself
    // sufficient rejection (see that function's doc comment).
    let mut coefficients: Vec<Scalar> = vec![master_secret];
    coefficients.extend((1..threshold).map(|_| Scalar::random(&mut rng)));

    let shares = operators
        .iter()
        .map(|(&id, public_key)| {
            let share = evaluate(&coefficients, scalar_from_id(id));
            let (ciphertext, shared_secret) = public_key.encapsulate_with_rng(&mut rng);
            let wrap_key = hkdf_expand_32(&shared_secret, SHARE_WRAP_INFO);
            let wrapped_share = aead_seal(&wrap_key, share.as_bytes());
            (
                id,
                OperatorShare {
                    ciphertext,
                    wrapped_share,
                },
            )
        })
        .collect();

    let payload_key = hkdf_expand_32(master_secret.as_bytes(), PAYLOAD_KEY_INFO);
    let payload = aead_seal(&payload_key, plaintext);

    GroupCiphertext {
        shares,
        threshold,
        payload,
    }
}

/// One operator's contribution toward reconstruction: decapsulates their
/// own ML-KEM ciphertext from `group_ciphertext` and AEAD-unwraps their
/// share of the master secret.
///
/// Returns `Err` if this operator has no entry in `group_ciphertext`
/// (wrong group, or excluded), or if AEAD authentication fails (tampered
/// ciphertext, or a ciphertext encapsulated to a different operator's key
/// entirely — the "wrong key" case, since ML-KEM never signals decryption
/// failure at the KEM layer itself, only the AEAD wrapped on top of it does).
pub fn partial_decrypt(
    operator: &OperatorKeyPair,
    group_ciphertext: &GroupCiphertext,
) -> Result<(ParticipantId, Scalar), String> {
    let my_share = group_ciphertext
        .shares
        .get(&operator.id)
        .ok_or("this operator has no share in the given ciphertext")?;
    let shared_secret = operator.secret.decapsulate(&my_share.ciphertext);
    let wrap_key = hkdf_expand_32(&shared_secret, SHARE_WRAP_INFO);
    let share_bytes = aead_open(&wrap_key, &my_share.wrapped_share)?;
    let share_arr: [u8; 32] = share_bytes
        .try_into()
        .map_err(|_| "unwrapped share had the wrong length".to_string())?;
    let share = Scalar::from_canonical_bytes(share_arr)
        .into_option()
        .ok_or("unwrapped share was not a canonical scalar")?;
    Ok((operator.id, share))
}

/// Combines `threshold`-or-more operators' [`partial_decrypt`] outputs into
/// the reconstructed master secret via Lagrange interpolation at zero (the
/// same technique [`crate::combine_partials`] uses in the exponent, applied
/// here directly to the shared scalar), then decrypts the payload.
///
/// A below-threshold or malformed set of `partials` reconstructs the
/// *wrong* scalar (Shamir gives no way to detect that from the shares
/// alone) — but that wrong scalar then fails to derive the payload's real
/// AEAD key, so decryption fails cleanly here rather than silently
/// returning garbage. This mirrors why [`encrypt_to_group`] doesn't bother
/// with Feldman commitments on the shares themselves: the payload's own
/// AEAD tag is already the check that matters.
pub fn combine_and_decrypt(
    partials: &[(ParticipantId, Scalar)],
    group_ciphertext: &GroupCiphertext,
) -> Result<Vec<u8>, String> {
    let ids: Vec<ParticipantId> = partials.iter().map(|(id, _)| *id).collect();
    let master_secret = partials.iter().fold(Scalar::ZERO, |acc, (id, share)| {
        acc + lagrange_coefficient_at_zero(*id, &ids) * share
    });
    let payload_key = hkdf_expand_32(master_secret.as_bytes(), PAYLOAD_KEY_INFO);
    aead_open(&payload_key, &group_ciphertext.payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_operators(n: u32) -> Vec<OperatorKeyPair> {
        (1..=n).map(OperatorKeyPair::generate).collect()
    }

    fn public_keys(
        operators: &[OperatorKeyPair],
    ) -> BTreeMap<ParticipantId, OperatorEncapsulationKey> {
        operators
            .iter()
            .map(|o| (o.id(), o.public().clone()))
            .collect()
    }

    #[test]
    fn a_threshold_quorum_recovers_the_plaintext() {
        let (threshold, n) = (3, 5);
        let operators = make_operators(n);
        let publics = public_keys(&operators);

        let plaintext = b"onion layer payload";
        let group_ct = encrypt_to_group(&publics, threshold, plaintext);

        for quorum in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let partials: Vec<(ParticipantId, Scalar)> = quorum
                .iter()
                .map(|&i| partial_decrypt(&operators[i], &group_ct).unwrap())
                .collect();
            let recovered = combine_and_decrypt(&partials, &group_ct).unwrap();
            assert_eq!(recovered, plaintext);
        }
    }

    #[test]
    fn below_threshold_quorum_fails_to_decrypt() {
        let (threshold, n) = (3, 5);
        let operators = make_operators(n);
        let publics = public_keys(&operators);
        let group_ct = encrypt_to_group(&publics, threshold, b"secret payload");

        let partials: Vec<(ParticipantId, Scalar)> = [0, 1]
            .iter()
            .map(|&i| partial_decrypt(&operators[i], &group_ct).unwrap())
            .collect();
        assert!(combine_and_decrypt(&partials, &group_ct).is_err());
    }

    #[test]
    fn an_operator_outside_the_group_has_no_share() {
        let operators = make_operators(3);
        let publics = public_keys(&operators[..2]); // group is only operators 1, 2
        let group_ct = encrypt_to_group(&publics, 2, b"payload");

        // operators[2] (id 3) is not part of this group's ciphertext.
        assert!(partial_decrypt(&operators[2], &group_ct).is_err());
    }

    #[test]
    fn a_ciphertext_meant_for_a_different_operator_fails_to_decapsulate_cleanly() {
        let operators = make_operators(2);
        let publics = public_keys(&operators);
        let group_ct = encrypt_to_group(&publics, 2, b"payload");

        // Swap the two operators' ciphertexts -- each operator now
        // decapsulates a ciphertext meant for the other, so the derived
        // shared secret (and thus wrap key) is wrong: AEAD authentication
        // on the wrapped share must fail, not silently unwrap garbage.
        let mut swapped = group_ct;
        let a = swapped.shares.remove(&1).unwrap();
        let b = swapped.shares.remove(&2).unwrap();
        swapped.shares.insert(
            1,
            OperatorShare {
                ciphertext: b.ciphertext,
                wrapped_share: a.wrapped_share,
            },
        );
        swapped.shares.insert(
            2,
            OperatorShare {
                ciphertext: a.ciphertext,
                wrapped_share: b.wrapped_share,
            },
        );

        assert!(partial_decrypt(&operators[0], &swapped).is_err());
        assert!(partial_decrypt(&operators[1], &swapped).is_err());
    }

    #[test]
    fn tampered_payload_ciphertext_is_rejected() {
        let (threshold, n) = (2, 3);
        let operators = make_operators(n);
        let publics = public_keys(&operators);
        let mut group_ct = encrypt_to_group(&publics, threshold, b"integrity matters");

        let last = group_ct.payload.len() - 1;
        group_ct.payload[last] ^= 0x01;

        let partials: Vec<(ParticipantId, Scalar)> = [0, 1]
            .iter()
            .map(|&i| partial_decrypt(&operators[i], &group_ct).unwrap())
            .collect();
        assert!(combine_and_decrypt(&partials, &group_ct).is_err());
    }

    #[test]
    fn each_operators_wrapped_share_is_independently_encapsulated() {
        // Not a shared/reused ML-KEM ciphertext across operators -- every
        // operator's `OperatorShare::ciphertext` must be its own fresh
        // encapsulation, since each is encapsulated to a different public
        // key. Confirms `encrypt_to_group` doesn't accidentally reuse one
        // ciphertext for every entry.
        let operators = make_operators(3);
        let publics = public_keys(&operators);
        let group_ct = encrypt_to_group(&publics, 2, b"payload");

        let bytes: Vec<Vec<u8>> = group_ct
            .shares
            .values()
            .map(|s| s.ciphertext.to_vec())
            .collect();
        assert_ne!(bytes[0], bytes[1]);
        assert_ne!(bytes[1], bytes[2]);
        assert_ne!(bytes[0], bytes[2]);
    }
}
