//! FROST (Flexible Round-Optimized Schnorr Threshold signatures, RFC 9591):
//! a `t`-of-`n` quorum of the same DKG-derived key shares as
//! [`crate::Dealer`]/[`crate::KeyShare`] can jointly produce one ordinary,
//! single Schnorr signature under the group public key — verifiable by
//! anyone, with nothing in the signature itself revealing that it was
//! produced by a threshold at all.
//!
//! # Where this fits
//! `crate`'s Pedersen DKG already lets `t` of `n` mixnode operators jointly
//! *decrypt* under a shared key (`partial_decrypt`/`combine_partials`).
//! FROST reuses the exact same DKG output ([`crate::KeyShare`]) to let the
//! same quorum jointly *sign* — attesting to a routing table, a membership
//! Merkle root, an operational decision — without any single operator ever
//! holding a usable signing key alone. This is the more current primitive
//! for that job: FROST (2020) is the state-of-the-art threshold-Schnorr
//! construction, two rounds, no restriction to a specific curve.
//!
//! # Protocol
//! Two rounds:
//! 1. [`round1_commit`]: each signer generates a fresh, single-use nonce
//!    pair and publishes its commitment. **A nonce must never be reused
//!    across signing sessions** — reuse leaks the signer's secret share,
//!    the exact failure mode that has broken real ECDSA/Schnorr deployments
//!    via nonce reuse before. [`SecretNonces`] is consumed by
//!    [`round2_sign`] specifically so reuse is a type error, not just a
//!    documented rule a caller has to remember.
//! 2. [`round2_sign`]: given the message and every signer's round-1
//!    commitment, each signer computes one signature share.
//!    [`verify_signature_share`] lets an aggregator catch a faulty or
//!    malicious signer's share *before* wasting an aggregate on it — same
//!    "identify the bad party, don't just fail blind" shape as
//!    [`crate::identify_faulty_dealers`]. [`aggregate`] then combines
//!    `threshold` valid shares into one ordinary Schnorr signature.
//!
//! [`verify`] takes only the group public key, the message, and the final
//! signature — it has no notion of thresholds, shares, or signers, because
//! a FROST signature is, on the wire, indistinguishable from one produced
//! by a single Schnorr signer.
//!
//! # Verified against RFC 9591's own test vectors
//! The hash domain-separation tags and byte encodings below (context
//! string, the `H1`/`H4`/`H5` construction, the exact layout of
//! `binding_factor_input`, identifiers as 32-byte little-endian canonical
//! scalars) are reverse-engineered from and checked against the official
//! `FROST(ristretto255, SHA-512)` test vector published in the CFRG
//! `draft-irtf-cfrg-frost` repository (`poc/frost-ristretto255-sha512.json`,
//! `master` branch), not guessed at from the RFC's prose alone. The
//! `official_test_vector_matches_rfc9591` test below reproduces every
//! `binding_factor`, both `sig_share`s, and the final aggregated signature
//! from that vector exactly. The one piece intentionally *not* matched is
//! `nonce_generate` (RFC 9591 §4.1's deterministic nonce derivation from a
//! random seed plus the secret share) — this crate draws nonces directly
//! from a CSPRNG instead (see [`round1_commit`]), which is a valid FROST
//! instantiation (the RFC allows any nonce generation that produces
//! uniform, secret, single-use scalars) but not a byte-identical one, so
//! the test feeds the vector's own pre-derived nonces in directly rather
//! than re-deriving them from `hiding_nonce_randomness`/
//! `binding_nonce_randomness`.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::csprng;
use zeroize::Zeroize;

use crate::{
    evaluate_commitment, lagrange_coefficient_at_zero, scalar_from_id, KeyShare, ParticipantId,
};

/// RFC 9591's ciphersuite context string for `FROST(ristretto255, SHA-512)`.
const CONTEXT_STRING: &[u8] = b"FROST-RISTRETTO255-SHA512-v1";

/// `H1`/`H3`: domain-separated hash-to-scalar via wide (64-byte) reduction
/// mod the group order — `Scalar::from_bytes_mod_order_wide` over
/// `SHA512(contextString || label || input)`.
fn hash_to_scalar(label: &[u8], input: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(CONTEXT_STRING);
    hasher.update(label);
    hasher.update(input);
    let digest = hasher.finalize();
    let bytes: [u8; 64] = digest
        .as_slice()
        .try_into()
        .expect("SHA-512 output is 64 bytes");
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// `H4`/`H5`: domain-separated *raw* SHA-512 (64-byte) output, used inside
/// `binding_factor_input` rather than reduced to a scalar directly —
/// `SHA512(contextString || label || input)`.
fn hash_raw(label: &[u8], input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(CONTEXT_STRING);
    hasher.update(label);
    hasher.update(input);
    hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("SHA-512 output is 64 bytes")
}

/// A participant identifier, encoded the same way RFC 9591 encodes it
/// everywhere a `binding_factor_input`/commitment-list entry needs one: as
/// a full 32-byte little-endian canonical scalar (`Scalar::from(id).to_bytes()`),
/// not a raw integer encoding.
fn encode_identifier(id: ParticipantId) -> [u8; 32] {
    scalar_from_id(id).to_bytes()
}

/// One signer's round-1 output: a fresh, single-use nonce pair. Zeroized on
/// drop; [`round2_sign`] takes it by value so a nonce cannot be fed into two
/// signing sessions by accident (§ module docs).
pub struct SecretNonces {
    hiding: Scalar,
    binding: Scalar,
}

impl Drop for SecretNonces {
    fn drop(&mut self) {
        self.hiding.zeroize();
        self.binding.zeroize();
    }
}

/// The public half of round 1: safe to broadcast to every other signer and
/// the aggregator.
#[derive(Clone, Copy)]
pub struct SigningCommitment {
    pub participant_id: ParticipantId,
    pub hiding: RistrettoPoint,
    pub binding: RistrettoPoint,
}

/// Round 1: generates this signer's nonce pair and commitment. Call once
/// per signing session, immediately before that session — not in advance
/// and reused, and never twice for the same session.
pub fn round1_commit(participant_id: ParticipantId) -> (SecretNonces, SigningCommitment) {
    let mut rng = csprng();
    let hiding = Scalar::random(&mut rng);
    let binding = Scalar::random(&mut rng);
    let commitment = SigningCommitment {
        participant_id,
        hiding: hiding * RISTRETTO_BASEPOINT_POINT,
        binding: binding * RISTRETTO_BASEPOINT_POINT,
    };
    (SecretNonces { hiding, binding }, commitment)
}

/// `encode_group_commitment_list` (RFC 9591 §4.3): every signer's round-1
/// commitments, sorted by identifier, each as
/// `encode_identifier(id) || compress(hiding) || compress(binding)`
/// concatenated directly (no length prefixes) — this is what binds each
/// signer's per-session binding factor to the *entire* signing set, so one
/// signer's nonce can't be reused in a session with a different co-signer
/// set.
fn encode_commitment_list(commitments: &[SigningCommitment]) -> Vec<u8> {
    let mut sorted: Vec<&SigningCommitment> = commitments.iter().collect();
    sorted.sort_by_key(|c| c.participant_id);
    let mut buf = Vec::with_capacity(sorted.len() * 96);
    for c in sorted {
        buf.extend_from_slice(&encode_identifier(c.participant_id));
        buf.extend_from_slice(c.hiding.compress().as_bytes());
        buf.extend_from_slice(c.binding.compress().as_bytes());
    }
    buf
}

/// RFC 9591 §4.3 `compute_binding_factor`:
/// `H1(compress(Y) || H4(msg) || H5(encode_commitment_list(B)) || encode_identifier(id))`.
fn binding_factor(
    participant_id: ParticipantId,
    group_public_key: &RistrettoPoint,
    message: &[u8],
    commitments: &[SigningCommitment],
) -> Scalar {
    let msg_hash = hash_raw(b"msg", message);
    let comm_hash = hash_raw(b"com", &encode_commitment_list(commitments));

    let mut input = Vec::with_capacity(32 + 64 + 64 + 32);
    input.extend_from_slice(group_public_key.compress().as_bytes());
    input.extend_from_slice(&msg_hash);
    input.extend_from_slice(&comm_hash);
    input.extend_from_slice(&encode_identifier(participant_id));
    hash_to_scalar(b"rho", &input)
}

/// RFC 9591 §4.3 `compute_group_commitment`:
/// `sum_i(hiding_i + binding_factor_i * binding_i)`.
fn group_commitment(
    group_public_key: &RistrettoPoint,
    message: &[u8],
    commitments: &[SigningCommitment],
) -> RistrettoPoint {
    commitments
        .iter()
        .fold(RistrettoPoint::default(), |acc, c| {
            let rho = binding_factor(c.participant_id, group_public_key, message, commitments);
            acc + c.hiding + rho * c.binding
        })
}

/// RFC 9591's Schnorr challenge, `H2(compress(R) || compress(Y) || msg)`.
fn challenge(
    group_commitment: &RistrettoPoint,
    group_public_key: &RistrettoPoint,
    message: &[u8],
) -> Scalar {
    let mut input = Vec::with_capacity(32 + 32 + message.len());
    input.extend_from_slice(group_commitment.compress().as_bytes());
    input.extend_from_slice(group_public_key.compress().as_bytes());
    input.extend_from_slice(message);
    hash_to_scalar(b"chal", &input)
}

/// Round 2: this signer's contribution to the final signature. Consumes
/// `nonces` — see module docs on why reuse is impossible here rather than
/// merely forbidden.
///
/// `signer_ids` is the full set of participants in *this signing session*
/// (needed to compute this signer's Lagrange coefficient relative to just
/// this quorum, not the whole DKG); `commitments` must be every one of
/// their round-1 [`SigningCommitment`]s, including this signer's own.
pub fn round2_sign(
    share: &KeyShare,
    nonces: SecretNonces,
    message: &[u8],
    signer_ids: &[ParticipantId],
    commitments: &[SigningCommitment],
) -> Scalar {
    let rho = binding_factor(
        share.participant_id,
        &share.group_public_key,
        message,
        commitments,
    );
    let r = group_commitment(&share.group_public_key, message, commitments);
    let c = challenge(&r, &share.group_public_key, message);
    let lambda = lagrange_coefficient_at_zero(share.participant_id, signer_ids);
    nonces.hiding + rho * nonces.binding + lambda * share.secret_share * c
}

/// A participant's implicit public key share: `sum` over every surviving
/// dealer of that dealer's Feldman commitment evaluated at `participant_id`
/// — the same evaluation [`crate::verify_share`] performs for one dealer,
/// summed the same way [`crate::finalize_key_share_excluding_faulty`] sums
/// secret shares. Needed by [`verify_signature_share`], since checking a
/// signature share requires the *public* counterpart of the secret share
/// that produced it, not the secret share itself.
pub fn public_verification_share(
    participant_id: ParticipantId,
    dealer_commitments: &[Vec<RistrettoPoint>],
    excluded: &[usize],
) -> RistrettoPoint {
    let id = scalar_from_id(participant_id);
    dealer_commitments
        .iter()
        .enumerate()
        .filter(|(d, _)| !excluded.contains(d))
        .fold(RistrettoPoint::default(), |acc, (_, commitments)| {
            acc + evaluate_commitment(commitments, id)
        })
}

/// Verifies one signer's round-2 share before aggregating — catches a
/// faulty or malicious signer's contribution before it can spoil the whole
/// aggregate, and identifies *which* signer to blame instead of only
/// learning that the final signature doesn't verify.
#[allow(clippy::too_many_arguments)]
pub fn verify_signature_share(
    participant_id: ParticipantId,
    verification_share: &RistrettoPoint,
    z_i: &Scalar,
    message: &[u8],
    signer_ids: &[ParticipantId],
    commitments: &[SigningCommitment],
    group_public_key: &RistrettoPoint,
) -> bool {
    let Some(my_commitment) = commitments
        .iter()
        .find(|c| c.participant_id == participant_id)
    else {
        return false;
    };
    let rho = binding_factor(participant_id, group_public_key, message, commitments);
    let r = group_commitment(group_public_key, message, commitments);
    let c = challenge(&r, group_public_key, message);
    let lambda = lagrange_coefficient_at_zero(participant_id, signer_ids);
    let expected =
        my_commitment.hiding + rho * my_commitment.binding + lambda * c * verification_share;
    z_i * RISTRETTO_BASEPOINT_POINT == expected
}

/// An ordinary Schnorr signature — nothing about its shape reveals it was
/// produced by a threshold of signers.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub r: RistrettoPoint,
    pub z: Scalar,
}

/// Combines `threshold` signers' round-2 shares into one [`Signature`].
/// Callers should run [`verify_signature_share`] on every share first —
/// aggregating an invalid share silently produces a signature that simply
/// fails [`verify`], with no indication of which share was at fault.
pub fn aggregate(
    group_public_key: &RistrettoPoint,
    message: &[u8],
    commitments: &[SigningCommitment],
    signature_shares: &[(ParticipantId, Scalar)],
) -> Signature {
    let r = group_commitment(group_public_key, message, commitments);
    let z = signature_shares
        .iter()
        .fold(Scalar::ZERO, |acc, (_, z_i)| acc + z_i);
    Signature { r, z }
}

/// Ordinary Schnorr verification: `z*G == R + c*Y`. No knowledge of
/// thresholds, shares, or signers required — this is the entire point of a
/// threshold *signature* scheme as opposed to a multi-signature scheme.
pub fn verify(signature: &Signature, group_public_key: &RistrettoPoint, message: &[u8]) -> bool {
    let c = challenge(&signature.r, group_public_key, message);
    signature.z * RISTRETTO_BASEPOINT_POINT == signature.r + c * group_public_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{finalize_key_share_excluding_faulty, identify_faulty_dealers, Dealer};
    use std::collections::BTreeMap;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex_decode(s, &mut out);
        out
    }

    fn hex_decode(s: &str, out: &mut [u8]) {
        assert_eq!(s.len(), out.len() * 2);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
    }

    fn hex_vec(s: &str) -> Vec<u8> {
        let mut out = vec![0u8; s.len() / 2];
        hex_decode(s, &mut out);
        out
    }

    fn scalar_hex(s: &str) -> Scalar {
        Scalar::from_canonical_bytes(hex32(s))
            .into_option()
            .unwrap()
    }

    fn point_hex(s: &str) -> RistrettoPoint {
        curve25519_dalek::ristretto::CompressedRistretto(hex32(s))
            .decompress()
            .unwrap()
    }

    /// Reproduces the official `FROST(ristretto255, SHA-512)` test vector
    /// from the CFRG `draft-irtf-cfrg-frost` repository
    /// (`poc/frost-ristretto255-sha512.json`, `master` branch), verifying
    /// this crate's hash domain separation and byte encoding against it —
    /// see the module-level "Verified against RFC 9591's own test vectors"
    /// note. `t=2, n=3`, signers `{1, 3}`. Round-1 nonces are taken
    /// directly from the vector (this crate's `round1_commit` draws them
    /// from a CSPRNG rather than the RFC's deterministic
    /// `nonce_generate`, so they can't be re-derived from the vector's
    /// own randomness inputs — see the module doc for why that's a valid,
    /// if not byte-identical, instantiation).
    #[test]
    fn official_test_vector_matches_rfc9591() {
        let group_public_key =
            point_hex("e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57");
        let message = hex_vec("74657374");

        let share1 = scalar_hex("5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e");
        let share3 = scalar_hex("f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04");

        let commitments = vec![
            SigningCommitment {
                participant_id: 1,
                hiding: point_hex(
                    "965def4d0958398391fc06d8c2d72932608b1e6255226de4fb8d972dac15fd57",
                ),
                binding: point_hex(
                    "ec5170920660820007ae9e1d363936659ef622f99879898db86e5bf1d5bf2a14",
                ),
            },
            SigningCommitment {
                participant_id: 3,
                hiding: point_hex(
                    "480e06e3de182bf83489c45d7441879932fd7b434a26af41455756264fbd5d6e",
                ),
                binding: point_hex(
                    "3064746dfd3c1862ef58fc68c706da287dd925066865ceacc816b3a28c7b363b",
                ),
            },
        ];

        let nonces1 = SecretNonces {
            hiding: scalar_hex("214f2cabb86ed71427ea7ad4283b0fae26b6746c801ce824b83ceb2b99278c03"),
            binding: scalar_hex("c9b8f5e16770d15603f744f8694c44e335e8faef00dad182b8d7a34a62552f0c"),
        };
        let nonces3 = SecretNonces {
            hiding: scalar_hex("3f7927872b0f9051dd98dd73eb2b91494173bbe0feb65a3e7e58d3e2318fa40f"),
            binding: scalar_hex("ffd79445fb8030f0a3ddd3861aa4b42b618759282bfe24f1f9304c7009728305"),
        };

        let signer_ids = [1u32, 3u32];

        let share1_kv = KeyShare {
            participant_id: 1,
            secret_share: share1,
            group_public_key,
        };
        let share3_kv = KeyShare {
            participant_id: 3,
            secret_share: share3,
            group_public_key,
        };

        let z1 = round2_sign(&share1_kv, nonces1, &message, &signer_ids, &commitments);
        let z3 = round2_sign(&share3_kv, nonces3, &message, &signer_ids, &commitments);

        let expected_z1 =
            scalar_hex("9285f875923ce7e0c491a592e9ea1865ec1b823ead4854b48c8a46287749ee09");
        let expected_z3 =
            scalar_hex("7cb211fe0e3d59d25db6e36b3fb32344794139602a7b24f1ae0dc4e26ad7b908");
        assert_eq!(
            z1, expected_z1,
            "signer 1's sig_share did not match the RFC 9591 vector"
        );
        assert_eq!(
            z3, expected_z3,
            "signer 3's sig_share did not match the RFC 9591 vector"
        );

        let sig = aggregate(
            &group_public_key,
            &message,
            &commitments,
            &[(1, z1), (3, z3)],
        );

        let expected_r =
            point_hex("fc45655fbc66bbffad654ea4ce5fdae253a49a64ace25d9adb62010dd9fb2555");
        let expected_z =
            scalar_hex("2164141787162e5b4cab915b4aa45d94655dbb9ed7c378a53b980a0be220a802");
        assert_eq!(
            sig.r, expected_r,
            "aggregated R did not match the RFC 9591 vector"
        );
        assert_eq!(
            sig.z, expected_z,
            "aggregated z did not match the RFC 9591 vector"
        );

        assert!(verify(&sig, &group_public_key, &message));
    }

    fn run_dkg(threshold: u32, n: u32) -> (Vec<KeyShare>, Vec<Vec<RistrettoPoint>>) {
        let dealers: Vec<Dealer> = (0..n).map(|_| Dealer::new(threshold, n)).collect();
        let _hashes: Vec<_> = dealers.iter().map(|d| d.commitment_hash()).collect();

        let mut dealer_commitments = Vec::new();
        let mut dealer_shares: Vec<BTreeMap<ParticipantId, Scalar>> = Vec::new();
        for d in &dealers {
            let (c, s) = d.reveal();
            dealer_commitments.push(c);
            dealer_shares.push(s);
        }

        let excluded = identify_faulty_dealers(&dealer_commitments, &dealer_shares);
        assert!(
            excluded.is_empty(),
            "no faulty dealer expected in this test setup"
        );

        let shares: Vec<KeyShare> = (1..=n)
            .map(|pid| {
                finalize_key_share_excluding_faulty(
                    pid,
                    &dealer_commitments,
                    &dealer_shares,
                    &excluded,
                )
            })
            .collect();
        (shares, dealer_commitments)
    }

    fn sign_with(shares: &[&KeyShare], message: &[u8]) -> Signature {
        let signer_ids: Vec<ParticipantId> = shares.iter().map(|s| s.participant_id).collect();

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for s in shares {
            let (n, c) = round1_commit(s.participant_id);
            nonces.push(n);
            commitments.push(c);
        }

        let shares_z: Vec<(ParticipantId, Scalar)> = shares
            .iter()
            .zip(nonces)
            .map(|(s, n)| {
                let z = round2_sign(s, n, message, &signer_ids, &commitments);
                (s.participant_id, z)
            })
            .collect();

        aggregate(
            &shares[0].group_public_key,
            message,
            &commitments,
            &shares_z,
        )
    }

    #[test]
    fn a_threshold_quorum_produces_a_signature_that_verifies() {
        let (threshold, n) = (3, 5);
        let (shares, _) = run_dkg(threshold, n);
        let group_key = shares[0].group_public_key;

        let message = b"route table epoch 42";
        let quorum: Vec<&KeyShare> = shares[0..3].iter().collect();
        let sig = sign_with(&quorum, message);

        assert!(verify(&sig, &group_key, message));
    }

    #[test]
    fn any_valid_quorum_produces_a_signature_that_verifies() {
        let (threshold, n) = (3, 5);
        let (shares, _) = run_dkg(threshold, n);
        let group_key = shares[0].group_public_key;
        let message = b"same claim, different signers";

        for indices in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let quorum: Vec<&KeyShare> = indices.iter().map(|&i| &shares[i]).collect();
            let sig = sign_with(&quorum, message);
            assert!(verify(&sig, &group_key, message));
        }
    }

    #[test]
    fn a_signature_does_not_verify_against_a_different_message() {
        let (threshold, n) = (2, 3);
        let (shares, _) = run_dkg(threshold, n);
        let group_key = shares[0].group_public_key;

        let quorum: Vec<&KeyShare> = shares[0..2].iter().collect();
        let sig = sign_with(&quorum, b"the actual message");

        assert!(!verify(&sig, &group_key, b"a different message"));
    }

    #[test]
    fn a_tampered_signature_share_fails_share_verification() {
        let (threshold, n) = (3, 5);
        let (shares, dealer_commitments) = run_dkg(threshold, n);
        let message = b"attest to this";
        let quorum: Vec<&KeyShare> = shares[0..3].iter().collect();
        let signer_ids: Vec<ParticipantId> = quorum.iter().map(|s| s.participant_id).collect();

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for s in &quorum {
            let (n, c) = round1_commit(s.participant_id);
            nonces.push(n);
            commitments.push(c);
        }

        let mut zs: Vec<Scalar> = quorum
            .iter()
            .zip(nonces)
            .map(|(s, n)| round2_sign(s, n, message, &signer_ids, &commitments))
            .collect();
        // Corrupt the first signer's share.
        zs[0] += Scalar::ONE;

        let target = quorum[0];
        let vshare = public_verification_share(target.participant_id, &dealer_commitments, &[]);
        assert!(!verify_signature_share(
            target.participant_id,
            &vshare,
            &zs[0],
            message,
            &signer_ids,
            &commitments,
            &target.group_public_key,
        ));

        // The other, honest shares still verify individually.
        let honest = quorum[1];
        let honest_vshare =
            public_verification_share(honest.participant_id, &dealer_commitments, &[]);
        assert!(verify_signature_share(
            honest.participant_id,
            &honest_vshare,
            &zs[1],
            message,
            &signer_ids,
            &commitments,
            &honest.group_public_key,
        ));
    }

    #[test]
    fn a_share_from_a_participant_absent_from_the_commitment_list_is_rejected() {
        let (threshold, n) = (3, 5);
        let (shares, dealer_commitments) = run_dkg(threshold, n);
        let message = b"attest to this";
        let quorum: Vec<&KeyShare> = shares[0..3].iter().collect();
        let signer_ids: Vec<ParticipantId> = quorum.iter().map(|s| s.participant_id).collect();

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for s in &quorum {
            let (n, c) = round1_commit(s.participant_id);
            nonces.push(n);
            commitments.push(c);
        }

        let (nonce, _) = round1_commit(quorum[0].participant_id);
        let z = round2_sign(quorum[0], nonce, message, &signer_ids, &commitments);

        // `4` never contributed a round-1 commitment, so it can't be found
        // in `commitments` — the lookup itself must fail closed rather than
        // panic or fall through to a default.
        let vshare = public_verification_share(4, &dealer_commitments, &[]);
        assert!(!verify_signature_share(
            4,
            &vshare,
            &z,
            message,
            &signer_ids,
            &commitments,
            &quorum[0].group_public_key,
        ));
    }
}
