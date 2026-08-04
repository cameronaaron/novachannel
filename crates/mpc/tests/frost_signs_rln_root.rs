//! Ties `novachannel-mpc` to `novachannel-rln` without either crate
//! depending on the other in `[dependencies]` — only here, in a test, via
//! a `[dev-dependencies]` edge that doesn't affect either crate's real
//! public API. The integration point is deliberately thin:
//! `MerkleTree::root_bytes()` (in `novachannel-rln`) returns an opaque
//! byte string; FROST's `sign`/`verify` (in `novachannel-mpc`) already
//! take an opaque `&[u8]` message. Composing them needs no glue code
//! beyond what's demonstrated here.
//!
//! # The gap this closes
//! `novachannel-rln` proves anonymous, rate-limited membership against a
//! Merkle root — but says nothing about how a client comes to trust *that
//! root is the real, current membership set* rather than one an attacker
//! fabricated. Requiring a full PKI just to distribute a 16-byte root is
//! disproportionate. Instead: the same `t`-of-`n` mixnode quorum already
//! running threshold decryption (`novachannel_mpc::partial_decrypt`) can
//! jointly *sign* the current root via FROST. A client only needs to trust
//! one long-lived value — the quorum's group public key — the same
//! trust-anchor shape `novachannel::handshake`'s peer-identity pinning
//! already uses elsewhere in this workspace.

use std::collections::BTreeMap;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use novachannel_mpc::frost::{aggregate, round1_commit, round2_sign, verify};
use novachannel_mpc::{
    finalize_key_share_excluding_faulty, identify_faulty_dealers, Dealer, KeyShare, ParticipantId,
};
use novachannel_rln::air::DEPTH;
use novachannel_rln::merkle::MerkleTree;
use novachannel_rln::Identity as RlnIdentity;

fn run_dkg(threshold: u32, n: u32) -> Vec<KeyShare> {
    let dealers: Vec<Dealer> = (0..n).map(|_| Dealer::new(threshold, n)).collect();
    let _hashes: Vec<_> = dealers.iter().map(|d| d.commitment_hash()).collect();

    let mut dealer_commitments: Vec<Vec<RistrettoPoint>> = Vec::new();
    let mut dealer_shares: Vec<BTreeMap<ParticipantId, Scalar>> = Vec::new();
    for d in &dealers {
        let (c, s) = d.reveal();
        dealer_commitments.push(c);
        dealer_shares.push(s);
    }
    let excluded = identify_faulty_dealers(&dealer_commitments, &dealer_shares);
    assert!(excluded.is_empty());

    (1..=n)
        .map(|pid| {
            finalize_key_share_excluding_faulty(pid, &dealer_commitments, &dealer_shares, &excluded)
        })
        .collect()
}

fn sign_root(shares: &[&KeyShare], message: &[u8]) -> novachannel_mpc::frost::Signature {
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
            (
                s.participant_id,
                round2_sign(s, n, message, &signer_ids, &commitments),
            )
        })
        .collect();
    aggregate(
        &shares[0].group_public_key,
        message,
        &commitments,
        &shares_z,
    )
}

fn build_rln_group(n: usize) -> MerkleTree {
    let identities: Vec<RlnIdentity> = (0..n).map(|_| RlnIdentity::generate()).collect();
    let params = novachannel_rln::permutation::Params::new();
    let leaves: Vec<_> = identities.iter().map(|id| id.commitment(&params)).collect();
    MerkleTree::new(DEPTH, &leaves)
}

#[test]
fn a_mixnode_quorum_can_attest_to_the_current_membership_root() {
    let (threshold, n) = (3, 5);
    let mixnode_shares = run_dkg(threshold, n);
    let group_public_key = mixnode_shares[0].group_public_key;

    let tree = build_rln_group(4);
    let root_bytes = tree.root_bytes();

    let quorum: Vec<&KeyShare> = mixnode_shares[0..3].iter().collect();
    let attestation = sign_root(&quorum, &root_bytes);

    assert!(verify(&attestation, &group_public_key, &root_bytes));
}

#[test]
fn an_attestation_does_not_verify_against_a_different_root() {
    let (threshold, n) = (3, 5);
    let mixnode_shares = run_dkg(threshold, n);
    let group_public_key = mixnode_shares[0].group_public_key;

    let tree_a = build_rln_group(4);
    let tree_b = build_rln_group(4); // different random identities -> different root

    let quorum: Vec<&KeyShare> = mixnode_shares[0..3].iter().collect();
    let attestation = sign_root(&quorum, &tree_a.root_bytes());

    // Vanishingly unlikely to collide for random groups, but assert the
    // real property rather than assume it.
    assert_ne!(tree_a.root_bytes(), tree_b.root_bytes());
    assert!(!verify(
        &attestation,
        &group_public_key,
        &tree_b.root_bytes()
    ));
}

#[test]
fn a_below_threshold_quorum_cannot_produce_a_valid_attestation() {
    // FROST itself already refuses to run with too few signers at the API
    // level (there's no way to call `sign_root` with fewer than enough
    // shares and get something `aggregate`/`verify` treats as valid,
    // since Lagrange interpolation over the wrong signer set produces a
    // `z` that doesn't satisfy the Schnorr equation for the FULL group
    // key) — checked directly rather than assumed from the DKG-level
    // `below_threshold_quorum_does_not_recover_the_secret` test, since
    // signing and decryption are different code paths.
    let (threshold, n) = (3, 5);
    let mixnode_shares = run_dkg(threshold, n);
    let group_public_key = mixnode_shares[0].group_public_key;

    let tree = build_rln_group(4);
    let root_bytes = tree.root_bytes();

    let quorum: Vec<&KeyShare> = mixnode_shares[0..2].iter().collect(); // below threshold
    let attestation = sign_root(&quorum, &root_bytes);

    assert!(!verify(&attestation, &group_public_key, &root_bytes));
}
