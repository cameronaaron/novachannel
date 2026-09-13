//! Fuzzes `Commit`/`Welcome` byte parsing and, when a `Commit` happens to
//! parse successfully, feeds it into `Group::apply_commit` against a
//! real, freshly created single-member group — covering not just the
//! wire format but the tree/resolution logic a well-formed-but-bogus
//! commit could still reach.
//!
//! # Why this splices into a genuine commit
//! Random bytes never got anywhere near that logic. A `Commit`'s
//! `GroupOp::Add` embeds a `LeafKeyPackage`, and `LeafKeyPackage::read`
//! verifies a proof-of-possession signature before returning — random
//! mutation does not produce a verifying hybrid Ed25519 + ML-DSA-87
//! signature, so the parse always stopped there. Measured, not assumed:
//! on raw bytes alone this target reached **69** covered edges across
//! 36 million cumulative executions, with a nine-input corpus. Three of
//! the defects `ENGINEERING-STANDARDS.md` §6.29 found sat behind exactly
//! that gate and had to be found by reading instead.
//!
//! Everything behind a signature check is a structural blind spot for
//! coverage-guided fuzzing. Splicing the fuzzer's bytes into a genuine
//! commit is how that blind spot gets covered: mutations land inside a
//! structurally valid message, so the parser walks into the path update,
//! the ciphertext counts, and the tree logic, instead of bouncing off the
//! first signature. See §6.31, where `rln_verify` had the same problem in
//! a sharper form.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use novachannel::group::{Commit, Group, LeafKeyPackage, MyLeafKeyPackage, Welcome};
use novachannel::identity::Identity;

struct Seed {
    commit: Vec<u8>,
    welcome: Vec<u8>,
    leaf_key_package: Vec<u8>,
}

/// A real commit/welcome pair, built once per process — hybrid key
/// generation is far too slow to repeat per iteration.
fn seed() -> &'static Seed {
    static SEED: OnceLock<Seed> = OnceLock::new();
    SEED.get_or_init(|| {
        let founder = Identity::generate();
        let joiner = Identity::generate();
        let joiner_kp = MyLeafKeyPackage::generate(&joiner);
        let mut group = Group::create(&founder, 4).expect("a 4-leaf group is valid");
        let (commit, welcome) = group
            .propose_add(&founder, joiner_kp.public())
            .expect("adding to an empty group succeeds");
        Seed {
            commit: commit.to_bytes(),
            welcome: welcome.to_bytes(),
            leaf_key_package: joiner_kp.public().to_bytes(),
        }
    })
}

fn splice(genuine: &[u8], offset_bytes: [u8; 4], patch: &[u8]) -> Option<Vec<u8>> {
    if patch.is_empty() {
        return None;
    }
    let offset = u32::from_le_bytes(offset_bytes) as usize % genuine.len();
    let mut out = genuine.to_vec();
    let end = (offset + patch.len()).min(out.len());
    out[offset..end].copy_from_slice(&patch[..end - offset]);
    Some(out)
}

/// Parses `bytes` as a commit and, if that succeeds, applies it to a
/// fresh group — the part of this target that exercises tree and
/// resolution logic rather than the wire format.
fn try_apply(bytes: &[u8]) {
    let Ok(commit) = Commit::from_bytes(bytes) else {
        return;
    };
    let founder_id = Identity::generate();
    let Ok(mut group) = Group::create(&founder_id, 4) else {
        return;
    };
    let _ = group.apply_commit(&commit);
}

fuzz_target!(|data: &[u8]| {
    let _ = Welcome::from_bytes(data);
    let _ = LeafKeyPackage::from_bytes(data);
    try_apply(data);

    let Some((offset_bytes, patch)) = data.split_first_chunk::<4>() else {
        return;
    };
    let seed = seed();

    if let Some(spliced) = splice(&seed.commit, *offset_bytes, patch) {
        try_apply(&spliced);
    }
    if let Some(spliced) = splice(&seed.welcome, *offset_bytes, patch) {
        let _ = Welcome::from_bytes(&spliced);
    }
    if let Some(spliced) = splice(&seed.leaf_key_package, *offset_bytes, patch) {
        let _ = LeafKeyPackage::from_bytes(&spliced);
    }
});
