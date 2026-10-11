//! Fuzzes `Commit`/`Welcome` parsing and, when a `Commit` parses, applies it
//! with `Group::apply_commit` to a fresh single-member group, covering the
//! tree and resolution logic a well-formed but bogus commit reaches, not
//! just the wire format.
//!
//! # Why this splices into a genuine commit
//! Random bytes never got there. A `GroupOp::Add` embeds a
//! `LeafKeyPackage`, whose `read` verifies a proof-of-possession signature,
//! and random mutation never yields a valid hybrid Ed25519 + ML-DSA-87
//! signature. Measured: on raw bytes this target covered **69** edges over
//! 36 million executions with a nine-input corpus, and three of the
//! defects in `ENGINEERING-STANDARDS.md` §6.29 sat behind that gate and were
//! found by reading.
//!
//! Anything behind a signature check is a blind spot for coverage-guided
//! fuzzing. Splicing the input into a genuine commit lands mutations inside
//! a structurally valid message, so the parser reaches the path update,
//! ciphertext counts and tree logic. See §6.31, where `rln_verify` had the
//! same problem in sharper form.
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

/// Parses `bytes` as a commit and, if that works, applies it to a fresh
/// group: the part that exercises tree and resolution logic.
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
