//! Fuzzes `novachannel_rln::air::verify`, the RLN STARK verifier: the part
//! of `novachannel-rln` a deployment runs on attacker-controlled bytes (a
//! proof from the network, against public inputs known independently).
//!
//! # Why a genuine proof is embedded and spliced into
//! Random bytes only exercise the first few bytes of winterfell's
//! deserializer. This target's whole corpus was 2-4 byte inputs, and every
//! crash it reported was a deserializer arithmetic panic on four bytes. The
//! genuine ~27KB proof below (made offline by
//! `cargo run -p novachannel-rln --release --example gen_fuzz_seed`) gets
//! past that: `splice` overwrites a fuzzer-chosen window of it, so
//! mutations land inside a proof the deserializer accepts and the verifier
//! examines.
//!
//! # Why raw bytes no longer go to the deserializer
//! That path made the target unable to run. `cargo fuzz` forces
//! `panic = "abort"`, so the known winterfell deserializer panics, some in
//! the corpus itself, killed each run within a second. That panic class is
//! closed generically by `Message::from_proof_bytes`'s `catch_unwind`, and
//! the three instances found are pinned in `crates/rln/tests/rln.rs`;
//! re-finding a fourth at the cost of never reaching the verifier is a bad
//! trade.
//!
//! The proof is made offline because `cargo fuzz build` keeps debug
//! assertions in release, which trips winterfell's witness-dependent check
//! (see `novachannel-rln`'s docs). Verifying a fixed good proof is also the
//! realistic boundary: deployed verifiers don't embed a prover.
//!
//! `seed_proof.bin` and its public inputs are shared with
//! `crates/rln/tests/rln.rs`, which checks on every gate run that the seed
//! still parses and verifies, so it can't silently go stale and return this
//! target to fuzzing four bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use novachannel_rln::air::{self, PublicInputs};
use winterfell::math::fields::f64::BaseElement;

/// The same fixture `crates/rln/tests/rln.rs` checks: one copy, two readers,
/// rather than a second 27KB transcription that drifts.
const PROOF_BYTES: &[u8] = include_bytes!("../../../rln/tests/data/seed_proof.bin");

const ROOT: u64 = 8990551817337309534;
const EPOCH: u64 = 4582183166585288392;
const X: u64 = 16198758081854987517;
const Y: u64 = 6616179152081910273;
const NULLIFIER: u64 = 16159738622640836405;

fn genuine_pub_inputs() -> PublicInputs {
    PublicInputs {
        root: BaseElement::new(ROOT),
        epoch: BaseElement::new(EPOCH),
        x: BaseElement::new(X),
        y: BaseElement::new(Y),
        nullifier: BaseElement::new(NULLIFIER),
    }
}

/// Overwrites a window of the genuine proof with `patch`, starting at a
/// fuzzer-chosen offset. Returns `None` when there is nothing to splice.
fn splice(offset_bytes: [u8; 4], patch: &[u8]) -> Option<Vec<u8>> {
    if patch.is_empty() {
        return None;
    }
    let offset = u32::from_le_bytes(offset_bytes) as usize % PROOF_BYTES.len();
    let mut out = PROOF_BYTES.to_vec();
    let end = (offset + patch.len()).min(out.len());
    out[offset..end].copy_from_slice(&patch[..end - offset]);
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    // Through `Message::from_proof_bytes`, not raw
    // `winterfell::Proof::from_bytes`: that is the fix for the panic this
    // target found, and fuzzing through it exercises the path real callers
    // use.
    if let Some((offset_bytes, patch)) = data.split_first_chunk::<4>() {
        if let Some(spliced) = splice(*offset_bytes, patch) {
            let _ = novachannel_rln::Message::from_proof_bytes(&spliced, genuine_pub_inputs())
                .map(|msg| air::verify(msg.proof, msg.public));
        }
    }
});
