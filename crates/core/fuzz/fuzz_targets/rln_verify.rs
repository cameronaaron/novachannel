//! Fuzzes `novachannel_rln::air::verify` — the RLN STARK proof verifier,
//! the one part of `novachannel-rln` a real deployment would run against
//! attacker-controlled bytes (a proof arriving over the network, presented
//! against public inputs the caller already knows independently).
//!
//! # Why a genuine proof is embedded, and why the target splices into it
//! Feeding the verifier purely random bytes only ever exercises the first
//! few bytes of winterfell's *deserializer* — every input is rejected long
//! before any constraint is checked. That is not a hypothetical: this
//! target's whole accumulated corpus was inputs of two to four bytes, and
//! every crash it has ever reported is a deserializer arithmetic panic on
//! a four-byte input. The genuine proof below (generated offline, once,
//! by `cargo run -p novachannel-rln --release --example gen_fuzz_seed`)
//! is what gets past that: `splice` overwrites a fuzzer-chosen window of a
//! structurally valid ~27KB proof, so mutations land *inside* a proof the
//! deserializer will accept and the verifier will actually examine.
//!
//! # Why raw bytes are no longer fed to the deserializer here
//! This target used to pass `data` straight through as well. That path is
//! removed, for a reason worth stating rather than quietly dropping: it
//! made the target unable to run at all. `cargo fuzz` forces
//! `panic = "abort"`, so every one of the winterfell deserializer panics
//! this target has already found aborts the binary on sight — including
//! the ones sitting in its own corpus, which means a run now dies within
//! the first second and explores nothing. Meanwhile that panic *class* is
//! already closed structurally, by `Message::from_proof_bytes`'s
//! `catch_unwind` (which is generic over any panic, not a list of known
//! inputs), and the three instances found so far are pinned by regression
//! tests in `crates/rln/tests/rln.rs`. Re-finding a fourth instance of a
//! class already handled, at the cost of never reaching the verifier at
//! all, is a bad trade.
//!
//! The proof is generated offline rather than by calling the prover from
//! inside this binary because `cargo fuzz build` enables debug-assertions
//! even under its own `--release` profile, which trips winterfell's
//! witness-dependent sparse-boundary-column sanity check that
//! `novachannel-rln`'s module docs warn is only safe to run in a *true*
//! release build. Fuzzing the verifier alone, against a fixed known-good
//! proof, is also the more realistic boundary: a real deployment's
//! verifier never embeds a prover at all.
//!
//! `seed_proof.bin` and its public inputs are shared with
//! `crates/rln/tests/rln.rs`, which asserts on every gate run that the
//! seed still parses and verifies. Without that check the seed could go
//! stale under an unrelated change and silently return this target to
//! fuzzing four bytes of deserializer — the exact state it was already in.
#![no_main]

use libfuzzer_sys::fuzz_target;
use novachannel_rln::air::{self, PublicInputs};
use winterfell::math::fields::f64::BaseElement;

/// The same fixture `crates/rln/tests/rln.rs` checks. One copy, two
/// readers — a second transcription of 27KB of proof bytes is exactly the
/// kind of duplicate that drifts.
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
    // Goes through `Message::from_proof_bytes`, not raw
    // `winterfell::Proof::from_bytes` -- that's the fix for the panic this
    // exact target found (see that function's doc comment), and fuzzing
    // through it rather than around it is what keeps this target actually
    // exercising the code path real callers use.
    if let Some((offset_bytes, patch)) = data.split_first_chunk::<4>() {
        if let Some(spliced) = splice(*offset_bytes, patch) {
            let _ = novachannel_rln::Message::from_proof_bytes(&spliced, genuine_pub_inputs())
                .map(|msg| air::verify(msg.proof, msg.public));
        }
    }
});
