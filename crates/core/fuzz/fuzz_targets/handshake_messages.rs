//! Fuzzes both untrusted-input boundaries of `crate::handshake`'s live
//! 3-message protocol: a responder parsing a hostile msg1 and an initiator
//! parsing a hostile msg2.
//!
//! # Why the identity is cached and inputs are spliced
//! The long-term `Identity` is made once per process. Per iteration,
//! ML-DSA-87 key generation dominated the loop and its hundreds of edges
//! inflated the coverage figure meant to show the parsers were reached.
//! `initiator_start()` stays per iteration because `complete` consumes its
//! state and the ephemeral exchange is cheap.
//!
//! Random bytes stop at the first field (msg1 is a 32-byte X25519 key, then
//! a length-prefixed ML-KEM-1024 key of exactly 1568 bytes), so each input
//! is also spliced into genuine msg1 and msg2, reaching transcript
//! construction, hybrid signature verification and identity decoding
//! (`ENGINEERING-STANDARDS.md` §6.31).
//!
//! The seed msg2 comes from a different handshake, so its signature never
//! verifies against the live transcript. That is deliberate: it is what a
//! hostile peer sends, and it still drives the full parse-and-verify path.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use novachannel::handshake::{initiator_start, responder_respond};
use novachannel::identity::Identity;

struct Seed {
    identity: Identity,
    msg1: Vec<u8>,
    msg2: Vec<u8>,
}

fn seed() -> &'static Seed {
    static SEED: OnceLock<Seed> = OnceLock::new();
    SEED.get_or_init(|| {
        let identity = Identity::generate();
        let (_state, msg1) = initiator_start(None);
        let (_responder_state, msg2) = responder_respond(&identity, None, &msg1)
            .expect("a freshly generated msg1 is well formed");
        Seed {
            identity,
            msg1,
            msg2,
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

fuzz_target!(|data: &[u8]| {
    let seed = seed();

    // Boundary 1: a responder receiving an arbitrary msg1.
    let _ = responder_respond(&seed.identity, None, data);

    // Boundary 2: an initiator receiving an arbitrary msg2 against a freshly
    // started handshake, so transcript and signature checks run against real
    // local state.
    let (state, _msg1) = initiator_start(None);
    let _ = state.complete(&seed.identity, data);

    let Some((offset_bytes, patch)) = data.split_first_chunk::<4>() else {
        return;
    };
    if let Some(spliced) = splice(&seed.msg1, *offset_bytes, patch) {
        let _ = responder_respond(&seed.identity, None, &spliced);
    }
    if let Some(spliced) = splice(&seed.msg2, *offset_bytes, patch) {
        let (state, _msg1) = initiator_start(None);
        let _ = state.complete(&seed.identity, &spliced);
    }
});
