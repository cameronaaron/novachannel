//! Fuzzes both untrusted-input boundaries in `crate::handshake`'s live
//! 3-message protocol: a responder parsing an attacker-controlled msg1,
//! and an initiator parsing an attacker-controlled msg2.
//!
//! # Why the identity is cached, and why inputs are spliced
//! The long-term `Identity` is generated once per process. Generating one
//! per iteration made this target slow — ML-DSA-87 key generation
//! dominated the loop — and inflated the coverage figure that was meant
//! to show the message parsers were being reached, since key generation
//! lights up hundreds of edges whatever the input is. The per-iteration
//! `initiator_start()` stays, because `complete` consumes its state and
//! the ephemeral exchange is cheap.
//!
//! Random bytes stop at the first field either way: msg1 is a 32-byte
//! X25519 key then a length-prefixed ML-KEM-1024 key that must be
//! exactly 1568 bytes. Each input is therefore also spliced over a window
//! of a genuine msg1 and a genuine msg2, so mutations land inside
//! messages the parsers walk into — the transcript construction, the
//! hybrid signature verification, the identity decode. Same reasoning,
//! and the same measured motivation, as `ENGINEERING-STANDARDS.md` §6.31.
//!
//! The seed msg2 comes from a different handshake than the one each
//! iteration starts, so its signature never verifies against the live
//! transcript. That is the point: it is exactly what a hostile peer
//! sends, and it still drives the full parse-and-verify path rather than
//! being rejected at the first length check.
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

    // Boundary 2: an initiator receiving an arbitrary msg2, against a
    // real, freshly started handshake (so the transcript/signature
    // checks are exercised against genuine local state, not immediately
    // short-circuited).
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
