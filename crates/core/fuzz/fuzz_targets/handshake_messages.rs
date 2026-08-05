//! Fuzzes both untrusted-input boundaries in `crate::handshake`'s live
//! 3-message protocol: a responder parsing an attacker-controlled msg1,
//! and an initiator parsing an attacker-controlled msg2. Both run against
//! real, freshly generated identities each iteration.
#![no_main]

use libfuzzer_sys::fuzz_target;
use novachannel::handshake::{initiator_start, responder_respond};
use novachannel::identity::Identity;

fuzz_target!(|data: &[u8]| {
    let identity = Identity::generate();

    // Boundary 1: a responder receiving an arbitrary msg1.
    let _ = responder_respond(&identity, None, data);

    // Boundary 2: an initiator receiving an arbitrary msg2, against a
    // real, freshly started handshake (so the transcript/signature
    // checks are exercised against genuine local state, not immediately
    // short-circuited).
    let (state, _msg1) = initiator_start(None);
    let _ = state.complete(&identity, data);
});
