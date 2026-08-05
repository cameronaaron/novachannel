//! Fuzzes `PreKeyBundle::from_bytes` — the one public entry point that
//! turns attacker-controlled bytes (a bundle fetched from an untrusted
//! directory service, in a real deployment) into parsed key material.
//! No panics, ever, regardless of input: a malformed bundle must come
//! back as `Err`, never a crash.
#![no_main]

use libfuzzer_sys::fuzz_target;
use novachannel::prekey::PreKeyBundle;

fuzz_target!(|data: &[u8]| {
    let _ = PreKeyBundle::from_bytes(data);
});
