//! Fuzzes `x3dh::respond` — the entry point that parses an attacker-
//! controlled init message against a *real* responder's key material
//! (an asynchronous message can arrive from anyone, so this is exactly
//! the untrusted-input boundary in a real deployment). Fresh identity,
//! DH identity, signed prekey, and one-time prekey each iteration so a
//! successful parse on one input can never change how a later input is
//! handled.
#![no_main]

use libfuzzer_sys::fuzz_target;
use novachannel::identity::Identity;
use novachannel::prekey::{DhIdentity, OneTimePreKey, OneTimePreKeyStore, SignedPreKey};
use novachannel::x3dh::respond;

fuzz_target!(|data: &[u8]| {
    let identity = Identity::generate();
    let dh_identity = DhIdentity::generate();
    let spk = SignedPreKey::generate(&identity);
    let mut opks = OneTimePreKeyStore::new();
    opks.add(OneTimePreKey::generate(1));

    let _ = respond(&dh_identity, &spk, &mut opks, data);
});
