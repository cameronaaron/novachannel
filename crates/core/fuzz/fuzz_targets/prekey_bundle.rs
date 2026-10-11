//! Fuzzes `PreKeyBundle::from_bytes`, the public entry point turning
//! attacker-controlled bytes (a bundle from an untrusted directory) into key
//! material. Any malformed input must return `Err`, never panic.
//!
//! # Why this splices into a genuine bundle
//! Random bytes don't reach the parser: a bundle opens with a
//! `PublicIdentity` whose ML-DSA-87 key is a length-prefixed field of
//! exactly 2592 bytes, which mutation essentially never produces. Measured:
//! on raw bytes this target covered 185 edges in 11.4 *million* executions
//! with five corpus inputs, testing only that a length prefix is a length
//! prefix while the exec count looked reassuring (`ENGINEERING-STANDARDS.md`
//! §6.31, first seen in `rln_verify`).
//!
//! So each input is also spliced into a real serialized bundle, made once
//! per process, putting mutations inside valid key material (well-formed
//! but wrong lengths, edge encodings of a real ML-KEM key, a flipped
//! one-time-prekey flag): what a hostile directory would send.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use novachannel::identity::Identity;
use novachannel::prekey::{
    DhIdentity, OneTimePreKey, OneTimePreKeyStore, PreKeyBundle, SignedPreKey,
};

/// A real bundle, built once: ML-DSA-87 key generation is far too slow per
/// iteration, and the seed doesn't need to vary.
fn genuine_bundle() -> &'static [u8] {
    static BUNDLE: OnceLock<Vec<u8>> = OnceLock::new();
    BUNDLE.get_or_init(|| {
        let identity = Identity::generate();
        let dh = DhIdentity::generate();
        let spk = SignedPreKey::generate(&identity);
        let mut opks = OneTimePreKeyStore::new();
        opks.add(OneTimePreKey::generate(1));
        PreKeyBundle::build(
            identity.public(),
            &dh,
            &spk,
            opks.public_keys().first().cloned(),
        )
        .to_bytes()
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = PreKeyBundle::from_bytes(data);

    // ...and the same bytes spliced into a bundle the parser will actually
    // walk into, which is the only way most of it is reached at all.
    if let Some((offset_bytes, patch)) = data.split_first_chunk::<4>() {
        if !patch.is_empty() {
            let genuine = genuine_bundle();
            let offset = u32::from_le_bytes(*offset_bytes) as usize % genuine.len();
            let mut spliced = genuine.to_vec();
            let end = (offset + patch.len()).min(spliced.len());
            spliced[offset..end].copy_from_slice(&patch[..end - offset]);
            if let Ok(bundle) = PreKeyBundle::from_bytes(&spliced) {
                // Parsing isn't trusting: `verify` is what a real caller does next, and it
                // reaches the signature path.
                let _ = bundle.verify();
            }
        }
    }
});
