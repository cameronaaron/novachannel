//! Fuzzes `PreKeyBundle::from_bytes` — the one public entry point that
//! turns attacker-controlled bytes (a bundle fetched from an untrusted
//! directory service, in a real deployment) into parsed key material.
//! No panics, ever, regardless of input: a malformed bundle must come
//! back as `Err`, never a crash.
//!
//! # Why this splices into a genuine bundle
//! Random bytes do not reach this parser. A bundle opens with a
//! `PublicIdentity`, whose ML-DSA-87 verifying key is a length-prefixed
//! field that must be exactly 2592 bytes — random mutation produces that
//! prefix essentially never. Measured rather than assumed: on raw bytes
//! alone this target reached 185 covered edges in 11.4 *million*
//! executions and a corpus of five inputs, i.e. it was testing that a
//! length prefix is a length prefix and nothing else, while its exec
//! count read as reassurance (`ENGINEERING-STANDARDS.md` §6.31, where the
//! same problem was found in `rln_verify` first).
//!
//! So each input is also spliced over a window of a real serialized
//! bundle, generated once per process. That lands mutations *inside*
//! structurally valid key material — wrong-but-well-formed lengths, edge
//! encodings of a real ML-KEM key, a flipped one-time-prekey presence
//! flag — which is the shape a hostile directory service would actually
//! send.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use novachannel::identity::Identity;
use novachannel::prekey::{
    DhIdentity, OneTimePreKey, OneTimePreKeyStore, PreKeyBundle, SignedPreKey,
};

/// A real bundle, built once per process: ML-DSA-87 key generation is far
/// too slow to repeat per iteration, and nothing about the seed needs to
/// vary for the splice to be useful.
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
                // A bundle that parses is not yet a bundle to trust —
                // `verify` is the check a real caller makes next, and it
                // is the one that touches the signature path.
                let _ = bundle.verify();
            }
        }
    }
});
