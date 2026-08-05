//! Fuzzes `sealed_sender::open` against a real recipient key — a sealed
//! envelope is exactly the "anyone can send this, unauthenticated until
//! opened" boundary the module's own docs describe.
#![no_main]

use libfuzzer_sys::fuzz_target;
use novachannel::identity::Identity;
use novachannel::prekey::SignedPreKey;
use novachannel::sealed_sender::{open, SealedEnvelope};

fuzz_target!(|data: &[u8]| {
    let identity = Identity::generate();
    let recipient_key = SignedPreKey::generate(&identity);
    let envelope = SealedEnvelope {
        bytes: data.to_vec(),
    };
    let _ = open(&recipient_key, &envelope);
});
