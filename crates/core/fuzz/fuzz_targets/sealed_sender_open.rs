//! Fuzzes `sealed_sender::open` against a real recipient key: a sealed
//! envelope is the "anyone can send, unauthenticated until opened"
//! boundary.
//!
//! # Why the recipient key is cached and inputs are spliced
//! Generating an `Identity` and `SignedPreKey` every iteration held this
//! target to about twenty executions a second and filled its coverage with
//! key-generation edges. The recipient is now cached in a `OnceLock`; the
//! envelope's own ephemeral key is what varies.
//!
//! Random bytes stop at the first field (a 32-byte X25519 key, then a
//! length-prefixed ML-KEM-1024 ciphertext of exactly 1568 bytes), so each
//! input is also spliced into a genuine envelope, reaching the AEAD path,
//! certificate parsing and payload framing (`ENGINEERING-STANDARDS.md`
//! §6.31).
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use novachannel::identity::Identity;
use novachannel::prekey::SignedPreKey;
use novachannel::sealed_sender::{open, seal, SealedEnvelope, SenderCertificate};

struct Recipient {
    key: SignedPreKey,
    genuine_envelope: Vec<u8>,
}

fn recipient() -> &'static Recipient {
    static RECIPIENT: OnceLock<Recipient> = OnceLock::new();
    RECIPIENT.get_or_init(|| {
        let identity = Identity::generate();
        let key = SignedPreKey::generate(&identity);

        let issuer = Identity::generate();
        let sender = Identity::generate();
        let certificate = SenderCertificate::issue(&issuer, sender.public(), u64::MAX);
        let genuine_envelope = seal(&key.sealing_public_key(), &certificate, b"fuzz seed")
            .expect("sealing to a freshly generated key succeeds")
            .bytes;

        Recipient {
            key,
            genuine_envelope,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let recipient = recipient();

    let _ = open(
        &recipient.key,
        &SealedEnvelope {
            bytes: data.to_vec(),
        },
    );

    if let Some((offset_bytes, patch)) = data.split_first_chunk::<4>() {
        if !patch.is_empty() {
            let genuine = &recipient.genuine_envelope;
            let offset = u32::from_le_bytes(*offset_bytes) as usize % genuine.len();
            let mut spliced = genuine.clone();
            let end = (offset + patch.len()).min(spliced.len());
            spliced[offset..end].copy_from_slice(&patch[..end - offset]);
            let _ = open(&recipient.key, &SealedEnvelope { bytes: spliced });
        }
    }
});
