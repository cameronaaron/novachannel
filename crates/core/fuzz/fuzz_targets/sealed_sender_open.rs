//! Fuzzes `sealed_sender::open` against a real recipient key — a sealed
//! envelope is exactly the "anyone can send this, unauthenticated until
//! opened" boundary the module's own docs describe.
//!
//! # Why the recipient key is cached, and why inputs are spliced
//! This target used to generate a fresh `Identity` and `SignedPreKey` on
//! every iteration. That cost two things at once. It made the target slow
//! — ML-DSA-87 and ML-KEM-1024 key generation dominated, holding it to
//! roughly twenty executions a second — and it inflated the coverage
//! number that was supposed to show the parser was being reached, since
//! thousands of edges inside key generation light up regardless of the
//! input. Caching the recipient in a `OnceLock` removes both problems;
//! nothing about the property under test needs a different key each time,
//! because the envelope's own ephemeral key is what varies.
//!
//! Random bytes also never reach past the first field: an envelope opens
//! with a 32-byte X25519 key and then a length-prefixed ML-KEM-1024
//! ciphertext that must be exactly 1568 bytes. Each input is therefore
//! also spliced over a window of a genuine envelope, so mutations land
//! inside a message the parser will actually walk into — the AEAD path,
//! the certificate parse, the payload framing. Same reasoning, and the
//! same measured motivation, as `ENGINEERING-STANDARDS.md` §6.31.
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
