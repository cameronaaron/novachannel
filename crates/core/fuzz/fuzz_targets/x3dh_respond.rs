//! Fuzzes `x3dh::respond` — the entry point that parses an attacker-
//! controlled init message against a *real* responder's key material
//! (an asynchronous message can arrive from anyone, so this is exactly
//! the untrusted-input boundary in a real deployment).
//!
//! # Why the responder's key material is cached, and why inputs are spliced
//! The responder's long-term material is built once per process rather
//! than per iteration. Regenerating it each time made this target slow
//! (ML-DSA-87 and ML-KEM-1024 key generation dominated, holding it to
//! roughly twenty executions a second) and inflated its coverage number,
//! since thousands of edges inside key generation light up whatever the
//! input is — the figure that was meant to show the *parser* was being
//! reached mostly showed that key generation runs.
//!
//! The one-time prekey store is refilled every iteration, which is the
//! part that genuinely must not carry over: `respond` consumes a prekey
//! on success, and a successful parse on one input must not change how a
//! later input is handled.
//!
//! The seed message deliberately references *no* one-time prekey. That is
//! what lets a splice landing outside the load-bearing bytes still decrypt
//! and reach the payload parsing behind the AEAD — the embedded
//! `PublicIdentity`, the payload framing — rather than always stopping at
//! an authentication failure. The store is populated anyway, so a splice
//! that flips the presence flag still exercises the prekey-lookup path.
//!
//! Random bytes also stop at the first field — an init message needs a
//! length-prefixed ML-KEM-1024 ciphertext of exactly 1568 bytes — so each
//! input is additionally spliced over a window of a genuine init message,
//! landing mutations inside something `respond` will actually walk into:
//! the one-time-prekey presence flag, the AEAD, the embedded identity,
//! the payload framing. Same reasoning as `ENGINEERING-STANDARDS.md` §6.31.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use novachannel::identity::Identity;
use novachannel::prekey::{
    DhIdentity, OneTimePreKey, OneTimePreKeyStore, PreKeyBundle, SignedPreKey,
};
use novachannel::x3dh::{initiate, respond};

/// The one-time prekey id the seed message below references, and the id
/// refilled into the store every iteration so the splice can reach the
/// OPK path rather than bouncing off `UnknownOneTimePreKey`.
const OPK_ID: u32 = 1;

struct Responder {
    dh_identity: DhIdentity,
    spk: SignedPreKey,
    genuine_init: Vec<u8>,
}

fn responder() -> &'static Responder {
    static RESPONDER: OnceLock<Responder> = OnceLock::new();
    RESPONDER.get_or_init(|| {
        let identity = Identity::generate();
        let dh_identity = DhIdentity::generate();
        let spk = SignedPreKey::generate(&identity);

        let bundle = PreKeyBundle::build(identity.public(), &dh_identity, &spk, None);

        let initiator = Identity::generate();
        let initiator_dh = DhIdentity::generate();
        let genuine_init = initiate(&initiator.public(), &initiator_dh, &bundle, b"fuzz seed")
            .expect("initiating against a freshly built bundle succeeds")
            .message
            .bytes;

        Responder {
            dh_identity,
            spk,
            genuine_init,
        }
    })
}

/// A store holding exactly the prekey the seed message references — fresh
/// every iteration, so consumption never carries between inputs.
fn fresh_opks() -> OneTimePreKeyStore {
    let mut opks = OneTimePreKeyStore::new();
    opks.add(OneTimePreKey::generate(OPK_ID));
    opks
}

fuzz_target!(|data: &[u8]| {
    let responder = responder();

    let _ = respond(
        &responder.dh_identity,
        &responder.spk,
        &mut fresh_opks(),
        data,
    );

    if let Some((offset_bytes, patch)) = data.split_first_chunk::<4>() {
        if !patch.is_empty() {
            let genuine = &responder.genuine_init;
            let offset = u32::from_le_bytes(*offset_bytes) as usize % genuine.len();
            let mut spliced = genuine.clone();
            let end = (offset + patch.len()).min(spliced.len());
            spliced[offset..end].copy_from_slice(&patch[..end - offset]);
            let _ = respond(
                &responder.dh_identity,
                &responder.spk,
                &mut fresh_opks(),
                &spliced,
            );
        }
    }
});
