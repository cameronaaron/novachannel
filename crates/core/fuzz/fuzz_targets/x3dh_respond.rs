//! Fuzzes `x3dh::respond`, which parses an attacker-controlled init message
//! against a real responder's keys: asynchronous messages can come from
//! anyone.
//!
//! # Why the responder is cached and inputs are spliced
//! The responder's long-term material is built once per process.
//! Per-iteration ML-DSA-87 and ML-KEM-1024 key generation held the target to
//! about twenty executions a second and filled its coverage with
//! key-generation edges.
//!
//! The one-time prekey store is refilled every iteration, since `respond`
//! consumes a prekey on success and one input must not affect the next.
//!
//! The seed message references *no* one-time prekey, so a splice outside
//! the load-bearing bytes still decrypts and reaches the payload parsing
//! behind the AEAD (embedded `PublicIdentity`, payload framing) instead of
//! failing authentication. The store is populated anyway, so a splice that
//! flips the presence flag reaches the prekey lookup.
//!
//! Random bytes stop at the first field (a length-prefixed ML-KEM-1024
//! ciphertext of exactly 1568 bytes), so each input is also spliced into a
//! genuine init message, reaching the prekey flag, AEAD, embedded identity
//! and payload framing (`ENGINEERING-STANDARDS.md` §6.31).
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use novachannel::identity::Identity;
use novachannel::prekey::{
    DhIdentity, OneTimePreKey, OneTimePreKeyStore, PreKeyBundle, SignedPreKey,
};
use novachannel::x3dh::{initiate, respond};

/// The one-time prekey id put in the store every iteration. The seed
/// message references none; this id lets a splice that sets the presence
/// flag reach the prekey path rather than `UnknownOneTimePreKey`.
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

/// A fresh store each iteration, holding [`OPK_ID`], so consumption never
/// carries over between inputs.
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
