//! Fuzzes `RatchetedSession::open` and `open_ratchet_chunk` — this
//! crate's most involved parser, covering both plain
//! application/ratchet-control records and the erasure-coded
//! incremental-ratchet chunk format.
//!
//! # Why the handshake is cached, and why inputs are spliced
//! This target used to run a complete three-message handshake, including
//! two ML-DSA-87 identity generations, on *every* iteration. That held it
//! to roughly eight executions a second — 644 in a 75-second run, which
//! is not fuzzing so much as running the same handshake repeatedly. It
//! also inflated its coverage figure with hundreds of edges from key
//! generation and the handshake itself, none of which is the parser under
//! test.
//!
//! The handshake now happens once per process. What must stay fresh is
//! the *receiving* session state, since `open` mutates chain keys,
//! sequence numbers and the skipped-key cache, and a successful open on
//! one input must not change how a later input is handled — so a new
//! `RatchetedSession` is built each iteration from the cached
//! `ratchet_root` via `EstablishedSession`'s public fields, which is
//! cheap.
//!
//! Random bytes reach the AEAD and stop: an application record is a
//! 12-byte header then a ciphertext that has to authenticate. Each input
//! is therefore also spliced over a window of genuine records — an
//! application record, a ratchet step-1 control record, and an
//! incremental-ratchet chunk — so mutations land inside messages whose
//! epoch and sequence framing is valid, reaching the epoch/sequence
//! handling, the skipped-key path, and the chunk accumulator rather than
//! bouncing off the first tag check. Same reasoning, and the same
//! measured motivation, as `ENGINEERING-STANDARDS.md` §6.31.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use novachannel::handshake::{initiator_start, responder_respond, EstablishedSession, PeerInfo};
use novachannel::identity::{Identity, PublicIdentity};
use novachannel::ratchet::RatchetedSession;
use novachannel::transport::{DirectionalKey, Receiver, Sender};

struct Seed {
    peer_identity: PublicIdentity,
    /// The server side's ratchet root, so every iteration can rebuild a
    /// receiving session that the genuine records below decrypt against.
    ratchet_root: [u8; 32],
    application_record: Vec<u8>,
    step1_record: Vec<u8>,
    chunk_record: Vec<u8>,
}

fn seed() -> &'static Seed {
    static SEED: OnceLock<Seed> = OnceLock::new();
    SEED.get_or_init(|| {
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let (init_state, msg1) = initiator_start(None);
        let (resp_state, msg2) =
            responder_respond(&server_identity, None, &msg1).expect("genuine msg1 parses");
        let (msg3, client_session) = init_state
            .complete(&client_identity, &msg2)
            .expect("genuine msg2 parses");
        let server_session = resp_state.complete(&msg3).expect("genuine msg3 parses");

        // The client seals; the server is what gets fuzzed, so these are
        // records the server's own receive chain would accept.
        let mut client = RatchetedSession::new(&client_session, true);
        let application_record = client.seal(b"fuzz seed").expect("sealing succeeds");
        let step1_record = client.initiate_ratchet().expect("initiating succeeds");

        // A second client, so its pending ratchet does not collide with
        // the one-shot step above.
        let mut chunk_client = RatchetedSession::new(&client_session, true);
        let chunk_record = chunk_client
            .initiate_incremental_ratchet(2, 1)
            .expect("incremental initiation succeeds")
            .remove(0);

        Seed {
            peer_identity: server_session.peer.identity.clone(),
            ratchet_root: server_session.ratchet_root,
            application_record,
            step1_record,
            chunk_record,
        }
    })
}

/// Rebuilds the receiving side from the cached root. The transport
/// `Sender`/`Receiver` halves are never exercised by this target — only
/// `ratchet_root` seeds the chains `open` uses — so they are constructed
/// from fixed keys rather than re-derived.
fn fresh_receiver(seed: &Seed) -> RatchetedSession {
    let session = EstablishedSession {
        peer: PeerInfo {
            identity: seed.peer_identity.clone(),
        },
        sender: Sender::new(DirectionalKey::new(&[0u8; 32], &[0u8; 12])),
        receiver: Receiver::new(DirectionalKey::new(&[0u8; 32], &[0u8; 12])),
        ratchet_root: seed.ratchet_root,
    };
    RatchetedSession::new(&session, false)
}

fn splice(genuine: &[u8], offset_bytes: [u8; 4], patch: &[u8]) -> Option<Vec<u8>> {
    if patch.is_empty() {
        return None;
    }
    let offset = u32::from_le_bytes(offset_bytes) as usize % genuine.len();
    let mut out = genuine.to_vec();
    let end = (offset + patch.len()).min(out.len());
    out[offset..end].copy_from_slice(&patch[..end - offset]);
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    let seed = seed();

    let mut server = fresh_receiver(seed);
    let _ = server.open(data);
    let _ = server.open_ratchet_chunk(data);

    let Some((offset_bytes, patch)) = data.split_first_chunk::<4>() else {
        return;
    };
    for genuine in [
        &seed.application_record,
        &seed.step1_record,
        &seed.chunk_record,
    ] {
        if let Some(spliced) = splice(genuine, *offset_bytes, patch) {
            // A fresh session per record: `open` mutates chain state, and
            // one record's effect must not decide another's outcome.
            let mut session = fresh_receiver(seed);
            let _ = session.open(&spliced);
            let _ = session.open_ratchet_chunk(&spliced);
        }
    }
});
