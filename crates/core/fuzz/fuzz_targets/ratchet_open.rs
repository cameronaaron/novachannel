//! Fuzzes `RatchetedSession::open` — this crate's most involved parser,
//! covering both plain application/ratchet-control records and the
//! erasure-coded incremental-ratchet chunk format. Runs against a real,
//! freshly completed handshake each iteration, so the AEAD/HKDF state
//! is genuine, not a stub.
#![no_main]

use libfuzzer_sys::fuzz_target;
use novachannel::handshake::{initiator_start, responder_respond};
use novachannel::identity::Identity;
use novachannel::ratchet::RatchetedSession;

fuzz_target!(|data: &[u8]| {
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    let (init_state, msg1) = initiator_start(None);
    let Ok((resp_state, msg2)) = responder_respond(&server_identity, None, &msg1) else {
        return;
    };
    let Ok((msg3, client_session)) = init_state.complete(&client_identity, &msg2) else {
        return;
    };
    let Ok(server_session) = resp_state.complete(&msg3) else {
        return;
    };

    let mut server = RatchetedSession::new(&server_session, false);
    let _ = server.open(data);
    let _ = server.open_ratchet_chunk(data);

    let mut client = RatchetedSession::new(&client_session, true);
    let _ = client.open(data);
    let _ = client.open_ratchet_chunk(data);
});
