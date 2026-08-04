use novachannel::handshake::{initiator_start, responder_respond};
use novachannel::identity::Identity;
use novachannel::Error;

fn run_handshake(
    pin_server_as: Option<()>,
    pin_client_as: Option<()>,
) -> (
    novachannel::EstablishedSession,
    novachannel::EstablishedSession,
    Identity,
    Identity,
) {
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    let expected_server = pin_server_as.map(|_| server_identity.public());
    let expected_client = pin_client_as.map(|_| client_identity.public());

    let (init_state, msg1) = initiator_start(expected_server);
    let (resp_state, msg2) = responder_respond(&server_identity, expected_client, &msg1).unwrap();
    let (msg3, client_session) = init_state.complete(&client_identity, &msg2).unwrap();
    let server_session = resp_state.complete(&msg3).unwrap();

    (
        client_session,
        server_session,
        server_identity,
        client_identity,
    )
}

#[test]
fn handshake_round_trip_and_transport() {
    let (mut client, mut server, server_id, client_id) = run_handshake(Some(()), Some(()));

    assert_eq!(client.peer.identity, server_id.public());
    assert_eq!(server.peer.identity, client_id.public());

    let record = client.sender.seal(b"ping").unwrap();
    let opened = server.receiver.open(&record).unwrap();
    assert_eq!(opened, b"ping");

    let record = server.sender.seal(b"pong").unwrap();
    let opened = client.receiver.open(&record).unwrap();
    assert_eq!(opened, b"pong");
}

#[test]
fn tampered_record_fails_to_decrypt() {
    let (mut client, mut server, _, _) = run_handshake(None, None);

    let mut record = client.sender.seal(b"authentic").unwrap();
    let last = record.len() - 1;
    record[last] ^= 0x01;

    assert!(matches!(server.receiver.open(&record), Err(Error::Decrypt)));
}

#[test]
fn replayed_record_is_rejected() {
    let (mut client, mut server, _, _) = run_handshake(None, None);

    let record = client.sender.seal(b"once").unwrap();
    assert!(server.receiver.open(&record).is_ok());
    assert!(matches!(server.receiver.open(&record), Err(Error::Replay)));
}

#[test]
fn out_of_order_records_within_window_are_accepted() {
    let (mut client, mut server, _, _) = run_handshake(None, None);

    let r1 = client.sender.seal(b"first").unwrap();
    let r2 = client.sender.seal(b"second").unwrap();

    assert_eq!(server.receiver.open(&r2).unwrap(), b"second");
    assert_eq!(server.receiver.open(&r1).unwrap(), b"first");
}

#[test]
fn wrong_pinned_server_identity_is_rejected() {
    let real_server = Identity::generate();
    let decoy_server_public = Identity::generate().public();
    let client_identity = Identity::generate();

    let (init_state, msg1) = initiator_start(Some(decoy_server_public));
    let (_resp_state, msg2) = responder_respond(&real_server, None, &msg1).unwrap();

    let result = init_state.complete(&client_identity, &msg2);
    assert!(matches!(result, Err(Error::IdentityMismatch)));
}

#[test]
fn wrong_pinned_initiator_identity_is_rejected() {
    let server_identity = Identity::generate();
    let real_client = Identity::generate();
    let decoy_client_public = Identity::generate().public();

    let (init_state, msg1) = initiator_start(None);
    let (resp_state, msg2) =
        responder_respond(&server_identity, Some(decoy_client_public), &msg1).unwrap();
    let (msg3, _client_session) = init_state.complete(&real_client, &msg2).unwrap();

    let result = resp_state.complete(&msg3);
    assert!(matches!(result, Err(Error::IdentityMismatch)));
}

#[test]
fn trailing_bytes_in_msg1_are_rejected() {
    let server_identity = Identity::generate();
    let (_init_state, mut msg1) = initiator_start(None);
    msg1.push(0xFF);
    assert!(matches!(
        responder_respond(&server_identity, None, &msg1),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn trailing_bytes_in_msg2_are_rejected() {
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    let (init_state, msg1) = initiator_start(None);
    let (_resp_state, mut msg2) = responder_respond(&server_identity, None, &msg1).unwrap();
    msg2.push(0xFF);

    let result = init_state.complete(&client_identity, &msg2);
    assert!(matches!(result, Err(Error::Malformed(_))));
}

#[test]
fn trailing_bytes_in_msg3_are_rejected() {
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    let (init_state, msg1) = initiator_start(None);
    let (resp_state, msg2) = responder_respond(&server_identity, None, &msg1).unwrap();
    let (mut msg3, _client_session) = init_state.complete(&client_identity, &msg2).unwrap();
    msg3.push(0xFF);

    let result = resp_state.complete(&msg3);
    assert!(matches!(result, Err(Error::Malformed(_))));
}

#[test]
fn public_identity_and_signature_debug_output_do_not_leak_raw_key_material() {
    // Also the only exercise of `Debug` for `PublicIdentity`/`HybridSignature`
    // — worth checking directly rather than incidentally, since the whole
    // point of the hand-written impls (over `#[derive(Debug)]`) is
    // summarizing the PQ component's length instead of dumping its bytes.
    let identity = Identity::generate();
    let public = identity.public();
    let sig = identity.sign(b"message");

    let public_debug = format!("{:?}", public);
    assert!(public_debug.contains("PublicIdentity"));
    assert!(public_debug.contains("bytes"));

    let sig_debug = format!("{:?}", sig);
    assert!(sig_debug.contains("HybridSignature"));
    assert!(sig_debug.contains("bytes"));
}

#[test]
fn forged_signature_is_rejected() {
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    let (init_state, msg1) = initiator_start(None);
    let (_resp_state, mut msg2) = responder_respond(&server_identity, None, &msg1).unwrap();

    // Flip a bit inside the signature tail to simulate a forged/corrupted
    // proof of identity; the transcript binding must still catch it even
    // though the KEM material is untouched and still decapsulates fine.
    let last = msg2.len() - 1;
    msg2[last] ^= 0x01;

    let result = init_state.complete(&client_identity, &msg2);
    assert!(result.is_err());
}
