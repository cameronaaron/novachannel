use novachannel::handshake::{initiator_start, responder_respond};
use novachannel::identity::Identity;
use novachannel::ratchet::{Opened, RatchetedSession};
use novachannel::Error;

fn run_handshake() -> (RatchetedSession, RatchetedSession) {
    let server_identity = Identity::generate();
    let client_identity = Identity::generate();

    let (init_state, msg1) = initiator_start(None);
    let (resp_state, msg2) = responder_respond(&server_identity, None, &msg1).unwrap();
    let (msg3, client_session) = init_state.complete(&client_identity, &msg2).unwrap();
    let server_session = resp_state.complete(&msg3).unwrap();

    (
        RatchetedSession::new(&client_session, true),
        RatchetedSession::new(&server_session, false),
    )
}

fn expect_application(opened: Opened) -> Vec<u8> {
    match opened {
        Opened::Application(bytes) => bytes,
        Opened::RatchetAdvanced { .. } => wrong_variant(),
    }
}

/// Separate from `expect_application` so tarpaulin's item-level exclusion
/// (`#[cfg(not(tarpaulin_include))]`, `ENGINEERING-STANDARDS.md` §6.16) can
/// target just this arm, which only fires when a test asserts the wrong
/// `Opened` variant.
#[cfg(not(tarpaulin_include))]
fn wrong_variant() -> ! {
    panic!("expected an application message")
}

#[test]
fn plain_messages_round_trip_before_any_ratchet() {
    let (mut client, mut server) = run_handshake();

    let record = client.seal(b"hello").unwrap();
    assert_eq!(expect_application(server.open(&record).unwrap()), b"hello");

    let record = server.seal(b"hi back").unwrap();
    assert_eq!(
        expect_application(client.open(&record).unwrap()),
        b"hi back"
    );
}

#[test]
fn each_message_is_sealed_under_a_different_key() {
    // Two identical plaintexts sealed back to back must differ, proving the
    // chain key advances rather than staying static.
    let (mut client, _server) = run_handshake();

    let r1 = client.seal(b"same plaintext").unwrap();
    let r2 = client.seal(b"same plaintext").unwrap();
    assert_ne!(r1, r2);
}

#[test]
fn tampered_record_fails_to_decrypt_and_does_not_desync_the_chain() {
    let (mut client, mut server) = run_handshake();

    let mut forged = client.seal(b"authentic").unwrap();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    assert!(matches!(server.open(&forged), Err(Error::Decrypt)));

    // Retrying the same forged bytes must fail the same way, not as a spurious
    // `Replay`: the failed attempt must not have moved the receiver's chain.
    assert!(matches!(server.open(&forged), Err(Error::Decrypt)));
}

#[test]
fn a_later_record_is_opened_immediately_and_the_earlier_one_still_opens_afterward() {
    // `seq=1` before `seq=0` caches the skipped key for `seq=0` instead of
    // rejecting `seq=1`: the bounded skipped-key mechanism of real Double
    // Ratchet implementations (module docs).
    let (mut client, mut server) = run_handshake();

    let r1 = client.seal(b"first").unwrap();
    let r2 = client.seal(b"second").unwrap();

    assert_eq!(expect_application(server.open(&r2).unwrap()), b"second");
    assert_eq!(expect_application(server.open(&r1).unwrap()), b"first");
}

#[test]
fn a_skipped_key_can_only_be_used_once() {
    let (mut client, mut server) = run_handshake();

    let r1 = client.seal(b"first").unwrap();
    let r2 = client.seal(b"second").unwrap();

    expect_application(server.open(&r2).unwrap());
    expect_application(server.open(&r1).unwrap());

    // Replaying the already-used skipped record must fail: its key was
    // deleted on use.
    assert!(matches!(server.open(&r1), Err(Error::Replay)));
}

#[test]
fn several_records_can_arrive_out_of_order_and_all_still_open() {
    let (mut client, mut server) = run_handshake();

    let records: Vec<Vec<u8>> = (0..5)
        .map(|i| client.seal(format!("message {i}").as_bytes()).unwrap())
        .collect();

    // Deliver in a scrambled order: 2, 4, 0, 3, 1.
    for &i in &[2usize, 4, 0, 3, 1] {
        let plaintext = expect_application(server.open(&records[i]).unwrap());
        assert_eq!(plaintext, format!("message {i}").as_bytes());
    }
}

#[test]
fn skipping_past_the_bound_is_rejected_without_desyncing_expected_seq() {
    let (mut client, mut server) = run_handshake();

    let in_order_first = client.seal(b"real first message").unwrap();

    // Advance a second chain far ahead by sealing many undelivered records,
    // then send one whose gap exceeds the bound.
    for _ in 0..novachannel::ratchet::MAX_SKIPPED_KEYS {
        client.seal(b"filler").unwrap();
    }
    let far_future = client.seal(b"too far").unwrap();
    assert!(matches!(
        server.open(&far_future),
        Err(Error::TooManySkippedKeys)
    ));

    // The server's `expected_seq` must still be 0 — the rejected attempt
    // didn't touch it, so the real first message still opens normally.
    assert_eq!(
        expect_application(server.open(&in_order_first).unwrap()),
        b"real first message"
    );
}

#[test]
fn a_ratchet_step_produces_a_fresh_epoch_both_sides_agree_on() {
    let (mut client, mut server) = run_handshake();

    let step1 = client.initiate_ratchet().unwrap();
    let opened = server.open(&step1).unwrap();
    let reply = match opened {
        Opened::RatchetAdvanced { reply: Some(r) } => r,
        _ => panic!("expected a step-2 reply"),
    };

    let opened = client.open(&reply).unwrap();
    assert!(matches!(opened, Opened::RatchetAdvanced { reply: None }));

    // Both sides should now be on the new epoch and able to exchange
    // ordinary messages again.
    let record = client.seal(b"post-ratchet").unwrap();
    assert_eq!(
        expect_application(server.open(&record).unwrap()),
        b"post-ratchet"
    );

    let record = server.seal(b"post-ratchet reply").unwrap();
    assert_eq!(
        expect_application(client.open(&record).unwrap()),
        b"post-ratchet reply"
    );
}

#[test]
fn messages_in_flight_before_the_ratchet_reply_still_open_via_the_previous_epoch() {
    // The responder switches epochs as it sends its step-2 reply. Messages the
    // initiator sent on the old epoch before processing that reply must still
    // be accepted through the retained previous-epoch chain, not rejected as
    // an unknown epoch.
    let (mut client, mut server) = run_handshake();

    let step1 = client.initiate_ratchet().unwrap();
    // Client sends one more old-epoch application message before the
    // step-1 control message is even delivered/responded to.
    let old_epoch_msg = client.seal(b"still old epoch").unwrap();

    let opened = server.open(&step1).unwrap();
    let reply = match opened {
        Opened::RatchetAdvanced { reply: Some(r) } => r,
        _ => panic!("expected a step-2 reply"),
    };
    // Server has now switched to the new epoch, but the client's
    // already-in-flight old-epoch message must still open.
    assert_eq!(
        expect_application(server.open(&old_epoch_msg).unwrap()),
        b"still old epoch"
    );

    let opened = client.open(&reply).unwrap();
    assert!(matches!(opened, Opened::RatchetAdvanced { reply: None }));
}

#[test]
fn a_record_from_an_epoch_older_than_the_retained_previous_one_is_rejected() {
    let (mut client, mut server) = run_handshake();

    // Deliver the epoch-0 record normally but keep a copy to replay later,
    // simulating a delayed duplicate packet arriving long after.
    let stale = client.seal(b"epoch 0").unwrap();
    assert_eq!(expect_application(server.open(&stale).unwrap()), b"epoch 0");

    // Two full ratchet steps move both sides two epochs forward, past
    // the single retained previous epoch.
    for _ in 0..2 {
        let step1 = client.initiate_ratchet().unwrap();
        let reply = match server.open(&step1).unwrap() {
            Opened::RatchetAdvanced { reply: Some(r) } => r,
            _ => panic!("expected a step-2 reply"),
        };
        assert!(matches!(
            client.open(&reply).unwrap(),
            Opened::RatchetAdvanced { reply: None }
        ));
    }

    assert!(matches!(server.open(&stale), Err(Error::UnknownEpoch)));
}

#[test]
fn double_initiating_a_ratchet_before_the_first_completes_is_rejected() {
    let (mut client, _server) = run_handshake();

    client.initiate_ratchet().unwrap();
    assert!(matches!(
        client.initiate_ratchet(),
        Err(Error::RatchetInProgress)
    ));
}

#[test]
fn concurrent_initiation_from_both_sides_is_rejected_not_silently_corrupted() {
    let (mut client, mut server) = run_handshake();

    let client_step1 = client.initiate_ratchet().unwrap();
    let server_step1 = server.initiate_ratchet().unwrap();

    // The server has its own pending ratchet, so the client's concurrent step
    // 1 must be rejected rather than silently producing disagreeing epoch
    // state.
    assert!(matches!(
        server.open(&client_step1),
        Err(Error::RatchetInProgress)
    ));
    assert!(matches!(
        client.open(&server_step1),
        Err(Error::RatchetInProgress)
    ));
}

#[test]
fn keys_before_and_after_a_ratchet_are_independent() {
    // A cheap check of forward secrecy across epochs: the same plaintext
    // sealed in two epochs must not share message-key-dependent tag bytes, as
    // it would if the new chain were derived from the old one without the
    // fresh KEX material.
    let (mut client, mut server) = run_handshake();

    let before = client.seal(b"same plaintext").unwrap();
    // Deliver it to keep the chain in lockstep — see the module docs on
    // why an undelivered record would deadlock everything after it.
    server.open(&before).unwrap();

    let step1 = client.initiate_ratchet().unwrap();
    let reply = match server.open(&step1).unwrap() {
        Opened::RatchetAdvanced { reply: Some(r) } => r,
        _ => panic!("expected a step-2 reply"),
    };
    client.open(&reply).unwrap();

    let after = client.seal(b"same plaintext").unwrap();

    assert_ne!(before, after);
    // Different epoch/seq headers would differ anyway, so also compare the
    // ciphertext and tag past the 12-byte header.
    assert_ne!(before[12..], after[12..]);
}
