use novachannel::handshake::{initiator_start, responder_respond};
use novachannel::identity::Identity;
use novachannel::ratchet::{ChunkOutcome, Opened, RatchetedSession};

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
        Opened::RatchetAdvanced { .. } => panic!("expected an application message"),
    }
}

/// Delivers each of `chunks` to `receiver` with `open_ratchet_chunk` and
/// returns the reply records from the call that produced `Step1Complete`
/// (at most one: the chunk that reaches `data_shards`).
fn deliver_step1_chunks(
    receiver: &mut RatchetedSession,
    chunks: &[Vec<u8>],
) -> Option<Vec<Vec<u8>>> {
    let mut reply = None;
    for chunk in chunks {
        match receiver.open_ratchet_chunk(chunk).unwrap() {
            ChunkOutcome::StillAccumulating => {}
            ChunkOutcome::Step1Complete { reply_records } => {
                assert!(reply.is_none(), "reconstruction completed twice");
                reply = Some(reply_records);
            }
            ChunkOutcome::Step2Complete => panic!("expected a step-1 outcome"),
        }
    }
    reply
}

/// Delivers every element of `chunks` (a step-2 reply) to `receiver`,
/// asserting exactly one produces `Step2Complete`.
fn deliver_step2_chunks(receiver: &mut RatchetedSession, chunks: &[Vec<u8>]) {
    let mut completed = false;
    for chunk in chunks {
        match receiver.open_ratchet_chunk(chunk).unwrap() {
            ChunkOutcome::StillAccumulating => {}
            ChunkOutcome::Step2Complete => {
                assert!(!completed, "step2 completed twice");
                completed = true;
            }
            ChunkOutcome::Step1Complete { .. } => panic!("expected a step-2 outcome"),
        }
    }
    assert!(completed, "step2 chunks never reconstructed");
}

#[test]
fn full_round_trip_with_no_losses() {
    let (mut client, mut server) = run_handshake();

    let step1_chunks = client.initiate_incremental_ratchet(5, 2).unwrap();
    assert_eq!(step1_chunks.len(), 7);

    let step2_records =
        deliver_step1_chunks(&mut server, &step1_chunks).expect("reconstruction completes");
    assert!(step2_records.len() > 1, "step2 was also chunked");

    deliver_step2_chunks(&mut client, &step2_records);

    // Both sides are now on the new epoch and can exchange ordinary
    // application data again over the ordinary sequential `seal`/`open`.
    let record = client.seal(b"post-incremental-ratchet").unwrap();
    assert_eq!(
        expect_application(server.open(&record).unwrap()),
        b"post-incremental-ratchet"
    );
}

#[test]
fn tolerates_losing_up_to_parity_shards_chunks_in_either_direction() {
    let (mut client, mut server) = run_handshake();

    let step1_chunks = client.initiate_incremental_ratchet(5, 2).unwrap();
    // Drop exactly `parity_shards` (2) of the 7 step-1 chunks.
    let surviving_step1: Vec<Vec<u8>> = step1_chunks
        .into_iter()
        .enumerate()
        .filter(|(i, _)| *i != 1 && *i != 4)
        .map(|(_, c)| c)
        .collect();
    assert_eq!(surviving_step1.len(), 5);

    let step2_records =
        deliver_step1_chunks(&mut server, &surviving_step1).expect("still reconstructs");

    // Drop 2 of the step-2 reply chunks too.
    let surviving_step2: Vec<Vec<u8>> = step2_records
        .into_iter()
        .enumerate()
        .filter(|(i, _)| *i != 0 && *i != 6)
        .map(|(_, c)| c)
        .collect();

    deliver_step2_chunks(&mut client, &surviving_step2);

    let record = client.seal(b"still works").unwrap();
    assert_eq!(
        expect_application(server.open(&record).unwrap()),
        b"still works"
    );
    let record = server.seal(b"me too").unwrap();
    assert_eq!(expect_application(client.open(&record).unwrap()), b"me too");
}

#[test]
fn chunk_arrival_order_does_not_matter() {
    let (mut client, mut server) = run_handshake();
    let mut step1_chunks = client.initiate_incremental_ratchet(4, 3).unwrap();
    step1_chunks.reverse();
    step1_chunks.swap(0, 3);

    let step2_records =
        deliver_step1_chunks(&mut server, &step1_chunks).expect("order-independent");
    deliver_step2_chunks(&mut client, &step2_records);

    let record = server.seal(b"order independent").unwrap();
    assert_eq!(
        expect_application(client.open(&record).unwrap()),
        b"order independent"
    );
}

#[test]
fn fewer_than_data_shards_never_completes_and_reports_partial_progress() {
    let (mut client, mut server) = run_handshake();
    let step1_chunks = client.initiate_incremental_ratchet(5, 2).unwrap();

    // Only 4 of the 5 needed shards ever arrive.
    let partial = &step1_chunks[..4];
    let reply = deliver_step1_chunks(&mut server, partial);
    assert!(reply.is_none());

    let (step1_progress, _step2_progress) = server.incremental_ratchet_progress();
    assert_eq!(step1_progress, Some((4, 5)));
}

#[test]
fn straggler_chunks_after_completion_are_ignored_not_treated_as_decrypt_failures() {
    // Regression test: `root_key` changes as soon as reconstruction completes.
    // A leftover chunk of the completed attempt (e.g. an unneeded parity shard)
    // arriving afterwards must be recognized and ignored, not decrypted with
    // the new root key and treated as corrupt.
    let (mut client, mut server) = run_handshake();

    // 5-of-7: reconstruction completes on the 5th chunk delivered, then
    // the 6th and 7th are exactly this scenario.
    let step1_chunks = client.initiate_incremental_ratchet(5, 2).unwrap();
    assert_eq!(step1_chunks.len(), 7);

    let mut reply_records = None;
    for chunk in &step1_chunks {
        match server.open_ratchet_chunk(chunk).unwrap() {
            ChunkOutcome::StillAccumulating => {}
            ChunkOutcome::Step1Complete { reply_records: r } => reply_records = Some(r),
            ChunkOutcome::Step2Complete => panic!("expected a step-1 outcome"),
        }
    }
    let reply_records = reply_records.expect("reconstruction completes on chunk 5");

    let mut step2_completed = false;
    for chunk in &reply_records {
        match client.open_ratchet_chunk(chunk).unwrap() {
            ChunkOutcome::StillAccumulating => {}
            ChunkOutcome::Step2Complete => step2_completed = true,
            ChunkOutcome::Step1Complete { .. } => panic!("expected a step-2 outcome"),
        }
    }
    assert!(step2_completed);

    // Both directions' stragglers were processed without error (the old
    // behavior panicked at the `.unwrap()`s); the session must still work.
    let record = client.seal(b"survived the stragglers").unwrap();
    assert_eq!(
        expect_application(server.open(&record).unwrap()),
        b"survived the stragglers"
    );
}

#[test]
fn one_shot_and_incremental_ratchets_produce_interoperable_established_sessions() {
    // Both variants drive the same epoch/root-key state machine: a one-shot
    // step must work on a session that never used the incremental path, and
    // vice versa, without either depending on the other's setup.
    let (mut client, mut server) = run_handshake();

    let step1 = client.initiate_ratchet().unwrap();
    let reply = match server.open(&step1).unwrap() {
        Opened::RatchetAdvanced { reply: Some(r) } => r,
        _ => panic!("expected a one-shot step-2 reply"),
    };
    assert!(matches!(
        client.open(&reply).unwrap(),
        Opened::RatchetAdvanced { reply: None }
    ));

    // Now do an *incremental* ratchet step on the same, already-once-
    // ratcheted session.
    let step1_chunks = client.initiate_incremental_ratchet(3, 2).unwrap();
    let step2_records = deliver_step1_chunks(&mut server, &step1_chunks).expect("reconstructs");
    deliver_step2_chunks(&mut client, &step2_records);

    let record = client.seal(b"mixed ratchet history").unwrap();
    assert_eq!(
        expect_application(server.open(&record).unwrap()),
        b"mixed ratchet history"
    );
}

#[test]
fn concurrent_pending_one_shot_ratchet_rejects_incoming_incremental_step1() {
    let (mut client, mut server) = run_handshake();
    // Server has its own pending one-shot ratchet outstanding.
    let _server_step1 = server.initiate_ratchet().unwrap();

    // The client tries an incremental ratchet while the server's own ratchet
    // is pending, which must be refused, mirroring the one-shot
    // `RatchetInProgress` guard.
    let step1_chunks = client.initiate_incremental_ratchet(3, 2).unwrap();
    let result = server.open_ratchet_chunk(&step1_chunks[0]);
    assert!(matches!(result, Err(novachannel::Error::RatchetInProgress)));
}

#[test]
fn a_ratchet_chunk_delivered_through_open_is_rejected_as_unknown_message_type() {
    // Chunks bypass `RatchetedSession::open`'s dispatch (module docs), so
    // delivering one there must fail rather than be accepted through the wrong
    // path.
    let (mut client, mut server) = run_handshake();
    let step1_chunks = client.initiate_incremental_ratchet(3, 2).unwrap();
    let result = server.open(&step1_chunks[0]);
    assert!(result.is_err());
}
