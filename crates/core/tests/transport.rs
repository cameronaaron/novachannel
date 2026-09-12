use novachannel::transport::{DirectionalKey, Receiver, Sender, MAX_PLAINTEXT_LEN};
use novachannel::Error;

fn pair() -> (Sender, Receiver) {
    let key = [0x42u8; 32];
    let iv = [0x24u8; 12];
    (
        Sender::new(DirectionalKey::new(&key, &iv)),
        Receiver::new(DirectionalKey::new(&key, &iv)),
    )
}

#[test]
fn several_in_order_messages_advance_the_replay_window_normally() {
    // The happy path where every message arrives strictly in order (the
    // common case in practice) exercises `check_replay`'s `seq > highest`
    // branch and `record_seen`'s matching shift branch, neither of which
    // a single-message-per-direction test reaches.
    let (mut sender, mut receiver) = pair();
    for i in 0..5u8 {
        let record = sender.seal(&[i]).unwrap();
        assert_eq!(receiver.open(&record).unwrap(), vec![i]);
    }
}

#[test]
fn a_large_forward_jump_still_advances_correctly() {
    // Exercises `record_seen`'s `shift >= REPLAY_WINDOW` reset-to-zero path.
    let (mut sender, mut receiver) = pair();
    let first = sender.seal(b"first").unwrap();
    receiver.open(&first).unwrap();

    for _ in 0..100 {
        sender.seal(b"skip").unwrap();
    }
    let far = sender.seal(b"far").unwrap();
    assert_eq!(receiver.open(&far).unwrap(), b"far");
}

#[test]
fn oversized_plaintext_is_rejected_before_sealing() {
    let (mut sender, _receiver) = pair();
    let too_big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
    assert!(matches!(sender.seal(&too_big), Err(Error::TooLarge)));
}

#[test]
fn a_record_shorter_than_header_plus_tag_is_rejected() {
    let (_sender, mut receiver) = pair();
    assert!(matches!(receiver.open(&[0u8; 4]), Err(Error::Malformed(_))));
}

#[test]
fn an_oversized_record_is_rejected_before_decryption() {
    let (_sender, mut receiver) = pair();
    let bogus = vec![0u8; 8 + 16 + MAX_PLAINTEXT_LEN + 1];
    assert!(matches!(receiver.open(&bogus), Err(Error::TooLarge)));
}

#[test]
fn a_record_far_outside_the_replay_window_is_rejected() {
    let (mut sender, mut receiver) = pair();
    let stale = sender.seal(b"stale").unwrap();

    for _ in 0..100 {
        let r = sender.seal(b"advance").unwrap();
        receiver.open(&r).unwrap();
    }

    assert!(matches!(receiver.open(&stale), Err(Error::Replay)));
}

#[test]
fn replay_window_boundaries_preserve_seen_records_and_accept_unseen_records() {
    for jump in [1usize, 63, 64, 65, 128] {
        let (mut sender, mut receiver) = pair();
        let records: Vec<_> = (0..=jump)
            .map(|_| sender.seal(b"record").unwrap())
            .collect();
        receiver.open(&records[0]).unwrap();
        receiver.open(&records[jump]).unwrap();
        assert!(
            matches!(receiver.open(&records[0]), Err(Error::Replay)),
            "jump {jump}"
        );
        for index in (1..jump).rev() {
            if jump - index <= 64 {
                assert_eq!(receiver.open(&records[index]).unwrap(), b"record");
            }
            assert!(matches!(receiver.open(&records[index]), Err(Error::Replay)));
        }
    }
}
