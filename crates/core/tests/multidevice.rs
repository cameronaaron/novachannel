use novachannel::identity::Identity;
use novachannel::multidevice::{
    DeviceId, DeviceListEntry, MultiDeviceSession, ReceivingDevice, RemoteAccount, SignedDeviceList,
};
use novachannel::prekey::{DhIdentity, PreKeyBundle, SignedPreKey};
use novachannel::ratchet::Opened;
use novachannel::Error;

struct Device {
    signing_identity: Identity,
    dh_identity: DhIdentity,
    spk: SignedPreKey,
}

fn make_device() -> Device {
    let signing_identity = Identity::generate();
    let dh_identity = DhIdentity::generate();
    let spk = SignedPreKey::generate(&signing_identity);
    Device {
        signing_identity,
        dh_identity,
        spk,
    }
}

fn bundle(d: &Device) -> PreKeyBundle {
    PreKeyBundle::build(d.signing_identity.public(), &d.dh_identity, &d.spk, None)
}

#[test]
fn a_message_fans_out_to_every_device_on_a_two_device_account() {
    let alice = Identity::generate();
    let alice_dh = DhIdentity::generate();

    let bob_phone = make_device();
    let bob_desktop = make_device();

    let mut remote = RemoteAccount::new();
    remote.add_device(DeviceId(1), bundle(&bob_phone));
    remote.add_device(DeviceId(2), bundle(&bob_desktop));

    let mut session = MultiDeviceSession::new(alice.public());
    let init = session.sync_devices(&alice_dh, &remote).unwrap();
    assert_eq!(init.messages.len(), 2);
    assert_eq!(session.device_count(), 2);

    let mut phone_receiver =
        ReceivingDevice::new(bob_phone.dh_identity, bob_phone.spk, Default::default());
    let mut desktop_receiver =
        ReceivingDevice::new(bob_desktop.dh_identity, bob_desktop.spk, Default::default());

    for (device_id, init_message) in &init.messages {
        let receiver = match device_id.0 {
            1 => &mut phone_receiver,
            2 => &mut desktop_receiver,
            _ => panic!("unexpected device id"),
        };
        let (identity, _payload) = receiver
            .receive_init(*device_id, &init_message.bytes)
            .unwrap();
        assert_eq!(identity, alice.public());
    }

    let fanned = session.fan_out(b"hello, both devices").unwrap();
    assert_eq!(fanned.len(), 2);

    for (device_id, record) in fanned {
        let receiver = match device_id.0 {
            1 => &mut phone_receiver,
            2 => &mut desktop_receiver,
            _ => panic!("unexpected device id"),
        };
        match receiver
            .open_from(&alice.public(), device_id, &record)
            .unwrap()
        {
            Opened::Application(bytes) => assert_eq!(bytes, b"hello, both devices"),
            Opened::RatchetAdvanced { .. } => panic!("expected application data"),
        }
    }
}

#[test]
fn sync_devices_is_idempotent_for_already_established_devices() {
    let alice = Identity::generate();
    let alice_dh = DhIdentity::generate();
    let bob_phone = make_device();

    let mut remote = RemoteAccount::new();
    remote.add_device(DeviceId(1), bundle(&bob_phone));

    let mut session = MultiDeviceSession::new(alice.public());
    let first = session.sync_devices(&alice_dh, &remote).unwrap();
    assert_eq!(first.messages.len(), 1);

    // Calling again with the same remote account must not re-establish
    // (and thus not re-key) a session for a device already present.
    let second = session.sync_devices(&alice_dh, &remote).unwrap();
    assert_eq!(second.messages.len(), 0);
    assert_eq!(session.device_count(), 1);
}

#[test]
fn a_newly_added_device_is_picked_up_without_disturbing_existing_ones() {
    let alice = Identity::generate();
    let alice_dh = DhIdentity::generate();
    let bob_phone = make_device();

    let mut remote = RemoteAccount::new();
    remote.add_device(DeviceId(1), bundle(&bob_phone));

    let mut session = MultiDeviceSession::new(alice.public());
    session.sync_devices(&alice_dh, &remote).unwrap();
    assert_eq!(session.device_count(), 1);

    let bob_tablet = make_device();
    remote.add_device(DeviceId(2), bundle(&bob_tablet));
    let second = session.sync_devices(&alice_dh, &remote).unwrap();

    assert_eq!(second.messages.len(), 1);
    assert_eq!(second.messages[0].0, DeviceId(2));
    assert_eq!(session.device_count(), 2);
}

#[test]
fn revoking_a_device_removes_it_from_fan_out() {
    let alice = Identity::generate();
    let alice_dh = DhIdentity::generate();
    let bob_phone = make_device();
    let bob_desktop = make_device();

    let mut remote = RemoteAccount::new();
    remote.add_device(DeviceId(1), bundle(&bob_phone));
    remote.add_device(DeviceId(2), bundle(&bob_desktop));

    let mut session = MultiDeviceSession::new(alice.public());
    session.sync_devices(&alice_dh, &remote).unwrap();
    assert_eq!(session.device_count(), 2);

    session.revoke_device(DeviceId(1));
    assert!(!session.has_device(DeviceId(1)));

    let fanned = session.fan_out(b"only desktop now").unwrap();
    assert_eq!(fanned.len(), 1);
    assert_eq!(fanned[0].0, DeviceId(2));
}

#[test]
fn opening_from_an_unknown_device_is_rejected() {
    let alice = Identity::generate();
    let mut session = MultiDeviceSession::new(alice.public());
    let result = session.open_from(DeviceId(99), b"anything");
    assert!(matches!(result, Err(novachannel::Error::UnknownDevice)));

    let bob = make_device();
    let mut receiver = ReceivingDevice::new(bob.dh_identity, bob.spk, Default::default());
    let result = receiver.open_from(&alice.public(), DeviceId(1), b"anything");
    assert!(matches!(result, Err(novachannel::Error::UnknownDevice)));
}

#[test]
fn two_peer_accounts_sending_to_the_same_receiving_device_stay_isolated() {
    // A single physical device (e.g. one of Bob's devices) can hold
    // sessions with many different senders at once; a message tagged as
    // coming from Alice's device 1 must never be openable via Carol's
    // session even if both use the same `DeviceId` value locally.
    let alice = Identity::generate();
    let alice_dh = DhIdentity::generate();
    let carol = Identity::generate();
    let carol_dh = DhIdentity::generate();
    let bob_phone = make_device();

    let mut remote = RemoteAccount::new();
    remote.add_device(DeviceId(1), bundle(&bob_phone));

    let mut alice_session = MultiDeviceSession::new(alice.public());
    let alice_init = alice_session.sync_devices(&alice_dh, &remote).unwrap();

    let mut carol_session = MultiDeviceSession::new(carol.public());
    let carol_init = carol_session.sync_devices(&carol_dh, &remote).unwrap();

    let mut bob_receiver =
        ReceivingDevice::new(bob_phone.dh_identity, bob_phone.spk, Default::default());
    bob_receiver
        .receive_init(DeviceId(1), &alice_init.messages[0].1.bytes)
        .unwrap();
    bob_receiver
        .receive_init(DeviceId(1), &carol_init.messages[0].1.bytes)
        .unwrap();

    assert!(bob_receiver.has_session(&alice.public(), DeviceId(1)));
    assert!(bob_receiver.has_session(&carol.public(), DeviceId(1)));

    let from_alice = alice_session.fan_out(b"from alice").unwrap();
    let opened = bob_receiver
        .open_from(&alice.public(), DeviceId(1), &from_alice[0].1)
        .unwrap();
    match opened {
        Opened::Application(bytes) => assert_eq!(bytes, b"from alice"),
        Opened::RatchetAdvanced { .. } => panic!("expected application data"),
    }

    // Carol's own session is untouched and still independently usable.
    let from_carol = carol_session.fan_out(b"from carol").unwrap();
    let opened = bob_receiver
        .open_from(&carol.public(), DeviceId(1), &from_carol[0].1)
        .unwrap();
    match opened {
        Opened::Application(bytes) => assert_eq!(bytes, b"from carol"),
        Opened::RatchetAdvanced { .. } => panic!("expected application data"),
    }
}

fn entry(d: &Device, device_id: DeviceId) -> DeviceListEntry {
    DeviceListEntry {
        device_id,
        identity: d.signing_identity.public(),
        dh_identity: d.dh_identity.public(),
    }
}

#[test]
fn signed_device_list_authorizes_matching_bundles_and_establishes_sessions() {
    let alice = Identity::generate();
    let alice_dh = DhIdentity::generate();

    let bob_account = Identity::generate();
    let bob_phone = make_device();
    let bob_desktop = make_device();

    let device_list = SignedDeviceList::issue(
        &bob_account,
        1,
        vec![
            entry(&bob_phone, DeviceId(1)),
            entry(&bob_desktop, DeviceId(2)),
        ],
    );
    let bundles = vec![
        (DeviceId(1), bundle(&bob_phone)),
        (DeviceId(2), bundle(&bob_desktop)),
    ];

    let mut session = MultiDeviceSession::new(alice.public());
    let result = session
        .sync_from_signed_device_list(&alice_dh, &bob_account.public(), &device_list, bundles)
        .unwrap();

    assert_eq!(result.messages.len(), 2);
    assert_eq!(session.device_count(), 2);
}

#[test]
fn a_bundle_not_matching_the_signed_list_is_rejected() {
    // Simulates a MITM (or a directory-service bug) handing out a bundle
    // for device 1 whose identity/DH identity don't match what the
    // account actually authorized for that device id.
    let bob_account = Identity::generate();
    let bob_phone = make_device();
    let impostor = make_device();

    let device_list =
        SignedDeviceList::issue(&bob_account, 1, vec![entry(&bob_phone, DeviceId(1))]);
    let bundles = vec![(DeviceId(1), bundle(&impostor))];

    let result =
        RemoteAccount::from_signed_device_list(&bob_account.public(), &device_list, bundles);
    assert!(matches!(result, Err(Error::UnauthorizedDevice)));
}

#[test]
fn a_bundle_for_a_device_id_absent_from_the_list_is_rejected() {
    let bob_account = Identity::generate();
    let bob_phone = make_device();
    let unlisted_device = make_device();

    let device_list =
        SignedDeviceList::issue(&bob_account, 1, vec![entry(&bob_phone, DeviceId(1))]);
    let bundles = vec![
        (DeviceId(1), bundle(&bob_phone)),
        (DeviceId(99), bundle(&unlisted_device)),
    ];

    let result =
        RemoteAccount::from_signed_device_list(&bob_account.public(), &device_list, bundles);
    assert!(matches!(result, Err(Error::UnauthorizedDevice)));
}

#[test]
fn device_list_signed_by_a_different_account_fails_verification() {
    let real_account = Identity::generate();
    let decoy_account = Identity::generate();
    let bob_phone = make_device();

    let device_list =
        SignedDeviceList::issue(&real_account, 1, vec![entry(&bob_phone, DeviceId(1))]);

    assert!(device_list.verify(&decoy_account.public()).is_err());
    let result = RemoteAccount::from_signed_device_list(
        &decoy_account.public(),
        &device_list,
        vec![(DeviceId(1), bundle(&bob_phone))],
    );
    assert!(result.is_err());
}

#[test]
fn stale_device_list_version_is_rejected() {
    let alice = Identity::generate();
    let alice_dh = DhIdentity::generate();
    let bob_account = Identity::generate();
    let bob_phone = make_device();

    let list_v2 = SignedDeviceList::issue(&bob_account, 2, vec![entry(&bob_phone, DeviceId(1))]);
    let mut session = MultiDeviceSession::new(alice.public());
    session
        .sync_from_signed_device_list(
            &alice_dh,
            &bob_account.public(),
            &list_v2,
            vec![(DeviceId(1), bundle(&bob_phone))],
        )
        .unwrap();

    // A replayed or rolled-back version-2 (or older) list must not be
    // accepted a second time, even though its signature is genuine.
    let result = session.sync_from_signed_device_list(
        &alice_dh,
        &bob_account.public(),
        &list_v2,
        vec![(DeviceId(1), bundle(&bob_phone))],
    );
    assert!(matches!(result, Err(Error::StaleDeviceList)));

    let list_v1 = SignedDeviceList::issue(&bob_account, 1, vec![entry(&bob_phone, DeviceId(1))]);
    let result = session.sync_from_signed_device_list(
        &alice_dh,
        &bob_account.public(),
        &list_v1,
        vec![(DeviceId(1), bundle(&bob_phone))],
    );
    assert!(matches!(result, Err(Error::StaleDeviceList)));
}

#[test]
fn a_device_removed_from_a_newer_list_has_its_session_revoked() {
    let alice = Identity::generate();
    let alice_dh = DhIdentity::generate();
    let bob_account = Identity::generate();
    let bob_phone = make_device();
    let bob_desktop = make_device();

    let list_v1 = SignedDeviceList::issue(
        &bob_account,
        1,
        vec![
            entry(&bob_phone, DeviceId(1)),
            entry(&bob_desktop, DeviceId(2)),
        ],
    );
    let mut session = MultiDeviceSession::new(alice.public());
    session
        .sync_from_signed_device_list(
            &alice_dh,
            &bob_account.public(),
            &list_v1,
            vec![
                (DeviceId(1), bundle(&bob_phone)),
                (DeviceId(2), bundle(&bob_desktop)),
            ],
        )
        .unwrap();
    assert_eq!(session.device_count(), 2);

    // Bob revokes his phone: a newer, signed list that no longer
    // includes device 1.
    let list_v2 = SignedDeviceList::issue(&bob_account, 2, vec![entry(&bob_desktop, DeviceId(2))]);
    session
        .sync_from_signed_device_list(
            &alice_dh,
            &bob_account.public(),
            &list_v2,
            vec![(DeviceId(2), bundle(&bob_desktop))],
        )
        .unwrap();

    assert!(!session.has_device(DeviceId(1)));
    assert!(session.has_device(DeviceId(2)));
    assert_eq!(session.device_count(), 1);
}
