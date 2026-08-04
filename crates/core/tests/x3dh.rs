use novachannel::identity::Identity;
use novachannel::prekey::{
    DhIdentity, OneTimePreKey, OneTimePreKeyStore, PreKeyBundle, SignedPreKey,
};
use novachannel::ratchet::{Opened, RatchetedSession};
use novachannel::x3dh::{initiate, respond};
use novachannel::Error;

struct Responder {
    signing_identity: Identity,
    dh_identity: DhIdentity,
    spk: SignedPreKey,
    opks: OneTimePreKeyStore,
}

fn make_responder(with_opk: bool) -> Responder {
    let signing_identity = Identity::generate();
    let dh_identity = DhIdentity::generate();
    let spk = SignedPreKey::generate(&signing_identity);
    let mut opks = OneTimePreKeyStore::new();
    if with_opk {
        opks.add(OneTimePreKey::generate(1));
    }
    Responder {
        signing_identity,
        dh_identity,
        spk,
        opks,
    }
}

fn bundle(r: &Responder) -> PreKeyBundle {
    let opk_public = r.opks.public_keys().first().copied();
    PreKeyBundle::build(
        r.signing_identity.public(),
        &r.dh_identity,
        &r.spk,
        opk_public,
    )
}

#[test]
fn round_trip_with_one_time_prekey_and_transport() {
    let mut responder = make_responder(true);
    let peer_bundle = bundle(&responder);
    peer_bundle.verify().unwrap();

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();

    let initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &peer_bundle,
        b"hello, asynchronously",
    )
    .unwrap();

    let responded = respond(
        &responder.dh_identity,
        &responder.spk,
        &mut responder.opks,
        &initiated.message.bytes,
    )
    .unwrap();

    assert_eq!(responded.initiator_identity, initiator_identity.public());
    assert_eq!(responded.initial_payload, b"hello, asynchronously");
    assert_eq!(
        initiated.session.peer.identity,
        responder.signing_identity.public()
    );

    let mut client_session = initiated.session;
    let mut server_session = responded.session;

    let record = client_session.sender.seal(b"ping").unwrap();
    assert_eq!(server_session.receiver.open(&record).unwrap(), b"ping");

    let record = server_session.sender.seal(b"pong").unwrap();
    assert_eq!(client_session.receiver.open(&record).unwrap(), b"pong");
}

#[test]
fn round_trip_without_one_time_prekey_still_works() {
    let mut responder = make_responder(false);
    let peer_bundle = bundle(&responder);
    assert!(peer_bundle.one_time_prekey.is_none());

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();
    let initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &peer_bundle,
        b"",
    )
    .unwrap();

    let responded = respond(
        &responder.dh_identity,
        &responder.spk,
        &mut responder.opks,
        &initiated.message.bytes,
    )
    .unwrap();

    assert_eq!(responded.initiator_identity, initiator_identity.public());
}

#[test]
fn one_time_prekey_is_consumed_and_cannot_be_reused() {
    let mut responder = make_responder(true);
    let peer_bundle = bundle(&responder);

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();
    let initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &peer_bundle,
        b"one",
    )
    .unwrap();

    // First use succeeds and removes the one-time prekey from the store.
    respond(
        &responder.dh_identity,
        &responder.spk,
        &mut responder.opks,
        &initiated.message.bytes,
    )
    .unwrap();

    // A second init message referencing the same (now-consumed) prekey id
    // must fail, not silently rederive the same session key.
    let second_initiator = Identity::generate();
    let second_dh = DhIdentity::generate();
    let second_init =
        initiate(&second_initiator.public(), &second_dh, &peer_bundle, b"two").unwrap();

    let result = respond(
        &responder.dh_identity,
        &responder.spk,
        &mut responder.opks,
        &second_init.message.bytes,
    );
    assert!(matches!(result, Err(Error::UnknownOneTimePreKey)));
}

#[test]
fn established_session_plugs_into_the_ratchet_unmodified() {
    // The whole point of producing `handshake::EstablishedSession` from
    // this module too (rather than a parallel type) is that
    // `crate::ratchet` and `crate::transport` don't need to know which
    // handshake produced their input. Proven directly: build a
    // `RatchetedSession` from an X3DH-established session on each side and
    // exchange both an application message and a real ratchet step.
    let mut responder = make_responder(true);
    let peer_bundle = bundle(&responder);

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();
    let initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &peer_bundle,
        b"",
    )
    .unwrap();
    let responded = respond(
        &responder.dh_identity,
        &responder.spk,
        &mut responder.opks,
        &initiated.message.bytes,
    )
    .unwrap();

    let mut client = RatchetedSession::new(&initiated.session, true);
    let mut server = RatchetedSession::new(&responded.session, false);

    let sealed = client.seal(b"ping").unwrap();
    match server.open(&sealed).unwrap() {
        Opened::Application(bytes) => assert_eq!(bytes, b"ping"),
        Opened::RatchetAdvanced { .. } => panic!("expected an application message"),
    }

    let step1 = client.initiate_ratchet().unwrap();
    let Opened::RatchetAdvanced { reply: Some(step2) } = server.open(&step1).unwrap() else {
        panic!("expected a ratchet step-2 reply");
    };
    assert!(matches!(
        client.open(&step2).unwrap(),
        Opened::RatchetAdvanced { reply: None }
    ));

    let sealed = client.seal(b"post-ratchet").unwrap();
    match server.open(&sealed).unwrap() {
        Opened::Application(bytes) => assert_eq!(bytes, b"post-ratchet"),
        Opened::RatchetAdvanced { .. } => panic!("expected an application message"),
    }
}

#[test]
fn bundle_signed_by_a_different_identity_fails_verification() {
    // The signed prekey's signature is only meaningful relative to the
    // identity it's presented alongside; splicing a genuine signature onto
    // a different claimed identity (e.g. a transport bug or an attacker
    // rewriting the identity field) must not verify.
    let responder = make_responder(false);
    let mut peer_bundle = bundle(&responder);
    peer_bundle.identity = Identity::generate().public();

    assert!(peer_bundle.verify().is_err());
}

#[test]
fn tampered_init_message_payload_fails_to_decrypt() {
    let mut responder = make_responder(true);
    let peer_bundle = bundle(&responder);

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();
    let mut initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &peer_bundle,
        b"secret",
    )
    .unwrap();

    let last = initiated.message.bytes.len() - 1;
    initiated.message.bytes[last] ^= 0x01;

    let result = respond(
        &responder.dh_identity,
        &responder.spk,
        &mut responder.opks,
        &initiated.message.bytes,
    );
    assert!(matches!(result, Err(Error::Decrypt)));
}

#[test]
fn wrong_responder_identity_fails_to_decrypt() {
    // A responder who did not actually publish this bundle (different DH
    // identity, different SPK secret) must not be able to complete the
    // exchange even if they somehow intercept the init message — the
    // implicit authentication (DH1/DH3) has to actually bind to the real
    // responder's secrets, not just to public bytes on the wire.
    let real_responder = make_responder(false);
    let peer_bundle = bundle(&real_responder);

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();
    let initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &peer_bundle,
        b"secret",
    )
    .unwrap();

    let mut impostor = make_responder(false);
    let result = respond(
        &impostor.dh_identity,
        &impostor.spk,
        &mut impostor.opks,
        &initiated.message.bytes,
    );
    assert!(matches!(result, Err(Error::Decrypt)));
}

#[test]
fn trailing_bytes_in_init_message_are_rejected() {
    let mut responder = make_responder(false);
    let peer_bundle = bundle(&responder);

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();
    let mut initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &peer_bundle,
        b"x",
    )
    .unwrap();
    initiated.message.bytes.push(0xFF);

    let result = respond(
        &responder.dh_identity,
        &responder.spk,
        &mut responder.opks,
        &initiated.message.bytes,
    );
    assert!(matches!(result, Err(Error::Malformed(_))));
}

#[test]
fn unknown_one_time_prekey_id_is_rejected() {
    // Simulates an init message whose header claims a one-time-prekey id
    // the responder never published (e.g. a stale/replayed bundle from
    // before rotation). Built by hand-crafting the bundle to reference an
    // id absent from the responder's store, rather than reaching into
    // wire internals from the integration-test crate.
    let mut responder = make_responder(false);
    let mut peer_bundle = bundle(&responder);
    peer_bundle.one_time_prekey = Some((999, DhIdentity::generate().public()));

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();
    let initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &peer_bundle,
        b"x",
    )
    .unwrap();

    let result = respond(
        &responder.dh_identity,
        &responder.spk,
        &mut responder.opks,
        &initiated.message.bytes,
    );
    assert!(matches!(result, Err(Error::UnknownOneTimePreKey)));
}

/// `PreKeyBundle::write`/`read` take this crate's own private
/// `Writer`/`Reader`, so nothing outside the crate could previously
/// serialize a bundle at all — a real gap, since this module's own doc
/// calls the bundle "published key material" and X3DH's entire
/// asynchronous property depends on a bundle actually reaching an
/// initiator somehow. `to_bytes`/`from_bytes` are the public door;
/// this proves the round trip preserves everything `initiate` needs,
/// with and without a one-time prekey.
#[test]
fn bundle_survives_a_to_bytes_from_bytes_round_trip() {
    for with_opk in [false, true] {
        let responder = make_responder(with_opk);
        let peer_bundle = bundle(&responder);

        let bytes = peer_bundle.to_bytes();
        let recovered = PreKeyBundle::from_bytes(&bytes).unwrap();
        recovered.verify().unwrap();

        let initiator_identity = Identity::generate();
        let initiator_dh = DhIdentity::generate();
        let initiated = initiate(
            &initiator_identity.public(),
            &initiator_dh,
            &recovered,
            b"round-tripped bundle still works",
        )
        .unwrap();

        let mut responder = responder;
        let responded = respond(
            &responder.dh_identity,
            &responder.spk,
            &mut responder.opks,
            &initiated.message.bytes,
        )
        .unwrap();

        assert_eq!(
            responded.initial_payload,
            b"round-tripped bundle still works"
        );
    }
}

/// Bytes that aren't a valid bundle at all — not just a corrupted real
/// one — are rejected with an error, not a panic.
#[test]
fn from_bytes_rejects_garbage() {
    let result = PreKeyBundle::from_bytes(&[0u8; 4]);
    assert!(result.is_err());
}
