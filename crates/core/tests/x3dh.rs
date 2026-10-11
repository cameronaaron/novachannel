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
    let opk_public = r.opks.public_keys().into_iter().next();
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
    // This module produces `handshake::EstablishedSession` (not a parallel
    // type) so `crate::ratchet` and `crate::transport` don't care which
    // handshake ran. Shown directly: build a `RatchetedSession` from X3DH on
    // each side and exchange an application message and a real ratchet step.
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
    // The signed prekey's signature only means something with its identity:
    // a genuine signature spliced onto a different claimed identity must not
    // verify.
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
    // A responder who didn't publish this bundle (different DH identity and
    // SPK secret) must not complete the exchange even holding the init
    // message: the implicit authentication (DH1/DH3) must bind the real
    // responder's secrets.
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
    // An init message naming a one-time-prekey id the responder never
    // published (e.g. a stale bundle from before rotation), built by crafting
    // the bundle rather than reaching into wire internals from this test
    // crate.
    let mut responder = make_responder(false);
    let mut peer_bundle = bundle(&responder);
    let (_, bogus_dh, bogus_kem) = OneTimePreKey::generate(999).public();
    peer_bundle.one_time_prekey = Some((999, bogus_dh, bogus_kem));

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

/// `PreKeyBundle::write`/`read` use the crate's private `Writer`/`Reader`,
/// so bundles couldn't be serialized from outside even though X3DH's
/// asynchrony depends on publishing them. `to_bytes`/`from_bytes` are the
/// public path; this checks the round trip keeps everything `initiate`
/// needs, with and without a one-time prekey.
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

/// A one-time prekey must survive a garbage init message referencing it. It
/// has to be used to derive the message's authentication key, but deleting
/// it before authentication let an attacker burn the whole supply, pushing
/// later honest sessions onto the no-OPK path: a real forward-secrecy loss
/// (see `OneTimePreKey` on the fourth DH term and single-use ML-KEM leg).
#[test]
fn a_forged_init_message_does_not_burn_the_one_time_prekey_it_references() {
    let responder_identity = Identity::generate();
    let responder_dh = DhIdentity::generate();
    let responder_spk = SignedPreKey::generate(&responder_identity);
    let mut opks = OneTimePreKeyStore::new();
    opks.add(OneTimePreKey::generate(77));

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();
    let bundle = PreKeyBundle::build(
        responder_identity.public(),
        &responder_dh,
        &responder_spk,
        opks.public_keys().first().cloned(),
    );

    // A genuine init message, then corrupted: its sealed payload will not
    // authenticate, so nothing about it is evidence the prekey was used.
    let initiated = initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &bundle,
        b"hello",
    )
    .unwrap();
    let mut forged = initiated.message.bytes.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0xFF;

    assert!(matches!(
        respond(&responder_dh, &responder_spk, &mut opks, &forged),
        Err(Error::Decrypt)
    ));
    assert_eq!(
        opks.public_keys().len(),
        1,
        "a message that never authenticated must not consume a one-time prekey"
    );

    // The honest message still works, and *does* consume it...
    let responded = respond(
        &responder_dh,
        &responder_spk,
        &mut opks,
        &initiated.message.bytes,
    )
    .unwrap();
    assert_eq!(responded.initial_payload, b"hello");
    assert!(
        opks.public_keys().is_empty(),
        "a one-time prekey must not survive the session that used it"
    );

    // ...so replaying it fails, which is the property consuming it exists
    // to provide.
    assert!(matches!(
        respond(
            &responder_dh,
            &responder_spk,
            &mut opks,
            &initiated.message.bytes
        ),
        Err(Error::UnknownOneTimePreKey)
    ));
}

/// A small-order X25519 public key forces a publicly known output whatever
/// this side's secret. RFC 7748 §6.1 recommends rejecting it;
/// `kex::checked_dh` does at every exchange, and this is the X3DH path.
#[test]
fn a_small_order_peer_key_is_rejected_rather_than_silently_contributing_nothing() {
    use x25519_dalek::PublicKey as X25519Public;

    let responder_identity = Identity::generate();
    let responder_dh = DhIdentity::generate();
    let responder_spk = SignedPreKey::generate(&responder_identity);
    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();

    // The canonical order-1 and order-2 encodings: u = 0 and u = p - 1.
    let mut p_minus_one = [0xFFu8; 32];
    p_minus_one[0] = 0xEC;
    p_minus_one[31] = 0x7F;
    let mut one = [0u8; 32];
    one[0] = 1;
    for small_order in [[0u8; 32], one, p_minus_one] {
        let mut bundle = PreKeyBundle::build(
            responder_identity.public(),
            &responder_dh,
            &responder_spk,
            None,
        );
        bundle.dh_identity = X25519Public::from(small_order);

        assert!(
            matches!(
                initiate(&initiator_identity.public(), &initiator_dh, &bundle, b"hi"),
                Err(Error::Malformed(_))
            ),
            "small-order key {small_order:?} was accepted"
        );
    }
}
