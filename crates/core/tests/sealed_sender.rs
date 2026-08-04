use novachannel::identity::Identity;
use novachannel::prekey::SignedPreKey;
use novachannel::sealed_sender::{open, seal, SenderCertificate};
use novachannel::Error;

#[test]
fn round_trip_recovers_sender_identity_and_plaintext() {
    let issuer = Identity::generate();
    let sender_identity = Identity::generate();
    let cert = SenderCertificate::issue(&issuer, sender_identity.public(), 1_000);

    let recipient_key = SignedPreKey::generate(&Identity::generate());
    let recipient_public = recipient_key.sealing_public_key();

    let envelope = seal(&recipient_public, &cert, b"who is this from?").unwrap();
    let unsealed = open(&recipient_key, &envelope).unwrap();

    assert_eq!(unsealed.plaintext, b"who is this from?");
    assert_eq!(
        unsealed.certificate.sender_identity,
        sender_identity.public()
    );
    unsealed.certificate.verify(&issuer.public(), 500).unwrap();
}

#[test]
fn expired_certificate_is_rejected_by_verify() {
    let issuer = Identity::generate();
    let sender_identity = Identity::generate();
    let cert = SenderCertificate::issue(&issuer, sender_identity.public(), 1_000);

    let recipient_key = SignedPreKey::generate(&Identity::generate());
    let envelope = seal(&recipient_key.sealing_public_key(), &cert, b"hi").unwrap();
    let unsealed = open(&recipient_key, &envelope).unwrap();

    // `open` itself does not check expiry -- the recipient must, explicitly.
    let result = unsealed.certificate.verify(&issuer.public(), 1_000);
    assert!(matches!(result, Err(Error::CertificateExpired)));
}

#[test]
fn certificate_signed_by_a_different_issuer_fails_verification() {
    let real_issuer = Identity::generate();
    let decoy_issuer = Identity::generate();
    let sender_identity = Identity::generate();
    let cert = SenderCertificate::issue(&real_issuer, sender_identity.public(), 1_000);

    let recipient_key = SignedPreKey::generate(&Identity::generate());
    let envelope = seal(&recipient_key.sealing_public_key(), &cert, b"hi").unwrap();
    let unsealed = open(&recipient_key, &envelope).unwrap();

    let result = unsealed.certificate.verify(&decoy_issuer.public(), 0);
    assert!(result.is_err());
}

#[test]
fn certificate_with_a_swapped_sender_identity_fails_verification() {
    // Confirms the certificate actually binds the specific sender identity,
    // not just "signed by a trusted issuer" -- swapping in an unrelated
    // identity after signing (simulating a relay tampering with the
    // opaque-to-it envelope's decrypted contents, or a bug that mismatches
    // sender and cert) must be caught.
    let issuer = Identity::generate();
    let sender_identity = Identity::generate();
    let mut cert = SenderCertificate::issue(&issuer, sender_identity.public(), 1_000);
    cert.sender_identity = Identity::generate().public();

    assert!(cert.verify(&issuer.public(), 0).is_err());
}

#[test]
fn tampered_envelope_fails_to_decrypt() {
    let issuer = Identity::generate();
    let cert = SenderCertificate::issue(&issuer, Identity::generate().public(), 1_000);
    let recipient_key = SignedPreKey::generate(&Identity::generate());

    let mut envelope = seal(&recipient_key.sealing_public_key(), &cert, b"secret").unwrap();
    let last = envelope.bytes.len() - 1;
    envelope.bytes[last] ^= 0x01;

    assert!(matches!(
        open(&recipient_key, &envelope),
        Err(Error::Decrypt)
    ));
}

#[test]
fn wrong_recipient_cannot_open_the_envelope() {
    let issuer = Identity::generate();
    let cert = SenderCertificate::issue(&issuer, Identity::generate().public(), 1_000);
    let real_recipient = SignedPreKey::generate(&Identity::generate());
    let envelope = seal(&real_recipient.sealing_public_key(), &cert, b"secret").unwrap();

    let impostor_recipient = SignedPreKey::generate(&Identity::generate());
    assert!(matches!(
        open(&impostor_recipient, &envelope),
        Err(Error::Decrypt)
    ));
}

#[test]
fn trailing_bytes_in_envelope_are_rejected() {
    let issuer = Identity::generate();
    let cert = SenderCertificate::issue(&issuer, Identity::generate().public(), 1_000);
    let recipient_key = SignedPreKey::generate(&Identity::generate());
    let mut envelope = seal(&recipient_key.sealing_public_key(), &cert, b"x").unwrap();
    envelope.bytes.push(0xFF);

    assert!(matches!(
        open(&recipient_key, &envelope),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn two_envelopes_to_the_same_recipient_use_unlinkable_ephemeral_keys() {
    // The whole point of sealing per-message with a fresh ephemeral key is
    // that a passive observer sees no repeated public value across two
    // envelopes from (unknown to them) the same or different senders to
    // the same recipient. Checked directly: the leading 32-byte ephemeral
    // public key differs between two envelopes sealed back to back.
    let issuer = Identity::generate();
    let cert = SenderCertificate::issue(&issuer, Identity::generate().public(), 1_000);
    let recipient_key = SignedPreKey::generate(&Identity::generate());
    let recipient_public = recipient_key.sealing_public_key();

    let e1 = seal(&recipient_public, &cert, b"a").unwrap();
    let e2 = seal(&recipient_public, &cert, b"b").unwrap();

    assert_ne!(&e1.bytes[..32], &e2.bytes[..32]);
}
