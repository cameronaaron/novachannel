//! Regression tests for the wire-format defects described in
//! `crates/core/src/wire.rs`'s module docs and `ENGINEERING-STANDARDS.md`
//! §6.29: a variable-length field longer than the old `u16` length prefix
//! silently truncated that prefix in release builds, and an
//! attacker-chosen count prefix drove an unbounded `Vec::with_capacity`
//! before a single one of the claimed elements was read.
//!
//! Every test here fails against the pre-fix code, which is the point —
//! they are the executable form of those two defects, not a restatement
//! of behaviour that already worked.

use novachannel::group::{Commit, Group, LeafKeyPackage, MyLeafKeyPackage, Welcome};
use novachannel::identity::Identity;
use novachannel::multidevice::{DeviceId, DeviceListEntry, SignedDeviceList};
use novachannel::prekey::{DhIdentity, OneTimePreKeyStore, PreKeyBundle, SignedPreKey};
use novachannel::sealed_sender::{self, SenderCertificate};
use novachannel::x3dh;

/// A group large enough that its commits exceed 65535 bytes. Measured, not
/// guessed: a 32-leaf group's commits run to roughly 73KB once every leaf
/// is occupied, because the committer's path update has to carry one
/// hybrid ciphertext per blank-subtree resolution and those resolutions
/// grow with the tree.
///
/// Before the fix, `Commit::to_bytes` here silently emitted bytes whose
/// length prefix had wrapped modulo 2^16, and `Commit::from_bytes`
/// rejected its own crate's output — with no error at serialization time
/// to say so. The group module was simply unusable past ~16 members, in
/// release builds only.
#[test]
fn commits_for_a_group_too_large_for_a_u16_length_prefix_round_trip() {
    let founder = Identity::generate();
    let mut group = Group::create(&founder, 32).unwrap();

    let mut largest = 0usize;
    for _ in 1..32 {
        let member = Identity::generate();
        let kp = MyLeafKeyPackage::generate(&member);
        let (commit, welcome) = group.propose_add(&founder, kp.public()).unwrap();

        let commit_bytes = commit.to_bytes();
        largest = largest.max(commit_bytes.len());
        Commit::from_bytes(&commit_bytes).expect("a commit must parse back from its own bytes");

        let welcome_bytes = welcome.to_bytes();
        Welcome::from_bytes(&welcome_bytes).expect("a welcome must parse back from its own bytes");
    }

    assert!(
        largest > u16::MAX as usize,
        "this test only proves anything if the commits actually exceed the old \
         u16 prefix; largest was {largest} bytes"
    );
}

/// The same property one level down: a `LeafKeyPackage`'s own serialized
/// form is dominated by ML-DSA-87 material and already sits near 9KB, so
/// this pins the encoding rather than the size, but it is the piece every
/// `Commit` and `Welcome` above embeds.
#[test]
fn a_leaf_key_package_round_trips_through_its_public_bytes() {
    let id = Identity::generate();
    let kp = MyLeafKeyPackage::generate(&id);
    let bytes = kp.public().to_bytes();
    let parsed = LeafKeyPackage::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.to_bytes(), bytes);
}

/// Sealed sender's payload is caller-supplied and unbounded; before the
/// fix, anything past 65535 bytes wrapped its length prefix and produced
/// an envelope that `open` could not parse — `seal` reporting success the
/// whole way.
#[test]
fn a_sealed_envelope_larger_than_the_old_u16_prefix_opens_correctly() {
    let issuer = Identity::generate();
    let sender = Identity::generate();
    let recipient_spk = SignedPreKey::generate(&Identity::generate());
    let certificate = SenderCertificate::issue(&issuer, sender.public(), 100);

    for len in [65_535usize, 65_536, 300_000] {
        let plaintext = vec![0x5Au8; len];
        let envelope = sealed_sender::seal(
            &recipient_spk.sealing_public_key(),
            &certificate,
            &plaintext,
        )
        .unwrap();
        let opened = sealed_sender::open(&recipient_spk, &envelope).unwrap();
        assert_eq!(opened.plaintext, plaintext, "len={len}");
    }
}

/// Same defect, same shape, on X3DH's initial application payload.
#[test]
fn an_x3dh_initial_payload_larger_than_the_old_u16_prefix_survives_the_round_trip() {
    let responder_identity = Identity::generate();
    let responder_dh = DhIdentity::generate();
    let responder_spk = SignedPreKey::generate(&responder_identity);
    let mut opks = OneTimePreKeyStore::new();

    let initiator_identity = Identity::generate();
    let initiator_dh = DhIdentity::generate();

    let bundle = PreKeyBundle::build(
        responder_identity.public(),
        &responder_dh,
        &responder_spk,
        None,
    );

    let payload = vec![0xC3u8; 200_000];
    let initiated = x3dh::initiate(
        &initiator_identity.public(),
        &initiator_dh,
        &bundle,
        &payload,
    )
    .unwrap();
    let responded = x3dh::respond(
        &responder_dh,
        &responder_spk,
        &mut opks,
        &initiated.message.bytes,
    )
    .unwrap();
    assert_eq!(responded.initial_payload, payload);
}

/// A commit declaring a four-billion-entry update path must be rejected as
/// a parse error, not reserved for. Built by patching a real commit's
/// `path_len` field in place — the signed section's layout is walked
/// exactly, and the assertion on the value found there is what proves the
/// test is patching the field it thinks it is (§0.5: validate the
/// instrument before trusting the measurement).
#[test]
fn a_commit_declaring_an_absurd_path_length_is_rejected_without_reserving_for_it() {
    let founder = Identity::generate();
    let joiner = Identity::generate();
    let joiner_kp = MyLeafKeyPackage::generate(&joiner);
    let mut group = Group::create(&founder, 4).unwrap();
    let (commit, _welcome) = group.propose_add(&founder, joiner_kp.public()).unwrap();
    let bytes = commit.to_bytes();

    let path_len_offset = commit_path_len_offset(&bytes);
    let declared = u32::from_be_bytes(
        bytes[path_len_offset..path_len_offset + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        declared, 2,
        "instrument check: a 4-leaf group's direct path from leaf 0 is 2 nodes; \
         if this is not 2 the test is patching the wrong field"
    );

    let mut patched = bytes;
    patched[path_len_offset..path_len_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(
        Commit::from_bytes(&patched).is_err(),
        "an update path longer than the whole message must not parse"
    );
}

/// Walks a serialized `Commit` to the byte offset of the `path_len` field
/// inside its signed section. Mirrors `Commit::write`'s layout exactly:
/// `var(signed) || HybridSignature`, where `signed` is
/// `CONTEXT || group_id(16) || from_epoch(8) || sender_leaf(4) || op || path_len(4) || nodes`.
fn commit_path_len_offset(bytes: &[u8]) -> usize {
    const CONTEXT: &[u8] = b"novachannel group v1 commit";
    const VAR_PREFIX: usize = 8;

    let mut pos = VAR_PREFIX; // past the signed section's own length prefix
    pos += CONTEXT.len() + 16 + 8 + 4;
    assert_eq!(bytes[pos], 0, "expected a GroupOp::Add tag");
    pos += 1 + 4; // op tag + leaf_index

    // LeafKeyPackage := PublicIdentity | NodePublicKey | HybridSignature
    let skip_var = |pos: &mut usize| {
        let len = u64::from_be_bytes(bytes[*pos..*pos + VAR_PREFIX].try_into().unwrap()) as usize;
        *pos += VAR_PREFIX + len;
    };
    pos += 32; // PublicIdentity.ed25519
    skip_var(&mut pos); // PublicIdentity.ml_dsa
    pos += 32; // NodePublicKey.dh_public
    skip_var(&mut pos); // NodePublicKey.kem_public
    pos += 64; // pop.ed25519
    skip_var(&mut pos); // pop.ml_dsa

    pos
}

/// The same unbounded-count defect in `SignedDeviceList`, reached through
/// the public byte serialization this change also added.
#[test]
fn a_device_list_declaring_an_absurd_entry_count_is_rejected_without_reserving_for_it() {
    let account = Identity::generate();
    let device_identity = Identity::generate();
    let device_dh = DhIdentity::generate();
    let list = SignedDeviceList::issue(
        &account,
        1,
        vec![DeviceListEntry {
            device_id: DeviceId(1),
            identity: device_identity.public(),
            dh_identity: device_dh.public(),
        }],
    );
    let bytes = list.to_bytes();

    // Layout: version(8) || count(4) || entries... — patch the count.
    let declared = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    assert_eq!(declared, 1, "instrument check: one entry was issued");

    let mut patched = bytes.clone();
    patched[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(SignedDeviceList::from_bytes(&patched).is_err());

    // And the honest list still round-trips and verifies.
    let parsed = SignedDeviceList::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.version, 1);
    parsed.verify(&account.public()).unwrap();
    assert!(parsed.verify(&Identity::generate().public()).is_err());
}

/// One value, one byte encoding: appending anything to a valid message
/// must be a parse error at every public deserialization entry point, so a
/// caller deduplicating or pinning by bytes cannot be shown two encodings
/// of the same value.
#[test]
fn trailing_bytes_are_rejected_at_every_public_deserialization_entry_point() {
    let founder = Identity::generate();
    let joiner = Identity::generate();
    let joiner_kp = MyLeafKeyPackage::generate(&joiner);
    let mut group = Group::create(&founder, 4).unwrap();
    let (commit, welcome) = group.propose_add(&founder, joiner_kp.public()).unwrap();

    let identity = Identity::generate();
    let dh = DhIdentity::generate();
    let spk = SignedPreKey::generate(&identity);
    let bundle = PreKeyBundle::build(identity.public(), &dh, &spk, None);
    let account = Identity::generate();
    let list = SignedDeviceList::issue(
        &account,
        1,
        vec![DeviceListEntry {
            device_id: DeviceId(1),
            identity: identity.public(),
            dh_identity: dh.public(),
        }],
    );

    let with_trailing = |mut b: Vec<u8>| {
        b.push(0xFF);
        b
    };

    assert!(Commit::from_bytes(&with_trailing(commit.to_bytes())).is_err());
    assert!(Welcome::from_bytes(&with_trailing(welcome.to_bytes())).is_err());
    assert!(PreKeyBundle::from_bytes(&with_trailing(bundle.to_bytes())).is_err());
    assert!(SignedDeviceList::from_bytes(&with_trailing(list.to_bytes())).is_err());
    assert!(LeafKeyPackage::from_bytes(&with_trailing(joiner_kp.public().to_bytes())).is_err());

    // ...and each still parses without the extra byte, so the assertions
    // above are about the trailing byte and not about a broken encoding.
    assert!(Commit::from_bytes(&commit.to_bytes()).is_ok());
    assert!(Welcome::from_bytes(&welcome.to_bytes()).is_ok());
    assert!(PreKeyBundle::from_bytes(&bundle.to_bytes()).is_ok());
    assert!(SignedDeviceList::from_bytes(&list.to_bytes()).is_ok());
    assert!(LeafKeyPackage::from_bytes(&joiner_kp.public().to_bytes()).is_ok());
}
