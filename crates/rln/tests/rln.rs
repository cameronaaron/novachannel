use novachannel_rln::air::DEPTH;
use novachannel_rln::merkle::MerkleTree;
use novachannel_rln::share::recover_secret;
use novachannel_rln::{bytes_to_field, epoch_field, prove_message, verify_message, Identity};

fn build_group(n: usize) -> (MerkleTree, Vec<Identity>) {
    let identities: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
    let params = novachannel_rln::permutation::Params::new();
    let leaves: Vec<_> = identities.iter().map(|id| id.commitment(&params)).collect();
    let tree = MerkleTree::new(DEPTH, &leaves);
    (tree, identities)
}

#[test]
fn valid_membership_proof_verifies() {
    let (tree, identities) = build_group(4);
    let epoch = epoch_field(1);
    let x = bytes_to_field(b"hello, mixnet");

    let msg = prove_message(&tree, 2, &identities[2], epoch, x).unwrap();
    let share = verify_message(tree.root(), msg).expect("valid proof must verify");

    assert_eq!(share.x, x);
}

#[test]
fn tampered_proof_bytes_are_rejected() {
    let (tree, identities) = build_group(4);
    let epoch = epoch_field(1);
    let x = bytes_to_field(b"first message");

    let mut msg = prove_message(&tree, 0, &identities[0], epoch, x).unwrap();
    // Winterfell proofs are opaque byte blobs under `to_bytes`/`from_bytes`;
    // flip a bit by round-tripping through bytes and corrupting them.
    let mut bytes = msg.proof.to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    msg.proof = winterfell::Proof::from_bytes(&bytes).expect("still well-formed encoding");

    assert!(verify_message(tree.root(), msg).is_err());
}

#[test]
fn wrong_root_is_rejected() {
    let (tree, identities) = build_group(4);
    let (other_tree, _other_identities) = build_group(4);
    let epoch = epoch_field(7);
    let x = bytes_to_field(b"m");

    let msg = prove_message(&tree, 1, &identities[1], epoch, x).unwrap();
    assert!(verify_message(other_tree.root(), msg).is_err());
}

#[test]
fn two_messages_in_same_epoch_reveal_the_secret_key() {
    let (tree, identities) = build_group(4);
    let epoch = epoch_field(42);
    let culprit = &identities[3];

    let msg1 = prove_message(&tree, 3, culprit, epoch, bytes_to_field(b"message one")).unwrap();
    let msg2 = prove_message(&tree, 3, culprit, epoch, bytes_to_field(b"message two")).unwrap();

    let share1 = verify_message(tree.root(), msg1).unwrap();
    let share2 = verify_message(tree.root(), msg2).unwrap();

    let recovered = recover_secret(&share1, &share2).expect("same epoch, different x");
    assert_eq!(recovered, culprit.sk);
}

#[test]
fn messages_in_different_epochs_do_not_leak_the_key() {
    let (tree, identities) = build_group(4);
    let culprit = &identities[0];

    let msg1 = prove_message(&tree, 0, culprit, epoch_field(1), bytes_to_field(b"a")).unwrap();
    let msg2 = prove_message(&tree, 0, culprit, epoch_field(2), bytes_to_field(b"b")).unwrap();

    let share1 = verify_message(tree.root(), msg1).unwrap();
    let share2 = verify_message(tree.root(), msg2).unwrap();

    assert!(recover_secret(&share1, &share2).is_none());
}
