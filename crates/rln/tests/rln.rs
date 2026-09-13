use novachannel_rln::air::{self, DEPTH};
use novachannel_rln::merkle::MerkleTree;
use novachannel_rln::permutation::Params;
use novachannel_rln::share::recover_secret;
use novachannel_rln::{bytes_to_field, epoch_field, prove_message, verify_message, Identity};
use winterfell::crypto::hashers::Blake3_256;
use winterfell::math::{fields::f64::BaseElement, FieldElement};
use winterfell::{BatchingMethod, FieldExtension, ProofOptions, Prover};

fn build_group(n: usize) -> (MerkleTree, Vec<Identity>) {
    build_group_at_depth(n, DEPTH)
}

fn build_group_at_depth(n: usize, depth: usize) -> (MerkleTree, Vec<Identity>) {
    let identities: Vec<Identity> = (0..n).map(|_| Identity::generate()).collect();
    let params = Params::new();
    let leaves: Vec<_> = identities.iter().map(|id| id.commitment(&params)).collect();
    let tree = MerkleTree::new(depth, &leaves);
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

    let mut msg = prove_message(&tree, 1, &identities[1], epoch, x).unwrap();
    // Winterfell proofs are opaque byte blobs under `to_bytes`/`from_bytes`;
    // flip a bit by round-tripping through bytes and corrupting them.
    let mut bytes = msg.proof.to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    msg.proof = winterfell::Proof::from_bytes(&bytes).expect("still well-formed encoding");

    assert!(verify_message(tree.root(), msg).is_err());
}

/// Regression test for a genuine debug-build-only footgun documented on
/// [`air::prove`]: a leaf whose Merkle path is every-left (index `0`) or
/// every-right (index `2^depth - 1`) makes the trace's `selector` column
/// literally constant across every row, which trips winterfell's
/// debug-mode `validate_transition_degrees` sanity check (that check
/// measures the *actual* trace polynomial's degree rather than trusting
/// our declared upper bound, and a coincidentally-constant column
/// legitimately measures lower than any single degree declaration can
/// commit to for every witness). This never affects release builds (the
/// check is compiled out there, and proofs for these two leaves are exactly
/// as sound as any other) — this test just confirms `prove`'s
/// `catch_unwind` turns the debug-build panic into a clean `Err` instead of
/// crashing the caller's process.
#[test]
#[cfg(debug_assertions)]
fn a_leftmost_leaf_fails_gracefully_rather_than_panicking_in_debug_builds() {
    let (tree, identities) = build_group(4);
    let epoch = epoch_field(1);
    let x = bytes_to_field(b"leftmost leaf");

    let result = prove_message(&tree, 0, &identities[0], epoch, x);
    assert!(result.is_err());
}

/// The release-build counterpart of the test above: with winterfell's
/// debug-mode degree sanity check compiled out, the leftmost leaf proves
/// and verifies exactly like any other — confirming the debug-build error
/// above really is a check-only artifact, not a real soundness gap for
/// that leaf.
#[test]
#[cfg(not(debug_assertions))]
fn a_leftmost_leaf_proves_and_verifies_in_release_builds() {
    let (tree, identities) = build_group(4);
    let epoch = epoch_field(1);
    let x = bytes_to_field(b"leftmost leaf");

    let msg = prove_message(&tree, 0, &identities[0], epoch, x).unwrap();
    let share = verify_message(tree.root(), msg).expect("valid proof must verify");
    assert_eq!(share.x, x);
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

/// [`wrong_root_is_rejected`] covers the root assertion; this covers the
/// other four public-input assertions (`epoch`, `x`, `y`, `nullifier`) one
/// at a time, so a bug that dropped or mis-wired any single assertion in
/// [`air::RlnAir::get_assertions`] shows up as a specific failing case here
/// rather than being masked by the others still catching a generic
/// "everything's wrong" tamper.
#[test]
fn each_public_input_is_independently_load_bearing() {
    use novachannel_rln::Message;

    let (tree, identities) = build_group(4);
    let epoch = epoch_field(3);
    let x = bytes_to_field(b"public input binding");

    let msg = prove_message(&tree, 1, &identities[1], epoch, x).unwrap();
    let proof_bytes = msg.proof.to_bytes();
    let genuine_public = msg.public.clone();

    let rebuild = |public: air::PublicInputs| Message {
        proof: winterfell::Proof::from_bytes(&proof_bytes).unwrap(),
        public,
    };

    // Wrong epoch: the nullifier (a1 = Hash(sk, epoch)) presented alongside
    // a different epoch than the one actually baked into the trace.
    let mut public = genuine_public.clone();
    public.epoch = epoch_field(4);
    assert!(
        verify_message(tree.root(), rebuild(public)).is_err(),
        "wrong epoch must be rejected"
    );

    // Wrong x: doesn't match the y = sk + a1*x relation the trace encodes.
    let mut public = genuine_public.clone();
    public.x = bytes_to_field(b"a different x");
    assert!(
        verify_message(tree.root(), rebuild(public)).is_err(),
        "wrong x must be rejected"
    );

    // Wrong y: same story, other side of the linear-check assertion.
    let mut public = genuine_public.clone();
    public.y = genuine_public.x; // any field element that isn't the real y
    assert!(
        verify_message(tree.root(), rebuild(public)).is_err(),
        "wrong y must be rejected"
    );

    // Wrong nullifier: claims a different a1 than Hash(sk, epoch) actually
    // produced -- the binding [`crate::share`]'s slashing mechanism relies on.
    let mut public = genuine_public.clone();
    public.nullifier += BaseElement::ONE;
    assert!(
        verify_message(tree.root(), rebuild(public)).is_err(),
        "wrong nullifier must be rejected"
    );
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
    let culprit = &identities[1];

    let msg1 = prove_message(&tree, 1, culprit, epoch_field(1), bytes_to_field(b"a")).unwrap();
    let msg2 = prove_message(&tree, 1, culprit, epoch_field(2), bytes_to_field(b"b")).unwrap();

    let share1 = verify_message(tree.root(), msg1).unwrap();
    let share2 = verify_message(tree.root(), msg2).unwrap();

    assert!(recover_secret(&share1, &share2).is_none());
}

/// [`air::DEPTH`] (32-member capacity) is this crate's convenient default,
/// not a hard limit -- `air::is_valid_depth` accepts any depth for which
/// `depth + 3` is a power of two, and `RlnAir::new` recovers the depth
/// straight from the trace length winterfell hands it rather than
/// assuming `DEPTH`. Depth 1 (the smallest valid depth, a 2-member group)
/// exercises that at the opposite end of the size range this crate's
/// other tests cover.
#[test]
fn a_non_default_depth_proves_and_verifies_end_to_end() {
    let depth = 1;
    assert!(air::is_valid_depth(depth));
    assert_ne!(depth, DEPTH);

    let (tree, identities) = build_group_at_depth(2, depth);
    let epoch = epoch_field(1);
    let x = bytes_to_field(b"a two-member group");

    let msg = prove_message(&tree, 1, &identities[1], epoch, x).unwrap();
    let share = verify_message(tree.root(), msg).expect("valid proof must verify");
    assert_eq!(share.x, x);
}

/// Regression test for a crash `crates/core/fuzz/fuzz_targets/rln_verify.rs`
/// found within seconds: these exact four bytes make winterfell 0.13.1's
/// `Proof::from_bytes` panic with "attempt to exponentiate with overflow"
/// while decoding an attacker-controlled trace-length exponent — a real
/// remote DoS for any caller parsing proof bytes directly, and it
/// reproduces under this workspace's own `overflow-checks = true` release
/// profile (see the root `Cargo.toml`), not just a fuzz build's extra
/// checks. [`Message::from_proof_bytes`] is this crate's fix: it must
/// turn this into a clean `Err`, not propagate the panic.
#[test]
fn a_four_byte_input_that_used_to_panic_winterfells_deserializer_is_rejected_cleanly() {
    let crash_bytes: &[u8] = &[0xdd, 0x00, 0x03, 0xdd];
    let dummy_public = air::PublicInputs {
        root: BaseElement::ZERO,
        epoch: BaseElement::ZERO,
        x: BaseElement::ZERO,
        y: BaseElement::ZERO,
        nullifier: BaseElement::ZERO,
    };
    assert!(novachannel_rln::Message::from_proof_bytes(crash_bytes, dummy_public).is_err());
}

/// A second, independent panicking input the same fuzz target found on a
/// later run, after the fix above -- confirming that `cargo fuzz`'s
/// ASan/libFuzzer build always aborts on any panic (needed for sanitizer
/// instrumentation to work at all), regardless of `catch_unwind` in the
/// code under test, so it keeps discovering new winterfell parser panic
/// paths as "crashes" even once each one is provably handled here. That's
/// still exactly the fuzz target's job -- finding panic-triggering inputs
/// in an untrusted-input parser -- it just means every crash it reports
/// needs verifying against a normal (unwind-enabled) build like this one,
/// not against the fuzz binary itself, and checking in as a regression
/// test here rather than assuming a fixed crash means no more will surface.
#[test]
fn a_second_four_byte_input_that_used_to_panic_winterfells_deserializer_is_rejected_cleanly() {
    let crash_bytes: &[u8] = &[0x7e, 0x0a, 0xb2, 0x7e];
    let dummy_public = air::PublicInputs {
        root: BaseElement::ZERO,
        epoch: BaseElement::ZERO,
        x: BaseElement::ZERO,
        y: BaseElement::ZERO,
        nullifier: BaseElement::ZERO,
    };
    assert!(novachannel_rln::Message::from_proof_bytes(crash_bytes, dummy_public).is_err());
}

/// A third such input, found by the same target on a later run. Each of
/// these is checked in as the fuzz README prescribes: a crash the fuzz
/// binary reports is verified against a normal, unwind-enabled build
/// before being called fixed, because `panic = "abort"` in the fuzz
/// profile means that binary can never stop reporting them.
#[test]
fn a_third_four_byte_input_that_used_to_panic_winterfells_deserializer_is_rejected_cleanly() {
    let crash_bytes: &[u8] = &[0xc1, 0x3b, 0xf5, 0xcc];
    let dummy_public = air::PublicInputs {
        root: BaseElement::ZERO,
        epoch: BaseElement::ZERO,
        x: BaseElement::ZERO,
        y: BaseElement::ZERO,
        nullifier: BaseElement::ZERO,
    };
    assert!(novachannel_rln::Message::from_proof_bytes(crash_bytes, dummy_public).is_err());
}

#[test]
fn invalid_depths_are_rejected_by_is_valid_depth() {
    // depth + 3 must be a power of two; 2 -> 5 is not.
    assert!(!air::is_valid_depth(2));
    // 0 -> 3 is not either (and a zero-depth "tree" -- a single leaf that
    // is its own root -- isn't a shape this AIR supports regardless).
    assert!(!air::is_valid_depth(0));
    for depth in [1, 5, 13, 29] {
        assert!(air::is_valid_depth(depth), "depth {depth} should be valid");
    }
}

/// The permutation being a verified port of an audited construction
/// (see `permutation.rs`'s module docs) says nothing about whether *this
/// crate's* AIR actually enforces the relation it claims to -- that's a
/// separate, entirely custom piece of code with its own soundness surface.
/// This test attacks that surface directly: take a genuinely valid trace
/// and corrupt one arbitrary interior cell, then confirm the system can't
/// be made to accept it -- either the prover refuses/fails on the
/// malformed trace, or, if it produces a proof anyway, that proof fails
/// verification. A soundness bug in the AIR would show up here as this
/// test's `assert!` firing on a proof that verifies against a corrupted
/// trace.
#[test]
fn corrupting_an_interior_trace_cell_never_produces_a_verifying_proof() {
    let (tree, identities) = build_group(2);
    let params = Params::new();
    let epoch = epoch_field(9);
    let x = bytes_to_field(b"adversarial trace mutation");

    let path = tree.path(0);
    let witness = air::Witness {
        sk: identities[0].sk,
        path,
    };
    let mut trace = air::build_trace(&params, &witness, epoch, x);

    // Row 3, column 2: an interior row of the first Merkle block's
    // internal-round region -- neither a boundary/injection row nor a
    // padding row past the trace's meaningful content, so corrupting it
    // exercises the internal-round constraint (D1/E1..E7) specifically,
    // not the boundary or assertion machinery a different row might hit
    // instead.
    let corrupted_row = 3;
    let corrupted_col = 2;
    let original = trace.get(corrupted_col, corrupted_row);
    trace.set(corrupted_col, corrupted_row, original + BaseElement::ONE);

    let a1 = novachannel_rln::permutation::compress2(&params, identities[0].sk, epoch);
    let y = identities[0].sk + a1 * x;
    let root = trace.get(0, air::root_row(witness.path.len()));
    let pub_inputs = air::PublicInputs {
        root,
        epoch,
        x,
        y,
        nullifier: a1,
    };

    let prover = air::RlnProver::new(air::default_proof_options(), pub_inputs.clone());
    let prove_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));

    match prove_result {
        // The prover itself rejected or panicked on the malformed trace --
        // sound, the corruption never got anywhere near a proof.
        Err(_) => {}
        Ok(Err(_)) => {}
        // The prover produced *something* from the corrupted trace (this
        // is what actually happens: winterfell doesn't self-validate a
        // trace against the AIR's constraints before proving); that's
        // only acceptable if verification then rejects it.
        Ok(Ok(proof)) => {
            assert!(
                air::verify(proof, pub_inputs).is_err(),
                "a proof built from a corrupted trace must not verify"
            );
        }
    }
}

/// Two distinct messages must not collide in the rate-limit share's
/// message-binding `x`, because RLN extracts a member's key only from two
/// shares that *differ* in `x` — so a collision buys a second message in
/// an epoch for free, which is the one thing this scheme exists to
/// prevent. Both collision families below were findable by hand in the
/// previous construction, with no cryptanalysis of the permutation at
/// all; see `bytes_to_field`'s own docs.
#[test]
fn distinct_messages_do_not_collide_in_the_rate_limit_binding_value() {
    // Family 1: the final chunk's zero padding was indistinguishable from
    // trailing zero bytes in the message itself.
    let padding_pairs: [(&[u8], &[u8]); 4] = [
        (b"a", b"a\0"),
        (b"hello", b"hello\0\0\0"),
        (b"", b"\0"),
        (b"transfer 10", b"transfer 10\0\0"),
    ];
    for (left, right) in padding_pairs {
        assert_ne!(
            bytes_to_field(left),
            bytes_to_field(right),
            "{left:?} and {right:?} bind to the same share"
        );
    }

    // Family 2: a full 8-byte chunk was read as a u64 and reduced mod the
    // Goldilocks prime, so `v` and `v + p` landed on the same element.
    const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;
    for v in [0u64, 1, 12_345, 0xFFFF_FFFE] {
        let left = v.to_le_bytes();
        let right = v.wrapping_add(GOLDILOCKS_P).to_le_bytes();
        assert_ne!(left, right, "test inputs must actually differ");
        assert_ne!(
            bytes_to_field(&left),
            bytes_to_field(&right),
            "chunks {v} and {v}+p bind to the same share"
        );
    }
}

/// The end-to-end consequence of the property above, stated as the
/// rate-limit rule itself: a member who sends two *different* messages in
/// one epoch has their key recovered. Under the previous
/// `bytes_to_field`, the two messages below produced an identical `x`,
/// so `recover_secret` returned `None` and the member kept their key.
#[test]
fn a_second_message_in_an_epoch_still_leaks_the_key_when_it_differs_only_by_a_trailing_zero() {
    let params = Params::new();
    let identity = Identity::generate();
    let leaves = vec![identity.commitment(&params)];
    let tree = MerkleTree::new(air::DEPTH, &leaves);
    let epoch = epoch_field(7);

    let first =
        novachannel_rln::prove_message(&tree, 0, &identity, epoch, bytes_to_field(b"pay alice"))
            .expect("first proof");
    let second =
        novachannel_rln::prove_message(&tree, 0, &identity, epoch, bytes_to_field(b"pay alice\0"))
            .expect("second proof");

    let root = tree.root();
    let share_a = novachannel_rln::verify_message(root, first).expect("first verifies");
    let share_b = novachannel_rln::verify_message(root, second).expect("second verifies");

    assert_eq!(
        share_a.nullifier, share_b.nullifier,
        "same member, same epoch: the nullifier must match"
    );
    assert_ne!(
        share_a.x, share_b.x,
        "two distinct messages must be two distinct points on the line"
    );
    assert_eq!(
        novachannel_rln::share::recover_secret(&share_a, &share_b),
        Some(identity.sk),
        "two messages in one epoch must leak the key"
    );
}

/// The verifier's floor is the only thing standing between a caller and a
/// deliberately weak proof, since a prover chooses its own
/// `ProofOptions`. It must reject a proof generated below the bar, and
/// accept this crate's own default — which sits exactly at it.
#[test]
fn a_proof_generated_below_the_security_floor_is_rejected() {
    let params = Params::new();
    let identity = Identity::generate();
    let leaves = vec![identity.commitment(&params)];
    let tree = MerkleTree::new(air::DEPTH, &leaves);
    let epoch = epoch_field(1);
    let x = bytes_to_field(b"security floor");
    let a1 = novachannel_rln::permutation::compress2(&params, identity.sk, epoch);
    let y = identity.sk + a1 * x;

    let witness = air::Witness {
        sk: identity.sk,
        path: tree.path(0),
    };
    let trace = air::build_trace(&params, &witness, epoch, x);
    let root = trace.get(0, air::root_row(air::DEPTH));
    let pub_inputs = air::PublicInputs {
        root,
        epoch,
        x,
        y,
        nullifier: a1,
    };

    // 24 queries with no field extension: what this crate shipped as its
    // default before the hardening pass, and what the old 95-bit floor
    // would still have accepted. It is worth 63 bits, not the ~96 it was
    // once labelled — `FieldExtension::None` caps a 64-bit base field's
    // contribution at 64, and the formula subtracts one.
    let weak = ProofOptions::new(
        24,
        16,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );
    let weak_proof = air::RlnProver::new(weak, pub_inputs.clone())
        .prove(air::build_trace(&params, &witness, epoch, x))
        .expect("a weak proof still generates");
    assert!(
        weak_proof
            .conjectured_security::<Blake3_256<BaseElement>>()
            .bits()
            < air::MIN_CONJECTURED_SECURITY_BITS,
        "instrument check: the 'weak' options must actually be below the floor"
    );
    assert!(
        air::verify(weak_proof, pub_inputs.clone()).is_err(),
        "a proof below the security floor must not verify"
    );

    // ...and the default, which sits exactly at the floor, still does.
    let good_proof = air::RlnProver::new(air::default_proof_options(), pub_inputs.clone())
        .prove(trace)
        .expect("the default options prove");
    assert_eq!(
        good_proof
            .conjectured_security::<Blake3_256<BaseElement>>()
            .bits(),
        air::MIN_CONJECTURED_SECURITY_BITS,
        "the floor is meant to sit exactly at what the default achieves"
    );
    air::verify(good_proof, pub_inputs).expect("the default options must verify");
}

/// The genuine proof `crates/core/fuzz/fuzz_targets/rln_verify.rs` splices
/// fuzzer bytes into must keep parsing and verifying, and its recorded
/// public inputs must keep matching it.
///
/// This check exists because of how that target failed silently. Feeding a
/// verifier random bytes only ever exercises the first few bytes of the
/// deserializer — the target's entire accumulated corpus was two-to-four
/// byte inputs, and every crash it ever reported was a deserializer
/// arithmetic panic on four bytes. A genuine proof had been generated
/// offline for exactly that reason and then never actually used, so the
/// target spent its whole life never reaching the verifier at all. The
/// same thing happens again, just as quietly, if this fixture goes stale
/// under an unrelated change — so it is checked here, in the gate, rather
/// than trusted to stay valid.
#[test]
fn the_seed_proof_fixture_still_parses_and_verifies() {
    const PROOF_BYTES: &[u8] = include_bytes!("data/seed_proof.bin");
    const PUBLIC_INPUTS: &str = include_str!("data/seed_public_inputs.txt");

    let values: Vec<u64> = PUBLIC_INPUTS
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .map(|l| l.trim().parse().expect("a decimal u64 per line"))
        .collect();
    assert_eq!(
        values.len(),
        5,
        "expected root, epoch, x, y, nullifier — one per line"
    );

    let public = air::PublicInputs {
        root: BaseElement::new(values[0]),
        epoch: BaseElement::new(values[1]),
        x: BaseElement::new(values[2]),
        y: BaseElement::new(values[3]),
        nullifier: BaseElement::new(values[4]),
    };

    let message = novachannel_rln::Message::from_proof_bytes(PROOF_BYTES, public)
        .expect("the seed proof must still parse");
    air::verify(message.proof, message.public).expect(
        "the seed proof must still verify — regenerate it and its public inputs together \
         with `cargo run -p novachannel-rln --release --example gen_fuzz_seed`",
    );
}

/// ...and it must clear the verifier's own security floor, since a seed
/// that did not would make the spliced fuzzing path reject everything
/// before reaching a single constraint.
#[test]
fn the_seed_proof_fixture_clears_the_security_floor() {
    const PROOF_BYTES: &[u8] = include_bytes!("data/seed_proof.bin");
    let dummy = air::PublicInputs {
        root: BaseElement::ZERO,
        epoch: BaseElement::ZERO,
        x: BaseElement::ZERO,
        y: BaseElement::ZERO,
        nullifier: BaseElement::ZERO,
    };
    let message = novachannel_rln::Message::from_proof_bytes(PROOF_BYTES, dummy).unwrap();
    assert!(
        message
            .proof
            .conjectured_security::<Blake3_256<BaseElement>>()
            .bits()
            >= air::MIN_CONJECTURED_SECURITY_BITS
    );
}

/// A proof declaring a trace shape this AIR could never have produced must
/// be rejected as an error, not by panicking inside `RlnAir::new` and
/// relying on `verify`'s `catch_unwind` to contain it — that containment
/// does not exist under `panic = "abort"`, which a size-optimized or
/// embedded consumer may well build with, turning a malformed proof into a
/// remote process abort.
///
/// The five-byte input below is what `crates/core/fuzz`'s `rln_verify`
/// target produced within seconds of being fixed to actually reach the
/// verifier: spliced over the start of a genuine proof, it yields a proof
/// whose header parses but declares a trace width of 5 against this AIR's
/// 11. See `ENGINEERING-STANDARDS.md` §6.31.
#[test]
fn a_proof_declaring_an_impossible_trace_shape_is_an_error_not_a_panic() {
    const PROOF_BYTES: &[u8] = include_bytes!("data/seed_proof.bin");
    let public = air::PublicInputs {
        root: BaseElement::ZERO,
        epoch: BaseElement::ZERO,
        x: BaseElement::ZERO,
        y: BaseElement::ZERO,
        nullifier: BaseElement::ZERO,
    };

    // The exact splice the fuzzer found: offset 0, patch [0x05].
    let mut spliced = PROOF_BYTES.to_vec();
    spliced[0] = 0x05;

    let message = novachannel_rln::Message::from_proof_bytes(&spliced, public)
        .expect("this input's header still parses — that is what makes it interesting");
    let err = air::verify(message.proof, message.public)
        .expect_err("a trace width this AIR never produces must not verify");
    assert!(
        err.contains("trace width"),
        "expected a trace-shape rejection, got: {err}"
    );
    assert!(
        !err.contains("panicked"),
        "the rejection must come from the up-front check, not from catching a panic: {err}"
    );
}

/// A named, currently-unfixable remote DoS, pinned by an executable check
/// rather than left as prose.
///
/// `winterfell` 0.13.1's `BatchMerkleProof::read_from`
/// (`winter-crypto/src/merkle/proofs.rs`) reads an attacker-controlled
/// count out of a proof and hands it straight to `Vec::with_capacity`,
/// then does the same again per node vector via `read_many`. That parse
/// happens *inside* `winterfell::verify` — not in `Proof::from_bytes` —
/// so `Message::from_proof_bytes`'s guard is upstream of it and cannot
/// help. Worse, `air::verify`'s `catch_unwind` cannot help either: an
/// allocation failure calls `handle_alloc_error`, which **aborts** rather
/// than unwinding, so there is nothing to catch.
///
/// Measured, not inferred: the input below makes a normal `--release`
/// build (no sanitizer) print `memory allocation of 2520802182910816
/// bytes failed` and die with SIGABRT. It is the exact splice
/// `crates/core/fuzz`'s `rln_verify` target found once it was fixed to
/// reach the verifier at all.
///
/// This is the same defect class this workspace fixed three times in its
/// own parsers (`ENGINEERING-STANDARDS.md` §6.29 — bound a declared count
/// against the bytes actually remaining). It cannot be fixed here:
/// `Queries`' raw bytes are private, so the only in-crate alternative
/// would be re-implementing winterfell's wire format to pre-scan it,
/// duplicating knowledge that drifts on every upgrade. 0.13.1 is the
/// latest published version, so there is no upgrade to take either.
///
/// The check runs in a subprocess so it can assert the abort without
/// taking the test runner down. **If this test starts failing because the
/// child exited cleanly, upstream has fixed it** — drop the warning from
/// `air::verify`'s docs and this test with it.
#[test]
fn a_known_unbounded_allocation_in_winterfells_verifier_still_aborts_the_process() {
    const CHILD_ENV: &str = "NOVACHANNEL_RLN_ALLOC_ABORT_CHILD";
    const PROOF_BYTES: &[u8] = include_bytes!("data/seed_proof.bin");

    if std::env::var(CHILD_ENV).is_ok() {
        let offset = u32::from_le_bytes([0x0a, 0x2f, 0x0a, 0x0a]) as usize % PROOF_BYTES.len();
        let patch = [0x3du8, 0x3d];
        let mut spliced = PROOF_BYTES.to_vec();
        let end = (offset + patch.len()).min(spliced.len());
        spliced[offset..end].copy_from_slice(&patch[..end - offset]);

        let public = air::PublicInputs {
            root: BaseElement::ZERO,
            epoch: BaseElement::ZERO,
            x: BaseElement::ZERO,
            y: BaseElement::ZERO,
            nullifier: BaseElement::ZERO,
        };
        if let Ok(message) = novachannel_rln::Message::from_proof_bytes(&spliced, public) {
            let _ = air::verify(message.proof, message.public);
        }
        // Reached only if upstream stopped over-allocating.
        std::process::exit(0);
    }

    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "a_known_unbounded_allocation_in_winterfells_verifier_still_aborts_the_process",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("re-run this test binary as a child");

    assert!(
        !output.status.success(),
        "the child exited cleanly, so winterfell no longer over-allocates here — \
         remove this test and the warning on `air::verify`"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("memory allocation of") && stderr.contains("failed"),
        "expected an allocation failure, got status {:?} and stderr:\n{stderr}",
        output.status
    );
}
