# Engineering Standards — novachannel workspace

The correctness and quality bar for this workspace: `novachannel` (hybrid
PQ/classical secure channel), `novachannel-rln` (ZK-STARK rate-limiting
nullifiers), `novachannel-dp` (cover traffic), `novachannel-oram` (Path ORAM)
and `novachannel-mpc` (threshold DKG, FROST, threshold KEM). **Every rule here
is enforced by a test.** A rule without a test is a suggestion; the first task
is to write the test.

> **Prime directive: when a test fails, fix the SOURCE, not the test.** Tests
> encode deliberate decisions, usually made after finding a real defect.
> Weakening one to make code pass inverts the system.

This is a cryptography workspace. The failures that matter are **silent
wrongness**: a proof that verifies when it shouldn't, a channel bound to the
wrong identity, a "post-quantum" claim that is classical arithmetic with extra
steps (the defect this workspace replaced: a Python prototype fed Curve25519
constants into plain modular exponentiation and called it "NIST PQC
compliant"; see §0.2). So:

- **A cryptographic claim in a doc comment is a claim under test** (§4).
- **A defect gets a permanent regression test in the change that fixes it**
  (§6).
- **Complexity claims are honest or absent** (§1).
- **Nothing ships on "should work."** The RLN AIR and the MPC DKG each had a
  real bug found by testing against a reference (§0.5, §6.3).
- **A security limitation is documented where trusting the API would be the
  mistake**, not in a README (§5).

## Enforcing tests

| Rule | Enforced by |
| --- | --- |
| §1 Complexity is stated honestly | `PathOram` and `Dealer` docs cite the proven bound; no `O(1)` claim exists for either |
| §1.1 No property claimed that the math doesn't give | `silence_is_a_counterexample_to_positive_epsilon_pure_dp` (§6.28) |
| §2 Secrets are zeroized and never logged | `Drop` impls on secret-holding types; static `ZeroizeOnDrop` assertions on dependency key types (§6.29); no `Debug` reaches key bytes |
| §3 Wire parsers never panic on attacker bytes | `wire::Reader` is `Result`-first; `Reader::remaining()` bounds every count (§6.29); fuzz targets in `crates/core/fuzz` |
| §4 Every security claim has a test that tries to break it | the table in §4 |
| §5 Limitations are documented at the API boundary | each crate's module docs (list in §5) |
| §6.2 A fix and its regression test are one change | e.g. the RLN Merkle off-by-one (§6.3) and `valid_membership_proof_verifies` |
| §6.8 Dependency hygiene | every declared dependency is used; `cargo audit` and `--locked` in `scripts/check.sh` |
| §6.10 A structural invariant beats a documented rule | ORAM's `Client`/`ServerStorage` split; `client_works_unchanged_against_a_different_server_impl` |
| §6.11 PQC on the ratified FIPS 203/204 standards | `ml-kem`/`ml-dsa`; RFC 9591 FROST vector still matches |
| §6.12 ORAM tampering is detected | `a_server_that_tampers_with_a_bucket_is_caught`, `a_server_that_replays_a_stale_bucket_is_caught` |
| §6.13 FROST-signed RLN roots without crate coupling | `crates/mpc/tests/frost_signs_rln_root.rs` |
| §6.14 `unsafe`/`unwrap` discipline is a lint | `#![forbid(unsafe_code)]`, `#![warn(clippy::unwrap_used)]` in every crate root |
| §6.15 Ratchet forward secrecy and post-compromise security | `crates/core/tests/ratchet.rs` |
| §6.17–§6.18 X3DH, sealed sender, multi-device, incremental ratchet, signed device lists | `crates/core/tests/{x3dh,sealed_sender,multidevice,incremental_ratchet}.rs` |
| §6.21 Verified Poseidon2 port | `matches_official_poseidon2_goldilocks_width8_test_vector`, `matches_the_real_upstream_crate_on_many_random_inputs` |
| §6.22 Dependency deserializer panics contained | `a_four_byte_input_that_used_to_panic_winterfells_deserializer_is_rejected_cleanly` and siblings |
| §6.29 Wire truncation, unbounded allocations, unauthenticated `Welcome`, ORAM size leaks, prekey exhaustion, RNG leak | `crates/core/tests/wire_limits.rs`, group/prekey/oram/dp tests named in §6.29 |
| §6.30 RLN security is 127 bits and the binding is injective | `a_proof_generated_below_the_security_floor_is_rejected`, `distinct_messages_do_not_collide_in_the_rate_limit_binding_value` |
| §6.31 The RLN fuzz seed reaches the verifier; known upstream DoS pinned | `the_seed_proof_fixture_still_parses_and_verifies`, `a_known_unbounded_allocation_in_winterfells_verifier_still_aborts_the_process` |
| §6.32 Fuzz targets splice into genuine messages | `crates/core/fuzz/README.md` coverage table |
| §0.4 Build-mode caveats are stated | `cargo test -p novachannel-rln --release` is the documented invocation, with the reason |

---

## 0. The first-principles doctrine

Reason from mechanics, not convention. "This is how ZK circuits are usually
built" imports someone else's constraints. Ask what is true for *this*
construction: the field, what the adversary observes, what the composition
math actually bounds.

### 0.1 "Impossible" is a claim you verify, not assume

The original design asked for `O(1)` ORAM and an "MPC" primitive with no
scenario. `O(1)` ORAM contradicts a **proven** lower bound
(Goldreich-Ostrovsky: `Ω(log n)` amortized bandwidth with `O(1)` client
state), so `PathOram` is `O(log n)` and says why. "MPC" was clarified into a
real scenario, threshold mixnode keys, before any code was written.

### 0.2 Delete before you optimize; ask before you build

The original `zkp.py` "zero-knowledge proof" was neither zero-knowledge nor
sound: modular exponentiation dressed in Curve25519 constants, logged as
"Post-Quantum Ready." It was deleted with the rest of the Python surface, not
repaired. Patching a construction that doesn't do what it claims keeps the
false claims.

### 0.3 Novelty requires evidence

A new construction is flagged as unreviewed until evidence says otherwise,
and doesn't borrow an established one's reputation. `NovaRescue`, this
workspace's original from-scratch STARK permutation, was flagged that way and
later replaced by a verified Poseidon2 port (§6.21). Rejected alternatives
are recorded with their measurements so they aren't retried blind (e.g. the
cubic extension in §6.30).

### 0.4 Say what is true

`cargo test -p novachannel-rln` fails in debug builds. The circuit is sound:
winterfell's debug-only check requires each declared constraint degree to
*equal* the measured degree for the witness, and this AIR's sparse
boundary-injection columns measure lower on some witnesses even though the
declarations are safe upper bounds. The fix was documenting the mechanism and
requiring `--release`, not hiding the failure or weakening the check.

### 0.5 Validate the instrument before trusting the measurement

A throwaway probe compared `build_trace`'s Merkle root with the reference
`MerkleTree` level by level: every level matched except the root, which
localized §6.3's bug. **When a black-box check fails, build a white-box check
before theorizing about the cause.**

---

## 1. The complexity-honesty law

**A complexity claim is backed by an argument or absent.**

- `PathOram::access` is `O(log n)`, and the doc says the Goldreich-Ostrovsky
  bound makes `O(1)` impossible.
- STARK verification (`novachannel_rln::air::verify`) is polylogarithmic in
  circuit size, never called `O(1)`.

Genuinely constant costs (`DummyScheduler::decide`, one AEAD call in
`Sender::seal`/`Receiver::open`) are stated as such, with nothing larger
implied.

### 1.1 Never claim a property the math doesn't give you

This section once said `novachannel-dp` delivers ε-differential privacy,
derived from

```text
Pr[o=1 | b=1] / Pr[o=1 | b=0] = 1 / q = e^ε
Pr[o=0 | b=1] / Pr[o=0 | b=0] = 0 / (1-q) = 0 ≤ e^ε
```

That checks one direction only. DP needs both: for silence,
`Pr[o=0 | b=0] / Pr[o=0 | b=1] = (1-q) / 0` is unbounded, so silence reveals
an empty slot. The claim was withdrawn (§6.28), the crate now says plainly
that positive ε is **not** DP, and
`silence_is_a_counterexample_to_positive_epsilon_pure_dp` pins the
counterexample. `sequential_epsilon` and `advanced_composition_epsilon`
remain the standard textbook bounds, documented as calculators for
mechanisms that are independently DP.

---

## 2. The secret-handling law

Key material is zeroized on drop and never reaches a `Debug` impl, a log line
or a wire message by accident.

### 2.1 Every long-lived secret has a `Drop` impl

Secret-holding types (`novachannel_mpc::{Dealer, KeyShare}`,
`novachannel::kex::SharedSecret`, `novachannel::group::{Group,
WelcomeSnapshot}`, `novachannel::x3dh::SessionKeys`,
`novachannel_rln::Identity`, `novachannel_oram::Client`) clear their secret
fields on drop. `novachannel::identity::Identity` has no `Drop` impl because
its key types zeroize themselves; a static assertion checks that (§6.29).
Public types (`PublicIdentity`, `HybridSignature`) implement `Debug`; secret
types don't derive it, so a stray `{:?}` fails to compile.

Dependencies count too: `ml-dsa`, `ml-kem` and `chacha20poly1305` only
zeroize with their `zeroize` cargo feature enabled, so it is enabled. `cargo
test` can't check a dependency's feature flags, which is why this is written
down here.

### 2.2 Comparisons over secret-derived values use the field's own equality, not a byte-by-byte shortcut that could branch on timing

`Scalar`/`RistrettoPoint` equality and AEAD tag checks are constant-time in
their crates; this workspace doesn't reimplement them. Its own comparisons
(e.g. `PublicIdentity::eq`) touch only public data.

### 2.3 A secret never has a natural home in a periodic/public wire column

`novachannel_rln::air`'s trace has public columns (round constants, boundary
flags) and private ones (`sk`, sibling, selector). `sk` is carried in a
constant private column, never derived from a public value: the constraint
that makes the nullifier scheme sound (§4.1).

---

## 3. The parser-safety law

**Every function accepting bytes from a peer returns `Result` and never
panics on malformed input.**

### 3.1 The wire reader is `Result`-first by construction

`novachannel::wire::Reader` bounds-checks every read and returns
`Error::Malformed` instead of slicing past the end. Downstream conversions
that look like they could panic (`try_into().unwrap()` on a slice) follow a
`get_fixed(n)` that already guaranteed the length. Count-prefixed sequences
are bounded by `Reader::remaining()` before reserving memory (§6.29).

### 3.2 A proving/verification entry point returns `Result`, even for "should never happen"

`novachannel_rln::air::prove` used to `.expect()` the prover's result; it now
returns `Result`, so a proving failure degrades one request instead of
aborting the caller.

### 3.3 A `Result`-returning entry point isn't enough if a *dependency* panics before returning one

The `rln_verify` fuzz target found that winterfell 0.13.1's
`Proof::from_bytes` panics on `[0xdd, 0x00, 0x03, 0xdd]` ("attempt to
exponentiate with overflow" on an attacker-chosen trace-length exponent),
reproducible under this workspace's `overflow-checks = true` release profile.
§3 held for this crate's code but not for the dependency parser in front of
it. `novachannel_rln::Message::from_proof_bytes` wraps it in `catch_unwind`
and returns `Err`; `verify` gets the same treatment defensively. Two
regression tests replay the exact crash inputs.

`cargo fuzz` forces `panic = "abort"`, so the fuzz binary keeps reporting a
handled panic as a crash. Check fixes against a normal build (the regression
tests), not by whether the fuzzer stops crashing; see
`crates/core/fuzz/README.md`. A panic in a dependency that *allocates* rather
than unwinds can't be contained this way at all (§6.31).

---

## 4. The proof-obligation law

**Every claim about what an adversary can't do is backed by a test that plays
the adversary.**

| Claim | Test that tries to break it |
| --- | --- |
| Tampering with a channel record is detected | `tampered_record_fails_to_decrypt` |
| Replaying a sealed record is detected | `replayed_record_is_rejected` |
| The replay window keeps its boundary record | `replay_window_boundaries_preserve_seen_records_and_accept_unseen_records` |
| A forged handshake signature is rejected | `forged_signature_is_rejected` |
| A pinned peer identity mismatch is rejected | `wrong_pinned_server_identity_is_rejected` |
| A tampered STARK proof fails verification | `tampered_proof_bytes_are_rejected` |
| A proof against the wrong Merkle root fails | `wrong_root_is_rejected` |
| Every RLN public input is independently load-bearing | `each_public_input_is_independently_load_bearing` |
| RLN messages in *different* epochs don't leak the key | `messages_in_different_epochs_do_not_leak_the_key` |
| Two messages in the *same* epoch **do** leak it | `two_messages_in_same_epoch_reveal_the_secret_key` |
| Distinct messages don't collide in the rate-limit binding | `distinct_messages_do_not_collide_in_the_rate_limit_binding_value` |
| A proof below the security floor is rejected | `a_proof_generated_below_the_security_floor_is_rejected` |
| A malformed RLN proof fails cleanly instead of crashing | `a_four_byte_input_that_used_to_panic_winterfells_deserializer_is_rejected_cleanly` and siblings |
| A tampered DKG share fails Feldman verification | `tampered_share_fails_feldman_verification` |
| A faulty dealer is excluded and honest participants converge | `a_faulty_dealer_is_identified_and_excluded_without_aborting_the_dkg` |
| A fabricating accuser can't evict honest dealers | `a_disagreement_the_evidence_cannot_attribute_is_reported_without_blaming_the_dealer` and the eviction test after it |
| A below-threshold quorum can't recover the secret | `below_threshold_quorum_does_not_recover_the_secret` |
| Positive-ε dummy traffic is not pure DP | `silence_is_a_counterexample_to_positive_epsilon_pure_dp` |
| Any valid FROST quorum produces a verifying signature | `a_threshold_quorum_produces_a_signature_that_verifies`, `any_valid_quorum_produces_a_signature_that_verifies` |
| A FROST signature doesn't verify for a different message | `a_signature_does_not_verify_against_a_different_message` |
| A tampered FROST share is caught and attributed | `a_tampered_signature_share_fails_share_verification` |
| FROST matches RFC 9591's published vector | `official_test_vector_matches_rfc9591` (§6.9) |
| A below-threshold quorum can't decrypt a `threshold_kem` payload | `below_threshold_quorum_fails_to_decrypt` |
| A ciphertext for one operator can't be opened by another | `a_ciphertext_meant_for_a_different_operator_fails_to_decapsulate_cleanly` |
| A tampered `threshold_kem` payload is rejected | `tampered_payload_ciphertext_is_rejected` |

A new cryptographic property needs a row here and a test before it's done.

### 4.1 Binding matters more than either half alone

The RLN AIR could have proved "I know a member `sk`" and computed
`a1 = Hash(sk, epoch)` outside the circuit. Easier, and wrong: nothing would
force the same `sk` in both, so a prover could use a different key for each
message's share. Both are bound to one constant trace column and proved in
one STARK.

### 4.2 A new primitive earns its place by reusing what's already sound, not by duplicating it

`novachannel_mpc::frost` lives inside the crate and shares
`lagrange_coefficient_at_zero` and `evaluate_commitment` with the DKG instead
of carrying its own copy. Two implementations of "evaluate a Shamir
polynomial" that quietly disagree are a soundness bug.

---

## 5. The stated-limitations law

**A limitation that matters to a caller's security is documented where the
caller reads it before relying on the API**, in the crate's own docs.

Current limitations, each stated in the crate that has it:

- `novachannel`: no PKI; callers pin peer identities. Ratchets have no formal
  verification (ProVerif covers only `handshake` and `x3dh`). The group
  ratchet is TreeKEM-inspired, not RFC 9420, needs a single agreed commit
  order, and decrypts only the current epoch.
- `novachannel-rln`: the Poseidon2 port is checked against the reference but
  not independently reviewed. A malformed proof can abort the verifying
  process through an unbounded allocation in winterfell (§6.31); isolate
  `air::verify`. Debug-build tests fail by design (§0.4).
- `novachannel-mpc`: `Dealer`, `frost` and `combine_partials` are classical
  (Ristretto255) and fall to a discrete-log break. `threshold_kem` covers
  post-quantum *decryption*; there is no post-quantum threshold *signing*
  (no production-ready scheme exists to adopt). The crate does no
  networking; `examples/networked_complaint.rs` shows a transport.
- `novachannel-oram`: plain `ServerStorage` is trusted; integrity
  (`VerifiableServerStorage`) and confidentiality with size hiding
  (`EncryptingServerStorage`) are opt-in. Stash values aren't zeroized. Key
  management is the caller's.
- `novachannel-dp`: positive ε is **not** differential privacy (§1.1); only
  ε = 0 hides the presence bit, given indistinguishable packets.
  `GridScheduler` hides within-slot timing at a latency cost; system-wide
  timing elsewhere is out of scope. `SizeBucketer` hides length up to the
  bucket.

### 5.1 A stray unrelated file gets excluded, not adopted

An `ENGINEERING-STANDARDS.md` from an unrelated project was in this directory
before this one existed and was swept up by `git add -A`. It was unstaged and
this document written from scratch: a standards document that doesn't
describe the code is worse than none, because it is read as authoritative.

---

## 6. The regression ratchet

### 6.1 The gate

`scripts/check.sh` defines "done": `cargo fmt --check`, clippy with
`-D warnings`, rustdoc with `-D warnings`, tests in release and debug (rln in
release only, §0.4), all `--locked`, then `cargo audit` and gitleaks.
`.github/workflows/ci.yml` runs that same script, not a YAML copy that could
drift. Run it before calling a change finished.

### 6.2 A fix and its regression test are one change

Every bug ships with the test that catches its recurrence, in the same
change. §6.3's off-by-one is covered by `valid_membership_proof_verifies` and
the rest of the RLN suite.

### 6.3 A found defect becomes a sweep for its class

**Defect:** `build_trace` ran `DEPTH` "rounds, then inject" cycles, but the
Merkle chain needs `DEPTH + 1` permutation blocks (leaf hash plus one per
combine), so the proof's root was one combine short: self-consistent, wrong
against the reference tree. Found by §0.5's probe, not inspection; every
individual piece was correct. **Sweep:** every row-index constant in `air.rs`
was re-derived from one corrected `NUM_MERKLE_BLOCKS = DEPTH + 1` rather than
patched one by one.

### 6.4 Assert properties, not tautologies

Tests assert the property itself (a measured ratio against its bound, two
same-bucket plaintexts padding to equal size), not something that would pass
under a broken implementation such as "nonzero" or "padding exists."

### 6.5 Debug-mode strictness is signal, not noise, until proven otherwise

The winterfell degree assertion (§0.4) was traced to a specific root cause
before being accepted as a false positive. A failing strict check is
evidence of *something*; find out what before deciding the check is wrong.

### 6.6 A stray file in the working tree is investigated before it's staged

Read an unfamiliar file before deciding to commit or ignore it (§5.1).

### 6.7 Boundaries are a place to test

`budget_tracks_spend_and_refuses_overspend` spends exactly to the limit and
asserts the next spend is refused. The replay window is tested at jumps 1,
63, 64, 65 and 128 (§6.28). The heavy ORAM workload's stash-size assertion is
a regression boundary on eviction correctness.

### 6.8 Dependency hygiene

Every declared dependency must be used (`thiserror` in `novachannel-rln` and
`signature` in `novachannel` were removed when found unused). The original
`.unwrap()`/`.expect()` audit found no attacker-reachable site; §6.14 turned
that one-time audit into a standing lint.

### 6.9 A claimed compatibility gets checked against the actual spec, not against your reading of it

FROST was first built to RFC 9591's *shape* with guessed domain separation
and byte layout, disclosed as unchecked. The CFRG publishes machine-readable
vectors (`cfrg/draft-irtf-cfrg-frost`, `poc/frost-ristretto255-sha512.json`,
on `master`). `binding_factor_input` is 192 bytes for a 4-byte message, which
only works if two components are SHA-512 hashes:
`group_public_key(32) || H4(msg)(64) || H5(commitment_list)(64) ||
encode_identifier(32)`. Candidate layouts were tested against the vector's
bytes until one matched. `official_test_vector_matches_rfc9591` hard-codes
the vector (no network in tests) and reproduces every share and the final
signature; once the encoding was right, no protocol logic needed changing.
Deterministic `nonce_generate` is deliberately not matched (CSPRNG nonces
instead) and documented as such.

### 6.10 A structural invariant beats a documented rule

ORAM's docs said the position map and stash must never sit with bucket
storage, while one struct held all three. A rule that must be remembered is
violated by the first field added in the wrong place. Now `Client` (position
map, stash) drives any `ServerStorage` implementation, and
`PathOram<V> = Client<V, InMemoryServer<V>>` kept every caller working.
`client_works_unchanged_against_a_different_server_impl` runs the workload
through a second, independent storage. The split protects *which* state the
server sees, not the content of blocks; that is `EncryptingServerStorage`'s
job (§6.24, §6.29).

### 6.11 A dependency upgrade is checked against real API compatibility before it's claimed

`pqcrypto-kyber`/`pqcrypto-dilithium` (C implementations of the round-3
submissions) were replaced by RustCrypto's pure-Rust `ml-kem`/`ml-dsa` (FIPS
203/204 as ratified in 2024), together with `curve25519-dalek` 5,
`ed25519-dalek`/`x25519-dalek` 3 and `chacha20poly1305` 0.11. A throwaway
probe crate first confirmed the set builds together (they moved jointly to
`rand_core` 0.10, which dropped `OsRng`), so the incompatibility surfaced in
a probe rather than mid-refactor. The wire format changed and is documented
as a breaking change. All tests, including the RFC 9591 vector, still pass.

### 6.12 Verifiable ORAM

`VerifiableServerStorage` adds a Merkle tree over the ORAM tree, so a server
that tampers, drops or replays is detected at no extra asymptotic cost.
**Defect found building it:** write-back stored each node's raw bucket hash
instead of `hash_node(bucket_hash, left, right)`, so every honest access
after the first failed. A two-access reproduction printing every hash showed
`hash[1] == hash[3]` for nodes with different children; the recompute now
returns every node's combined hash. Tests corrupt a bucket directly and
replay a stale but internally valid bucket (only a root comparison catches
the latter).

### 6.13 Composing two crates needs no coupling if the interface is bytes

A mixnode quorum FROST-signs the RLN membership root so clients can trust it.
`MerkleTree::root_bytes()` returns bytes and FROST signs bytes, so the only
link is a dev-dependency in `crates/mpc/tests/frost_signs_rln_root.rs`. Three
tests: the attestation verifies, it doesn't verify for another root, and a
below-threshold quorum can't produce one (signing and decryption are
different code paths, so this is checked again here).

### 6.14 A one-time audit became a standing lint, on evidence from libsignal

libsignal's `libsignal-protocol` and `zkgroup` roots (read directly) carry
`#![warn(clippy::unwrap_used)]` and `#![deny(unsafe_code)]`. Adopted here; the
nine non-test `.unwrap()` sites became `.expect("reason")`, with tests
exempt. A lint survives the next PR; a note saying "we checked" doesn't.
`docs/LIBSIGNAL_COMPARISON.md` records what was and wasn't adopted. It also
surfaced the absence of in-session post-compromise security, closed in §6.15.

### 6.15 The ratchet gap from §6.14, closed with an explicitly bounded scope

SPQR's source (`src/v1/unchunked/send_ek.rs` and siblings) showed its step is
an incremental re-encoding of ML-KEM-768 over a multi-round state machine,
machine-verified with hax/F* and ProVerif: not something to clone from one
reading. `crates/core/src/ratchet.rs` gets the same two properties with a
mechanism that could be checked here: an HMAC hash chain for per-message
forward secrecy, and a mid-session re-run of `kex.rs`'s hybrid exchange mixed
into an HKDF root for post-compromise security.

Writing the tests first exposed a real subtlety: the responder changes epoch
when it sends its reply, the initiator when it receives it, so records in
flight arrive on the old epoch. One prior epoch's receive chain is retained
(the same shape as SPQR's `EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH = 1`), tested
both ways (in-flight delivery works; older epochs are rejected). Concurrent
initiation fails with `Error::RatchetInProgress` rather than silently
diverging, since resolving it needs a tie-break rule this crate doesn't
choose for callers. The module originally required strict in-order delivery;
it now tolerates bounded out-of-order delivery with a skipped-key cache
(`MAX_SKIPPED_KEYS`).

### 6.16 Chasing line coverage found real gaps and one real dead function

Measured with `cargo tarpaulin`. 100% was not the goal: many uncovered lines
are `.expect()` on invariants meant to stay unreachable. Every genuinely
reachable gap was closed. Findings: `permutation::hash2` duplicated
`compress2` with no callers (deleted); `MerkleTree::verify_path`,
`recover_secret`'s same-`x` branch, malformed-message branches in
`handshake.rs`/`ratchet.rs` and in-order transport delivery gained direct
tests. Unreachable-from-public-API ratchet branches are tested from a
`#[cfg(test)]` module inside `ratchet.rs` instead of widening visibility.

Tarpaulin under-reports `novachannel-rln` in `--release` (inlining), so those
numbers are recorded as an instrument limitation, not hidden with exemptions.
`#[cfg(not(tarpaulin_include))]` (allowed in `[workspace.lints.rust]`
`check-cfg`) is used once, on a test helper's wrong-variant panic, and the
dispatch line still shows uncovered, because "never executed" is true.

### 6.17 X3DH, sealed sender, Sesame-style multi-device, and an incremental erasure-coded ratchet

Four additive modules following the existing patterns: `prekey`/`x3dh`
(asynchronous, deniable, yielding the same `EstablishedSession`, shown by
running a full ratchet over it); `sealed_sender` (certificate checked by the
recipient, since relays can't see it); `multidevice` (sessions keyed by
sender identity and device id, tested for cross-sender isolation); and an
erasure-coded incremental ratchet (its from-scratch Reed-Solomon code was
later replaced, §6.21).

Two defects found by testing the real property:

1. **Strict ordering defeats loss tolerance.** Routing chunks through the
   sequential record chain turned loss or reordering into `Replay` or desync.
   Chunks now carry their own AEAD keyed from `root_key` and a random
   per-attempt nonce, independent of record sequence numbers. Loosening the
   replay window instead would have reintroduced silent wrongness.
2. **Stale root key for stragglers.** With every chunk delivered, extra parity
   chunks arriving after reconstruction (and the epoch change) failed to
   decrypt. The last completed attempt's nonce is recorded and its stragglers
   are ignored; the regression test delivers the full chunk set rather than a
   loss pattern that avoids the bug.

### 6.18 Closing `crate::multidevice`'s named gap: a signed, version-authenticated device list

A MITM serving bundles could inject a device. Now the account's long-term
identity signs a versioned `SignedDeviceList`;
`RemoteAccount::from_signed_device_list` checks every bundle against it;
`sync_from_signed_device_list` rejects any version not strictly newer
(rollback) and revokes sessions for devices a newer list drops. Each property
has a test that attempts the attack. Fetching the list and choosing the
account key remain the caller's job, and the unauthenticated path still
exists for callers who opt out.

### 6.19 Dependency currency

`cargo audit` and Dependabot both reported zero open advisories. Direct
dependencies moved to current majors (`thiserror` 2, `rand` 0.10 with its
`RngExt`/`random_bool` renames, `sha2`/`hkdf`/`hmac` 0.11/0.13/0.13). One
test broke for an instrument reason: `rand_chacha` 0.10 changed
`seed_from_u64`, so the ORAM replay test's seed no longer changed the root
bucket and the "replay" became a no-op. A probe swept seeds for one that
exercises the real scenario (127), and the comment says why the seed matters.
The `zeroize` features required by §2.1 were enabled in this pass.

### 6.20 Raising RLN's STARK parameters and permutation round count to match the rest of the workspace's ≥128-bit bar

Proof options moved to 32 queries, blowup 16, grinding 20 and a quadratic
field extension, and `NovaRescue` to 31 rounds (keeping `BLOCK_LEN` a power
of two). Proof size grew from ~25.8KB to ~36.7KB, measured by
`examples/proof_size.rs`. The security figures recorded here at the time
(~96 to ~148 bits) were wrong; the real ones are 63 to 127 (§6.30).

### 6.21 `NovaRescue` replaced with a verified port of an audited Poseidon2 instance; `crate::erasure` replaced with a maintained Reed-Solomon crate

`permutation.rs` now ports Poseidon2-over-Goldilocks from
`p3-goldilocks`/`p3-poseidon2` 0.6.3 (used by audited provers such as SP1 and
RISC Zero), checked byte-for-byte against Plonky3's vector. That removes the
"invented construction" risk but isn't an independent review of the port,
and the docs say so. Matching the reference changed the field to Goldilocks
(`f64`) and the width to 8 (Plonky3 publishes no width-4 constants), so
`MerkleTree::root_bytes` went from 16 to 8 bytes: a breaking change, stated.

The hand-rolled GF(256) Reed-Solomon code became a wrapper around
`reed_solomon_simd` (Leopard-RS), chosen after `cargo audit` showed the
alternative `reed-solomon-erasure` pins an advisory-flagged `lru`. The
dependency `assert!`-panics on odd shard lengths, so `decode` rejects them as
`Malformed` first: a parser boundary owns its untrusted-input handling even
when it delegates the algorithm.

### 6.22 A fuzz target found a real remote-DoS panic in a dependency; two real coverage gaps closed; post-quantum threshold decryption added to `novachannel-mpc`

- **Fuzzing:** new `rln_verify` and `mpc_frost_verify` targets. `rln_verify`
  found the winterfell deserializer panic in §3.3 within seconds.
- **Coverage drift:** re-measuring found `multidevice.rs` at 63% and
  `air.rs` (the constraint system) at 55%. New tests cover `RlnAir::new`'s
  malformed-`TraceInfo` guards (one is provably unreachable through
  `verify`, since `TraceInfo::new` rejects non-power-of-two lengths first),
  every public input individually, `SignedDeviceList` wire round-trips and
  unknown senders.
- **`threshold_kem`:** each operator holds an independent ML-KEM-1024 key; a
  sender Shamir-shares a per-message secret and wraps each share with a fresh
  encapsulation, reusing the crate's `evaluate`/`lagrange_coefficient_at_zero`
  (§4.2). Shamir secrecy is information-theoretic and the shared scalar never
  multiplies a public point, so breaking Ristretto gains nothing; an attacker
  needs `t` operators' ML-KEM keys. No Feldman commitments: a wrong share
  fails the payload AEAD. It covers decryption only; threshold signing stays
  classical (`lattice-safe/threshold-ml-dsa` was unaudited research code when
  checked).

### 6.23 `crate::group`: a module that fell outside this document's own audit trail, and two real defects that gap let through

`group.rs` (~1,700 lines, exported) was missing from every audit and had no
integration test file. Asking "what can someone holding only a victim's
*published* invite material make this do?" found:

- **A forgeable remote panic.** `Welcome` travels in a sender-anonymous
  envelope, so its plaintext is attacker-chosen. A forged `capacity = 0`
  underflowed `2 * capacity - 1` (panicking under `overflow-checks`), and
  `target_leaf >= capacity` indexed out of bounds in `join`. Both are now
  checked against `Group::create`'s invariant and return `Malformed`.
- **No proof-of-possession on `LeafKeyPackage`.** A victim's identity could be
  paired with an attacker's key. The package is now signed by the member's
  identity over `(identity, public_key)` and verified in `read`, the one
  choke point for every deserialization path.

`threshold_kem`'s intermediate secrets are now zeroized, and `Group`
zeroizes superseded epoch secrets when replaced. Remaining gaps named here
(self-removal, wrong-group commits and tampered `Add` packages had no tests)
were closed in §6.25.

### 6.24 Three of `docs/SYSTEMIZATION.md` §9's own named gaps, closed

Two of its five gaps aren't fixable here (no production post-quantum
threshold signature exists; a directory service is a separate system).
Three were:

- **MPC complaint protocol:** `Complaint`/`Dealer::share_for`/
  `resolve_complaint` give the per-accusation step for participants who see
  only their own shares, and a test shows it agrees with the batch
  `identify_faulty_dealers`. (The verdict rules were corrected in §6.29's
  review: only a disclosure failing the dealer's own commitments disqualifies
  a dealer.)
- **ORAM confidentiality:** `EncryptingServerStorage` seals `id` and `value`
  together (a clear id would let the server correlate updates). A block
  failing authentication is dropped rather than panicking; with the
  integrity layer that changes the bucket hash and surfaces as
  `IntegrityError`, tested directly. Nonces come from a counter, avoiding the
  birthday bound of random 96-bit nonces at high volume.
- **DP size channel:** `SizeBucketer` pads to fixed buckets; the key test
  checks two lengths in one bucket pad to identical sizes.

### 6.25 Continuous fuzzing, further `crate::group` hardening, a real cross-check for the RLN permutation, and a key-custody seam

- **ClusterFuzzLite** replaced a hand-maintained daily fuzz matrix that had
  silently omitted two targets. `build.sh` discovers every target, PRs get 10
  minutes per target, and a batch run goes every 6 hours. OSS-Fuzz's
  acceptance bar (significant user base or critical infrastructure) isn't met.
- **Group hardening:** self-removal converges, wrong-group commits are
  rejected, tampered `Add` packages inside a `Commit` are rejected, and a
  re-signed commit with swapped path keys fails as `PathKeyMismatch` rather
  than passing on its signature.
- **Permutation cross-check:** with `p3-goldilocks`/`p3-poseidon2` now on
  crates.io, `matches_the_real_upstream_crate_on_many_random_inputs` compares
  10,000 random inputs. The port remains necessary because winterfell's and
  Plonky3's field traits have no adapter. Cost: a dev-only transitive
  dependency on `paste` (RUSTSEC-2024-0436, unmaintained), disclosed.
- **Key custody:** `Ed25519SigningBackend`/`MlDsaSigningBackend` and
  `Identity::from_backends` let keys live in an HSM or KMS; `try_sign`
  surfaces backend failures. No vendor SDK is a dependency. AWS KMS supports
  both legs (ML-DSA-87, Ed25519); no KMS offered ML-KEM when checked, so key
  exchange stays in-process.

`docs/LIBCRUX_MIGRATION.md` scopes, without attempting, a move to Cryspen's
formally verified `libcrux`, so that breaking change can be decided
deliberately.

### 6.26 Real networked deployments of two protocols that were reference-implementation-only

Both crates stay transport-agnostic, so the fix is examples, not library
networking: `crates/mpc/examples/networked_complaint.rs` (five threads with
their own TCP sockets to a broadcast relay run a real complaint round and
reach the same verdict) and `crates/oram/examples/networked_server.rs` (a
`std::net` `TcpServerStorage` under an unchanged `Client`). Neither is a
production transport; the relay is unauthenticated and the storage assumes
one trusted connection.

### 6.27 RLN proving-time measurement; a real fix for `novachannel-dp`'s within-slot timing gap

`examples/proving_time.rs` measures proving and verification time across the
`proof_size` configurations (one machine; scale for target hardware).
`GridScheduler` closes within-slot timing: `enqueue` only queues, and `tick`
(driven by the caller's clock, never by `enqueue`) is the only transmitter and
never sees a timestamp. A test enqueues at different points in a slot and
asserts identical output. The cost is latency; system-wide timing elsewhere
remains out of scope.

### 6.28 Production review: replay-window boundary and withdrawn DP claim

**Replay window:** the bitmap tracks ages 1 to 64, and advancing exactly 64
cleared it, forgetting the previous highest record, which could then be
replayed. Bit 63 is now preserved at exactly 64. The regression test failed
on the old code and covers jumps 1, 63, 64, 65 and 128; no other replay
window exists in the workspace.

**DP:** §1.1's claim checked one ordered pair. Silence breaks the reverse
inequality at any positive ε; `silence_is_a_counterexample_to_positive_epsilon_pure_dp`
witnesses it in the real scheduler. Existing tests stayed as they were, since
changing them to hide this would violate the prime directive. A positive-ε DP
mechanism would need different delivery semantics and an explicit
adjacent-input model.

Also: a yanked locked `chacha20` 0.10.1 was replaced by 0.10.2, and rustdoc
with `-D warnings` joined the gate after finding stale and private-item links.
Links were fixed at the source, not suppressed.

### 6.29 A second production review: nine defects, and what fuzzing structurally could not reach

A full read of all five crates. Each fix shipped with a test confirmed to
fail on the pre-fix source.

- **`debug_assert!` load-bearing in release.** `put_var`'s `u16` prefix
  wrapped silently above 65535 bytes, so a 32-leaf group's ~73KB `Commit`
  serialized to unparseable bytes, as did large sealed-sender and X3DH
  payloads. Now `u64`: lossless on every target, so `put_var` needs no error
  path (a `u32` prefix would have made every `to_bytes` fallible for an
  unreachable case). Six bytes per field.
- **Three unbounded allocations** (`Commit` path length, `UpdatePathNode`
  ciphertext count, `SignedDeviceList` entries) from raw `u32` counts. A
  10.8 TiB reservation actually *succeeds* on macOS, so the honest impact is
  "aborts wherever such a reservation fails." Bounded by `Reader::remaining()`.
- **Why fuzzing missed it:** `group_commit` never got past a
  `LeafKeyPackage` signature in 36 million executions. Fields behind a
  signature check need reading or splicing, not more CPU (§6.32).
- **Two ratchet state-machine faults:** a step 1 on the previous epoch's chain
  re-derived an epoch number already in use; and the incremental step-2 path
  consumed `pending` before parsing, stranding a retryable step.
- **Unauthenticated `Welcome`.** Only `capacity`/`target_leaf` were checked;
  the tree, epoch and secrets were unauthenticated. The committer now signs
  the snapshot and `join` checks four bindings. `Group::member_identity` was
  added so messages and committers are attributable.
- **One-time prekeys burnable by anyone:** `respond` deleted the prekey
  before authentication. Now `peek`, then `consume` after the AEAD verifies.
- **ORAM size leaks:** bucket occupancy (0 to Z) and value length reached the
  server. Fixed block size and dummy padding to `Z` per bucket, with no change
  to `Client` or the Merkle layer.
- **RNG consumption tracked the hidden bit:** `decide` short-circuited its
  draw. Now it draws unconditionally.
- **Overflow before bounds check:** `group::spliced` and
  `oram::depth_for_capacity` (an `f64` log2 inexact above `2^53`).

Other hardening: `kex::checked_dh` rejects all-zero X25519 output (RFC 7748
§6.1) instead of using a twelve-entry small-order table that one wrong byte
would weaken; `verify_strict` for Ed25519; trailing-byte rejection in
`Commit`/`PreKeyBundle`; public `SignedDeviceList` encoding. The gate now also
runs tests in debug for every crate but rln, so `debug_assert!`s execute.
`Identity`'s `Drop` impl was **deleted**: it copied the secret to zeroize the
copy, clearing nothing. A static `ZeroizeOnDrop` assertion on the key types
replaces it (§0.2).

### 6.30 The proof-security number this workspace has been quoting was wrong in both directions

§6.20's figures used `num_queries * log2(blowup_factor) + grinding_factor`,
only the query term. Winterfell computes

```text
min(min(field_security, query_security) - 1, hash_collision_resistance)
```

with `field_security = base_field_bits * extension_degree = 64 * 2 = 128`,
so the default is `min(min(128, 148) - 1, 128) = 127`, and the old default
(no extension) was `min(64, 96) - 1 = 63`. The field was always the binding
term. It surfaced when raising the verifier floor from 95 to the documented
128 failed every test with winterfell reporting 127: the instrument was right
and the expectation wrong.

`FieldExtension::Cubic` reaches 128 (Blake3_256 caps it there) but costs
**5.6x proving time** (5.4ms to 29.8ms median) and 18% more proof bytes for
one bit; rejected and recorded in `default_proof_options`. The floor is now
127, matching the default and rejecting the 63-bit configurations the old
floor admitted. The examples now read `Proof::conjectured_security` instead
of re-deriving it.

**Second defect:** `bytes_to_field` (the share's message binding `x`) wasn't
injective: zero-padding made `b"a"` and `b"a\0"` collide, and reading full
`u64` chunks mod `p` made `v` and `v + p` collide. Either let a member send a
second message per epoch without revealing its key. It now absorbs the length
first and packs seven bytes per element.

### 6.31 A fuzz target that had never reached the code it was named for, and the two defects that hid behind it

`rln_verify` embedded a genuine ~27KB proof to get past the deserializer and
then **never used it**; the only symptom was a `dead_code` warning. Its corpus
was 2-4 byte inputs. Splicing fuzzer bytes into the genuine proof took
coverage from 84 to **2041** edges. The raw-bytes path was removed: under
`panic = "abort"` known deserializer panics in the corpus killed every run
within a second, and that class is already handled generically. The seed is
now a file checked by a gate test so it can't go stale silently.

It then found:

- **Fixable:** `RlnAir::new` asserts on `TraceInfo` from attacker bytes,
  relying on `verify`'s `catch_unwind`, which doesn't exist under
  `panic = "abort"`. A five-byte input aborted such builds. `verify` now runs
  the checks as a `Result` first.
- **Not fixable here:** winterfell 0.13.1's `BatchMerkleProof::read_from`
  passes an attacker-chosen count to `Vec::with_capacity`; a six-byte
  mutation requests 2520802182910816 bytes and aborts with SIGABRT. It runs
  inside `winterfell::verify`, `catch_unwind` can't catch allocation failure,
  and there is no newer release. Documented at `air::verify` and pinned by a
  subprocess test that fails when upstream fixes it.

### 6.32 The same blind spot in five more fuzz targets, and why exec count is not coverage

Measuring coverage rather than execution counts found two failure shapes:

- **Never reaching the parser:** `prekey_bundle` and `group_commit` stopped
  at a length-checked or signature-gated first field (185 and 69 edges after
  millions of executions). Splicing into genuine messages took them to 2410
  and 3735.
- **Coverage that was key generation:** four targets generated ML-DSA-87
  identities per iteration; `ratchet_open` ran two handshakes per input at
  eight executions a second. Caching immutable setup *lowered* reported
  coverage (2878 to 1514 edges for `ratchet_open`) while throughput rose to
  2.54 million executions. Mutable state (`RatchetedSession`, the prekey
  store) is still rebuilt per input so inputs can't affect each other.

Standing rules:

1. **Exec count is not coverage.** They moved in opposite directions here.
2. **Coverage is not parser coverage.** Ask how much of the number is setup.
3. **Anything behind a length check, signature or AEAD tag is unreachable by
   random mutation.** Seed from a genuine message and splice.

No new defects appeared in 150-240 second runs of the reworked targets: a
weaker statement than the old "zero crashes across all targets," and a more
honest one.
