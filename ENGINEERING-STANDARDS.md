# Engineering Standards — novachannel workspace

This document is the permanent record of the correctness and quality bar for
this codebase: `novachannel` (hybrid PQ/classical secure channel),
`novachannel-rln` (ZK-STARK rate-limiting nullifiers), `novachannel-dp`
(differential-privacy cover traffic), `novachannel-oram` (Path ORAM),
`novachannel-mpc` (threshold DKG). **Every rule here is enforced by a test.**
If a rule matters and has no test, the first task is to write the test — a
standard that isn't executable is a suggestion.

> **Prime directive: when a test fails, fix the SOURCE, not the test.**
> Tests encode decisions made deliberately, usually after finding a real
> defect. Weakening a test to make code pass inverts the entire system.

This is a cryptography workspace. The failure modes that matter are not "the
server falls over under load" — there is no server — they are **silent
wrongness**: a proof that verifies when it shouldn't, a channel that looks
encrypted but isn't bound to the right identity, a "post-quantum" claim that
turns out to be classical discrete-log with extra steps (the exact defect
this workspace replaced — see `zkp.py` in git history: Curve25519 constants
fed into plain modular exponentiation, labeled "NIST PQC compliant," which
was neither elliptic-curve arithmetic nor quantum-resistant). Concretely:

- **A cryptographic claim in a doc comment is a claim under test.** "This is
  ε-differential-private," "this binds `sk` across membership and share,"
  "this rejects a tampered proof" — each of those is asserted by a test in
  this repo, not just asserted in prose. See §4.
- **A defect, once found, gets a permanent regression test in the same
  change that fixes it.** §6.
- **Complexity claims are honest or absent.** `O(1)` is claimed nowhere in
  this workspace where the real bound is `O(log n)` or worse — see §1.
- **Nothing ships on "should work."** Every non-trivial primitive in this
  workspace (the AIR in `novachannel-rln`, the DKG in `novachannel-mpc`) was
  built, then had a real bug found in it by testing it against a reference
  implementation, then fixed. §0.5, §6.3.
- **A security limitation is documented at the point where trusting it would
  be a mistake**, not buried in a README nobody reads while implementing
  against the API. §5.

## Enforcing tests

| Rule | Enforced by |
| --- | --- |
| §1 Complexity is stated honestly | doc comments on `PathOram`, `Dealer` cite the proven lower bound; no `O(1)` claim exists for either |
| §2 Secrets are zeroized and never logged | `Drop` impls on `Identity`, `SharedSecret`, `Dealer`, `KeyShare`; no `Debug` derive reaches raw scalar/key bytes |
| §3 Wire parsers never panic on attacker bytes | `wire::Reader` returns `Result` for every read; `crates/*/src` audit (§6.8) — zero unguarded `.unwrap()`/`.expect()` on externally-supplied bytes |
| §4 Every security claim has a test that tries to break it | `crates/core/tests/handshake.rs` (tamper, replay, forged signature, identity mismatch), `crates/rln/tests/rln.rs` (tampered proof, wrong root, cross-epoch non-leakage, same-epoch key recovery), `crates/dp/src/lib.rs::tests` (empirical likelihood ratio), `crates/mpc/src/lib.rs::tests` (below-threshold quorum fails, tampered share fails Feldman check, faulty dealer excluded), `crates/mpc/src/frost.rs::tests` (valid quorum verifies, wrong message rejected, tampered share caught before aggregation, official RFC 9591 vector matches exactly — §6.9) |
| §5 Every non-obvious limitation is documented at the API boundary | module-level doc comments: `novachannel-rln`'s permutation is uncryptanalyzed; `novachannel-mpc`'s DKG has no complaint sub-protocol; `novachannel-oram`'s `Block` payload is unencrypted over `ServerStorage` |
| §6.10 A structural invariant beats a documented rule | `novachannel-oram`'s `Client`/`ServerStorage` split (no shared struct to misuse), proven by `client_works_unchanged_against_a_different_server_impl` |
| §6.11 PQC stack upgraded to the ratified FIPS 203/204 standards | `ml-kem`/`ml-dsa` replacing `pqcrypto-kyber`/`pqcrypto-dilithium`; compatibility checked via a throwaway probe before the real migration; all 26 workspace tests (incl. the RFC 9591 vector) still pass |
| §6.12 ORAM integrity: server tampering is detected, not just theoretically detectable | `VerifiableServerStorage`/`Client::verified_read`/`verified_write`; `a_server_that_tampers_with_a_bucket_is_caught`, `a_server_that_replays_a_stale_bucket_is_caught` |
| §6.13 FROST-signed RLN membership roots (no new inter-crate dependency) | `MerkleTree::root_bytes()` + `frost::sign`/`verify`; `crates/mpc/tests/frost_signs_rln_root.rs` (attests, binds to the specific root, refuses below threshold) |
| §6.14 `unsafe`/`unwrap` discipline promoted from audit to lint, per libsignal | `#![deny(unsafe_code)]` + `#![warn(clippy::unwrap_used)]` in every crate root; `docs/LIBSIGNAL_COMPARISON.md` |
| §6.15 `novachannel::ratchet`: forward secrecy + post-compromise security, honestly scoped against SPQR | `crates/core/src/ratchet.rs` module docs (reads SPQR's real `src/v1/unchunked/send_ek.rs`, not just its README); `crates/core/tests/ratchet.rs` (10 tests: per-message key independence, tamper does not desync, in-order enforcement, epoch transition, in-flight-during-ratchet delivery, stale-epoch rejection, concurrent-initiation rejection) |
| §6.16 Real line-coverage gaps closed (not chased to a literal 100%) | 86 tests total (up from 49); `permutation::hash2` (dead code) deleted; `MerkleTree::verify_path`, `share::recover_secret`'s degenerate branch, malformed/trailing-bytes parser paths in `handshake.rs`/`ratchet.rs`, in-order transport delivery now directly tested |
| §6.17 X3DH, sealed sender, Sesame-style multi-device, and an incremental erasure-coded ratchet — each additive, none replacing already-tested code | `crates/core/src/{x3dh,prekey,sealed_sender,multidevice,erasure}.rs` + their module docs; `crates/core/tests/{x3dh,sealed_sender,multidevice,incremental_ratchet}.rs` (126 tests total, up from 86); two real defects found and fixed in the same change as their regression tests (below) |
| §6.18 Signed, version-authenticated device lists close `crate::multidevice`'s trust-provisioning gap | `SignedDeviceList`/`RemoteAccount::from_signed_device_list`/`MultiDeviceSession::sync_from_signed_device_list`; `crates/core/tests/multidevice.rs` (6 new tests: mismatched-bundle rejection, unlisted-device rejection, wrong-signer rejection, version-rollback rejection, automatic revocation on a newer list) |
| §6.19 Zeroization gaps closed workspace-wide; `unsafe_code` promoted `deny`→`forbid`; supply chain gated per-PR | `ml-dsa`/`ml-kem`/`chacha20poly1305`'s optional `zeroize` cargo features enabled (their `Drop` impls were feature-gated and silently absent without it); `novachannel_rln::Identity` lost its `Debug` derive and gained a `Drop` impl (was leaking `sk` via `{:?}`, the one secret type in the workspace §2.1 missed); `Group`/`WelcomeSnapshot`/`x3dh::SessionKeys`/`oram::Client` gained `Drop` impls for `epoch_secret`/`application_secret`/`known_secrets`/`ratchet_root`/`init_payload_key`/`position_map`; all five crate roots use `#![forbid(unsafe_code)]` (a local `#[allow(unsafe_code)]` could previously override `deny`); `scripts/check.sh` runs `--locked` (catches an unreviewed `Cargo.lock` drift) and `cargo audit` on every invocation, and CI now installs `cargo-audit` and runs the same gate per-PR instead of only via `scheduled-security.yml`'s daily cron; `SECURITY.md` added |
| §6.2 A fix and its regression test are one change | the RLN Merkle off-by-one fix (§6.3) and `valid_membership_proof_verifies` |
| §6.8 Dependency hygiene | every crate's declared dependencies are used; checked by grep audit (§6.8), no dead dependency left unresolved |
| §9 Fair claims about proof/build status | `cargo test -p novachannel-rln --release` documented as the required invocation, with the debug-mode caveat explained rather than hidden |

---

## 0. The first-principles doctrine

Reason from the mechanics, not the convention. "This is how ZK circuits are
usually built" or "everyone uses AES here" is an analogy, and analogies
import someone else's constraints along with their solution. Ask what's
actually true for *this* construction — which field it's over, what the
adversary can observe, what the composition math actually bounds — and build
from there.

### 0.1 "Impossible" is a claim you verify, not assume

When this workspace's design doc was proposed, it asked for `O(1)` ORAM and
an "MPC" primitive with no stated multi-party scenario. Both got pushed back
on with the actual reason, not a shrug:

- `O(1)` ORAM contradicts a **proven** lower bound (Goldreich-Ostrovsky):
  hiding access patterns over `n` blocks with `O(1)` client state requires
  `Ω(log n)` amortized bandwidth. `PathOram` is `O(log n)` and says so in its
  own doc comment, with the citation, instead of quietly shipping a false
  claim or silently ignoring the request.
- "MPC" with no concrete scenario was clarified into a real one — threshold
  mixnode key generation — before any code was written. A primitive without
  a stated threat model is not simplified by building it anyway.

### 0.2 Delete before you optimize; ask before you build

Applied here: the original `zkp.py` implemented a "zero-knowledge proof"
that was neither zero-knowledge in a meaningful sense nor sound — plain
modular exponentiation mod a 256-bit prime, dressed in Curve25519 constants,
logged as "Post-Quantum Ready." It was not repaired. It was deleted, along
with the rest of the Python surface (`main.py`, `api.py`, `novaq.py`, `u.py`)
once the Rust replacement covered its role. Patching a construction that
doesn't do what its comments claim is worse than replacing it, because the
patch inherits the false claims along with the bug fix.

### 0.3 Novelty requires evidence

`novachannel-rln`'s in-circuit hash (`NovaRescue`) is a new, from-scratch
permutation, not a repackaged existing one, because no published Rust
STARK-friendly hash matched this field and this framework version. That
novelty is flagged, loudly, at the top of `permutation.rs` and again in the
crate's `lib.rs`: it has not been independently cryptanalyzed, and the crate
says so rather than borrowing Rescue-Prime or Poseidon's reputation for a
construction that isn't actually either of them.

### 0.4 Say what is true

`cargo test -p novachannel-rln` **fails in debug mode** — not because the
circuit is unsound, but because winterfell's debug-only assertion demands
the *declared* transition-constraint degree exactly equal the *measured*
degree for a specific witness, and this AIR's sparse boundary-injection
columns make that measurement witness-dependent even though the declared
bound is a safe upper bound. The honest fix was documenting the mechanism
and requiring `--release`, not hiding the failure or weakening the check
that would have caught a genuine degree underestimate. See §0.5 and the
doc comment on `novachannel_rln::lib`.

### 0.5 Validate the instrument before trusting the measurement

The clearest example this workspace produced: a throwaway probe built
specifically to check whether `build_trace`'s computed Merkle root matched
the reference `MerkleTree`'s root, level by level. It found that the first
several levels matched and the last one — the actual root — didn't, which
localized a real bug (§6.3) that "the proof doesn't verify" alone would only
have said existed, not where. **When a black-box check fails, build a
white-box check before theorizing about the cause.**

---

## 1. The complexity-honesty law

**A complexity claim in this workspace is either backed by an argument or
absent.** Two places state a bound explicitly, and both cite why it can't be
beaten:

- `PathOram::access` is `O(log n)` per access — the Goldreich-Ostrovsky bound
  makes `O(1)` client-storage ORAM provably impossible, so the doc comment
  says so instead of describing the log factor as a limitation to fix later.
- STARK proof verification (`novachannel_rln::air::verify`) is polylogarithmic
  in circuit size, not constant — the crate never describes it as `O(1)`.

Where a bound genuinely is small and constant — `DummyScheduler::decide` is
one `Rng::gen_bool` call, `Sender::seal`/`Receiver::open` are one AEAD call
each — that's stated as what it is, with no larger claim implied.

### 1.1 Never claim a property the math doesn't give you

The original ask for this workspace included "give users a provable
mathematical guarantee" on send/no-send indistinguishability. `novachannel-dp`
delivers exactly that, and the crate's doc comment derives it inline rather
than asserting it:

```text
Pr[o=1 | b=1] / Pr[o=1 | b=0] = 1 / q = e^ε
Pr[o=0 | b=1] / Pr[o=0 | b=0] = 0 / (1-q) = 0 ≤ e^ε
```

Both ratios bounded by `e^ε` is the actual definition being satisfied, not a
hand-wave toward "differential privacy" as a buzzword. `sequential_epsilon`
and `advanced_composition_epsilon` are the two standard, textbook composition
bounds (basic and Dwork-Rothblum-Vadhan), not an invented in-between number.

---

## 2. The secret-handling law

Every crate that holds key material zeroizes it on drop and never lets it
reach a `Debug` implementation, a log line, or a wire message by accident.

### 2.1 Every long-lived secret has a `Drop` impl

`novachannel::identity::Identity`, `novachannel_mpc::Dealer`,
`novachannel_mpc::KeyShare`, `novachannel::kex::SharedSecret`,
`novachannel::group::{Group, WelcomeSnapshot}`, `novachannel::x3dh::SessionKeys`,
`novachannel_rln::Identity`, and `novachannel_oram::Client` all zero their
secret fields on drop. `PublicIdentity` and `HybridSignature` deliberately
implement `Debug` (they're public data); their secret-holding counterparts
deliberately don't derive it at all, so a stray `{:?}` in a log statement
fails to compile instead of leaking a scalar.

This extends past this workspace's own code: `ml-dsa`, `ml-kem`, and
`chacha20poly1305` are each built with their `zeroize` cargo feature
enabled. Without it, each crate's own `Drop` impl for its signing/
decapsulation keys and cipher state is entirely `#[cfg(feature =
"zeroize")]`-gated and doesn't exist — so a `Drop` impl on this workspace's
own wrapper struct that assumes the dependency clears its internal state
(as `identity.rs`'s comment on `impl Drop for Identity` says outright) is
only true once the feature is actually turned on in `Cargo.toml`. A rule
enforced by a test only covers this workspace's own code; verifying a
*dependency's* Cargo features actually match what a doc comment assumes
about it is not something `cargo test` can check on its own, which is why
this note exists here instead of only in the dependency's own docs.

### 2.2 Comparisons over secret-derived values use the field's own equality, not a byte-by-byte shortcut that could branch on timing

`Scalar` and `RistrettoPoint` equality (`curve25519-dalek`) and the AEAD tag
check (`chacha20poly1305`) are both constant-time by construction in their
respective crates; this workspace doesn't re-implement comparison logic that
would need its own timing audit. Where this workspace introduces its own
comparison — `PublicIdentity::eq`, used only on public data — timing safety
doesn't apply, and the doc trail (§2.1) is what marks the boundary between
"public, ordinary equality is fine" and "secret, must go through a
constant-time path."

### 2.3 A secret never has a natural home in a periodic/public wire column

`novachannel_rln::air`'s trace has both public columns (round constants,
block-boundary flags) and private ones (`sk`, sibling, selector). The AIR's
own design note (`air.rs` module doc) explains why `sk` is carried through
via a *constant private trace column*, not derived from any publicly-visible
value — the one design constraint that makes the whole nullifier scheme
sound (§4).

---

## 3. The parser-safety law

**Every function that accepts bytes from a peer returns `Result`; none of
them panic on malformed input.** A handshake message, a proof blob, and an
ORAM stash entry differ in what they hold, but not in this rule.

### 3.1 The wire reader is `Result`-first by construction

`novachannel::wire::Reader::get_fixed`/`get_var` bounds-check before every
read and return `Err(Error::Malformed(..))` rather than slicing past the end
of a buffer. Every place downstream that looks like it could panic —
`ed_bytes.try_into().unwrap()` in `identity.rs`, `seq_bytes.try_into().unwrap()`
in `transport.rs` — is unwrapping a slice whose length was *already*
guaranteed by a preceding `get_fixed(32)`/`get_fixed(8)`, not by trusting
the peer. Audited explicitly (§6.8); none of the eight `.unwrap()`/`.expect()`
call sites in `crates/*/src` are reachable with attacker-chosen bytes — the
full list and the reasoning for each is in the §6.8 entry.

### 3.2 A proving/verification entry point returns `Result`, even for "should never happen"

`novachannel_rln::air::prove` used to call `.expect("proof generation
failed")` on the underlying prover's result. Fixed to return
`Result<(Proof, PublicInputs), String>` instead: a proving hiccup on this
crate's side should degrade the one caller's request, not abort their
process. `verify` already followed this shape; `prove` didn't, and now does.
Pinned by the existing `cargo test -p novachannel-rln --release` suite still
passing after the signature change (all five tests call `prove_message`,
which now propagates the `Result`).

---

## 4. The proof-obligation law

**Every claim this workspace makes about what an adversary can't do is
backed by a test that plays the adversary.** Writing "this is bound"/"this
is hidden"/"this is rejected" in a doc comment is not the proof; the test
that tries to violate it is.

| Claim | Test that tries to break it |
| --- | --- |
| Tampering with a channel record is detected | `tampered_record_fails_to_decrypt` |
| Replaying a sealed record is detected | `replayed_record_is_rejected` |
| A forged handshake signature is rejected | `forged_signature_is_rejected` |
| A pinned peer identity mismatch is rejected | `wrong_pinned_server_identity_is_rejected` |
| A tampered STARK proof fails verification | `tampered_proof_bytes_are_rejected` |
| A proof against the wrong Merkle root fails | `wrong_root_is_rejected` |
| Two RLN messages in *different* epochs don't leak the sender's key | `messages_in_different_epochs_do_not_leak_the_key` |
| Two RLN messages in the *same* epoch **do** leak the sender's key (the rate-limit mechanism working as designed) | `two_messages_in_same_epoch_reveal_the_secret_key` |
| A tampered DKG share fails Feldman verification | `tampered_share_fails_feldman_verification` |
| A faulty dealer is identified and excluded, and honest participants still converge on one working key | `a_faulty_dealer_is_identified_and_excluded_without_aborting_the_dkg` |
| A below-threshold quorum cannot recover the shared secret | `below_threshold_quorum_does_not_recover_the_secret` |
| The dummy-traffic likelihood ratio matches the declared ε, not just in theory | `empirical_likelihood_ratio_matches_bound` |
| Any valid `t`-of-`n` FROST quorum produces a signature that verifies | `a_threshold_quorum_produces_a_signature_that_verifies`, `any_valid_quorum_produces_a_signature_that_verifies` |
| A FROST signature does not verify against a different message | `a_signature_does_not_verify_against_a_different_message` |
| A tampered FROST signature share is caught before aggregation, and identifies the signer at fault | `a_tampered_signature_share_fails_share_verification` |
| FROST signature shares and the final signature match RFC 9591's own published test vector exactly | `official_test_vector_matches_rfc9591` (§6.9) |

A new cryptographic property added to any crate needs a row here and a test
next to it before it's considered done — a property with no adversarial test
is a claim, not a guarantee.

### 4.1 Binding matters more than either half alone

`novachannel_rln`'s AIR could easily have proved "I know an `sk` that's a
tree member" and, separately, computed `a1 = Hash(sk, epoch)` outside the
circuit. That would have been strictly easier to build and strictly wrong:
nothing would force the *same* `sk` in both places, so a prover could use one
key for membership and a different one per message for the rate-limit share,
defeating the entire point of RLN (§4, `air.rs` module doc walks through why
this specific decomposition doesn't work). The harder, correct version binds
both to one constant trace column and proves them together in one STARK.

### 4.2 A new primitive earns its place by reusing what's already sound, not by duplicating it

`novachannel_mpc::frost` needed the same DKG output (`KeyShare`, Lagrange
interpolation at zero, Feldman commitment evaluation) that
`novachannel_mpc`'s threshold decryption already used. It was built as a
module *inside* that crate, sharing `lagrange_coefficient_at_zero` and a new
`evaluate_commitment` helper factored out of `verify_share` — not as a
parallel implementation with its own copy of the same math that could drift
out of sync with the original (the exact failure shape §1.4b on the server
side of this document's ancestor called out, applied here to cryptographic
arithmetic instead of a free-name-pool). Adding a "novel, current" primitive
is not exempt from that rule; if anything it's where the rule matters most,
since two independent implementations of "evaluate a Shamir polynomial at a
participant's id" that quietly disagree is a soundness bug, not a cosmetic
one.

---

## 5. The stated-limitations law

**A limitation that matters to a caller's security is documented where the
caller will read it before they rely on the API — the crate's top-level doc
comment — not in a README, changelog, or commit message they may never see.**

Current limitations, each documented in the crate that has them:

- `novachannel-rln`: the in-circuit permutation is new and uncryptanalyzed
  (§0.3). The peer-identity pinning model has no PKI/CA — trust provisioning
  is the caller's job (`novachannel::handshake` module doc).
- `novachannel-mpc`: joint-Feldman DKG is commit-then-reveal (blocks the
  rushing bias attack) and now identifies and excludes a faulty dealer
  (`identify_faulty_dealers` / `finalize_key_share_excluding_faulty`, §4)
  rather than requiring the whole run to abort. What's still not
  implemented is the *networked* broadcast/reveal exchange that mechanism
  is modeled on — this crate has no networking; it's a pure state machine,
  and computes the same decision procedure directly because every dealer's
  shares are already visible in one process. `frost` (§4.2) is verified
  against the official `FROST(ristretto255, SHA-512)` test vector from the
  CFRG `draft-irtf-cfrg-frost` repository — see §6.9 for how that
  verification actually happened and what it did and didn't confirm.
- `novachannel-oram`: the position map and stash (`Client`) are structurally
  separated from bucket storage (`ServerStorage`/`InMemoryServer`, §6.10) —
  no longer just a documented rule, a real deployment implements
  `ServerStorage` over its network transport and `Client`'s logic doesn't
  change. A server that actively tampers with, drops, or replays bucket
  contents is now detected via `VerifiableServerStorage` and
  `verified_read`/`verified_write` (§6.12) — `ServerStorage` alone (without
  the `Verifiable` variant) is still fully trusted, so callers who need
  integrity must opt into the verified path explicitly. What's still not
  covered even with verification: `Block`'s `id`/`value` travel through
  `ServerStorage` in the clear — encrypting both before they leave the
  client is the caller's job (`novachannel`'s AEAD is the natural fit),
  not something this crate does for you.
- `novachannel-dp`: the guarantee is about the presence bit only. Timing/
  latency correlation and message-size side channels are explicitly out of
  scope, stated as such rather than left for a caller to assume were covered.

### 5.1 A stray unrelated file gets excluded, not adopted

An `ENGINEERING-STANDARDS.md` from an unrelated project (a chat server) was
present in this directory before this document existed, swept up by `git add
-A`. It was unstaged rather than committed, and rewritten from scratch for
this workspace rather than reused wholesale — a standards document that
doesn't describe the actual code is worse than none, because it's read as
authoritative.

---

## 6. The regression ratchet

### 6.1 The gate

`cargo fmt --check`, `cargo clippy --workspace --all-targets --release -D
warnings`, and `cargo test --workspace --release` (RLN specifically requires
`--release`, §0.4) are what "done" means for a change in this workspace, and
`scripts/check.sh` runs exactly those steps in that order, exiting on the
first failure. `.github/workflows/ci.yml` runs that same script — not a
reimplementation of its steps in YAML, which could silently drift from what
the local script actually checks — on every push to `main` and every pull
request. Run `scripts/check.sh` locally before considering any change
finished; CI is the backstop for the case where it wasn't.

### 6.2 A fix and its regression test are one change

Every bug found this session shipped with the test that would catch it
recurring, in the same change: §6.3's off-by-one has
`valid_membership_proof_verifies` (and the other four RLN tests, all of
which depend on the same corrected block accounting) as its permanent
regression coverage.

### 6.3 A found defect becomes a sweep for its class

**The defect:** `build_trace`'s main loop ran exactly `DEPTH` "compute
rounds, then inject" cycles — one per Merkle *level* — but the Merkle chain
actually needs `DEPTH + 1` permutation blocks (one for the leaf hash, plus
one per combine step). The loop silently produced a value at
`ROOT_ROW` that was one combine short of the real root, self-consistent
within the proof but wrong relative to the reference `MerkleTree`.

**Found by** the white-box level-by-level probe in §0.5, not by inspection —
every individual piece (the injection formula, the AIR's boundary
constraints, the Merkle tree's own path/verify logic) was independently
correct, and the bug was purely in how many times the loop ran.

**The sweep, not just the instance:** every row-index constant in `air.rs`
(`A1_TRANSITION_ROW`, `A1_INPUT_ROW`, `LINEARCHECK_TRANSITION_ROW`,
`Y_ROW`) was re-derived from a single corrected `NUM_MERKLE_BLOCKS = DEPTH +
1` rather than patched individually, so the same off-by-one couldn't
reappear in a sibling constant that happened not to be covered by the probe
that found the first one.

### 6.4 Assert properties, not tautologies

`empirical_likelihood_ratio_matches_bound` asserts the *measured* ratio is
within a stated tolerance of `e^ε` — not that it's merely "close to 1" or
"nonzero," which would pass regardless of whether the calibration was
correct. A property test that would pass under a broken implementation is
not testing the property.

### 6.5 Debug-mode strictness is signal, not noise, until proven otherwise

The winterfell debug-mode degree assertion (§0.4) was investigated to a
specific root cause (sparse witness-dependent columns) before being
accepted as a false positive — not disabled or ignored on sight. A strict
check failing is evidence of *something*; the obligation is to find out
what before deciding it's the check that's wrong.

### 6.6 A stray file in the working tree is investigated before it's staged

`git add -A` picks up everything, including files this session didn't
create. `ENGINEERING-STANDARDS.md`'s original content was read in full
before any decision about it was made (§5.1) — never assume an unfamiliar
file is safe to commit, or safe to ignore, without reading it.

### 6.7 Boundaries are a place to test

- `Budget::spend_slot` returning `false` exactly at the total-budget boundary
  is covered by `budget_tracks_spend_and_refuses_overspend` (spends exactly
  to the limit, then asserts the next spend is refused).
- `PathOram`'s stash-size assertion in the heavy-workload test is a
  regression boundary on eviction correctness, not an arbitrary sanity
  number — if eviction breaks, the stash grows without bound and the
  assertion is what catches it before a caller notices from latency alone.

### 6.8 Dependency hygiene

Every crate's `Cargo.toml` was audited against actual `use` sites this
session. Finding: `novachannel-rln` declared `thiserror` and never used it
(no error type in that crate reaches for it) — removed. Every remaining
declared dependency in every crate has at least one real reference outside
its own `Cargo.toml`.

The `.unwrap()`/`.expect()`/`panic!`/`unreachable!` audit, in full:

| Site | Reachable with attacker-controlled input? | Why |
| --- | --- | --- |
| `core/transport.rs:113` | No | slice length already checked by the caller before this line |
| `core/identity.rs:61` | No | preceded by `get_fixed(32)`, which guarantees the length |
| `core/handshake.rs:63-64` | No | slicing a fixed-size local array, not peer-controlled data |
| `oram/lib.rs:149` | No | internal invariant (every stashed block was added via `access`, which always assigns a position first) — a library bug, not a network input |
| `rln/merkle.rs:45` | No | `levels` is seeded with one element before the loop that reads `.last()`; the tree is built from the application's own identity list, not parsed from untrusted bytes |
| `rln/permutation.rs:151` | No | `trace_permutation` always returns `ROUNDS + 1` non-empty fixed-size arrays by construction |
| `rln/air.rs` (`prove`) | N/A — was a library API panicking on its own internal failure, not attacker input | fixed to return `Result` (§3.2) |
| `mpc/lib.rs` (`tampered_share_fails_feldman_verification`) | No | inside `#[cfg(test)]`, not shipped code |

None of the remaining seven are attacker-reachable, but each one is listed
here specifically so a future change that makes one of those preconditions
no longer hold has a table entry to update, not a silent gap.

### 6.9 A claimed compatibility gets checked against the actual spec, not against your reading of it

`novachannel_mpc::frost` was originally built matching RFC 9591's protocol
*shape* — two rounds, domain-separated hashing, a binding factor — with
made-up domain-separation strings and a hand-guessed byte layout for
`binding_factor_input`, disclosed honestly as "not checked against the
RFC's test vectors." That disclosure was true, but it was also a stopping
point that didn't have to be one: the RFC's authors publish machine-readable
test vectors for exactly this purpose, in
`github.com/cfrg/draft-irtf-cfrg-frost` (`poc/frost-ristretto255-sha512.json`
on the `master` branch — not `main`, which doesn't exist on that repo).

Fetching them and diffing against a guessed encoding is itself a
reverse-engineering exercise: `binding_factor_input` in the vector is 192
bytes for a 4-byte message, which is only possible if two of its components
are *hashes* (fixed 64 bytes each, from SHA-512) rather than raw
concatenated data — `group_public_key(32) || H4(msg)(64) || H5(commitment_list)(64)
|| encode_identifier(32)`. Confirming `H4(msg) = SHA512(contextString ||
"msg" || msg)` (and the analogous derivation for `H1`'s binding factor and
`H5`'s commitment-list hash) meant testing candidate byte layouts against
the vector's actual bytes in a scratch Python script until one matched
exactly — the same "validate against ground truth, don't theorize from the
prose" instinct as §0.5, applied to a published spec instead of this
codebase's own output.

The result, `official_test_vector_matches_rfc9591`, hard-codes the vector's
own hex values (not a runtime fetch — a test shouldn't depend on network
access or an upstream repository staying reachable) and checks this crate's
`round2_sign`/`aggregate`/`verify` reproduce the vector's `sig_share`s and
final signature exactly. It does — on the first attempt after the encoding
was corrected, which is itself informative: once the byte layout is
actually right, the surrounding protocol logic (Lagrange coefficients,
challenge computation, aggregation) needed no further changes, because
that logic was never what was wrong. The one part of the RFC intentionally
still not matched — `nonce_generate`'s deterministic seed-to-nonce
derivation — is scoped out explicitly in the module doc, with the reason
(this crate draws nonces from a CSPRNG instead, a valid but not
byte-identical instantiation) stated next to the claim it qualifies, not
left for a reader to discover by noticing a missing function.

### 6.10 A structural invariant beats a documented rule

`novachannel-oram` originally stated, correctly, that the position map and
stash must never be colocated with server-visible bucket storage in a real
deployment — and then defined exactly one struct holding all three fields
together, relying on a reader to keep the rule in mind while extending it.
That's the same shape as this document's ancestor's §5.11 ("release in a
wrapper, not at every exit"): a rule that must be *remembered* is a rule a
future change can violate by adding one field in the wrong place, and
nothing catches it.

The fix was the split already planned in the original doc comment: `Client`
(secret state — position map, stash) drives an arbitrary `ServerStorage`
trait implementation (bucket storage) rather than owning buckets directly.
`PathOram<V>` is now a type alias for `Client<V, InMemoryServer<V>>`, so
every existing caller and test kept working unchanged — the split is
additive, not a breaking rewrite. `client_works_unchanged_against_a_different_server_impl`
is the test that makes this a checked claim rather than an assertion: it
builds a second, independent `ServerStorage` (`CountingServer`, wrapping
`InMemoryServer` with access counters) and runs the exact same read/write
workload as the other tests directly through `Client`, with zero changes
to `Client`'s own code. If a future change accidentally re-coupled `Client`
to `InMemoryServer` specifically, that test — not just the type signature
— would catch it.

What the split does *not* claim to fix: `Block`'s `id` and `value` still
cross the `ServerStorage` boundary in the clear. A trait boundary enforces
*which secret state* the server never sees (positions, stash membership);
it says nothing about the *content* of what does cross it, which stays the
caller's responsibility exactly as documented in §5.

### 6.11 A dependency upgrade is checked against real API compatibility before it's claimed

`novachannel` (core) and `novachannel-mpc` moved to a coordinated set of
newer major versions: `pqcrypto-kyber`/`pqcrypto-dilithium` (C/PQClean
wrappers around the pre-standardization NIST round-3 submissions) replaced
by RustCrypto's `ml-kem`/`ml-dsa` — pure Rust, implementing the algorithms
NIST actually ratified as FIPS 203/204 in 2024, not an earlier draft —
alongside `curve25519-dalek` 4→5, `ed25519-dalek`/`x25519-dalek` 2→3, and
`chacha20poly1305` 0.10→0.11.

**Checked before committing to it, not after:** before touching any crate
source, a throwaway probe crate (`/tmp/mlkem_probe`, deleted once the real
migration compiled) confirmed the whole coordinated dependency set actually
builds *together* — these crates jointly moved from `rand_core` 0.6 to 0.10,
which dropped the familiar `OsRng` type entirely in favor of `getrandom`'s
`SysRng` wrapped in `UnwrapErr`. Discovering that incompatibility inside the
real crate, mid-refactor, would have meant partially-migrated code in a
broken state; discovering it in a probe cost one throwaway `cargo build`.
Same instinct as §0.5 applied to a dependency graph instead of a runtime
behavior: validate the thing you're about to depend on before restructuring
around it.

**The wire format changed, and that's stated as a breaking change, not
hidden as an implementation detail** — `novachannel`'s crate-level doc
comment says so explicitly, because a caller who persisted or transmitted
bytes produced by the old `pqcrypto`-based encoding cannot read them with
this version, and pretending otherwise would be exactly the kind of false
claim §0.4 exists to prevent.

**One genuinely dead dependency turned up during the migration**:
`signature = "3"` was added to `novachannel`'s `Cargo.toml` because ml-dsa's
types implement the `signature` crate's traits — but every actual use goes
through `ml_dsa::signature::...`'s re-export, so the direct dependency
declaration was never referenced. Removed per §6.8's standing rule, caught
by the same grep audit, not a one-time exception for this change.

All 26 tests across the workspace — including
`official_test_vector_matches_rfc9591`, which depends on
`curve25519-dalek`'s exact canonical scalar byte encoding — still pass
after the version bump, which is itself a check that the upgrade didn't
silently change wire-visible behavior anywhere it wasn't supposed to.

### 6.12 Verifiable ORAM: a second real bug, found the same way as the first

`novachannel-oram`'s own limitations list said, correctly, that
`ServerStorage` is fully trusted — a malicious server could tamper with
bucket contents undetected. `VerifiableServerStorage` closes that: a
Merkle hash tree over the same binary tree Path ORAM already uses, so
verifying a path costs nothing beyond what an access already touches.
`Client` keeps only a 32-byte root (not secret — its job is to be checked,
not hidden).

**A real defect, found by the same method as §6.3's RLN bug**: the
write-back loop stored `hash_bucket(contents)` — the *raw* bucket-content
hash — as each node's Merkle hash, instead of the properly combined
`hash_node(bucket_hash, left, right)`. Every honest access after the first
failed its own integrity check, because the sibling hashes a later access
read back from the server were the wrong value for every node except a
tree's deepest level (where the bug's missing wrap and the correct formula
happen to diverge less). Found the same way §3.3/§6.3 found the RLN
off-by-one: not by reading the code, but by building a minimal
two-access reproduction and printing every intermediate hash, which showed
`hash[1] == hash[3]` — two nodes with different children and different
bucket contents, sharing one hash value, which is exactly what "the code
is throwing away the tree structure" looks like from the outside. Fixed by
making the recompute function return every node's *combined* hash, not
just the final root, so the write-back loop has the right value to store
for every node on the path, not only the one at the root.

Two adversarial tests pin the actual property, not just "does it round
trip": `a_server_that_tampers_with_a_bucket_is_caught` corrupts a bucket
directly, bypassing `Client` entirely; `a_server_that_replays_a_stale_bucket_is_caught`
feeds back a bucket that was *itself* valid at an earlier point in time —
the harder case, since a naive "is this bucket well-formed" check would
miss a stale-but-internally-consistent replay, and only a root comparison
catches it.

### 6.13 Composing two crates needs no coupling if the interface is bytes

`novachannel-rln` proves anonymous, rate-limited membership against a
Merkle root, but says nothing about how a client comes to trust that a
given root is the real, current membership set rather than one an
attacker fabricated. `novachannel-mpc` already has a `t`-of-`n` mixnode
quorum capable of jointly signing via FROST. Composing them — the quorum
attests to the current root — needed no new dependency edge between the
two crates' real `[dependencies]`: `MerkleTree::root_bytes()` returns an
opaque byte string, FROST's `sign`/`verify` already take an opaque
`&[u8]` message, and the only place the two crates' names appear together
is a `[dev-dependencies]` edge scoped to one integration test
(`crates/mpc/tests/frost_signs_rln_root.rs`). Neither crate's public API
changed shape to accommodate the other. This is the same instinct as
§4.2's "reuse what's already sound instead of duplicating it," pointed the
other direction: two already-sound pieces composed through their existing
narrow interfaces, not merged into one wider one.

Three tests, not one: the happy path (a quorum's attestation verifies
against the root it actually signed), the binding property (it does *not*
verify against a different root — the attestation isn't just "a valid
mixnode signature," it's a signature *of this specific root*), and the
threshold property checked in this new context rather than assumed from
the DKG-level test that already covers it elsewhere (a below-threshold
quorum's aggregate does not verify) — signing and decryption are different
code paths through the same key material, so the property needed its own
check here.

### 6.14 A one-time audit became a standing lint, on evidence from libsignal

`crates/*/src` had already been through the `.unwrap()` audit in §6.8 —
correct, but a one-time, human-run check that a future change could
silently invalidate by adding a new unguarded `.unwrap()` nobody re-audits
for. Checked against `signalapp/libsignal`'s actual crate roots (fetched
directly, not recalled) rather than assumed as generic best practice:
`libsignal-protocol` and `zkgroup` both carry
`#![warn(clippy::unwrap_used)]` and `#![deny(unsafe_code)]`. Adopted
verbatim in every crate here — `deny(unsafe_code)` costs nothing (this
workspace already had zero `unsafe` blocks; the lint just forecloses ever
adding one silently), and the nine non-test `.unwrap()` sites the
`unwrap_used` lint found were converted to `.expect("reason")`, with test
code exempted via `#![cfg_attr(test, allow(clippy::unwrap_used))]` since
`.unwrap()` on a value a test just constructed is normal, not a smell.
This is the same instinct as §6.10's ORAM split, sourced this time from an
external, heavily-audited codebase instead of derived internally: **prefer
a structure the compiler enforces over a rule that has to be
re-remembered** — a docstring in §6.8 saying "we checked this" doesn't
survive the next PR the way a lint does.

`docs/LIBSIGNAL_COMPARISON.md` has the full comparison, including what
didn't get adopted and why: Signal's own PQXDH independently validates
this workspace's hybrid-KEX design (§6.11); their Sigma-protocol-based
`zkgroup`/`poksho` is a genuine, considered alternative to
`novachannel-rln`'s STARK that wasn't converged on because it's
discrete-log-based, not post-quantum; and their production ratchet now
depends on a dedicated post-quantum ratchet crate
(`SparsePostQuantumRatchet`), which surfaces a real, precisely-scoped gap
this workspace doesn't close — `novachannel`'s handshake is PQ-hybrid once,
at session start, with no ongoing re-keying, so there is no
post-compromise security within a session. Left open rather than patched
with something smaller than the real problem.

### 6.15 The ratchet gap from §6.14, closed with an explicitly bounded scope

§6.14 left "no post-compromise security within a session" open rather than
closing it with a hand-wave. Closing it properly meant reading SPQR's real
source before writing anything — not just its README. Fetched directly:
`src/v1/unchunked/send_ek.rs` and its siblings, which showed the actual
mechanism is `incremental_mlkem768`, a from-scratch re-encoding of
ML-KEM-768 that splits the encapsulation key and ciphertext into a
`header`/`ek`/`ct1`/`ct2` sequence sent across an explicit
`KeysUnsampled -> HeaderSent -> EkSent -> EkSentCt1Received` state machine
(with Reed-Solomon erasure coding layered on top in `src/v1/chunked/`),
machine-verified with `hax_lib`/F* refinement types and separate ProVerif
models. That is not a mechanism this workspace can responsibly clone from
one source read — it is a from-scratch cryptographic re-engineering of a
NIST-standardized primitive, verified with tooling this workspace does not
have wired up anywhere.

So `crates/core/src/ratchet.rs` does not attempt it. It builds the same two
named properties — forward secrecy, post-compromise security — through a
mechanism sized to what could actually be checked here:

- **Per-message forward secrecy**: an HMAC-SHA256 hash chain
  (`ChainKey::advance`) yields a fresh, single-use AEAD key per record,
  discarded immediately after use. `each_message_is_sealed_under_a_different_key`
  proves the chain is actually advancing, not silently reusing one key.
- **Post-compromise security**: `initiate_ratchet` re-runs the *existing*,
  already-tested hybrid X25519 + ML-KEM-1024 exchange from `kex.rs`
  mid-session — one full KEM payload each way, not SPQR's incrementally
  chunked one — and mixes the fresh shared secret into a new root key via
  HKDF, exactly mirroring `handshake::finalize_keys`'s own derivation
  shape. `keys_before_and_after_a_ratchet_are_independent` and
  `a_ratchet_step_produces_a_fresh_epoch_both_sides_agree_on` cover this.

Building it surfaced one more real design subtlety, caught the same way
every other defect in this document was: writing the test before trusting
the design. The responder switches to the new epoch the instant it sends
its step-2 reply, but the initiator only switches once it *receives* that
reply — so an application message the initiator sent while the reply was
still in flight arrives at the responder tagged with the *old* epoch, after
the responder has already moved on. Retaining exactly one prior epoch's
receive chain (deliberately mirroring SPQR's own
`EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH = 1` constant, seen in `src/chain.rs`,
as evidence this is the right *shape* of fix rather than an arbitrary
choice) resolves it; `messages_in_flight_before_the_ratchet_reply_still_open_via_the_previous_epoch`
is the regression test, and `a_record_from_an_epoch_older_than_the_retained_previous_one_is_rejected`
confirms the retention is bounded, not unbounded.

Writing the tests also caught two bugs in the tests themselves, not the
code: three tests initially withheld a sealed record from the peer (to set
up a "stale" or "before" comparison) while continuing to call `seal`/`open`
on the same session — which deadlocks under this module's own documented
in-order-delivery contract, since a withheld record permanently blocks
every record after it, ratchet control messages included. The fix was
delivering each record before using its bytes for comparison, not
loosening the module — the in-order requirement is not a bug, it's a
scope decision made explicit in the module's own doc comment: this module
does not attempt SPQR's out-of-order tolerance, and a test that assumes
otherwise is testing the wrong contract.

Concurrent ratchet initiation (both peers calling `initiate_ratchet` before
seeing the other's step) is explicitly rejected with
`Error::RatchetInProgress` rather than resolved automatically — resolving
it would need a tie-breaking rule (e.g. "lower identity key wins"), which
is a real protocol decision this change does not make on the caller's
behalf. `concurrent_initiation_from_both_sides_is_rejected_not_silently_corrupted`
is the test that keeps this an explicit error instead of silent epoch
divergence.

### 6.16 Chasing line coverage found real gaps and one real dead function

Measured with `cargo tarpaulin` rather than assumed: before this pass, the
non-`novachannel-rln` crates sat around 77–98% line coverage and
`novachannel-rln` itself (measured separately, `--release`, per the
winterfell debug-mode quirk in §6.5) was as low as 10% on `merkle.rs`.
**Literal 100% was explicitly not the target** — a real share of the
uncovered lines were `.expect("reason")` branches on invariants meant to
be unreachable (the entire point of the `unwrap_used` audit in §6.14 is
that they *stay* unreachable), and driving those to green would mean
either deleting the safety net or writing a test that deliberately breaks
an invariant just to paint a line — worse than leaving it uncovered and
documented. The target was closing every *genuinely reachable* gap.

That turned up one real defect in the codebase itself, not just in test
coverage: `permutation::hash2` was a byte-for-byte duplicate of
`compress2` with zero call sites anywhere in the crate — dead code that
existed only because nothing had ever needed a differently-named alias
it was written for. Per §6.8's dependency-hygiene standard, it was
deleted rather than given a hollow test just to close the line-coverage
gap it caused.

It also turned up a few real untested branches, closed with direct tests
rather than only end-to-end ones: `MerkleTree::verify_path` (a reference
Merkle-path verifier that was written, documented as "used in tests," and
then never actually called by any test); `share::recover_secret`'s
degenerate same-`x` branch (the division-by-zero guard, distinct from the
already-tested different-nullifier branch); several malformed/trailing-
bytes parser branches in `handshake.rs` and `ratchet.rs` that no
successful protocol run ever exercises, reached with hand-crafted
malformed messages; and `transport.rs`'s ordinary in-order-message path,
which — surprisingly — no existing test had exercised directly, since
every prior transport test sent exactly one message per direction or
deliberately reordered two.

Four of `ratchet.rs`'s branches (an empty decrypted payload, an
unrecognized message type, trailing bytes inside a ratchet-control
payload, a step-2 reply tagged with the wrong pending epoch) are not
reachable through the public protocol at all — every real caller of
`seal`/`initiate_ratchet` only ever produces well-formed messages, so
these are true defense-in-depth branches, not just hard to trigger.
Reaching them for a test needs the same private `seal_payload` the public
methods use internally, or in the epoch-mismatch case, calling the
private `handle_step2` directly with a fabricated epoch — both done from
a `#[cfg(test)] mod tests` nested inside `ratchet.rs` itself (Rust's
privacy rules give a descendant module access to its parent's private
items), rather than weakening those methods' visibility just to make them
testable from the public integration-test crate.

One measurement caveat worth recording rather than hiding: `tarpaulin`'s
line attribution for `novachannel-rln`'s `lib.rs` and `air.rs` remains
low (33% and 80%) even after this pass, despite `tests/rln.rs`'s five
tests calling every public function in `lib.rs` and, transitively, every
trait method in `air.rs`'s `Air`/`Prover` implementations, on every run.
Manual review of both files found no remaining conditional branch that
isn't already forced by an existing test — `verify_message`'s one
`if` (wrong root) is covered by `wrong_root_is_rejected`, and its only
other failure path (a STARK proof that fails to verify) is covered by
`tampered_proof_bytes_are_rejected`. The likely cause is release-mode
inlining: this crate can only be tested with `cargo test --release`
(§6.5), and LLVM's coverage instrumentation is well known to under-attribute
hits back to source lines for short functions aggressively inlined at
their call sites — visible directly in this workspace by comparing two
different tarpaulin runs of the same `lib.rs` that report different,
only-partially-overlapping "covered" line sets depending on what else was
compiled alongside it. Recorded here rather than either quietly accepted
as a real gap or hidden by writing tests to satisfy a number that may not
reflect real coverage.

Final state: 86 tests (up from 49), full `scripts/check.sh` green.

**Coverage exemptions, applied narrowly.** Tarpaulin supports
`#[cfg(not(tarpaulin_include))]` (declared in `[workspace.lints.rust]` in
the root `Cargo.toml`, since it isn't a real cfg rustc knows about — it's a
marker tarpaulin's own reporter parses, which is why it needs a
`check-cfg` allowlist entry to avoid an `unexpected_cfgs` warning under
`-D warnings`, and why it changes nothing about what compiles or runs).
It only excludes whole *items*, not individual lines within a function —
which doesn't fit this codebase's actual pattern of inline `.expect()`
calls, and after this pass there's little left in `core`/`dp`/`mpc`/`oram`
that's genuinely unreachable rather than already tested. The one clean
match: `crates/core/tests/ratchet.rs`'s `expect_application` test helper
had a `panic!` arm that only fires if a test itself asserts the wrong
`Opened` variant — never in a passing suite. Split into its own
`wrong_variant() -> !` function tagged `#[cfg(not(tarpaulin_include))]` so
the exclusion targets exactly that, without also hiding
`expect_application`'s real (and genuinely exercised) success path.

Two things were deliberately *not* exempted, because doing so would be
dishonest rather than accurate:

- `novachannel-rln`'s `air.rs`/`lib.rs` numbers, still low under
  `--release` — that code **is** exercised by `tests/rln.rs` on every run;
  tarpaulin just under-attributes it due to release-mode inlining (see
  above). Marking it `tarpaulin_include`-excluded would misrepresent
  tested code as "decided untestable," the opposite of what the exclusion
  is for.
- The match-arm *dispatch line* itself (`=> wrong_variant()`) still shows
  as uncovered even after the split — hiding the panic's body doesn't
  hide the fact that this branch was never taken, and it shouldn't: "this
  branch never executed" is true, real information whether the branch
  exists by design or by accident, and no coverage tool should erase it.

---

### 6.17 X3DH, sealed sender, Sesame-style multi-device, and an incremental erasure-coded ratchet

Four additions, each landed as its own additive module rather than a
change to already-tested code, each following this document's existing
patterns rather than inventing new ones:

- `crates/core/src/{prekey,x3dh}.rs`: an asynchronous, deniable
  alternative to `handshake.rs`'s live 3-message exchange, following
  X3DH/PQXDH's own design (`docs/SYSTEMIZATION.md` §4.2). Produces the
  same `EstablishedSession` type `handshake.rs` does — proven directly by
  `crates/core/tests/x3dh.rs::established_session_plugs_into_the_ratchet_unmodified`,
  which runs a full `crate::ratchet` session (application message *and* a
  real ratchet step) over an X3DH-established pair, not just asserted
  from the type signature matching.
- `crates/core/src/sealed_sender.rs`: a one-shot envelope hiding sender
  identity from a relay, modeled on Signal's own sealed sender
  (`docs/SYSTEMIZATION.md` §4.3). `SenderCertificate::verify` is a
  separate step from `open` deliberately — the relay never learns enough
  to check it either way, so pretending `open` could validate trust would
  misstate what the function actually does.
- `crates/core/src/multidevice.rs`: Sesame-style fan-out/fan-in across an
  account's devices (`docs/SYSTEMIZATION.md` §4.4).
  `two_peer_accounts_sending_to_the_same_receiving_device_stay_isolated`
  is the sharper of its tests: two different senders' sessions to the
  same physical device, keyed only by (sender identity, local device id),
  must never cross-contaminate even when both use the same `DeviceId`
  value locally — checked by actually decrypting each and asserting the
  right plaintext comes back, not just checking the sessions are distinct
  objects.
- `crates/core/src/erasure.rs` + `ratchet.rs`'s
  `initiate_incremental_ratchet`/`open_ratchet_chunk`: a from-scratch
  Cauchy-Reed-Solomon-style erasure code (§0.3's "novelty requires
  evidence" standard applies here exactly as it does to `NovaRescue` —
  flagged as unvetted in the module's own doc, not presented as
  equivalent to a reviewed erasure-coding library) used to split a
  re-key into loss-tolerant chunks, narrowing (not closing) the gap to
  SPQR's chunked design named in `docs/LIBSIGNAL_COMPARISON.md` §3.

**Two real defects found building the incremental ratchet, both by
testing the actual property rather than a synthetic case chosen to avoid
the bug:**

1. **Strict ordering is fundamentally incompatible with chunk-level loss
   tolerance, and the first implementation attempt didn't notice until a
   test caught it.** The first version routed each chunk through
   `RatchetedSession::seal_payload`/`open_on` — the same strict,
   gapless, per-record sequence `ratchet.rs`'s own module docs already
   require or reordering/loss is intolerable. Delivering chunks
   out of order, or dropping any of them, immediately produced
   `Error::Replay` or left the chain permanently desynced — not a subtle
   bug, but one the initial design didn't surface until
   `chunk_arrival_order_does_not_matter` and
   `tolerates_losing_up_to_parity_shards_chunks_in_either_direction`
   were written and failed. The fix was architectural, not a patch: each
   incremental-ratchet chunk now carries its own AEAD authentication,
   keyed by HKDF over the session's current `root_key` (a value both
   peers already agree on) mixed with a fresh random per-attempt nonce,
   entirely independent of `seal`/`open`'s sequence numbers. This is the
   same class of finding as §3.3/§6.3's Merkle off-by-one and §6.12's
   ORAM write-back bug: a black-box symptom (`Replay`/desync) that only
   pointed at *something* being wrong, root-caused by building the
   thing that actually needed building (an independent chunk-auth
   mechanism) rather than patching the symptom (e.g., loosening the
   replay window, which would have reintroduced exactly the kind of
   silent-wrongness risk this document's whole premise warns against).
2. **A stale-root-key bug on chunks arriving after reconstruction already
   completed.** Once the redesigned chunk-auth mechanism was in place,
   `full_round_trip_with_no_losses` — delivering *every* chunk, including
   the `parity_shards` worth beyond the `data_shards` actually needed —
   still failed with `Error::Decrypt`, while a test that dropped exactly
   two chunks passed. The two facts together localized it: reconstruction
   completes and the epoch advances (changing `root_key`) as soon as
   `data_shards` chunks arrive, but the remaining, already-in-flight
   chunks from that same attempt can still show up afterward; deriving
   *their* chunk key from the now-changed `root_key` produced the wrong
   key, not a forged-ciphertext failure. Fixed by recording the most
   recently *completed* attempt's nonce per direction
   (`last_completed_step1_attempt`/`last_completed_step2_attempt`) and
   short-circuiting a straggler matching it before attempting to derive
   any key at all, rather than letting it fall through to a decrypt
   attempt that was always going to fail. Regression test:
   `straggler_chunks_after_completion_are_ignored_not_treated_as_decrypt_failures`,
   which specifically delivers the full, undiminished 7-chunk set rather
   than a loss pattern that would avoid the bug by construction — the
   same "assert the full property, not a convenient case of it" standard
   §6.4 already states.

Final state after this section: 126 tests (up from 86), full
`scripts/check.sh` green.

---

### 6.18 Closing `crate::multidevice`'s named gap: a signed, version-authenticated device list

`docs/SYSTEMIZATION.md` §4.4 and `docs/LIBSIGNAL_COMPARISON.md`'s
production-readiness list both named the same real gap when
`crate::multidevice` first landed: `RemoteAccount` was assembled by the
caller and trusted as given, with nothing stopping a MITM controlling
wherever bundles are fetched from injecting a device the account owner
never added. Closed the same way this document's own doctrine says to
close a named gap — properly, not with a hand-wave — by adding exactly
the authority the earlier design was missing:

- **`SignedDeviceList`**: the *account's* long-term signing `Identity`
  (never any one device's — mirrors the real distinction between "this
  person" and "this person's phone") signs a versioned list of `(device
  id, identity, DH identity)` triples. `RemoteAccount::from_signed_device_list`
  verifies that signature, then checks every supplied `PreKeyBundle`'s
  identity and DH identity actually match what the list authorizes for
  its device id — `a_bundle_not_matching_the_signed_list_is_rejected`
  and `a_bundle_for_a_device_id_absent_from_the_list_is_rejected` both
  simulate exactly the injection this gap allowed, checked against the
  actual rejection, not just against the signature check existing in
  isolation.
- **Rollback protection**: a signature alone doesn't stop a MITM from
  replaying an *older*, genuinely-signed list to hide a revocation or
  resurrect a removed device — the classic version-rollback attack every
  signed-list scheme needs to account for.
  `MultiDeviceSession::sync_from_signed_device_list` tracks the highest
  `version` it has accepted per account and rejects anything not
  strictly greater, checked directly by `stale_device_list_version_is_rejected`
  against both a replay of the same version and an older one — not
  merely asserted as "versions must increase" in a doc comment (§4's
  "the test that tries to break it" standard, applied here).
- **Automatic revocation on a newer list**: a device dropped from a
  newer, validly-signed list has its session removed the moment that
  list is processed, rather than requiring a separate explicit
  `revoke_device` call the caller might forget —
  `a_device_removed_from_a_newer_list_has_its_session_revoked` checks
  this directly by fanning out after the revoking sync and confirming
  the dropped device's id is genuinely gone from both `has_device` and
  the fan-out set, not just that the call didn't error.

What this does *not* do, stated per §5's standard rather than left
implicit: this crate still has no directory service, so *fetching* a
`SignedDeviceList` and deciding which account key to trust as its signer
in the first place remain entirely the caller's problem — the same scope
boundary `crate::handshake` already draws for peer-identity provisioning.
`RemoteAccount::new`/`add_device` also remain available fully
unauthenticated; a caller that uses them instead of the signed path is
opting out of this protection, not exposed to a defect in it.

Final state after this section: 132 tests (up from 126), full
`scripts/check.sh` green.

---

### 6.19 Dependency currency: zero vulnerabilities, every direct dependency bumped to its latest major where feasible

Checked against both sources, not just one: `cargo audit` against the
full RustSec advisory database (1189 advisories) found zero
vulnerabilities, zero unmaintained crates, zero unsound crates, and zero
yanked versions across all resolved dependencies — and GitHub's
Dependabot API (`gh api repos/.../dependabot/alerts`) confirmed zero
*open* alerts directly, independent of what's checked out locally.

Beyond vulnerabilities, every direct dependency pinned to an older major
than what's published was bumped where the resulting breakage was small
enough to fix and verify in this pass: `thiserror` 1→2 (no source changes
needed), `rand`/`rand_chacha` 0.8/0.3→0.10 (source changes: `Rng` split
into a base trait plus the `RngExt` extension trait that now hosts
`random_bool`/`random_range` — renamed from `gen_bool`/`gen_range` —
`thread_rng()` renamed to `rng()`, and the old `RngCore` trait's methods
moved onto the renamed base `Rng` trait), and `sha2`/`hkdf`/`hmac`
0.10/0.12/0.12→0.11/0.13/0.13 (source change: `Hmac::new_from_slice`
needs `hmac::KeyInit` explicitly in scope in the new major, where it
previously resolved without it).

**One test's assumption broke, and it was the test's assumption that was
stale, not the code — checked, not just asserted, per §0's doctrine.**
`a_server_that_replays_a_stale_bucket_is_caught` (`crates/oram/src/lib.rs`,
§6.12) hardcoded `ChaCha20Rng::seed_from_u64(13)` to force a specific
scenario: the root bucket (node 1, on *every* access's path) must
actually change contents between two writes, so restoring a snapshot of
it afterward is a genuine tamper, not a no-op. `rand_chacha` 0.10 changed
`seed_from_u64`'s internal seed-expansion algorithm from 0.3's — a
documented, intentional upstream change, not a bug in either version —
so seed 13 no longer produces that scenario: the two writes end up
leaving the root bucket in the *same* state, making the "replay" a no-op
and the test fail (`Ok(Some(...))`, not the expected `Err(IntegrityError)`).
The fix was not to loosen the assertion — it was to find a seed that
still produces the real scenario, the same "validate the instrument"
habit §0.5 already prescribes: a throwaway probe (`crates/oram` test,
deleted after use) swept seeds 0..200 checking which ones actually change
the root bucket's block-id set between the two writes, found seed 127,
and the test now uses it with a comment explaining *why* the seed value
is load-bearing — so a future dependency bump that breaks it again gets
found by re-running the same probe, not by guessing.

`cargo update --dry-run --verbose` after this pass: every dependency
this workspace can control is at its latest compatible version; the one
remaining entry (`generic-array` 0.14.7, available 0.14.9) is a transitive
dependency of crates this workspace doesn't declare a direct requirement
on, so there is no `Cargo.toml` line here to bump — it updates
automatically once whatever pulls it in raises its own requirement.

Final state after this section: 104 resolved crate dependencies (down
from 107 — the version bumps consolidated some previously-duplicated
versions in the tree), full `scripts/check.sh` green, `cargo audit` clean.
