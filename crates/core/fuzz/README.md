# Fuzz targets

Eight [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) harnesses, one
per untrusted-input parsing boundary in this crate — the places a real
deployment would feed attacker-controlled bytes into a parser before any
authentication has happened:

- `prekey_bundle` — `PreKeyBundle::from_bytes` (a bundle fetched from an
  untrusted directory service).
- `x3dh_respond` — `x3dh::respond` against a real responder's key
  material (an async init message can arrive from anyone).
- `sealed_sender_open` — `sealed_sender::open` against a real recipient
  key.
- `handshake_messages` — both `handshake::responder_respond`'s msg1
  parsing and `InitiatorHandshakeState::complete`'s msg2 parsing.
- `ratchet_open` — `RatchetedSession::open` and `open_ratchet_chunk`
  (plain records and the erasure-coded incremental-ratchet chunk format),
  against a real completed handshake.
- `group_commit` — `Commit`/`Welcome` byte parsing, and, when a `Commit`
  happens to parse, `Group::apply_commit` against a real single-member
  group.
- `rln_verify` — `novachannel_rln::Message::from_proof_bytes` +
  `air::verify` (the RLN STARK proof verifier), against a real proof
  generated once offline (see that target's doc comment for why: proving
  live inside the fuzz binary hits a winterfell debug-assertion quirk
  `novachannel-rln`'s own module docs already warn about).
- `mpc_frost_verify` — decodes fuzzed bytes into a `RistrettoPoint`/
  `Scalar` FROST signature and calls `novachannel_mpc::frost::verify`;
  `novachannel-mpc` does no wire framing of its own (see its module docs),
  so this fuzzes the decode-then-verify shape any real transport layer
  would have.

Each target builds fresh key material every iteration rather than reusing
state across runs, so a successful parse on one input never changes how a
later input is handled (important for `x3dh_respond` in particular, since
`OneTimePreKeyStore::take` is one-shot).

This is a standalone crate (its own `[workspace]`, own `Cargo.lock`) so it
stays out of the main workspace's stable-toolchain build/test/clippy runs
— `cargo-fuzz` needs nightly for its sanitizer instrumentation.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run prekey_bundle          # or any target above
```

Add `-- -max_total_time=60` (or `-runs=N`) to bound a run; omit it to fuzz
until interrupted. A crash writes a reproducer to `artifacts/<target>/`
and cargo-fuzz prints the exact re-run command — check that file in as a
regression test (a new `fuzz_target!` input, or a `#[test]` in the main
crate replaying the same bytes) rather than just fixing the bug and
discarding it.

`cargo +nightly fuzz run <target> -- -help=1` lists libFuzzer's own flags
(corpus minimization, coverage reports, dictionaries, etc.).

## `catch_unwind`-based fixes and this fuzz harness's own blind spot

`cargo fuzz` builds with ASan/libFuzzer instrumentation, which forces
`panic = "abort"` regardless of the crate under test's own profile
settings — needed for the sanitizer to treat a panic as a reportable crash
at all. That means a `std::panic::catch_unwind`-based fix (like
`novachannel_rln::Message::from_proof_bytes`, added after `rln_verify`
found a real panic in winterfell's proof deserializer) can never make the
*fuzz binary itself* stop reporting that input as a crash — the process
aborts before `catch_unwind` ever gets a chance to run, even though the
exact same code correctly returns `Err` in a normal (unwind-enabled)
`cargo build`/`cargo test`. Don't take a fuzz target "still crashing" on a
previously-fixed input as evidence the fix didn't work; verify the fix
against a normal build instead (a `#[test]` replaying the same bytes, per
the workflow above — see `crates/rln/tests/rln.rs`'s two
`..._is_rejected_cleanly` tests for the pattern). The fuzz target remains
exactly as useful for what it's actually for: finding new
panic-triggering inputs in an untrusted-input parser, one crash-file at a
time, regardless of whether the library under test catches them.

## Status

All eight targets have been smoke-tested (a few seconds to low tens of
seconds each, on the order of 10^3–10^6 executions depending on how
expensive that target's per-iteration setup is) with zero crashes found
beyond the ones `rln_verify` keeps finding in `winterfell`'s own proof
deserializer (§3.3/§6.22 — each one handled by `catch_unwind` and
regression-tested against a normal build, per the section above; a third
such input, `[0xc1, 0x3b, 0xf5, 0xcc]`, came out of the run below). That
target no longer feeds raw bytes to the deserializer at all — see §6.31
and the target's own module docs for why keeping that path made the
binary abort on startup and explore nothing.

Re-run after the `ENGINEERING-STANDARDS.md` §6.29 fixes, 75 seconds per
target: `prekey_bundle` 11.4M execs, `group_commit` 1.9M, `mpc_frost_verify`
39K, `handshake_messages` 28K, `x3dh_respond` 1.8K, `sealed_sender_open`
1.6K, `ratchet_open` 644 — no crashes in any of them.

Those numbers are superseded, and the reason is the most useful thing in
this file. `rln_verify` turned out to have embedded a genuine proof
specifically so it could get past the deserializer, never used it, and
spent its entire life fuzzing four bytes of `Proof::from_bytes` — its
whole corpus was two-to-four byte inputs (§6.31). Checking the *other*
targets' coverage rather than their exec counts found the same problem in
several more, in two different shapes.

**Targets that never reached their parser.** `prekey_bundle` and
`group_commit` build nothing per iteration, so their coverage was an
honest measure — and it was 185 and 69 edges, after 11.4 million and 1.9
million executions respectively. Both bounce off a length or signature
check in the first field. Splicing fixed both.

**Targets whose coverage was mostly key generation.**
`handshake_messages`, `x3dh_respond`, `sealed_sender_open` and
`ratchet_open` generated fresh ML-DSA-87 identities (and, for
`ratchet_open`, a complete three-message handshake) on *every* iteration.
That made them slow — `ratchet_open` managed eight executions a second —
and it inflated the coverage figure that was supposed to show the parser
was being reached, since key generation lights up hundreds of edges
whatever the input is. Caching that setup makes the coverage number
*drop* while the target does far more real work; the lower number is the
honest one.

| target | edges before | edges after | executions before | executions after |
| --- | --- | --- | --- | --- |
| `rln_verify` | 84 | 2041 | — | — |
| `group_commit` | 69 | 3735 | 1.9M | — |
| `prekey_bundle` | 185 | 2410 | 11.4M | — |
| `handshake_messages` | 1360 | 2116 | 27.5K | 75.5K |
| `ratchet_open` | 2878 | 1514 | 644 | 2.54M |
| `sealed_sender_open` | 1837 | 1145 | 1.6K | 488K |
| `x3dh_respond` | 1876 | 1680 | 1.8K | 169K |

(Before/after runs are 75-180s each; executions for the first three were
not comparable across the change.) No crashes in any of them after the
rework.

**The lesson, not the numbers: a target that runs clean may be running
clean over almost nothing.** Exec count measures how fast the harness
loops, not how much of the parser it reaches, and the two can move in
opposite directions. When adding or reviewing a target here, check what
it covers and what fraction of that is setup rather than the code under
test — and if the code under test sits behind a length check, a
signature, or an AEAD tag, assume random bytes never get there and splice
into a genuine message instead.

A smoke test alone is not a clean bill of health — a few seconds of
fuzzing per target finds the shallow bugs, not the deep ones, which is
exactly what continuous fuzzing below is for. It is also not *uniformly*
useful: `group_commit` reached 36M executions across these runs without
ever parsing past a `LeafKeyPackage`, because doing so requires a
proof-of-possession signature that verifies, and random mutation will not
produce one. Everything behind a signature check in a parser is a
structural blind spot for coverage-guided fuzzing — §6.29 found three
unbounded allocations there by reading, not by running this. Budget
attention accordingly.

**Continuous fuzzing runs via [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/)**,
not a hand-rolled GitHub Actions loop: `.clusterfuzzlite/` (`project.yaml`,
`Dockerfile`, `build.sh`) defines the build, and
`.github/workflows/cflite_pr.yml`/`cflite_batch.yml` run it — 10 minutes
per target on every PR touching `crates/`, and up to an hour per target
every 6 hours on a schedule (`workflow_dispatch`-able on demand too), with
corpus and coverage reports persisted as GitHub Actions artifacts between
runs so coverage compounds over time instead of restarting cold every
run. `build.sh` auto-discovers every file under `fuzz_targets/`, so a
newly added target needs no matching edit to either workflow — the
previous hand-rolled version of this setup listed each target explicitly
in a job matrix and silently missed `rln_verify`/`mpc_frost_verify` for a
while after they were added, exactly the class of drift auto-discovery
avoids. A crash fails the run and is reported via the configured output
(SARIF); pull the reproducer down, add it as a regression input (a new
file under `corpus/<target>/`, or a `#[test]` in the main crate replaying
the same bytes), fix the bug, and confirm the same input passes before
considering it closed.

`.github/workflows/scheduled-security.yml` separately runs `cargo audit`
daily against both `Cargo.lock`s (this crate's and this fuzz crate's
own), independent of whether anything changed — a dependency can go from
clean to CVE'd on a day nobody touches the repo, and
`ENGINEERING-STANDARDS.md`'s "run cargo audit before committing"
convention only ever checks the day of the commit.

**`oss-fuzz` itself was considered and rejected, for now**: acceptance
requires "a significant user base and/or [being] critical to global IT
infrastructure," which this project doesn't yet meet, on top of an
application/review process with no fixed turnaround.
[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) is the same
underlying tooling family (Google's, built for exactly this fuzz-target
shape) with no acceptance gate at all — worth revisiting `oss-fuzz` itself
if this project's user base ever changes that calculus.
