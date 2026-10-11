# Fuzz targets

Eight [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) harnesses, one
per boundary where a deployment parses attacker-controlled bytes before any
authentication:

- `prekey_bundle`: `PreKeyBundle::from_bytes` (a bundle from an untrusted
  directory).
- `x3dh_respond`: `x3dh::respond` against a real responder.
- `sealed_sender_open`: `sealed_sender::open` against a real recipient key.
- `handshake_messages`: msg1 parsing in `handshake::responder_respond` and
  msg2 parsing in `InitiatorHandshakeState::complete`.
- `ratchet_open`: `RatchetedSession::open` and `open_ratchet_chunk`, after a
  real handshake.
- `group_commit`: `Commit`/`Welcome` parsing, then `Group::apply_commit` on a
  real group when a commit parses.
- `rln_verify`: `novachannel_rln::Message::from_proof_bytes` and
  `air::verify`, against a genuine proof made offline (the target's docs say
  why).
- `mpc_frost_verify`: decodes bytes into a FROST signature and calls
  `novachannel_mpc::frost::verify`, the decode-then-verify shape a transport
  would have.

**Every target splices each input into a genuine message**, because random
bytes never get past a length check, signature or AEAD tag. Expensive
immutable setup (identities, keys, a completed handshake) is built once per
process; state the code under test mutates (a receiving ratchet session, a
one-time prekey store) is rebuilt per input, so one input never affects how
another is handled.

This is a standalone crate (its own `[workspace]` and `Cargo.lock`) so the
main workspace stays on stable; `cargo-fuzz` needs nightly.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run prekey_bundle          # or any target above
```

Bound a run with `-- -max_total_time=60` or `-runs=N`. A crash writes a
reproducer to `artifacts/<target>/`; keep it as a regression test (a corpus
input or a `#[test]` replaying the bytes) instead of discarding it after the
fix. `cargo +nightly fuzz run <target> -- -help=1` lists libFuzzer's flags.

## `catch_unwind` fixes and this harness's blind spot

`cargo fuzz` forces `panic = "abort"` so sanitizers treat panics as crashes.
A `catch_unwind` fix (like `novachannel_rln::Message::from_proof_bytes`) can
therefore never stop the fuzz binary from reporting that input, even though a
normal build returns `Err`. Verify such fixes with a `#[test]` replaying the
bytes in a normal build (see the `..._is_rejected_cleanly` tests in
`crates/rln/tests/rln.rs`), not by whether the fuzzer stops crashing.

## Coverage, and why execution counts misled

Six targets were rewritten (`ENGINEERING-STANDARDS.md` §6.31-§6.32) after
checking coverage instead of execution counts:

| target | edges before | edges after | executions before | executions after |
| --- | --- | --- | --- | --- |
| `rln_verify` | 84 | 2041 | — | — |
| `group_commit` | 69 | 3735 | 1.9M | — |
| `prekey_bundle` | 185 | 2410 | 11.4M | — |
| `handshake_messages` | 1360 | 2116 | 27.5K | 75.5K |
| `ratchet_open` | 2878 | 1514 | 644 | 2.54M |
| `sealed_sender_open` | 1837 | 1145 | 1.6K | 488K |
| `x3dh_respond` | 1876 | 1680 | 1.8K | 169K |

(Runs of 75-180 seconds; executions for the first three weren't comparable
across the change.) No crashes after the rework.

- `rln_verify` had embedded a genuine proof and never used it, so it fuzzed
  four bytes of deserializer.
- `group_commit` and `prekey_bundle` stopped at a signature or length check
  in their first field.
- Four targets generated identities every iteration, so their coverage was
  mostly key generation; `ratchet_open` ran at eight executions a second.
  Caching that setup *lowers* the edge count while the target does far more
  real work: the lower number is the honest one.

**A target that runs clean may be running over almost nothing.** When adding
or reviewing a target, check what it covers and how much of that is setup,
and splice into a genuine message whenever the code sits behind a length
check, signature or AEAD tag. A short smoke run finds shallow bugs only;
§6.29 found three unbounded allocations behind a signature check by reading.

`rln_verify` keeps finding winterfell deserializer panics (a third input,
`[0xc1, 0x3b, 0xf5, 0xcc]`, among them). All are contained by `catch_unwind`
and regression-tested; the target no longer feeds raw bytes to the
deserializer (§6.31).

## Continuous fuzzing

[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) runs the targets:
`.clusterfuzzlite/` defines the build and
`.github/workflows/cflite_pr.yml`/`cflite_batch.yml` run it for 10 minutes per
target on PRs touching `crates/` and up to an hour per target every 6 hours,
keeping corpus and coverage between runs. `build.sh` discovers every file in
`fuzz_targets/`, so new targets need no workflow change (the old hand-written
matrix silently missed two). A crash fails the run with a SARIF report: add
the reproducer as a regression input, fix it, and confirm the input passes.

`.github/workflows/scheduled-security.yml` runs `cargo audit` daily on both
lockfiles, since a dependency can gain an advisory on a day nobody commits.

OSS-Fuzz requires "a significant user base and/or [being] critical to global
IT infrastructure," which this project doesn't meet; ClusterFuzzLite is the
same tooling without an acceptance gate.
