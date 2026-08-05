# Fuzz targets

Six [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) harnesses, one
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

## Status

All six targets have been smoke-tested (a few seconds to low tens of
seconds each, on the order of 10^3–10^6 executions depending on how
expensive that target's per-iteration setup is) with zero crashes found.
That is a smoke test, not a clean bill of health — a few seconds of
fuzzing per target finds the shallow bugs, not the deep ones. Real
confidence comes from sustained fuzzing (hours to days, ideally in CI on
a schedule) with a growing, retained corpus, which this workspace does
not currently run anywhere automated. If you're looking for a next step
here, wiring these into a scheduled CI job (or `oss-fuzz`, given this is
a security-relevant crate) with a persistent corpus is it.
