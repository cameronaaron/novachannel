# Research release validation — 2026-09-13

This release is a research artifact, not an audited production messaging
product. Its tests support specific properties; they don't prove the whole
protocol or its composition.

## Reproduce

Validated on `aarch64-apple-darwin` with rustc
`1.99.0-nightly (1ed2df61a 2026-08-04)` and Cargo
`1.99.0-nightly (7c83d4cc0 2026-07-29)`: the tested environment, not a
minimum supported version. Keep both `Cargo.lock` files.

```sh
./scripts/check.sh
cargo audit --file crates/core/fuzz/Cargo.lock
```

Install `cargo-audit` and `gitleaks` first; the gate skips them, saying so,
if absent (the recorded run had both). The gate checks formatting, clippy and
public rustdoc with warnings denied, and tests in **release and debug**
(debug was added in this review so `debug_assert!`s actually run;
`novachannel-rln` stays release-only, `ENGINEERING-STANDARDS.md` §0.4).

## Verified in this review

- 241 tests pass, including a regression test for each defect below, each
  confirmed to fail on the pre-fix source.
- All eight fuzz targets re-run on the fixed code with no new crashes, after
  six were rewritten to reach their parsers (§6.31-§6.32).
- Public docs build with warnings denied; CI runs the same gate.
- Dependency audits report no vulnerabilities, apart from the disclosed
  unmaintained dev-only `paste`.
- gitleaks finds no leaks in history (which says nothing about untracked
  files or hosting-provider retention).

## Corrected results

Full detail is in `ENGINEERING-STANDARDS.md` §6.29-§6.32. The findings that
change what the project can be said to do:

- **Groups broke at 16 members.** A `u16` length prefix guarded only by
  `debug_assert!` silently wrapped in release: a 16-leaf `Welcome` is
  147.0KB and a 32-leaf `Commit` 73.4KB, and both serialized to bytes their
  own parsers rejected. Large sealed-sender and X3DH payloads were affected
  too. Now `u64`. **Breaking wire-format change.**
- **The group `Welcome` was unauthenticated**; it is now signed by the
  committer and bound to its `Commit`. `Group::member_identity` was added.
- **Two DKG complaint defects**: naming participant 0 extracted a dealer's
  secret, and one participant could evict every honest dealer. Now only
  Gennaro et al.'s rule disqualifies.
- **RLN's rate limit was evadable**: `bytes_to_field` collided on `b"a"`
  vs `b"a\0"` and `v` vs `v + p`. Fixed; **every nullifier and identity
  commitment changes.**
- **RLN security figures were wrong both ways**: 127 bits at the default, not
  ~148; 63 before hardening, not ~96. The verifier floor rose from 95 to 127.
- **ORAM leaked bucket occupancy and value length**; closed with fixed-size
  blocks and dummy padding.
- Smaller: three unbounded allocations, two ratchet state-machine faults,
  burnable one-time prekeys, RNG consumption tracking the DP presence bit,
  and two overflow-before-bounds-check orderings.
- **Six of eight fuzz targets weren't testing what they appeared to.**
  `rln_verify` had never reached the verifier; two stopped at a first-field
  length or signature check; four were mostly measuring key generation
  (`ratchet_open`: 8 executions a second). After rewriting, `ratchet_open`
  ran 2,541,083 executions and `group_commit` reached 3735 edges, up from 69.
- **Found by the fixed `rln_verify`:** a five-byte input aborting
  `panic = "abort"` builds (fixed: `verify` validates trace shape as a
  `Result`), and an **unfixable remote DoS in winterfell 0.13.1**: an
  attacker-chosen count reaches `Vec::with_capacity` inside
  `winterfell::verify`, so a six-byte mutation requests 2520802182910816
  bytes and aborts. `catch_unwind` can't contain allocation failure and no
  fixed release exists. **Any caller of `novachannel_rln::air::verify` can be
  killed by whoever supplies the proof; isolate that call.** Pinned by a
  subprocess test that fails when upstream fixes it.

Compatibility notes: `novachannel-oram`'s Merkle bucket hash now mixes lengths
as `u64`, so stored roots from earlier versions won't match; and
`depth_for_capacity` is exact integer arithmetic with an explicit `MAX_DEPTH`.

Corrections from the 2026-09-11 review stand: the replay-window boundary at
exactly 64, and the withdrawn positive-epsilon DP claim
([analysis](RLN_DP_COMPOSITION.md)).

## Unverified boundaries

No independent audit, new formal verification, sustained fuzzing campaign,
cross-platform matrix, mobile benchmark or end-to-end anonymity analysis was
done. The fuzzing was a few minutes per target: enough to show the targets
reach their parsers, not to call them explored. Splicing gets past signature
checks only for the shapes the seed messages have.

Only §3.2's proof-size and proving-time figures were re-measured, on the
machine above; other measurements in `SYSTEMIZATION.md` are historical. The
TCP examples are demonstrations, not hardened services. Persistence, crash
recovery, application integration and operator security are outside this
evidence. No crate was published.
