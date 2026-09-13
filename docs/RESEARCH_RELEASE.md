# Research release validation — 2026-09-13

This release is a research artifact, not a security-audited production
messaging product. Its executable tests support specific properties; they
are not a proof of the complete protocol or its composition.

## Reproduce

Validated on `aarch64-apple-darwin` using rustc
`1.99.0-nightly (1ed2df61a 2026-08-04)` and Cargo
`1.99.0-nightly (7c83d4cc0 2026-07-29)`. These identify the tested environment,
not a claimed minimum supported Rust version. Preserve both Cargo.lock files.

```sh
./scripts/check.sh
cargo audit --file crates/core/fuzz/Cargo.lock
```

Install cargo-audit and gitleaks before running the gate if absent: its
local security-tool checks otherwise explicitly skip. The recorded run had
both installed. The gate checks formatting, Clippy with warnings denied,
public rustdoc with warnings denied, and release-mode tests. RLN must run
in release mode; see ENGINEERING-STANDARDS.md for the known debug-assertion
limitation. This release does not claim debug-mode compatibility.

## Verified in this review

- 237 tests pass across the five crates, including every regression test
  added for the defects listed below. Each of those was run against the
  pre-fix source and observed to fail there.
- All eight `cargo-fuzz` targets re-run for 75 seconds each against the
  fixed code with no new crashes: `prekey_bundle` 11.4M executions,
  `group_commit` 1.9M, `mpc_frost_verify` 39K, `handshake_messages` 28K,
  `x3dh_respond` 1.8K, `sealed_sender_open` 1.6K, `ratchet_open` 644.
  `rln_verify` surfaced one further input into winterfell's proof
  deserializer, handled by the existing `catch_unwind` guard and verified
  against a normal unwind-enabled build (see `crates/core/fuzz/README.md`
  on why the fuzz binary always reports these regardless).
- Public documentation builds with warnings denied; CI uses the same gate.
- Workspace and fuzz dependency audits report no vulnerabilities. The
  workspace retains the disclosed unmaintained, dev-only `paste` warning.
- The gate's gitleaks history scan reports no leaks. This is not evidence
  about untracked files or hosting-provider retention.

## Corrected results

A second full review of all five crates found nine defects, recorded in
full in `ENGINEERING-STANDARDS.md` §6.29 and §6.30. The ones that change
what this project can be said to do:

- **Groups were unusable past ~16 members.** `wire::Writer::put_var` wrote
  a `u16` length prefix guarded only by a `debug_assert!`, so in release
  builds any field over 65535 bytes silently wrapped its prefix. A
  `Commit` for a 32-leaf group measures ~73KB, so `Commit::to_bytes`
  emitted bytes `Commit::from_bytes` could not parse, with no error on the
  write path. `sealed_sender::seal` and `x3dh::initiate` did the same for
  caller payloads over 64KiB. The prefix is now `u64`, which makes the
  truncation impossible by construction rather than documented. **This is
  a breaking wire-format change.**
- **The group `Welcome` was unauthenticated.** It travels in a
  sender-anonymous envelope, so the tree, epoch and epoch secret a joiner
  built their entire group state from were attacker-choosable bytes bound
  to the accompanying `Commit` by nothing. The snapshot is now signed by
  the committer and `join` checks four bindings before believing it.
  `Group::member_identity` was added alongside, so a received group
  message is attributable and a joiner can pin whoever committed them in.
- **Two DKG complaint-protocol defects.** A complaint naming participant 0
  made an honest dealer publish its own secret contribution, since zero is
  the point at which its polynomial *is* that secret. Separately,
  disqualifying a dealer on the accuser's unverifiable claim about what
  they received let one malicious participant evict every honest dealer
  and be left alone determining the group key; Gennaro et al.'s actual
  rule — disqualify iff the broadcast share fails verification against the
  dealer's own commitments — is now the only faulty verdict.
- **RLN's rate limit was evadable.** `bytes_to_field`, which produces the
  message-binding `x` of every share, was not injective: `b"a"` and
  `b"a\0"` collided, as did any chunk `v` and `v + p`. Two shares that
  agree in `x` recover nothing, so a member could send a second message in
  an epoch by appending a zero byte. Now length-seeded and packed seven
  bytes per element. **This changes every nullifier and identity
  commitment the crate produces.**
- **The RLN proof-security numbers in SYSTEMIZATION §3.2 were wrong in
  both directions.** They came from `num_queries * log2(blowup) +
  grinding`, which is only the query term of winterfell's actual formula
  `min(min(field_security, query_security) - 1, collision_resistance)`.
  Over 64-bit Goldilocks the field term binds: the current default is
  **127** bits, not the ~148 claimed, and the pre-hardening default was
  **63**, not ~96. The verifier's floor, which is the number that actually
  gates anything, was 95 and is now 127. Both measurement examples now
  read the figure off `Proof::conjectured_security` rather than
  re-deriving it.
- **The ORAM leaked bucket occupancy and block length.** Sealing each
  block's contents left how many blocks a bucket held, and how long each
  value was, visible to the server — both correlated with the access
  pattern the crate exists to hide. Fixed block size plus dummy padding to
  `bucket_capacity` closes it.

Smaller fixes in the same review: three unbounded attacker-chosen
`Vec::with_capacity` calls; two ratchet state-machine faults; one-time
prekeys burnable by an unauthenticated party; RNG consumption in
`novachannel-dp` tracking the presence bit it exists to hide; and two
overflow-before-bounds-check reorderings.

Earlier corrections from the 2026-09-11 review stand unchanged: the
replay-window boundary at exactly 64 sequence numbers, and the withdrawal
of the positive-epsilon differential-privacy claim (silence is possible
only when there is no real message, so the reverse DP inequality fails).
See [the corrected analysis](RLN_DP_COMPOSITION.md).

## Unverified boundaries

No independent cryptographic audit, new formal verification run, sustained
fuzzing campaign, cross-platform test matrix, mobile benchmark, or end-to-end
anonymity analysis was performed in this review. The fuzzing above is a
75-second-per-target smoke run, and `group_commit`'s 36 million cumulative
executions have never parsed past a signature-gated field — coverage-guided
fuzzing structurally cannot reach those, which is why three of this
review's findings came from reading instead.

The proof-size and proving-time figures in SYSTEMIZATION §3.2 were
re-measured in this review on the machine described above; every other
measurement in that document is a historical result, not newly reproduced.
The TCP examples remain demonstrations, not hardened network services.
Persistence, crash recovery, application integration, and operator security
remain outside the evidence recorded here. No crate publication or remote
release was performed.
