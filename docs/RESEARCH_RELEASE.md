# Research release validation — 2026-09-11

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

- 206 tests pass across the five crates, including the new replay boundary
  regression and the counterexample to the former DP claim.
- Public documentation builds with warnings denied. Broken links and links
  to private implementation details were corrected; CI uses the same gate.
- Workspace and fuzz dependency audits report no vulnerabilities. The
  workspace retains the disclosed unmaintained, dev-only `paste` warning.
- Both lockfiles use chacha20 0.10.2 in place of yanked 0.10.1.
- The gate's gitleaks history scan reports no leaks. This is not evidence
  about untracked files or hosting-provider retention.

## Corrected results

The receiver previously forgot an authenticated record after advancing
exactly 64 sequence numbers and accepted its replay. The regression fails
on the old implementation at jump 64. The fix preserves the oldest bitmap
bit and tests both replayed and previously unseen records around the boundary.

The cover-traffic mechanism does not provide pure differential privacy for
positive epsilon: silence is possible only when there is no real message.
The reverse DP inequality therefore fails. The API behavior remains compatible;
the incorrect privacy and composition claims have been withdrawn. See
[the corrected analysis](RLN_DP_COMPOSITION.md). Epsilon zero gives constant
slot presence subject to indistinguishable packet framing and timing.

## Unverified boundaries

No independent cryptographic audit, new formal verification run, sustained
fuzzing campaign, cross-platform test matrix, mobile benchmark, or end-to-end
anonymity analysis was performed in this review. Existing measurements in
SYSTEMIZATION.md are historical results, not newly reproduced benchmarks.
The TCP examples remain demonstrations, not hardened network services.
Persistence, crash recovery, application integration, and operator security
remain outside the evidence recorded here. No crate publication or remote
release was performed.
