#!/usr/bin/env bash
# The gate: what "done" means here (ENGINEERING-STANDARDS.md §6.1).
# Stops at the first failing step.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> cargo fmt --check"
cargo fmt --check

# --locked: fail if Cargo.lock drifted from Cargo.toml rather than silently
# re-resolving to unreviewed versions (cargo audit only checks the lockfile).
echo "==> cargo clippy --workspace --all-targets --release --locked -D warnings"
cargo clippy --workspace --all-targets --release --locked -- -D warnings

# Public docs ship with the release: reject broken or private links.
echo "==> cargo doc --workspace --no-deps --release --locked (-D warnings)"
RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -D warnings" cargo doc --workspace --no-deps --release --locked

echo "==> cargo test --workspace --release --locked --exclude novachannel-rln"
cargo test --workspace --release --locked --exclude novachannel-rln

# Also debug mode: release-only testing let a load-bearing debug_assert! in
# wire::Writer::put_var never run while release silently truncated fields
# over 64KiB (ENGINEERING-STANDARDS.md §6.29). Debug also checks real
# invariants (mpc participant ids, rln trace rows).
echo "==> cargo test --workspace --locked --exclude novachannel-rln (debug)"
cargo test --workspace --locked --exclude novachannel-rln

# novachannel-rln runs in release only; see ENGINEERING-STANDARDS.md §0.4.
echo "==> cargo test -p novachannel-rln --release --locked"
cargo test -p novachannel-rln --release --locked

# Per commit as well as daily (scheduled-security.yml): a PR adding a
# vulnerable dependency should never merge. Needs cargo-audit locally; CI
# installs it.
if command -v cargo-audit >/dev/null 2>&1; then
    echo "==> cargo audit"
    cargo audit
else
    echo "==> cargo audit (skipped: cargo-audit not installed locally; CI always runs it)"
fi

# The local twin of oss-guard.yml's gitleaks scan. Needs gitleaks locally.
if command -v gitleaks >/dev/null 2>&1; then
    echo "==> gitleaks detect"
    gitleaks detect --source . --redact
else
    echo "==> gitleaks detect (skipped: gitleaks not installed locally; CI always runs it)"
fi

echo "==> all checks passed"
