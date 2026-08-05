#!/usr/bin/env bash
# The gate: what "done" means for a change in this workspace (see
# ENGINEERING-STANDARDS.md §6.1). Run this before considering any change
# finished. Exits non-zero on the first failing step.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> cargo fmt --check"
cargo fmt --check

# --locked: fail loudly if Cargo.lock is out of sync with Cargo.toml instead
# of cargo silently re-resolving and building against dependency versions
# nobody reviewed. A lockfile that drifts unnoticed between commits is
# exactly the supply-chain gap `cargo audit` below can't catch on its own —
# audit only checks what's *in* the lockfile, not whether the lockfile still
# matches what was declared and reviewed.
echo "==> cargo clippy --workspace --all-targets --release --locked -D warnings"
cargo clippy --workspace --all-targets --release --locked -- -D warnings

echo "==> cargo test --workspace --release --locked --exclude novachannel-rln"
cargo test --workspace --release --locked --exclude novachannel-rln

# novachannel-rln is run separately, in --release only: winterfell's
# debug-mode transition-degree assertion is witness-dependent for this AIR's
# sparse boundary columns even though the declared degrees are safe upper
# bounds — see ENGINEERING-STANDARDS.md §0.4 for why debug mode is not the
# right gate for this one crate.
echo "==> cargo test -p novachannel-rln --release --locked"
cargo test -p novachannel-rln --release --locked

# Runs on every commit here, not just the daily cron in
# scheduled-security.yml — that cron catches a dependency that *becomes*
# vulnerable while main sits still, but a PR that *adds* a
# newly-vulnerable dependency should never merge in the first place. This
# needs `cargo audit` installed locally (`cargo install cargo-audit`); CI
# installs it fresh every run.
if command -v cargo-audit >/dev/null 2>&1; then
    echo "==> cargo audit"
    cargo audit
else
    echo "==> cargo audit (skipped: cargo-audit not installed locally; CI always runs it)"
fi

echo "==> all checks passed"
