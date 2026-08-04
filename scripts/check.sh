#!/usr/bin/env bash
# The gate: what "done" means for a change in this workspace (see
# ENGINEERING-STANDARDS.md §6.1). Run this before considering any change
# finished. Exits non-zero on the first failing step.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> cargo fmt --check"
cargo fmt --check

echo "==> cargo clippy --workspace --all-targets --release -D warnings"
cargo clippy --workspace --all-targets --release -- -D warnings

echo "==> cargo test --workspace --release --exclude novachannel-rln"
cargo test --workspace --release --exclude novachannel-rln

# novachannel-rln is run separately, in --release only: winterfell's
# debug-mode transition-degree assertion is witness-dependent for this AIR's
# sparse boundary columns even though the declared degrees are safe upper
# bounds — see ENGINEERING-STANDARDS.md §0.4 for why debug mode is not the
# right gate for this one crate.
echo "==> cargo test -p novachannel-rln --release"
cargo test -p novachannel-rln --release

echo "==> all checks passed"
