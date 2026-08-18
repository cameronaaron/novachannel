#!/bin/bash -eu
# All 8 of this workspace's fuzz targets live under crates/core/fuzz (a
# standalone cargo-fuzz workspace that dev-depends on novachannel-rln and
# novachannel-mpc too — see that directory's own Cargo.toml comment for
# why it's kept out of the main workspace's stable-toolchain build).
cd "$SRC/novachannel/crates/core"

cargo fuzz build -O --debug-assertions

FUZZ_TARGET_OUTPUT_DIR="target/x86_64-unknown-linux-gnu/release"
for f in fuzz/fuzz_targets/*.rs; do
    FUZZ_TARGET_NAME="$(basename "${f%.*}")"
    cp "$FUZZ_TARGET_OUTPUT_DIR/$FUZZ_TARGET_NAME" "$OUT/"
done
