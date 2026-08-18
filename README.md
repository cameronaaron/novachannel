# novachannel

[![CI](https://github.com/cameronaaron/novachannel/actions/workflows/ci.yml/badge.svg)](https://github.com/cameronaaron/novachannel/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A five-crate Rust workspace implementing a hybrid classical/post-quantum
secure messaging stack: an authenticated channel with async/deniable X3DH
session establishment, sealed sender, Sesame-style multi-device fan-out, and
a forward-secret ratchet; zero-knowledge rate-limiting nullifiers over a
hash-based STARK; differential-privacy-calibrated cover traffic; oblivious
server-side storage; and threshold key generation, decryption, and signing
(including FROST).

Every non-trivial primitive here composes standard, published constructions.
The contribution is a verified, tested, honestly-scoped *integration* of them
into a coherent metadata-resistant messaging stack — not a new cryptographic
primitive. Two pieces are genuinely new code and are flagged as unvetted
rather than presented as equivalent to a cryptanalyzed construction: see
[§3.2](docs/SYSTEMIZATION.md#32-why-a-stark-and-the-cost-of-that-choice) and
[§4.1.1](docs/SYSTEMIZATION.md#411-an-incremental-erasure-coded-alternative-re-key)
of the engineering report below.

**Start here:** [`docs/SYSTEMIZATION.md`](docs/SYSTEMIZATION.md) is a full
engineering report — what was built, why each design choice was made, what
was verified and how, and which parts are novel versus reused from published
work. It is written to be precise about what is and isn't claimed; read it
before assuming any component's security properties.

## Workspace layout

```
crates/core   novachannel          hybrid PQ/classical authenticated channel, ratchet, X3DH, sealed sender, multi-device
crates/rln    novachannel-rln      zero-knowledge rate-limiting nullifiers (STARK-proved Merkle membership)
crates/dp     novachannel-dp       differential-privacy-calibrated cover traffic scheduling
crates/oram   novachannel-oram     Path ORAM: oblivious server-side storage
crates/mpc    novachannel-mpc      threshold DKG, decryption, and FROST (RFC 9591) signing
```

The four peripheral crates are independent of each other and of `core`; each
addresses a distinct gap that encryption alone leaves open — see
[§2](docs/SYSTEMIZATION.md#2-architecture) for the full picture.

## Building and testing

```sh
git clone https://github.com/cameronaaron/novachannel.git
cd novachannel
./scripts/check.sh          # fmt, clippy -D warnings, full test suite — the CI gate, run locally
```

Individual crates, in particular `novachannel-rln`, require `--release`:

```sh
cargo test -p novachannel-rln --release
cargo run -p novachannel-rln --release --example proof_size
cargo test -p novachannel-mpc --release official_test_vector_matches_rfc9591
cargo test -p novachannel --release --test x3dh
```

See the ["Reproducing the claims in this document"](docs/SYSTEMIZATION.md#reproducing-the-claims-in-this-document)
section of the engineering report for the complete list.

## Documentation

- [`docs/SYSTEMIZATION.md`](docs/SYSTEMIZATION.md) — the full engineering report (architecture, verification, limitations).
- [`docs/RLN_DP_COMPOSITION.md`](docs/RLN_DP_COMPOSITION.md) — whether composing the RLN rate limit with the DP cover-traffic scheme costs any privacy budget.
- [`docs/LIBSIGNAL_COMPARISON.md`](docs/LIBSIGNAL_COMPARISON.md) — how the design choices here compare to libsignal's.
- [`ENGINEERING-STANDARDS.md`](ENGINEERING-STANDARDS.md) — the standing engineering bar (what `scripts/check.sh` enforces) and the audit trail of defects found and fixed.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability.

## Status

This is a reference implementation and engineering exercise, not an audited
or production-hardened product. `novachannel-rln`'s in-circuit hash is now a
verified port of Poseidon2-over-Goldilocks (`p3-goldilocks`/`p3-poseidon2`,
checked against its published test vector byte-for-byte) rather than a
from-scratch construction, and the incremental ratchet's erasure coding is
now the maintained `reed_solomon_simd` crate rather than a hand-rolled
GF(256) implementation — but porting an algorithm is not the same as an
independent review of this codebase's specific use of it, and neither claim
has had one.
[§9 of the engineering report](docs/SYSTEMIZATION.md#9-limitations-and-what-would-be-needed-for-a-real-research-contribution)
states plainly what is and isn't established here, and what a publishable
research contribution would still require.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
