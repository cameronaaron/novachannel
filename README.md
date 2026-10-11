# novachannel

[![CI](https://github.com/cameronaaron/novachannel/actions/workflows/ci.yml/badge.svg)](https://github.com/cameronaaron/novachannel/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](#license)

> **Research code, not approved for production.** It is unaudited, and the
> positive-epsilon cover scheduler is **not** differentially private
> ([corrected analysis](docs/RLN_DP_COMPOSITION.md)).

A five-crate Rust workspace for a hybrid classical/post-quantum messaging
stack: an authenticated channel with asynchronous deniable X3DH, sealed
sender, Sesame-style multi-device, a forward-secret ratchet and a
TreeKEM-inspired group ratchet; zero-knowledge rate-limiting nullifiers over a
hash-based STARK; cover traffic; oblivious server-side storage; and threshold
key generation, decryption and FROST signing.

Every primitive is a standard published construction or a verified port of
one (ML-KEM-1024, ML-DSA-87, X25519, Ed25519, Poseidon2, FROST/RFC 9591). The
contribution is a tested, honestly scoped *integration*, not new
cryptography. The circuit, protocol glue and erasure-coding framing are this
project's own and have had no outside review.

**Start with [`docs/SYSTEMIZATION.md`](docs/SYSTEMIZATION.md)**: what was
built, why, how it was verified, and what is and isn't claimed. Read it before
relying on any component's security properties.

## Workspace layout

```
crates/core   novachannel          hybrid PQ/classical channel, ratchets, X3DH, sealed sender, multi-device, groups
crates/rln    novachannel-rln      zero-knowledge rate-limiting nullifiers (STARK-proved Merkle membership)
crates/dp     novachannel-dp       cover traffic scheduling and size bucketing
crates/oram   novachannel-oram     Path ORAM with optional integrity and encryption layers
crates/mpc    novachannel-mpc      threshold DKG, decryption, post-quantum threshold KEM, FROST signing
```

The four peripheral crates are independent of each other and of `core`; each
covers a gap encryption alone leaves open
([§2](docs/SYSTEMIZATION.md#2-architecture)).

## Building and testing

```sh
git clone https://github.com/cameronaaron/novachannel.git
cd novachannel
./scripts/check.sh   # format, clippy, rustdoc, tests, cargo audit, gitleaks: the CI gate
```

`novachannel-rln` must be tested in `--release` (its docs explain why):

```sh
cargo test -p novachannel-rln --release
cargo run -p novachannel-rln --release --example proof_size
cargo test -p novachannel-mpc --release official_test_vector_matches_rfc9591
cargo test -p novachannel --release --test x3dh
```

The full list is in ["Reproducing the claims in this document"](docs/SYSTEMIZATION.md#reproducing-the-claims-in-this-document).

## Documentation

- [`docs/SYSTEMIZATION.md`](docs/SYSTEMIZATION.md): the engineering report.
- [`docs/RLN_DP_COMPOSITION.md`](docs/RLN_DP_COMPOSITION.md): why the
  RLN/cover-traffic composition claim was withdrawn.
- [`docs/LIBSIGNAL_COMPARISON.md`](docs/LIBSIGNAL_COMPARISON.md): design
  choices compared with libsignal's.
- [`docs/RESEARCH_RELEASE.md`](docs/RESEARCH_RELEASE.md): tested environment,
  reproduction commands and unverified boundaries.
- [`ENGINEERING-STANDARDS.md`](ENGINEERING-STANDARDS.md): the engineering bar
  and the audit trail of defects found and fixed.
- [`SECURITY.md`](SECURITY.md): reporting a vulnerability.

## Status and known limitations

A reference implementation, not an audited product. Things to know before
using any of it:

- **A malformed RLN proof can kill any process that calls
  `novachannel_rln::air::verify`**, through an unbounded allocation in
  `winterfell` that can't be contained in-process. Isolate that call.
  Documented at the function and pinned by a test.
- **Positive-epsilon cover traffic is not differentially private**; only
  epsilon = 0 hides the presence bit.
- **Threshold signing is classical** (Ristretto255). Threshold decryption has
  a post-quantum path (`threshold_kem`).
- **The wire format and RLN proof format have changed incompatibly** across
  reviews (ML-KEM/ML-DSA migration, `u64` length prefixes, Poseidon2, injective
  message binding). No compatibility with earlier versions is offered.
- Reviews of all five crates found and fixed real defects, among them silent
  truncation of large group messages, an unauthenticated group `Welcome`, a
  DKG complaint rule that let one participant evict honest dealers, and RLN
  security figures that were wrong in both directions (127 bits, not ~148).
  See [`ENGINEERING-STANDARDS.md`](ENGINEERING-STANDARDS.md) §6.28-§6.32 and
  [`crates/core/fuzz/README.md`](crates/core/fuzz/README.md).

[§9 of the engineering report](docs/SYSTEMIZATION.md#9-limitations-and-what-would-be-needed-for-a-real-research-contribution)
lists what remains open and what a publishable research contribution would
still require.

## License

[AGPL-3.0-or-later](LICENSE). You can use, modify and redistribute this,
including commercially; if you distribute it or run a modified version as a
network service, you must publish your source under the same license.
