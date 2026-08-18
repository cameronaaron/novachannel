# Migrating `crates/core` to Cryspen's `libcrux`: a scoping document

**Status: a scoping document, not a decision or a code change.** This
workspace currently builds `crates/core`'s classical and post-quantum
primitives on RustCrypto (`ml-kem`, `ml-dsa`) and `dalek-cryptography`
(`x25519-dalek`, `ed25519-dalek`, and `curve25519-dalek` in `crates/mpc`).
Cryspen's `libcrux` — formally verified (via the `hax` toolchain and F*,
for panic-freedom, functional correctness, and secret-independence) — is a
materially stronger assurance story for the same set of primitives, and is
already production-proven: it backs OpenMLS's post-quantum ciphersuite.
This document scopes what actually migrating to it would take, so that
decision can be made deliberately rather than either dismissed or
attempted casually.

## Why this is a scoping document, not a PR

Every previous crypto-backend swap in this workspace's history
(`pqcrypto-kyber`/`pqcrypto-dilithium` → RustCrypto's `ml-kem`/`ml-dsa`;
the hand-rolled `NovaRescue` permutation → a verified Poseidon2 port) was
treated as a deliberate, documented, breaking event — never folded
silently into an unrelated change. A `libcrux` migration is the same
category of change, but larger: it would touch every primitive
`crates/core` uses except AEAD (`chacha20poly1305` stays; `libcrux` isn't
in that business) and HKDF/SHA-256 (ditto), and it would very likely
change this crate's wire format again, the same way the ML-KEM migration
did. That's not a reason to avoid it — it's a reason to scope it first.

## What would actually change

| Primitive | Current | `libcrux` crate | API shape difference |
| --- | --- | --- | --- |
| X25519 | `x25519-dalek` | `libcrux-curve25519` (via `libcrux-kem`'s unified KEM API, or standalone) | `libcrux-kem`'s `Kem` trait wraps X25519 *as a KEM*, not as raw DH — `crate::kex`'s Diffie-Hellman-shaped calls (`StaticSecret::diffie_hellman`) would need either the standalone `libcrux-curve25519` crate (closer to today's shape) or a rework around `libcrux-kem`'s encapsulate/decapsulate framing. |
| Ed25519 | `ed25519-dalek` | `libcrux-ed25519` | Closer to a drop-in — same sign/verify shape — but a different key/signature byte type, so `identity.rs`'s wire encoding (`HybridSignature::write`/`read`) needs re-checking byte-for-byte, not assumed compatible. |
| ML-KEM-1024 | `ml-kem` (RustCrypto) | `libcrux-ml-kem` (via `libcrux-kem`) | Different `EncapsulationKey`/`DecapsulationKey`/`Ciphertext` types; `crate::kex`'s wire format (`kex::ml_kem_public_from_bytes` etc.) needs re-verification against the new encoding, even though FIPS 203 itself is unchanged — the *library's* byte layout is what's actually on the wire, not the standard's abstract description of it. |
| ML-DSA-87 | `ml-dsa` (RustCrypto) | `libcrux-ml-dsa` | Same category of change as ML-KEM above, for `identity.rs`'s post-quantum leg. |
| Ristretto255 (`crates/mpc`, FROST/DKG) | `curve25519-dalek` | **no `libcrux` equivalent** | Out of scope for `libcrux` entirely — Ristretto isn't something `libcrux` implements. `curve25519-dalek` stays regardless of what happens to `crates/core`. |
| AEAD, HKDF, SHA-256 | `chacha20poly1305`, `hkdf`, `sha2` | unchanged | `libcrux` doesn't cover these; no change needed or possible here. |

Every wire-format-touching module in `crates/core` is a candidate for
re-verification, not just the four rows above: `kex.rs` (obviously),
`identity.rs`, `prekey.rs`, `handshake.rs`, `x3dh.rs`, `sealed_sender.rs`,
`ratchet.rs`, `group.rs`, `multidevice.rs` — anything that serializes a
public key, ciphertext, or signature onto the wire depends on the
*current* library's exact byte encoding, and `ENGINEERING-STANDARDS.md`
§6.9's standard ("a claimed compatibility gets checked against the actual
spec") applies with equal force to "the new library produces the same
bytes for the same semantic value" as it did to the ML-KEM migration.

## Effort estimate, honestly

This is not a mechanical `s/x25519_dalek/libcrux_curve25519/` pass. In
rough order:

1. **API-shape investigation** for each primitive row above — in
   particular, whether `crate::kex`'s Diffie-Hellman-shaped X25519 usage
   maps cleanly onto `libcrux-kem`'s KEM-shaped API or needs the
   standalone `libcrux-curve25519` crate instead, and whether that
   crate's API is stable enough to build on (Cryspen's own docs recommend
   the per-algorithm sub-crates over the umbrella `libcrux` crate
   specifically because the umbrella crate's API is less stable).
2. **A new wire format**, version-bumped and documented as a breaking
   change the same way the ML-KEM migration was (`ENGINEERING-STANDARDS.md`
   references that migration directly) — every byte encoding this crate
   currently guarantees needs re-deriving from `libcrux`'s actual output,
   not assumed compatible with the old one.
3. **Full re-verification** of every test this workspace already has for
   `crates/core` (168+ tests touch this crate directly or indirectly) plus
   new tests specifically checking the new library's byte encodings
   against known test vectors, the same discipline
   `permutation.rs`'s Poseidon2 port and `frost.rs`'s RFC 9591 test vector
   check already apply elsewhere in this workspace.
4. **Re-running the existing formal models** (`crates/core/formal/proverif/x3dh.pv`)
   against whatever new session-key derivation shape falls out of the
   migration, if any — unlikely to change since HKDF/the derivation
   *logic* stays the same, but not assumed without checking.
5. **A fresh fuzzing pass** (§6.22's standard: a new untrusted-input
   parsing boundary is exactly where this workspace's fuzz targets have
   found real bugs before) against every changed wire-format parser.

None of this is a reason not to do it eventually — it's the actual cost,
stated plainly, so "worth doing" can be weighed against "how much effort"
rather than against an assumed-small effort that turns out to be large
mid-migration.

## What would NOT change

- The protocol *design* — X3DH's four-DH-plus-KEM shape, the ratchet's
  hash-chain forward secrecy, TreeKEM's path-update structure, sealed
  sender's ephemeral-key envelope — none of this depends on which library
  computes the underlying field/curve arithmetic. This is a primitive
  swap, not a protocol redesign.
- `crates/rln`, `crates/dp`, `crates/oram` — none of them touch
  `x25519-dalek`/`ed25519-dalek`/`ml-kem`/`ml-dsa` at all.
- `crates/mpc`'s Ristretto255-based `Dealer`/`frost`/`combine_partials` —
  no `libcrux` equivalent exists, so this stays on `curve25519-dalek`
  regardless of what happens elsewhere. `threshold_kem.rs` *does* use
  `ml-kem` and would be a migration candidate if `crates/core`'s ML-KEM
  usage moves, for the same "one dependency, one version, one place it's
  vetted" reason `ENGINEERING-STANDARDS.md` §4.2 already argues for reuse
  over duplication.

## Decision criteria — what would make this worth doing

- **A concrete assurance gap materializes**: a disclosed vulnerability in
  RustCrypto's `ml-kem`/`ml-dsa` or `dalek-cryptography`'s
  `x25519-dalek`/`ed25519-dalek` that `libcrux`'s formal verification
  would have caught (`curve25519-dalek`'s 2024 timing-variability CVE,
  RUSTSEC-2024-0344, is exactly the shape of issue formal verification for
  secret-independence is meant to rule out — worth revisiting this
  document if something similar surfaces again).
- **This project's user base grows** to where the assurance gap between
  "actively maintained, not independently audited" and "formally verified,
  production-proven in OpenMLS" actually matters to someone depending on
  it — the same threshold `SECURITY.md`'s own scope section and the
  `oss-fuzz` acceptance criteria (`ENGINEERING-STANDARDS.md` §6.23's
  fuzzing section) already name for other decisions in this workspace.
- **`libcrux`'s per-algorithm sub-crate APIs stabilize** enough that a
  migration isn't immediately followed by another one when the API
  shifts — worth re-checking the crates' own stability posture at
  migration time, not assuming today's snapshot holds.

## What's already true today, independent of this migration

`ml-kem`/`ml-dsa` (RustCrypto) are actively maintained pure-Rust
implementations tested against NIST's own test vectors, not
independently audited but also not the weakest option available (`pqcrypto`'s
PQClean bindings and `liboqs-rust` are both explicitly *not*
recommended for production use by their own maintainers, as of this
writing). `chacha20poly1305` — which stays regardless of this
migration — already has a real, completed audit (NCC Group, 2019/2020,
funded by MobileCoin, no significant findings). This workspace's current
primitive choices are defensible, not negligent; `libcrux` is a
*stronger* option, not a fix for a known-broken one.
