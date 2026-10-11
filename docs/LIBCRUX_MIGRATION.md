# Migrating `crates/core` to Cryspen's `libcrux`: a scoping document

**A scoping document, not a decision or a change.** `crates/core` uses
RustCrypto (`ml-kem`, `ml-dsa`) and dalek (`x25519-dalek`, `ed25519-dalek`;
`curve25519-dalek` in `crates/mpc`). Cryspen's `libcrux` is formally verified
with hax and F\* (panic freedom, functional correctness, secret independence)
and backs OpenMLS's post-quantum ciphersuite. This scopes what moving to it
would take, so the decision is made deliberately.

## Why a scoping document, not a PR

Every backend swap so far (the PQClean bindings to RustCrypto ML-KEM/ML-DSA;
`NovaRescue` to a Poseidon2 port) was a deliberate, documented breaking
change. This would be larger: every primitive in `crates/core` except AEAD and
HKDF/SHA-256, and very likely another wire-format change.

## What would change

| Primitive | Current | `libcrux` crate | Difference |
| --- | --- | --- | --- |
| X25519 | `x25519-dalek` | `libcrux-curve25519` (standalone, or via `libcrux-kem`) | `libcrux-kem` wraps X25519 as a KEM, not raw DH; `crate::kex`'s `diffie_hellman` calls need the standalone crate or a rework to encapsulate/decapsulate. |
| Ed25519 | `ed25519-dalek` | `libcrux-ed25519` | Same sign/verify shape, different byte types; `HybridSignature::write`/`read` must be re-checked byte for byte. |
| ML-KEM-1024 | `ml-kem` | `libcrux-ml-kem` | Different key and ciphertext types; the *library's* byte layout is what's on the wire, so `kex`'s encoding needs re-verification even though FIPS 203 is unchanged. |
| ML-DSA-87 | `ml-dsa` | `libcrux-ml-dsa` | As ML-KEM, for `identity.rs`'s PQ leg. |
| Ristretto255 (`crates/mpc`) | `curve25519-dalek` | none | Not in `libcrux`; stays on `curve25519-dalek`. |
| AEAD, HKDF, SHA-256 | `chacha20poly1305`, `hkdf`, `sha2` | none | Unchanged. |

Every module that serializes keys, ciphertexts or signatures would need its
encoding re-verified: `kex`, `identity`, `prekey`, `handshake`, `x3dh`,
`sealed_sender`, `ratchet`, `group`, `multidevice`. The §6.9 rule applies:
"produces the same bytes" is checked, not assumed.

## Effort

1. **API investigation** per primitive, especially whether `crate::kex` fits
   `libcrux-kem` or needs `libcrux-curve25519`, and how stable the
   per-algorithm crates are (Cryspen recommends them over the less stable
   umbrella crate).
2. **A new, versioned wire format**, documented as breaking, with every
   encoding re-derived from `libcrux`'s actual output.
3. **Re-verification**: the existing tests touching `crates/core` plus new
   known-answer tests for the new encodings, as the Poseidon2 port and FROST
   vector checks do.
4. **Re-running `crates/core/formal/proverif/x3dh.pv`** if key derivation
   changes shape (unlikely, but checked rather than assumed).
5. **A fresh fuzzing pass** over every changed parser.

## What would not change

- Protocol design (X3DH's DH-plus-KEM shape, the ratchet chains, TreeKEM's
  path updates, sealed sender's envelope): this is a primitive swap.
- `crates/rln`, `crates/dp`, `crates/oram`.
- `crates/mpc`'s Ristretto255 `Dealer`/`frost`/`combine_partials`.
  `threshold_kem.rs` uses `ml-kem` and should move with `crates/core` so one
  vetted dependency serves both (§4.2).

## When it would be worth doing

- **A concrete assurance gap appears**: a vulnerability in the current crates
  of the kind verification rules out (`curve25519-dalek`'s timing issue,
  RUSTSEC-2024-0344, fixed in 2024, is that shape).
- **Users depend on it** enough for "maintained but unaudited" versus
  "verified and used in OpenMLS" to matter, the same threshold applied to
  OSS-Fuzz (`ENGINEERING-STANDARDS.md` §6.25).
- **The per-algorithm `libcrux` APIs are stable** enough that one migration
  isn't followed by another; check at the time.

## The current position

RustCrypto's `ml-kem`/`ml-dsa` are maintained, pure Rust and tested against
NIST vectors, though not independently audited; PQClean bindings and
`liboqs-rust` are explicitly not recommended for production by their own
maintainers. `chacha20poly1305`, which stays either way, was audited by NCC
Group (2019/2020, MobileCoin-funded) without significant findings. The
current choices are defensible; `libcrux` would be stronger, not a fix for a
known break.
