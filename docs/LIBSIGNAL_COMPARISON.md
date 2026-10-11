# What libsignal actually does, checked against this workspace

Findings from the real repository (`github.com/signalapp/libsignal`; the file
listings, `Cargo.toml`s and `lib.rs` headers quoted here were read directly,
not recalled). Signal's Rust core is the most audited and deployed messaging
cryptography codebase there is, so where this workspace diverges from it,
the divergence should be deliberate.

## 1. Adopted directly: `unsafe` and `unwrap` lints

Signal's crate roots (`libsignal-protocol`, `zkgroup`) carry:

```rust
#![warn(clippy::unwrap_used)]
#![deny(unsafe_code)]
```

This workspace had done the `.unwrap()` audit once by hand
(`ENGINEERING-STANDARDS.md` §6.8); Signal makes it a standing lint. Adopted in
every crate here, later tightened to `#![forbid(unsafe_code)]`. The nine
non-test `.unwrap()` sites the lint found became `.expect("reason")`, and test
code is exempt via `#![cfg_attr(test, allow(clippy::unwrap_used))]`.

## 2. Confirms a design choice already made here: PQXDH

Signal's key agreement is PQXDH: X3DH plus an ML-KEM encapsulation, hybrid
by the same logic as this workspace's core (`docs/SYSTEMIZATION.md` §4).
Independent confirmation of the hybrid-KEX bet, not a change of direction.

## 3. A real gap, since closed with a bounded scope

Signal's Double Ratchet gives **post-compromise security**: a session whose
state leaked becomes secure again once fresh key material is mixed in.
`novachannel`'s handshake derives directional keys once per session, so it
had forward secrecy from ephemeral keys but no recovery from a mid-session
compromise.

Signal now depends on
[`signalapp/SparsePostQuantumRatchet`](https://github.com/signalapp/SparsePostQuantumRatchet)
(`spqr`, pinned to `v1.5.3` in libsignal's workspace `Cargo.toml`), a
post-quantum ratchet. Its source (`src/v1/unchunked/send_ek.rs` and
neighbors) shows the step is not "run ML-KEM again" but
`incremental_mlkem768`: a re-encoding of ML-KEM-768 into
`header`/`ek`/`ct1`/`ct2` pieces sent through a
`KeysUnsampled -> HeaderSent -> EkSent -> EkSentCt1Received` state machine,
erasure-coded in `src/v1/chunked/`, and verified with `hax_lib`/F* and
ProVerif. Cloning that from one reading would be overclaiming.

`novachannel::ratchet` (`ENGINEERING-STANDARDS.md` §6.15) provides the same
two properties more simply: an HMAC-SHA256 chain for per-message forward
secrecy and a periodic hybrid X25519 + ML-KEM-1024 re-key reusing `kex.rs`
for post-compromise security. The tradeoffs: a step sends a full ~1.6KB KEM
payload each way rather than spreading it across messages, and it has
adversarial unit tests rather than formal verification. Records may arrive out
of order within a bound (a capped skipped-key cache).

The incremental variant (`initiate_incremental_ratchet`,
`docs/SYSTEMIZATION.md` §4.1.1) is closer to SPQR's *shape*: the re-key is
split into erasure-coded chunks (via `reed_solomon_simd`) so some can be
lost. It splits ordinary serialized ML-KEM-1024 bytes rather than
re-encoding the algorithm, and its framing and reassembly are this project's
own and unreviewed. Building it showed chunks can't use the record
sequence, and found a stale-root-key bug on late chunks
(`ENGINEERING-STANDARDS.md` §6.17).

## 4. A real alternative, deliberately not adopted: Sigma protocols

Signal's `zkgroup` and `poksho` aren't SNARKs or STARKs. `poksho`'s
`Cargo.toml` depends only on `curve25519-dalek`, `hmac` and `sha2`: these are
Sigma protocols, discrete-log zero-knowledge proofs over Ristretto. For linear
statements they are far simpler, faster and smaller than circuit-based
proofs, and production-hardened since 2020.

`novachannel-rln` didn't use them because discrete log is exactly what a
quantum computer breaks, and post-quantum soundness is the RLN crate's reason
for being a STARK (`docs/SYSTEMIZATION.md` §3.2). Signal's credentials don't
claim to need that. Both choices fit their threat models; the STARK is a
deliberate trade for PQ safety at a measured size cost, and a Sigma-protocol
RLN would be smaller and faster until a cryptographically relevant quantum
computer exists.

## 5. Gaps from an earlier comparison, since closed

An earlier pass against Signal's full protocol suite named an asynchronous
prekey handshake, sealed sender and Sesame-style multi-device as missing. All
three now exist (`crate::x3dh`, `crate::sealed_sender`,
`crate::multidevice`; `docs/SYSTEMIZATION.md` §4.2-§4.4), each modeled on
Signal's design. Still not attempted: a formally verified ratchet matching
SPQR (§3), `zkgroup`-style anonymous credentials (§4, by choice), and
deniability for the live handshake (`crate::x3dh` is deniable;
`crate::handshake` stays transcript-signed and non-repudiable by design).

## Is this workspace production-ready?

No. The specific reasons, compared with Signal:

- **No external audit** of anything here; Signal's code is heavily audited.
- **Verification depth:** the ratchets are hand-tested, not hax/F*/ProVerif
  verified like SPQR; the Poseidon2 port and erasure-coding framing have had
  no outside review.
- **A malformed RLN proof can abort the verifying process** through
  winterfell's unbounded allocation (`novachannel_rln::air::verify`; pinned by
  a test). Isolate that call.
- **Fuzzing is far smaller than Signal's:** 8 targets on ClusterFuzzLite. Six
  were rewritten in September 2026 because they weren't testing what their
  execution counts suggested (`ENGINEERING-STANDARDS.md` §6.31-§6.32).
- **No directory service:** device lists and identities must be fetched and
  trusted by the caller; the unauthenticated multi-device path remains
  available.
- **The networked examples aren't production transports:** the MPC relay is
  unauthenticated and `TcpServerStorage` assumes one trusted connection.
- **RLN proofs are large:** 211x a Groth16 proof at the default
  (`docs/SYSTEMIZATION.md` §3.2), a bandwidth cost no deployment has accepted
  yet.

That is a reason not to call it production-ready, not a reason it shouldn't
exist: a correct, tested, honestly scoped reference implementation is useful
in its own right.
