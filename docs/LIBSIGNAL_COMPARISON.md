# What libsignal actually does, checked against this workspace

**Status: findings grounded in the real repository** (`github.com/signalapp/libsignal`,
fetched directly — file listings, `Cargo.toml`s, and `lib.rs` headers quoted
below are real, not recalled from training data), not a generic "best
practices" list. Signal's Rust core is the most-audited, most-deployed
messaging cryptography codebase that exists; where this workspace diverges
from it, that divergence is worth being deliberate about, not accidental.

## 1. Adopted directly: `deny(unsafe_code)` + `warn(clippy::unwrap_used)`

Every Signal crate root carries this pair. Confirmed in `libsignal-protocol`'s
`lib.rs`:

```rust
#![warn(clippy::unwrap_used)]
#![deny(unsafe_code)]
```

and identically in `zkgroup`'s. This workspace had already done the
`.unwrap()` audit manually (`ENGINEERING-STANDARDS.md` §6.8) — a one-time,
human-run check. Signal's version is the same audit turned into a standing
compiler lint that fires on every future change, not just the one commit
where someone remembered to look. Adopted verbatim in every crate here
(`crates/*/src/lib.rs`): `#![deny(unsafe_code)]` (free — this workspace
already had zero `unsafe` blocks, so the lint costs nothing and forecloses
ever adding one silently) and `#![warn(clippy::unwrap_used)]`, with the
nine non-test `.unwrap()` call sites the lint found converted to
`.expect("reason")` (the fix clippy itself recommends), and test code
exempted via `#![cfg_attr(test, allow(clippy::unwrap_used))]` — `.unwrap()`
on a value the test itself just constructed is normal, not a smell.

## 2. Validates a design choice already made here: PQXDH

Signal's production key-agreement is PQXDH — X3DH extended with a
Kyber/ML-KEM encapsulation alongside the classical X25519 exchange, hybrid
by the same logic this workspace's `novachannel` core already uses
(`docs/SYSTEMIZATION.md` §4). This isn't new information changing a
decision; it's independent confirmation that the hybrid-KEX pattern this
workspace bet on is exactly what the most heavily-reviewed production
messaging system in existence also shipped.

## 3. A real, concrete gap — since closed with an explicitly bounded scope

Signal's Double Ratchet re-keys on essentially every round trip, giving
**post-compromise security**: if a session's state is exposed at some
point, *future* messages become secure again once fresh key material is
mixed in, without needing to restart the session. `novachannel`'s
handshake (`crates/core/src/handshake.rs`) derives one pair of directional
keys once, at session establishment, and every subsequent record just
increments a sequence number under those same keys (`transport.rs`). Every
session gets forward secrecy from fresh ephemeral handshake keys, but
nothing there recovers if a session's derived keys are exposed mid-session.

Signal's own ratchet depends on a separate crate,
[`signalapp/SparsePostQuantumRatchet`](https://github.com/signalapp/SparsePostQuantumRatchet)
(`spqr`, pinned to tag `v1.5.3` in libsignal's workspace `Cargo.toml`) — a
**post-quantum** ratchet, meaning the ongoing re-keying itself resists a
future quantum adversary, not just the initial handshake. Reading its real
source (`src/v1/unchunked/send_ek.rs` and neighbors, not just the README)
turned up something the README alone doesn't convey: SPQR's ratchet step
isn't "run ML-KEM again" — it's `incremental_mlkem768`, a from-scratch
re-encoding of ML-KEM-768 that splits the encapsulation key and ciphertext
into a `header`/`ek`/`ct1`/`ct2` sequence sent across an explicit
`KeysUnsampled -> HeaderSent -> EkSent -> EkSentCt1Received` state machine
(plus Reed-Solomon erasure coding over that, in `src/v1/chunked/`), all
checked with `hax_lib`/F* refinement types and separate ProVerif models.
That's not a small patch to add on top of the existing hybrid handshake —
it's a from-scratch, formally-verified cryptographic construction, and
cloning it from one source read would be exactly the kind of overclaiming
this document exists to avoid.

`novachannel::ratchet` (added subsequently, see
`ENGINEERING-STANDARDS.md` §6.15) closes the gap a different way: the same
two named properties — forward secrecy per message via an HMAC-SHA256 hash
chain, post-compromise security via a periodic hybrid X25519+ML-KEM-768
re-key — through a synchronous, one-shot re-key (reusing the *existing*,
already-tested `kex.rs` exchange, not a new incremental encoding) instead
of SPQR's chunked/erasure-coded one. The tradeoff is explicit: a ratchet
step costs one full ~1.2KB KEM payload each way instead of being spread
thin across many messages, it requires in-order delivery (no reordering
tolerance the way the base transport has), and it has ordinary adversarial
unit tests, not hax/F*/ProVerif-level formal verification. A real,
useful, honestly-scoped gap-closer — not a claim of parity with SPQR.

## 4. A genuine alternative worth naming, not necessarily adopting: Sigma protocols over STARKs

Signal's `zkgroup` (group membership / profile credentials) and `poksho`
("proof of knowledge of a Sho" — their Fiat-Shamir transcript
abstraction) are **not** SNARKs or STARKs. Confirmed from `poksho`'s
actual `Cargo.toml`: `curve25519-dalek`, `hmac`, `sha2` — nothing else.
It's Sigma-protocol machinery: classical, discrete-log-based
zero-knowledge proofs of knowledge, generalized via a small statement DSL,
over Ristretto. For their specific relation (knowledge of a value
satisfying a linear/homomorphic statement), this is dramatically simpler,
faster, and smaller than general-purpose circuit-based proving — and it's
been production-hardened since 2020.

This is a real, considered alternative to `novachannel-rln`'s STARK
approach, and it's worth being precise about why this workspace didn't
converge on it: Sigma protocols are discrete-log-based, which is exactly
the assumption a quantum computer breaks. `novachannel-rln`'s entire
reason for existing as a STARK rather than reaching for the simpler tool
is post-quantum soundness (`docs/SYSTEMIZATION.md` §3.2) — a property
Signal's own group-credential system does not have and, as of this
comparison, does not claim to need for that specific use case. Both
choices are defensible for their respective threat models; the point of
naming this is that the STARK is a *deliberate* trade for PQ-safety at a
real proof-size cost (measured: §3.2, `examples/proof_size.rs`), not the
default "obviously correct" choice — a simpler Sigma-protocol RLN would be
smaller and faster today, and would need replacing the day a
cryptographically-relevant quantum computer exists.

## Is this workspace production-ready?

No, and the specific reasons (not a hedge):

- `NovaRescue` (the RLN in-circuit hash) has had zero independent
  cryptanalysis (`docs/SYSTEMIZATION.md` §3.2, §9).
- The ratchet added per §3 gives real forward secrecy and post-compromise
  security, but is a synchronous, one-shot, hand-tested design, not
  SPQR's chunked/erasure-coded, hax/F*/ProVerif-verified one — see §3 for
  the precise gap that remains between the two.
- No fuzzing anywhere in this workspace. Signal fuzzes `libsignal-protocol`
  extensively; nothing here has been fuzzed at all.
- No external security audit of anything in this workspace.
- The DKG's complaint mechanism (`novachannel-mpc`) has no networked
  broadcast/reveal implementation — reference-implementation only.
- Every `ServerStorage`/transport "server" in this workspace
  (`InMemoryServer`, etc.) is an in-process reference implementation, not
  a networked one.
- RLN proofs run 85–230x larger than a Groth16 equivalent for the same
  relation (§3.2) — a real bandwidth cost nobody has yet decided is
  acceptable for a specific deployment.

None of that is a reason not to have built this — a correct, tested,
honestly-scoped reference implementation of a real system is a legitimate
and useful thing to have. It's a reason not to call it production-ready,
and the standards doc's whole purpose is making sure that distinction
stays visible instead of eroding one confident-sounding sentence at a
time.
