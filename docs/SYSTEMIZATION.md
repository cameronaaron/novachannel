# A Hybrid Post-Quantum Messaging Stack: Engineering Report

**Status: engineering report, not a research paper.** This document
describes what was built in the `novachannel` workspace, why each design
choice was made, what was verified and how, and — explicitly — which parts
are novel contributions versus reuses of published work. Where a claim
would need a security proof, cryptanalysis, or peer review to be
publishable, this document says that instead of asserting the claim.

## Abstract

`novachannel` is a five-crate Rust workspace implementing a hybrid
classical/post-quantum secure channel (`novachannel`), zero-knowledge
rate-limiting nullifiers over a hash-based STARK
(`novachannel-rln`), differential-privacy-calibrated cover traffic
(`novachannel-dp`), oblivious server-side storage
(`novachannel-oram`), and threshold key generation, decryption, and
signing (`novachannel-mpc`, including FROST). Every non-trivial primitive
composes standard, published constructions; the contribution here is a
verified, tested, honestly-scoped *integration* of them into a coherent
metadata-resistant messaging stack, not a new cryptographic primitive. One
component (`novachannel-rln`'s in-circuit hash) is genuinely new code and
is flagged as unvetted rather than presented as equivalent to a
cryptanalyzed permutation.

## 1. What "novel" means here, precisely

Before describing the system, it's worth being precise about what kind of
novelty is and isn't being claimed, because the difference matters and is
usually where over-claiming creeps in.

**Not claimed**: a new hardness assumption, a new proof technique, a new
attack, a new asymptotic bound with a proof, or cryptanalysis of any
primitive used here. None of that exists in this workspace.

**Claimed, narrowly**: the specific combination of a hash-based (and
therefore post-quantum-safe by construction, no elliptic-curve or pairing
assumption) STARK proving *both* Merkle membership *and* a Shamir-style
rate-limit share inside one proof (§3) is, as far as this project's authors
could determine, not something with a public reference implementation —
production RLN systems (Semaphore-RLN, Waku-RLN) prove the same combined
relation using a pairing-based Groth16 circuit instead. Whether that
specific substitution (STARK instead of Groth16, for this specific
combined relation) constitutes a publishable systems contribution is a
question for people who do that peer review, not a conclusion this
document draws for them. What this document claims is narrower and
checkable: the STARK version was built, a real bug in it was found and
fixed (§3.3), and it is verified end-to-end against a reference
implementation of the non-ZK relation.

## 2. Architecture

```
                    ┌─────────────────────────┐
                    │   novachannel (core)     │
                    │  hybrid PQ/classical      │
                    │  authenticated channel    │
                    └───────────┬───────────────┘
                                │ transports messages for
        ┌───────────────────┬──┴───────────────┬────────────────────┐
        │                    │                   │                    │
┌───────▼────────┐  ┌───────▼────────┐  ┌───────▼────────┐  ┌────────▼───────┐
│ novachannel-rln │  │ novachannel-dp │  │novachannel-oram│  │ novachannel-mpc│
│ anonymous       │  │ cover traffic  │  │ oblivious      │  │ DKG, threshold │
│ rate-limited    │  │ scheduling     │  │ server state   │  │ decrypt, FROST │
│ membership proof│  │ (metadata      │  │ (metadata      │  │ signatures     │
│                 │  │ resistance)    │  │ resistance)    │  │ (mixnode trust)│
└─────────────────┘  └────────────────┘  └────────────────┘  └────────────────┘
```

The four peripheral crates are independent — none depends on another —
and each addresses a distinct point in the threat model a naively
"encrypted" messaging system leaves open: encryption alone doesn't hide
*who* sent a message (→ RLN), *when* they sent it relative to their queue
state (→ DP), *which server record* their session touched (→ ORAM), or
*who controls* a relay node's key (→ MPC/FROST).

## 3. `novachannel-rln`: zero-knowledge rate-limiting nullifiers

### 3.1 The relation, and why it must be proved as one circuit

RLN (Rate-Limiting Nullifiers) lets a member of a group send a message
anonymously — a ZK proof shows membership without revealing which
member — while enforcing a per-epoch rate limit: a member who sends a
*second* message in the same epoch leaks their identity secret to anyone
who observes both messages, via Shamir-style polynomial reconstruction.
Concretely, for secret `sk`, epoch `e`, message binding value `x`:

- membership: `Hash(sk, 0)` is a leaf of a public Merkle tree with root `R`
- rate-limit share: `a1 = Hash(sk, e)`, `y = sk + a1·x`

The relation must be proved as *one* circuit, not membership-then-share as
two independent steps, because decoupling them breaks the scheme: nothing
would force the *same* `sk` to appear in both the membership proof and the
share computation, so a prover could satisfy membership once and then
compute the rate-limit share with a different `sk` per message, defeating
the entire point of the rate limit. This is not a new observation — it's
exactly why real RLN circuits (Semaphore-RLN) already combine both checks
in one SNARK. The choice made here is the proof *system*: a STARK instead
of a Groth16 SNARK.

### 3.2 Why a STARK, and the cost of that choice

STARKs need no trusted setup and their soundness rests on hash-function
collision resistance, not on an elliptic-curve or pairing assumption — so
unlike Groth16, they don't need to be replaced when a quantum computer
threatens discrete-log-based curves. That is the actual motivation, and it
is a real one for a project already built around post-quantum
primitives elsewhere in the stack (§4).

The cost: verifying membership inside a STARK circuit needs an
algebraic hash whose round function is a low-degree polynomial (so it
compiles to inexpensive AIR transition constraints). No published Rust
implementation of a STARK-friendly hash matched the specific field
(`winterfell`'s `f128`) and framework version used here, so this project
defines one (`NovaRescue`, `crates/rln/src/permutation.rs`): a
Rescue-Prime-shaped permutation (additive round constants, `x^5` S-box, a
Cauchy-construction MDS matrix — the MDS property follows from the Cauchy
construction algebraically, not from manual verification of a hardcoded
matrix) with round constants generated deterministically from a fixed seed
rather than hand-copied from a paper.

**This is the one place this project introduces new cryptographic code,
and it has not been cryptanalyzed.** Poseidon, Rescue-Prime, Griffin, and
similar algebraic hashes earned trust through years of public differential/
algebraic cryptanalysis before their round counts were considered safe.
`NovaRescue` has had none. It demonstrates the *shape* of a working
STARK-based RLN circuit; it is not a hash function this document
recommends deploying.

There is a second, more concrete cost: proof size. Unlike Groth16 (2 G1 +
1 G2 elements — 128 bytes compressed on BN254, independent of circuit
size or chosen security level), a STARK's proof size scales with both the
circuit and the query count chosen for soundness. `crates/rln/examples/proof_size.rs`
measures this crate's actual proofs — same tiny RLN circuit (§3.4),
`ProofOptions`' query count varied with blowup factor held at 8 (this
AIR's minimum, derived from its own constraint degrees):

| queries | blowup | conjectured bits | measured proof size |
| --- | --- | --- | --- |
| 16 | 8 | ~48 | ~10.6 KB |
| 32 | 8 (this crate's default) | ~96 | ~18.3–18.6 KB |
| 64 | 8 | ~192 | ~29.5–29.8 KB |

(sizes vary a few percent run to run — the circuit's own randomized
witness data — hence the ranges; run the example to reproduce.) That's
roughly **85–230x** Groth16's constant 128 bytes, for a genuinely tiny
circuit — the gap would only widen for a production-sized membership set.
If per-message bandwidth matters more than avoiding a trusted setup and
PQ-hardening the proof system for a given deployment, that's a real reason
to prefer Groth16 instead; this project's choice optimizes for the
opposite priority, and the number above is what that choice actually
costs, not an abstract tradeoff.

### 3.3 A defect found by validating against ground truth

While building the circuit, a discrepancy surfaced between the STARK's
computed Merkle root and a plain reference implementation of the same
tree. Root-causing it required a white-box probe comparing intermediate
values level-by-level rather than trusting the black-box "proof doesn't
verify" signal — the STARK's trace-building loop was running one fewer
hash-permutation block than the Merkle chain actually needs (it counted
tree *levels*, which is one less than the number of *hash calls* a leaf
plus its combine steps require). Every individual piece — the injection
formula, the AIR's boundary constraints, the tree's own path/verify
logic — was independently correct; the defect was purely in how many times
a loop ran. Fixed by re-deriving every dependent row-index constant from a
single corrected block count rather than patching the one visible symptom,
so the same class of off-by-one couldn't resurface in a sibling constant.

### 3.4 Verification performed

- `valid_membership_proof_verifies`, `tampered_proof_bytes_are_rejected`,
  `wrong_root_is_rejected`: the proof accepts valid witnesses and rejects
  tampering and wrong public inputs.
- `two_messages_in_same_epoch_reveal_the_secret_key`,
  `messages_in_different_epochs_do_not_leak_the_key`: the rate-limit
  mechanism's core claim — Shamir reconstruction across two same-epoch
  shares, and non-reconstruction across different epochs — checked
  directly against the field arithmetic, not merely asserted.
- Concrete parameters: Merkle depth 5 (32-member group), permutation
  width 4, 7 rounds per hash call, trace length 64 rows (a power of two,
  as the STARK domain requires) — small values chosen for a runnable
  reference implementation, not claimed as production-scale.

## 4. `novachannel` (core): hybrid post-quantum channel

Hybrid key exchange (X25519 + ML-KEM-768) and hybrid signatures (Ed25519 +
ML-DSA-65) — the exact algorithms NIST ratified as FIPS 203 and FIPS 204 in
2024, via RustCrypto's pure-Rust `ml-kem`/`ml-dsa` crates (this project
originally used `pqcrypto-kyber`/`pqcrypto-dilithium`, C bindings to the
pre-standardization round-3 submissions; migrating was a real breaking
change to the wire format, documented as such, not a transparent bump).
"Hybrid" here has a specific, standard meaning: the session key requires
breaking *both* the classical and the post-quantum leg, so a future
cryptanalytic break of either alone — including of ML-KEM/ML-DSA
themselves, which are new enough that "no known break" is a weaker
statement than for AES or RSA at maturity — does not by itself compromise
past sessions. This composition pattern is what Chrome, Cloudflare, and
OpenSSH already deploy; it is current best practice, not a novel
contribution.

The three-message handshake signs the transcript rather than a fixed
challenge, binding identity to *this specific exchange* rather than to a
replayable value, and derives traffic keys from a hash of the entire
transcript including both signatures — standard "channel binding," applied
here rather than invented here.

### 4.1 `ratchet`: forward secrecy per message, post-compromise security per epoch

The plain handshake above derives one pair of directional keys once, at
session start; every record after that just increments a sequence number
under those same keys. `novachannel::ratchet` is an additive, opt-in layer
seeded from the handshake's transcript hash (`EstablishedSession::ratchet_root`,
via its own HKDF label — independent of the plain transport keys) that adds
two properties the base session doesn't have: a fresh, single-use AEAD key
per record derived from a one-way HMAC-SHA256 hash chain (forward secrecy —
recovering the chain's current state cannot recover a past message key),
and an explicit, coordinated re-key step (`initiate_ratchet`) that reruns
the same hybrid X25519 + ML-KEM-768 exchange from `kex.rs` mid-session and
mixes the result into a fresh root key (post-compromise security — a
session compromised at some point recovers confidentiality once a ratchet
step completes).

This is deliberately not a reimplementation of Signal's own post-quantum
ratchet, [SPQR](https://github.com/signalapp/SparsePostQuantumRatchet) —
its real mechanism, read directly from `src/v1/unchunked/send_ek.rs`
rather than assumed from its README, is a from-scratch incremental
re-encoding of ML-KEM-768 spread across multiple round trips with
Reed-Solomon erasure coding and hax/F*+ProVerif formal verification, which
is out of reach for a from-scratch build checked only by hand-written
tests. `novachannel::ratchet` instead does a synchronous, one-shot hybrid
re-key — a full ~1.2KB KEM payload each way, not spread thin — giving the
same two named properties through a mechanism small enough to actually
verify here. It also, unlike the base transport, requires reliable
in-order delivery (no reordering tolerance), and rejects concurrent
ratchet initiation from both peers rather than trying to resolve it. Full
scoping rationale in the module's own doc comment
(`crates/core/src/ratchet.rs`) and `ENGINEERING-STANDARDS.md` §6.15.

## 5. `novachannel-dp`: formal differential privacy on the presence bit

The specific engineering claim — "an observer watching the channel has
bounded statistical advantage in distinguishing a real send from cover
traffic" — is given an exact mechanism and an exact proof, not just
asserted: randomized response. A real message is always sent immediately;
an empty slot sends a dummy independently with probability `q = e^{-ε}`.
This gives *exact* `ε`-differential privacy for the single-slot presence
bit (not an approximation, and not requiring a `δ` slack term):

```
Pr[send | real message]  / Pr[send | no message]  = 1/q = e^ε
Pr[silent | real message] / Pr[silent | no message] = 0/(1-q) = 0 ≤ e^ε
```

both directions bounded by `e^ε`, which is the definition being satisfied.
Composition across many slots uses the two standard textbook bounds
(sequential, and the tighter Dwork-Rothblum-Vadhan advanced composition) —
foundational results from the differential privacy literature, not new
ones. `empirical_likelihood_ratio_matches_bound` checks the *measured*
ratio from 200,000 simulated trials against the theoretical `e^ε`, rather
than asserting a property that would pass under a broken calibration.

`docs/RLN_DP_COMPOSITION.md` works out, from first principles, whether
composing this with `novachannel-rln`'s rate limit — which gives a user a
real incentive to correlate their true send pattern within an epoch —
costs any additional privacy budget. Short answer: no, and the reason is
structural (DP composition theorems are proved over the mechanism's own
randomness, never assuming anything about how the underlying secret bits
are correlated), not a new argument specific to this pairing — but the
same document is precise about what that argument does *not* cover
(cross-epoch traffic-pattern fingerprinting), which is a real, different,
still-open gap.

## 6. `novachannel-oram`: access-pattern obliviousness for server state

Standard Path ORAM (Stefanov et al., CCS 2013): `O(log n)` bucket touches
per access to hide *which* server-side record (rate-limit counter,
nullifier-set entry, ...) a request touched — a channel that's otherwise
end-to-end encrypted can still leak identity through server access
patterns alone. `O(1)`-client-storage ORAM was requested during this
project's design phase and explicitly not attempted: the
Goldreich-Ostrovsky lower bound proves it impossible, not merely
difficult, so the honest response was to say so rather than silently
under-deliver or silently ignore the request.

The one structural choice worth naming: the secret client state (position
map, stash) and the server-visible bucket storage are separated by a
`ServerStorage` trait rather than living in one struct with a comment
warning against colocating them in a real deployment. A documented rule a
future change can quietly violate is weaker than a type the compiler
enforces; `client_works_unchanged_against_a_different_server_impl` proves
the separation is real by running the full protocol through a second,
independent `ServerStorage` implementation with zero changes to the client
logic.

Obliviousness alone assumes the server executes the protocol honestly —
nothing stops an *active* server from tampering with, dropping, or
replaying bucket contents. `VerifiableServerStorage` closes that: a Merkle
hash tree layered over the same binary tree Path ORAM already touches, so
verification costs nothing beyond an access's existing `O(log n)` bound.
Building it surfaced a real bug the same way §3.3's did — the write-back
path stored each node's raw bucket-content hash instead of the properly
combined parent/child hash, so every access after the first failed its
own integrity check against a perfectly honest server; found by building a
two-access reproduction and printing every intermediate hash rather than
by re-reading the code, and fixed by returning every node's combined hash
from the recomputation step instead of just the final root.
`a_server_that_replays_a_stale_bucket_is_caught` is the sharper of the two
adversarial tests here: replaying a bucket that was *itself* genuinely
valid at an earlier point is exactly what a "does this look well-formed"
check would miss, and only a root comparison against the client's own
history catches it.

## 7. `novachannel-mpc`: threshold trust for relay operators

A conventional mix-network relay has one operator holding one decryption
key — coercible, subpoenable, or simply malicious, exposing every onion
layer meant for that node. `novachannel-mpc` splits a relay's key across
`n` independent operators via a joint-Feldman DKG (commit-then-reveal,
specifically to block the classic bias attack where a rushing participant
picks their contribution after seeing everyone else's), so that
compromising the relay requires compromising `t` operators simultaneously,
not one. A single faulty dealer is identified and excluded
(`identify_faulty_dealers`) rather than aborting the whole key-generation
run for everyone.

FROST (Flexible Round-Optimized Schnorr Threshold signatures, RFC 9591,
2024) reuses the same DKG output to let the same operator quorum jointly
*sign* — e.g. attesting to a routing table — producing an ordinary Schnorr
signature indistinguishable on the wire from a single-signer one. This
implementation's hash domain-separation and byte encoding were
reverse-engineered against, and are checked directly by
`official_test_vector_matches_rfc9591` against, the official
`FROST(ristretto255, SHA-512)` test vector published in the CFRG
`draft-irtf-cfrg-frost` repository — every signature share and the final
aggregated signature reproduce the vector's own values exactly. The one
piece of the RFC intentionally not matched is `nonce_generate`'s
deterministic seed-to-nonce derivation; this implementation draws nonces
from a CSPRNG instead, a valid but not byte-identical FROST instantiation,
stated as such rather than implied to be full interoperability.

`novachannel-rln` (§3) proves anonymous membership against a Merkle root
but has nothing to say about how a client comes to trust that a given
root is the real, current one rather than an attacker's fabrication.
Composing it with this crate's FROST closes that gap without adding a
real dependency between the two: `MerkleTree::root_bytes()` returns an
opaque byte string, `frost::sign`/`verify` already take an opaque
message, and the only place the two crates meet is a `[dev-dependencies]`
edge scoped to `crates/mpc/tests/frost_signs_rln_root.rs`. A client then
needs to trust exactly one long-lived value — the mixnode quorum's group
public key — the same trust-anchor shape `novachannel::handshake`'s
peer-identity pinning already uses.

## 8. What was actually verified, and how

49 tests across the workspace, all adversarial where the claim is
adversarial (not merely "does the happy path run"): tamper, replay,
wrong-key, wrong-message, below-threshold-quorum, server-tampers-a-bucket,
server-replays-a-stale-bucket, cross-epoch/same-epoch rate-limit tests, and
`novachannel::ratchet`'s epoch-transition/stale-epoch/concurrent-initiation
tests (§4.1) each try to break a specific stated property rather than
exercise code paths incidentally. `scripts/check.sh` runs
`cargo fmt --check`, `cargo clippy --workspace --all-targets --release -D
warnings`, and the full test suite as the standing bar for "done";
`.github/workflows/ci.yml` runs the identical script, not a
reimplementation of its steps, on every push and pull request.

`ENGINEERING-STANDARDS.md` in the repository root is the fuller,
continuously-updated record of specific defects found, how each was
diagnosed, and what class of defect each fix was checked against
recurring — this document summarizes the system; that one is the audit
trail.

## 9. Limitations and what would be needed for a real research contribution

Stated plainly, per §1:

- `NovaRescue` needs independent cryptanalysis (differential, linear,
  algebraic) before any deployment claim beyond "reference implementation
  of a circuit shape" is defensible. This is a research task for someone
  with that specialization, not an engineering task this project can
  complete by writing more code.
- Whether STARK-based RLN with this combined-relation circuit design is
  actually novel relative to the full literature (including unpublished
  or industry-internal implementations this project's authors have no
  visibility into) has not been established by a systematic literature
  review — only checked against the publicly known production systems
  named in §3.1.
- A publishable version of any claim here would need: a formal security
  reduction (not just adversarial unit tests), comparison against related
  work with matched assumptions, and peer review. None of that exists in
  this repository, and this document does not claim it does.

## Reproducing the claims in this document

```
git clone <this repo>
cd novachannel
./scripts/check.sh          # fmt, clippy -D warnings, full test suite
cargo test -p novachannel-mpc --release official_test_vector_matches_rfc9591
cargo test -p novachannel-rln --release   # requires --release; see novachannel_rln::lib docs
cargo run -p novachannel-rln --release --example proof_size   # §3.2's proof-size table
cargo test -p novachannel-mpc --release --test frost_signs_rln_root
```
