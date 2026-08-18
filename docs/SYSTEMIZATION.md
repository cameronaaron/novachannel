# A Hybrid Post-Quantum Messaging Stack: Engineering Report

**Status: engineering report, not a research paper.** This document
describes what was built in the `novachannel` workspace, why each design
choice was made, what was verified and how, and — explicitly — which parts
are novel contributions versus reuses of published work. Where a claim
would need a security proof, cryptanalysis, or peer review to be
publishable, this document says that instead of asserting the claim.

## Abstract

`novachannel` is a five-crate Rust workspace implementing a hybrid
classical/post-quantum secure channel (`novachannel`, with async/deniable
X3DH session establishment, sealed sender, Sesame-style multi-device
fan-out, a one-shot or incremental/erasure-coded ratchet, and an
`O(log n)` TreeKEM-inspired group ratchet), zero-knowledge
rate-limiting nullifiers over a hash-based STARK
(`novachannel-rln`), differential-privacy-calibrated cover traffic
(`novachannel-dp`), oblivious server-side storage
(`novachannel-oram`), and threshold key generation, decryption, and
signing (`novachannel-mpc`, including FROST). Every non-trivial primitive
composes standard, published constructions; the contribution here is a
verified, tested, honestly-scoped *integration* of them into a coherent
metadata-resistant messaging stack, not a new cryptographic primitive. Two
components are genuinely new code and flagged as unvetted rather than
presented as equivalent to a cryptanalyzed construction:
`novachannel-rln`'s in-circuit hash (§3.2), and the Cauchy-Reed-Solomon
erasure code the incremental ratchet uses to spread a re-key across
loss-tolerant chunks (§4.1.1).

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
compiles to inexpensive AIR transition constraints). This crate originally
defined one from scratch (`NovaRescue`: a Rescue-Prime-shaped permutation
with round constants generated deterministically from a fixed seed, over
`winterfell`'s `f128` field, at width 4) because no published Rust
implementation matched that exact field/framework combination at the
time. **That from-scratch construction has since been replaced**
(`ENGINEERING-STANDARDS.md` §6.21) by a verbatim port of
Poseidon2-over-Goldilocks from `p3-goldilocks`/`p3-poseidon2` 0.6.3 —
Plonky3's own instantiation, the hash underlying multiple independently
audited production STARK provers (Succinct's SP1, RISC Zero). Every round
constant and the internal diffusion matrix are copied directly from that
crate's source, not reinterpreted, and checked against its own published
test vector byte-for-byte
(`permutation::tests::matches_official_poseidon2_goldilocks_width8_test_vector`).
Matching a published instance meant matching its field (`f64`/Goldilocks,
not `f128`) and its smallest published width (8, not this crate's
previous 4 — `p3-goldilocks` only ships constants for widths 8, 12, 16,
and 20).

**Porting the algorithm is not the same as an independent review of this
specific port**, and this document does not claim more than the former:
a transcription error in a constant is a real bug the test-vector check
happens to catch, not one any port is guaranteed to catch in general —
see `permutation.rs`'s own module doc and `SECURITY.md` for the precise
scope of what's been checked. What porting *does* close is the risk
category §0.3 originally flagged for `NovaRescue`: an invented,
uncryptanalyzed algebraic construction with no public scrutiny at all.
That category is closed; "independently reviewed as deployed in this
crate" is not yet true, and isn't claimed to be.

There is a second, more concrete cost: proof size. Unlike Groth16 (2 G1 +
1 G2 elements — 128 bytes compressed on BN254, independent of circuit
size or chosen security level), a STARK's proof size scales with the
circuit, the query count, and the blowup factor chosen for soundness.
`crates/rln/examples/proof_size.rs` measures this crate's actual proofs —
same tiny RLN circuit (§3.4), re-measured after the Poseidon2/Goldilocks
port:

| queries | blowup | grinding | conjectured bits | measured proof size |
| --- | --- | --- | --- | --- |
| 16 | 16 | 0 | ~64 | ~13.3 KB |
| 24 | 16 | 0 (pre-hardening default) | ~96 | ~19.9 KB |
| 32 | 16 | 20 (**this crate's default**) | ~148 | ~30.0 KB |
| 48 | 16 | 0 | ~192 | ~32.7 KB |

(run the example to reproduce; exact bytes vary a little run to run from
the circuit's own randomized witness data.) At the current default, proof
size is roughly **230x** Groth16's constant 128 bytes, for a genuinely
tiny circuit — the gap would only widen for a production-sized membership
set. If per-message bandwidth matters more than avoiding a trusted setup
and PQ-hardening the proof system for a given deployment, that's a real
reason to prefer Groth16 instead; this project's choice optimizes for the
opposite priority, and the numbers above are what that choice actually
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
  width 8 (Poseidon2-over-Goldilocks's smallest published instance — see
  §3.2), 31 rounds per hash call (unchanged by the Poseidon2 port; still
  the value `crates/rln/src/permutation.rs`'s `ROUNDS` doc comment derives
  security-margin reasoning for), trace length a power of two per block
  count (as the STARK domain requires) — small values chosen for a
  runnable reference implementation, not claimed as production-scale.

## 4. `novachannel` (core): hybrid post-quantum channel

Hybrid key exchange (X25519 + ML-KEM-1024) and hybrid signatures (Ed25519 +
ML-DSA-87) — the exact algorithms NIST ratified as FIPS 203 and FIPS 204 in
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
the same hybrid X25519 + ML-KEM-1024 exchange from `kex.rs` mid-session and
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
tests. `novachannel::ratchet`'s *default* re-key
(`initiate_ratchet`/`handle_step1`/`handle_step2`) instead does a
synchronous, one-shot hybrid re-key — a full ~1.2KB KEM payload each way,
not spread thin — giving the same two named properties through a
mechanism small enough to actually verify here. It also, unlike the base
transport, requires reliable in-order delivery (no reordering tolerance),
and rejects concurrent ratchet initiation from both peers rather than
trying to resolve it. Full scoping rationale in the module's own doc
comment (`crates/core/src/ratchet.rs`) and `ENGINEERING-STANDARDS.md`
§6.15.

#### 4.1.1 An incremental, erasure-coded alternative re-key

`RatchetedSession::initiate_incremental_ratchet` /
`open_ratchet_chunk` offer a second re-key mechanism, closer in *shape* to
SPQR's chunked, loss-tolerant design without claiming parity with it. The
same KEX material the one-shot path sends in one message is split into
`data_shards + parity_shards` independently AEAD-sealed chunks via
`novachannel::erasure`, a thin wrapper around the maintained
`reed_solomon_simd` crate (Leopard-RS, FFT-based) rather than this
module's original hand-rolled Cauchy-matrix GF(2^8) implementation
(`ENGINEERING-STANDARDS.md` §6.21) — the chunk framing and reassembly
logic built on top remains this workspace's own. Any `data_shards` of the
resulting chunks, arriving in any order, interleaved with anything else,
reconstruct the original bytes exactly.

The one real architectural finding from building this: chunks cannot be
sent through the base ratchet's existing `seal`/`open` — that mechanism
requires strict, gapless in-order delivery by design (§4.1), so routing
loss-tolerant chunks through it would mean a single lost chunk
permanently desyncs the chain, defeating the entire point of erasure
coding. The incremental re-key's chunks instead travel over their own
independent AEAD key, derived via HKDF from the session's current
`root_key` (a value both peers already agree on) mixed with a fresh
random per-attempt nonce — authenticated and bound to the session without
depending on the strict sequential chain at all. This was not the first
design tried: an earlier version *did* route chunks through
`seal`/`open`'s sequence numbers, and delivering all chunks with none
missing failed outright (`Error::Replay`/`Decrypt` depending on delivery
order) — a concrete demonstration, not just an argument, of why the
strict-ordering assumption and chunk-level loss tolerance are
incompatible in the same channel.

A second real defect surfaced once chunks were decoupled this way:
reconstruction completing early (once `data_shards` chunks arrive)
advances the epoch and its `root_key` immediately, but `parity_shards`
worth of already-in-flight chunks from that same attempt can still arrive
*afterward*. Deriving their chunk key from the (now-changed) current
`root_key` produced spurious AEAD failures on those stragglers — not a
security bug (nothing forged verified), but a correctness one that would
have broken any deployment sending more chunks than the strict minimum
needed. Fixed by remembering the most recently *completed* attempt's
nonce per direction and short-circuiting stragglers matching it before
attempting to derive a key at all, found the same way every other defect
in this workspace was: by testing the full, undiminished chunk set, not
just a synthetic loss pattern chosen to avoid the bug by construction.

What this does *not* claim relative to SPQR: it serializes the same
ordinary ML-KEM-1024 bytes `kex.rs` already produces and splits *those*
into shards, rather than re-encoding the KEM algorithm's own internal
structure the way SPQR's `incremental_mlkem768` does — simpler, but it
doesn't shrink any single chunk's *meaning*, only its size on the wire.
Nor is the erasure code itself formally verified — see
`crates/core/src/erasure.rs`'s own module doc for what was and wasn't
checked (an exhaustive any-`k`-of-`n` reconstruction test for one
parameter set, not a proof for all of them).

### 4.2 `x3dh`: asynchronous, deniable session establishment

`crate::handshake` (§4) needs both peers online for a live 3-message
round trip, and authenticates by *signing the transcript* with each
party's long-term identity — a real audit-trail feature, and a real cost
for private messaging, since a leaked or subpoenaed transcript then
proves who authenticated that specific exchange. `crate::x3dh` is a
second, additive session-establishment path (producing the same
`EstablishedSession` type, so it plugs into `ratchet`/`transport`
unmodified) built on the classic X3DH design Signal's own protocol
originates from, extended with a hybrid ML-KEM-1024 leg the way Signal's
PQXDH extends it: `crate::prekey::PreKeyBundle` publishes a long-term DH
identity key, a medium-term signed prekey (DH + ML-KEM, signed once by
the owner's `Identity` and reused across many sessions), and an optional
one-time prekey. An initiator combines four Diffie-Hellman terms plus one
ML-KEM encapsulation (`DH1..DH4 + SS_pq`, module doc for exactly which
term binds which identity) into the session key in a single message —
no live round trip needed, and no signature over anything
session-specific: the only signature anywhere in the scheme covers the
reused signed-prekey pair, not this particular exchange, which is what
makes a completed session deniable — either party could derive the same
session key alone from their own secrets and the other's public keys, so
neither can prove to a third party the other participated.

### 4.3 `sealed_sender`: hiding who sent a message from whatever relays it

Neither `crate::handshake` nor `crate::x3dh` hides the sender's identity
from a server or relay routing the bytes between two peers — `crate::x3dh`
encrypts the sender's identity so only the *recipient* can read it, but a
relay never needs to open that payload to do its job. `crate::sealed_sender`
is a distinct, one-shot envelope built for exactly the relay's-eye view,
modeled on Signal's own sealed sender: a fresh, single-use ephemeral
hybrid key (X25519 + ML-KEM-1024), generated new per message and never
reused, is the only value an outside observer sees. It's combined with
the *recipient's* long-term key to derive a one-time AEAD key that seals
a `SenderCertificate` (the sender's identity, signed by whatever the
application designates as its trusted issuer — this crate has no
server/CA of its own, the same stance `crate::handshake` already takes on
peer-identity provisioning) together with the plaintext. Because nothing
about the sender's long-term identity ever appears outside that
encrypted payload, whatever relays the envelope cannot verify the sender
is legitimate before delivering it — abuse filtering on sealed traffic
has to happen after the recipient unseals it, the exact tradeoff Signal's
own sealed sender makes, not an oversight specific to this
implementation.

### 4.4 `multidevice`: Sesame-style fan-out across an account's devices

Every other module speaks in terms of one session between two parties;
real accounts have more than one device, each needing its own
`crate::x3dh` session since there's no secret shared *across* a peer's
devices to encrypt under once. `crate::multidevice::MultiDeviceSession`
is the bookkeeping that makes "send one message to this account" fan out
to a `RatchetedSession` per device the account has published a bundle
for — modeled on the role Signal's own "Sesame" algorithm plays over
X3DH/Double Ratchet, and, like Sesame, introducing no new cryptographic
primitive of its own. `ReceivingDevice` is the fan-*in* counterpart: one
physical device filing sessions from any number of distinct peer devices
(even across different peer accounts) into independent, isolated
sessions keyed by (sender identity, device id).

Trusting *which* devices belong to an account at all is a separate
problem `RemoteAccount::new`/`add_device` don't solve on their own — a
MITM controlling wherever bundles are fetched from could otherwise inject
an unauthorized device. `SignedDeviceList` closes that: the account's own
long-term signing identity (distinct from any one device's) attests to a
versioned list of `(device id, identity, DH identity)` triples.
`RemoteAccount::from_signed_device_list` verifies that signature and
rejects any supplied bundle whose identity or DH identity doesn't match
what the list authorizes for its device id, and
`MultiDeviceSession::sync_from_signed_device_list` additionally rejects a
list that isn't strictly newer than the last one accepted (blocking a
rollback that would hide a revocation) and automatically drops sessions
for devices a newer list no longer includes. What it still does not
attempt: retroactive history sync to a newly linked device (each
device's session starts exactly where its own `crate::x3dh` handshake
began), and *delivering* a `SignedDeviceList` in the first place — this
crate has no directory service, so fetching one and deciding which
account key to trust as its signer remain the caller's problem, the same
scope boundary `crate::handshake` already draws for peer-identity
provisioning.

### 4.5 `group`: `O(log n)` group rekeying via a TreeKEM-inspired ratchet

`crate::multidevice` (§4.4) fans one sender's message out to every device
of a *known set of peers*; it says nothing about groups whose membership
itself changes over time, or about doing that at less than `O(n)` pairwise
sessions. `crate::group::Group` borrows MLS/TreeKEM's central idea — an
array-based binary tree where committing a membership change or a
plain re-key means re-encrypting one root-to-leaf path, each step sealed
to the resolution of its sibling subtree so only current members can
decrypt it — reusing this crate's own primitives (hybrid X25519 +
ML-KEM-1024 sealing, HKDF, the hybrid Ed25519 + ML-DSA-87
`crate::identity::Identity` for signing commits) rather than a second,
independent set of cryptographic building blocks. It is explicitly **not**
RFC 9420: no TLS presentation-language wire encoding, no HPKE per RFC 9180
specifically, no X.509/credential machinery, no interoperability with any
other MLS implementation, fixed capacity chosen once at creation (no tree
resizing), one proposal per commit, and current-epoch-only message
decryption with no MLS "secret tree" — a member's send chain for an epoch
is a single forward hash chain, mirroring `crate::ratchet::ChainKey`, so
in-order delivery within an epoch is required. What is preserved is what
actually justifies TreeKEM over pairwise ratchets: `O(log n)` hybrid-sealed
values per commit instead of one per other member, forward secrecy and
post-compromise security on every commit, and a removed member
structurally excluded going forward — their entire ancestor path is
blanked and never re-sent, not merely told to stop.

A `LeafKeyPackage` — the public half of a prospective member's leaf,
published so an existing member can invite them — carries a
proof-of-possession signature binding its `PublicIdentity` to its leaf key
material, checked by every deserialization path before the package is
trusted; without it, a `LeafKeyPackage` naming a real victim's identity
could be paired with an attacker's own key material by whoever publishes
it, the same class of gap `SignedPreKey` (§4.2) and `SignedDeviceList`
(§4.4) already close for their own published key material.
`WelcomeSnapshot::read`'s `capacity`/`target_leaf` fields are validated
against the same invariant `Group::create` enforces before either drives
an allocation or an index — both defects, and why they're reachable by
anyone who merely knows a victim's published `LeafKeyPackage` rather than
by an actual group member, are recorded in
`ENGINEERING-STANDARDS.md` §6.23.

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

**`Dealer`, `frost`, and `combine_partials` are entirely classical
elliptic-curve constructions** — every one of them collapses the moment a
cryptographically relevant quantum computer breaks Ristretto255's
discrete log, unlike the rest of this workspace's hybrid PQ/classical
design (§4). No production-ready post-quantum threshold *signature*
scheme exists to replace FROST with (checked directly, not assumed —
the closest candidate, `lattice-safe/threshold-ml-dsa`, is unaudited
research code, and NIST's IR 8214C is a call for submissions, not a
standard), so that gap stays open for callers who need threshold signing
specifically. But the mixnode-operator threat model this crate actually
serves — no single operator can decrypt traffic alone — is a threshold
*decryption* problem, not a signing one, and that narrower problem has a
real answer buildable from primitives already vetted elsewhere in this
workspace: `threshold_kem` (`crates/mpc/src/threshold_kem.rs`,
`ENGINEERING-STANDARDS.md` §6.22) gives each operator an independent
ML-KEM-1024 keypair — the same FIPS 203 KEM `novachannel::kex` already
uses, needing no group DKG at all since there's no shared EC point to
commit to — and Shamir-shares a per-message master secret across them,
reusing this crate's own Lagrange-interpolation machinery (§4.2) rather
than a second implementation. Reconstructing anything now costs an
attacker `t` independent module-LWE problems (one per compromised
operator's ML-KEM secret key); a full break of Ristretto's discrete log,
which fully breaks `Dealer`/`frost`, gains nothing against this path.
`frost`/`Dealer` remain available, unchanged, for callers whose use case
is signing rather than decryption — `threshold_kem` is additive, not a
replacement.

## 8. What was actually verified, and how

172 tests across the workspace (up from 132), plus 8 `cargo-fuzz` targets
(up from 6) covering every crate with an untrusted-input parsing
boundary — `novachannel-rln`'s STARK proof verifier and
`novachannel-mpc`'s FROST signature verifier are new additions, and
`rln_verify` found a real remote-DoS panic in a dependency's proof
deserializer within seconds of running (`ENGINEERING-STANDARDS.md` §3.3,
§6.22), now fixed and regression-tested. A later audit of `crate::group`
against the same "what can an unauthenticated party do" standard (§4.5)
found two more defects of the identical class in this workspace's own
code — a forgeable zero-capacity panic and a missing proof-of-possession
binding on `LeafKeyPackage` — recorded and fixed in
`ENGINEERING-STANDARDS.md` §6.23. All adversarial where the claim
is adversarial (not merely "does the happy path run"): tamper, replay,
wrong-key, wrong-message, below-threshold-quorum,
server-tampers-a-bucket, server-replays-a-stale-bucket,
cross-epoch/same-epoch rate-limit tests,
`novachannel::ratchet`'s epoch-transition/stale-epoch/concurrent-initiation
tests (§4.1), `crate::x3dh`'s wrong-responder/tampered-payload/consumed-
one-time-prekey tests (§4.2), `crate::sealed_sender`'s
wrong-recipient/expired-certificate/swapped-identity tests (§4.3),
`crate::multidevice`'s cross-account session-isolation test (§4.4), and
the incremental ratchet's any-order/bounded-loss/exhaustive-shard-
combination tests (§4.1.1) each try to break a specific stated property
rather than exercise code paths incidentally — including two real defects
the incremental ratchet's own test suite caught before this document was
written (§4.1.1): a strict-ordering/loss-tolerance incompatibility, and
a stale-root-key bug on chunks arriving after reconstruction already
completed. A subsequent line-coverage pass
(`ENGINEERING-STANDARDS.md` §6.16) closed the remaining genuinely-reachable
gaps rather than chasing a literal 100% — which also found and removed one
real piece of dead code (`permutation::hash2`, an unused duplicate of
`compress2`). `scripts/check.sh` runs
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

- `novachannel-rln`'s in-circuit permutation is now a verified port of
  Poseidon2-over-Goldilocks (`ENGINEERING-STANDARDS.md` §6.21) rather than
  the from-scratch `NovaRescue` construction this document originally
  described — the "invented, uncryptanalyzed construction" risk category
  is closed. What remains open: independent review of *this specific
  port* (a transcription error in a constant is a real risk category a
  test-vector match doesn't fully rule out) has not happened, and this
  document does not claim it has.
- `novachannel-mpc`'s `Dealer`/`frost` remain entirely classical
  elliptic-curve constructions with no post-quantum alternative for the
  threshold-*signing* use case — none exists yet that's production-ready
  (§7). The threshold-*decryption* use case this crate actually serves
  for mixnode operators does now have a post-quantum path
  (`threshold_kem`, §7, §6.22); signing does not.
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
- The incremental ratchet's erasure coding (§4.1.1) now delegates the
  actual Reed-Solomon algorithm to the maintained `reed_solomon_simd`
  crate rather than a from-scratch implementation. What remains this
  project's own, and unreviewed by anyone outside it: the chunk framing,
  AEAD-per-chunk authentication, and reassembly logic built on top,
  checked against its own stated combinatorial property (any `k`-of-`n`
  shards reconstruct) exhaustively for one parameter set, not proven for
  all of them.
- `crate::multidevice::SignedDeviceList` (§4.4) authenticates *which*
  devices an account currently has and rejects a rollback to a stale
  version, but this crate still has no directory service to actually
  deliver one — fetching a list and deciding which account key to trust
  as its signer remain the caller's problem, the same "trust provisioning
  is the caller's job" boundary the rest of this workspace draws
  elsewhere. `RemoteAccount::new`/`add_device` also remain available
  entirely unauthenticated, for callers that don't use the signed path —
  using them is opting out of the protection `SignedDeviceList` provides,
  not a limitation of the mechanism itself.
- `crate::x3dh`'s deniability argument (§4.2) is the standard textbook
  X3DH argument, not a formal proof specific to this implementation's
  exact wire encoding — the property has not been independently checked
  by anyone outside this project either.

## Reproducing the claims in this document

```
git clone <this repo>
cd novachannel
./scripts/check.sh          # fmt, clippy -D warnings, full test suite
cargo test -p novachannel-mpc --release official_test_vector_matches_rfc9591
cargo test -p novachannel-rln --release   # requires --release; see novachannel_rln::lib docs
cargo run -p novachannel-rln --release --example proof_size   # §3.2's proof-size table
cargo test -p novachannel-mpc --release --test frost_signs_rln_root
cargo test -p novachannel --release --test x3dh
cargo test -p novachannel --release --test sealed_sender
cargo test -p novachannel --release --test multidevice
cargo test -p novachannel --release --test incremental_ratchet
```
