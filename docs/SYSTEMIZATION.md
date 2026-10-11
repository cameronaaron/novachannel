# A Hybrid Post-Quantum Messaging Stack: Engineering Report

> **Not approved for production.** This workspace is unaudited. The
> positive-epsilon cover scheduler is not differentially private (§5;
> [corrected analysis](RLN_DP_COMPOSITION.md)).

**Status: engineering report, not a research paper.** It describes what the
`novachannel` workspace builds, why, how it was verified, and which parts are
reuse of published work. Where a claim would need a proof, cryptanalysis or
peer review, this document says so instead of making the claim.

## Abstract

`novachannel` is a five-crate Rust workspace: a hybrid classical/post-quantum
secure channel (`novachannel`: a signed 3-message handshake, asynchronous
deniable X3DH, sealed sender, Sesame-style multi-device, a one-shot or
erasure-coded ratchet, and an `O(log n)` TreeKEM-inspired group ratchet);
zero-knowledge rate-limiting nullifiers over a hash-based STARK
(`novachannel-rln`); cover traffic (`novachannel-dp`); oblivious server-side
storage (`novachannel-oram`); and threshold key generation, decryption and
signing (`novachannel-mpc`, including FROST). Every primitive is a standard
published construction or a verified port of one; the contribution is a
tested, honestly scoped *integration*, not a new primitive. What remains this
project's own and unreviewed is integration logic: the STARK circuit (§3),
the erasure-coded ratchet's chunk framing (§4.1.1), and the protocol glue
throughout.

## 1. What "novel" means here, precisely

**Not claimed:** a new hardness assumption, proof technique, attack, proven
bound, or cryptanalysis of any primitive used.

**Claimed, narrowly:** proving *both* Merkle membership *and* a Shamir-style
rate-limit share inside one hash-based (so post-quantum, no curve or pairing
assumption) STARK (§3) has, as far as the authors could find, no public
reference implementation; production RLN (Semaphore-RLN, Waku-RLN) proves
the same relation with Groth16. Whether that substitution is a publishable
contribution is for peer reviewers. What is claimed and checkable: the STARK
version was built, a real bug in it was found and fixed (§3.3), and it is
verified end to end against a reference implementation of the non-ZK
relation.

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

The four peripheral crates are independent of each other. Each covers
something encryption alone leaves open: *who* sent a message (RLN), *whether*
they sent anything in a slot (DP), *which server record* their session
touched (ORAM), and *who controls* a relay's key (MPC/FROST).

## 3. `novachannel-rln`: zero-knowledge rate-limiting nullifiers

### 3.1 The relation, and why it must be proved as one circuit

RLN lets a group member send anonymously (a ZK proof of membership that
doesn't say which member) under a per-epoch rate limit: a second message in
the same epoch leaks the sender's secret via Shamir reconstruction. For
secret `sk`, epoch `e` and message binding value `x`:

- membership: `Hash(sk, 0)` is a leaf of the public tree with root `R`;
- rate-limit share: `a1 = Hash(sk, e)`, `y = sk + a1·x`.

Both must be proved in *one* circuit; otherwise nothing forces the same `sk`
into both, and a prover could pass membership once and use a fresh `sk` per
share. Real RLN circuits already combine them; the choice here is the proof
system: a STARK instead of Groth16.

### 3.2 Why a STARK, and the cost of that choice

STARKs need no trusted setup and rest on hash collision resistance rather
than curve or pairing assumptions, so a quantum break of discrete log doesn't
affect them: the motivation for a stack that is post-quantum elsewhere (§4).

They need an algebraic hash with a low-degree round function. This crate
first defined its own (`NovaRescue`); it now ports Poseidon2-over-Goldilocks
verbatim from `p3-goldilocks`/`p3-poseidon2` 0.6.3 (Plonky3's instance, used
by audited provers such as SP1 and RISC Zero). Constants and the diffusion
matrix are copied, checked against Plonky3's vector
(`matches_official_poseidon2_goldilocks_width8_test_vector`) and against the
published crate on 10,000 random inputs
(`matches_the_real_upstream_crate_on_many_random_inputs`). Matching the
instance meant using its field (Goldilocks) and smallest published width (8).
**This is not an independent review of the port**; it closes the "invented,
uncryptanalyzed construction" risk only.

Proof size, measured by `crates/rln/examples/proof_size.rs` with the
security column read from winterfell's `Proof::conjectured_security`:

| queries | blowup | grinding | field extension | conjectured bits | measured proof size |
| --- | --- | --- | --- | --- | --- |
| 16 | 16 | 0 | none | 63 | ~13.8 KB |
| 24 | 16 | 0 (pre-hardening default) | none | 63 | ~18.3 KB |
| 32 | 16 | 20 (**this crate's default**) | quadratic | 127 | ~27.0 KB |
| 32 | 16 | 20 | cubic | 128 | ~31.8 KB |
| 48 | 16 | 20 | cubic | 128 | ~45.0 KB |

(Bytes vary slightly per run with the randomized witness.)

Winterfell computes `min(min(field_security, query_security) - 1,
hash_collision_resistance)` with `field_security = 64 * extension_degree`,
so over Goldilocks the field term binds. Earlier revisions printed only the
query term and claimed ~96 and ~148 bits where the real figures are 63 and
127. A cubic extension reaches 128 (capped by Blake3_256) but costs 5.6x the
proving time for one bit and was rejected; the last row shows extra queries
then change size, not security.

At the default a proof is roughly **211x** Groth16's 128 bytes (2 G1 + 1 G2
on BN254), for a tiny circuit; the gap grows with the membership set. Where
per-message bandwidth matters more than avoiding a trusted setup and
quantum-safe proofs, Groth16 is the better choice; these numbers are the
real cost of this project's priorities.

Proving time, from `crates/rln/examples/proving_time.rs` (5 runs per
configuration, on the machine that ran it, not a phone): ~3.0-3.5ms median
without an extension, ~5.4ms at the default, ~29.8ms for the rejected cubic
variant. The extension degree dominates; verification is sub-millisecond
throughout. A mobile deployment pays this per rate-limited action and should
measure on its own hardware.

### 3.3 A defect found by validating against ground truth

The STARK's Merkle root disagreed with a plain reference tree. A white-box
probe comparing levels showed every level matched except the root: the
trace loop ran once per tree *level*, one fewer than the hash calls the
chain needs (leaf hash plus one per combine). Each piece was individually
correct; only the loop count was wrong. Every dependent row-index constant
was re-derived from one corrected block count, so the same off-by-one can't
recur in a sibling constant.

### 3.4 Verification performed

- `valid_membership_proof_verifies`, `tampered_proof_bytes_are_rejected`,
  `wrong_root_is_rejected`, `each_public_input_is_independently_load_bearing`.
- `two_messages_in_same_epoch_reveal_the_secret_key`,
  `messages_in_different_epochs_do_not_leak_the_key`,
  `distinct_messages_do_not_collide_in_the_rate_limit_binding_value`: the
  rate-limit mechanism checked against the field arithmetic.
- `a_proof_generated_below_the_security_floor_is_rejected`: the verifier
  enforces 127 bits whatever options a prover chose.
- Parameters: Merkle depth 5 (32 members; any depth with `depth + 3` a power
  of two works), width 8, 31 rounds per hash call. Chosen for a runnable
  reference, not production scale.

## 4. `novachannel` (core): hybrid post-quantum channel

Hybrid key exchange (X25519 + ML-KEM-1024) and hybrid signatures (Ed25519 +
ML-DSA-87), the algorithms NIST ratified as FIPS 203/204 in 2024, via
RustCrypto's pure-Rust `ml-kem`/`ml-dsa` (replacing earlier C bindings to the
round-3 submissions, a documented breaking change). Breaking a session needs
breaking *both* legs, so a future break of either alone (ML-KEM/ML-DSA are
young) doesn't expose past sessions. Chrome, Cloudflare and OpenSSH deploy
the same pattern; it is current practice, not a contribution.

The handshake signs the transcript rather than a fixed challenge, binding
identity to this exchange, and derives traffic keys from a hash of the whole
transcript including both signatures (standard channel binding).

Identity keys can live outside the process: `Ed25519SigningBackend` and
`MlDsaSigningBackend` with `Identity::from_backends` delegate signing to an
HSM, KMS or token, with no change elsewhere and no vendor SDK dependency. AWS
KMS supports both legs (ML-DSA-87 and Ed25519). No KMS offered ML-KEM
encapsulation when checked, so key exchange stays in-process.

### 4.1 `ratchet`: forward secrecy per message, post-compromise security per epoch

The plain session uses one pair of directional keys for its lifetime.
`novachannel::ratchet` is an opt-in layer seeded from
`EstablishedSession::ratchet_root` (its own HKDF label) that adds:

- **forward secrecy:** a fresh single-use AEAD key per record from a one-way
  HMAC-SHA256 chain;
- **post-compromise security:** `initiate_ratchet` reruns `kex.rs`'s hybrid
  exchange mid-session and mixes it into a new root key.

It deliberately isn't Signal's
[SPQR](https://github.com/signalapp/SparsePostQuantumRatchet), whose step
(read from `src/v1/unchunked/send_ek.rs`) is an incremental re-encoding of
ML-KEM-768 across several round trips, erasure-coded and verified with
hax/F* and ProVerif: out of reach for a build checked by hand-written tests.
The default re-key is synchronous and one-shot (a full KEM payload each
way). Records may arrive out of order or be lost, within a bound: skipped
message keys are cached up to `MAX_SKIPPED_KEYS` per chain, each usable once.
Concurrent initiation by both peers is rejected rather than resolved. See
the module docs and `ENGINEERING-STANDARDS.md` §6.15.

#### 4.1.1 An incremental, erasure-coded alternative re-key

`initiate_incremental_ratchet`/`open_ratchet_chunk` split the same KEX
material into `data_shards + parity_shards` AEAD-sealed chunks using
`reed_solomon_simd` (Leopard-RS); any `data_shards` of them, in any order,
reconstruct it. This is closer in shape to SPQR's chunked design, without
parity: it splits ordinary serialized ML-KEM-1024 bytes rather than
re-encoding the algorithm, so chunks get smaller on the wire but not in
meaning.

Two defects surfaced building it. Routing chunks through the record
sequence turned any loss or reordering into a desync, so chunks now carry
their own AEAD key, derived from the session's `root_key` and a random
per-attempt nonce. And parity chunks arriving after reconstruction (and the
epoch change) failed to decrypt, so the last completed attempt is
remembered and its stragglers ignored. Both were found by testing the full
chunk set rather than a loss pattern that avoids the bug. The framing and
reassembly are this project's own and unreviewed; the any-`k`-of-`n`
property is tested exhaustively for one parameter set, not proven.

### 4.2 `x3dh`: asynchronous, deniable session establishment

The handshake needs both peers online and signs the transcript, so a leaked
transcript proves who took part: useful for audit trails, a cost for private
messaging. `crate::x3dh` is an additive alternative producing the same
`EstablishedSession`. It follows X3DH with a hybrid ML-KEM-1024 leg, as
Signal's PQXDH does: `PreKeyBundle` publishes a DH identity key, a signed
medium-term prekey (DH + ML-KEM) and an optional one-time prekey, and the
initiator combines four DH terms and one or two encapsulations into the
session key in one message. The only signature covers the reused prekey, not
the exchange, and either party could derive the key alone, so neither can
prove the other took part. The deniability argument is the standard X3DH one,
not a proof specific to this encoding.

### 4.3 `sealed_sender`: hiding who sent a message from whatever relays it

Neither handshake hides the sender from relays. `crate::sealed_sender`
follows Signal's sealed sender: the only visible value is a fresh single-use
hybrid ephemeral key, combined with the recipient's long-term key to seal a
`SenderCertificate` (the sender's identity signed by an issuer the
application chooses) with the plaintext. Relays therefore can't check the
sender before delivery; abuse filtering happens after unsealing, the same
tradeoff Signal makes.

### 4.4 `multidevice`: Sesame-style fan-out across an account's devices

Accounts have several devices and no secret spans them.
`MultiDeviceSession` fans one send out to a `RatchetedSession` per device;
`ReceivingDevice` files incoming sessions by (sender identity, device id),
isolated across senders. Like Sesame, it adds no primitive.
`SignedDeviceList`, signed by the account identity, says which devices
belong to an account: bundles that don't match it are rejected, older
versions are refused (no rollback), and devices dropped from a newer list
lose their sessions. Fetching the list and choosing which account key to
trust remain the caller's job; there is no directory service, and new
devices get no history.

### 4.5 `group`: `O(log n)` group rekeying via a TreeKEM-inspired ratchet

`crate::group::Group` borrows MLS/TreeKEM's tree: a membership change or
re-key re-encrypts one leaf-to-root path, each step sealed to its sibling
subtree's resolution, using this crate's own hybrid sealing, HKDF and
identities. It is **not** RFC 9420: no TLS encoding, RFC 9180 HPKE,
credentials or interoperability; fixed capacity; one proposal per commit;
current-epoch decryption with one in-order chain per sender per epoch. It
keeps what justifies TreeKEM: `O(log n)` sealed values per commit, forward
secrecy and post-compromise security on every commit, and removed members
structurally excluded because their ancestor path is blanked.

`LeafKeyPackage`s carry a proof-of-possession binding identity to key,
checked on every deserialization path. Because a `Welcome` travels in a
sender-anonymous envelope, every field of it is attacker-chosen unless
authenticated: the committer now signs the snapshot, and `join` checks the
group id, the epoch, that the commit adds this member at this leaf, and that
the signature verifies under the committer's identity, as MLS signs its
`GroupInfo`. `Group::member_identity` makes senders and committers
attributable. See `ENGINEERING-STANDARDS.md` §6.23 and §6.29.

## 5. `novachannel-dp`: cover traffic and a withdrawn privacy claim

A real message always sends; an empty slot sends a dummy with probability
`q = exp(-epsilon)`. **This is not pure epsilon-DP for positive epsilon.**
Silence has probability `1-q` in an empty slot and zero in a busy one, which
breaks the reverse DP inequality; the original argument checked one
direction only. `empirical_likelihood_ratio_matches_bound` measures the send
event and proves nothing about DP;
`silence_is_a_counterexample_to_positive_epsilon_pure_dp` witnesses the
failure in the implementation. DP composition doesn't apply, and the former
RLN composition claim is withdrawn in [RLN_DP_COMPOSITION.md](RLN_DP_COMPOSITION.md).

At epsilon zero every slot sends, hiding the presence bit only if real and
dummy packets are indistinguishable and transmission timing doesn't depend on
arrival. Positive epsilon trades bandwidth for observable silence; it is not
a privacy budget. Neither mode hides endpoints or gives end-to-end anonymity.

`GridScheduler` removes within-slot timing: `enqueue` only queues, and
`tick`, driven by the caller's clock, is the only transmitter, so send times
sit on the grid whatever the arrival time. The cost is latency (messages wait
for the next tick, FIFO). Timing elsewhere in the caller's system is out of
scope. `SizeBucketer` pads plaintext to fixed buckets before encryption.

## 6. `novachannel-oram`: access-pattern obliviousness for server state

Standard Path ORAM (Stefanov et al., CCS 2013): `O(log n)` bucket touches per
access hide which server record (rate-limit counter, nullifier entry) a
request touched, since an encrypted channel can still leak identity through
access patterns. `O(1)` ORAM was requested and declined: the
Goldreich-Ostrovsky bound makes it impossible.

The client's secret state (position map, stash) and server bucket storage are
separated by the `ServerStorage` trait rather than a comment;
`client_works_unchanged_against_a_different_server_impl` runs the protocol
through a second implementation unchanged.

`VerifiableServerStorage` adds a Merkle tree over the ORAM tree, detecting a
server that tampers, drops or replays at no extra asymptotic cost. Building
it surfaced a write-back bug (raw bucket hashes stored instead of combined
node hashes), found by printing intermediate hashes in a two-access
reproduction. Replaying a stale but once-valid bucket is the sharper test:
only a root comparison catches it.

`EncryptingServerStorage` seals each block's id and value, pads every block
to a fixed size and writes every bucket with exactly `bucket_capacity`
ciphertexts, so neither occupancy nor value length reaches the server
(`every_written_bucket_looks_identical_to_the_server_whatever_it_holds`).
Neither `Client` nor the Merkle layer needed changes. Key distribution is the
caller's.

## 7. `novachannel-mpc`: threshold trust for relay operators

A single-operator relay key can be coerced, subpoenaed or abused.
`novachannel-mpc` splits it with a joint-Feldman DKG (commit-then-reveal
against the rushing bias attack), so compromise needs `t` operators. Faulty
dealers are excluded instead of aborting the run.

A later review fixed two defects in the networked complaint protocol, each
exploitable by one malicious participant: a complaint naming participant 0
made an honest dealer publish `f(0)`, its secret (id 0 is now rejected
everywhere), and a dealer was disqualified whenever its verified disclosure
differed from the accuser's unverifiable claim, letting one participant
evict every honest dealer. Now, per Gennaro et al., a dealer is disqualified
only if its broadcast share fails its own commitments; the unattributable case
is reported with its repair. The prose had claimed Gennaro et al.'s rule
without checking the paper (`ENGINEERING-STANDARDS.md` §6.9, §6.29).

FROST (RFC 9591) reuses the DKG output to sign jointly (e.g. a routing
table), producing an ordinary Schnorr signature. Its encodings were
reverse-engineered against, and are tested by
`official_test_vector_matches_rfc9591`, the CFRG `FROST(ristretto255,
SHA-512)` vector; deterministic `nonce_generate` is deliberately not matched
(CSPRNG nonces). A quorum signing the RLN membership root lets clients trust
one long-lived key instead of a PKI, with only a test-scoped dependency
between the crates (`crates/mpc/tests/frost_signs_rln_root.rs`).

**`Dealer`, `frost` and `combine_partials` are classical** (Ristretto255)
and fall to a discrete-log break. No production post-quantum threshold
signature exists to adopt (`lattice-safe/threshold-ml-dsa` was unaudited
research code when checked; NIST IR 8214C is a call for submissions). The
mixnode use case needs threshold *decryption*, which `threshold_kem`
provides: independent ML-KEM-1024 keys per operator and a Shamir-shared
per-message secret, so an attacker needs `t` module-LWE breaks and a
discrete-log break gains nothing. Signing remains classical.

## 8. What was actually verified, and how

241 tests across the workspace and 8 fuzz targets run continuously with
[ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) (on PRs and
every 6 hours). Fuzzing found a remote-DoS panic in winterfell's proof
deserializer, now contained (`ENGINEERING-STANDARDS.md` §3.3), and an
unbounded allocation in winterfell's verifier that can't be contained
in-process (pinned by a test; §6.31). Reviews asking "what can an
unauthenticated party do?" found the group and complaint-protocol defects in
§4.5 and §7, plus wire-format truncation, unbounded allocations, prekey
exhaustion and ORAM size leaks (§6.29).

Two results from those reviews are lessons rather than fixes. Coverage-guided
fuzzing can't reach anything behind a signature, length check or AEAD tag:
`group_commit` ran 36 million executions without passing a `LeafKeyPackage`
signature, and three defects behind it were found by reading. Fuzz targets
now splice into genuine messages (§6.31, §6.32). And this document's own
security figures for RLN were wrong in both directions until read from the
library (§3.2).

The adversarial tests try to break each stated property: tamper, replay,
wrong key or message, below-threshold quorums, server tampering and replay,
same- and cross-epoch rate limiting, ratchet epoch transitions and concurrent
initiation, X3DH wrong-responder and prekey cases, sealed-sender
wrong-recipient and expired-certificate cases, multi-device isolation, and the
incremental ratchet's any-order and bounded-loss reconstruction.
`scripts/check.sh` (format, clippy and rustdoc with `-D warnings`, debug and
release tests, `cargo audit`, gitleaks) is the bar for "done", and CI runs
the same script.

`ENGINEERING-STANDARDS.md` is the full audit trail of defects found, how each
was diagnosed, and the class each fix was checked against.

## 9. Limitations and what would be needed for a real research contribution

| Area | State |
| --- | --- |
| Threshold signing | Classical only (§7); no production post-quantum scheme exists to adopt, and building one would mean an unreviewed primitive. Open by design. |
| DKG complaint protocol | Closed: per-accusation `Complaint`/`share_for`/`resolve_complaint`, corrected to Gennaro et al.'s rule, with a TCP example (`crates/mpc/examples/networked_complaint.rs`). Production deployments supply their own transport. |
| ORAM confidentiality | Closed, opt-in: `EncryptingServerStorage` hides contents, occupancy and value length and composes with integrity checking. Key distribution is the caller's. |
| DP size correlation | Closed at the application layer by `SizeBucketer`, to bucket granularity; ciphertext sizes still reveal the bucket unless a lower layer pads to uniform cells, as Tor does. |
| DP within-slot timing | Closed by `GridScheduler`, at a latency cost; timing elsewhere in a system is out of scope. |
| DP privacy guarantee | Positive epsilon is not DP (§5). A DP replacement needs different delivery semantics and an adjacency model. |
| PKI / directory | Open and out of scope for a library: fetching identities and device lists is the caller's job. |
| Network anonymity | Not addressed: IP addresses and connection metadata are visible; use Tor or a mixnet underneath. |
| Device resource cost | Proof size and proving time measured on one non-mobile machine; dummy-traffic battery and data cost unmeasured. |
| Primitive assurance | RustCrypto and dalek crates are maintained but not independently audited (`curve25519-dalek` had RUSTSEC-2024-0344, fixed). `docs/LIBCRUX_MIGRATION.md` scopes a breaking move to formally verified `libcrux`. |
| Untrusted RLN proofs | A malformed proof can abort the verifying process via winterfell's allocation (§8); isolate `air::verify`. |

Stated plainly:

- The Poseidon2 port, the erasure-coding framing, the STARK circuit and all
  protocol glue have had no review outside this project.
- Whether this STARK-based RLN design is novel has been checked only against
  the public production systems in §3.1, not by a systematic literature
  review.
- A publishable version of any claim needs a formal security reduction,
  comparison with related work under matched assumptions, and peer review.
  None of that exists here.
- X3DH deniability rests on the standard argument, not a proof about this
  implementation.

## Reproducing the claims in this document

```
git clone https://github.com/cameronaaron/novachannel
cd novachannel
./scripts/check.sh          # format, clippy, rustdoc, tests, audit
cargo test -p novachannel-mpc --release official_test_vector_matches_rfc9591
cargo test -p novachannel-rln --release   # release only; see novachannel_rln docs
cargo run -p novachannel-rln --release --example proof_size   # §3.2 size table
cargo run -p novachannel-rln --release --example proving_time # §3.2 timing
cargo test -p novachannel-mpc --release --test frost_signs_rln_root
cargo test -p novachannel --release --test x3dh
cargo test -p novachannel --release --test sealed_sender
cargo test -p novachannel --release --test multidevice
cargo test -p novachannel --release --test incremental_ratchet
```
