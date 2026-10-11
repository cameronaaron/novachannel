# ProVerif protocol models

Two Dolev-Yao models of this crate's session establishment, checked with
[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/):

- `handshake.pv`: `crate::handshake`'s 3-message mutually authenticated
  handshake.
- `x3dh.pv`: `crate::x3dh`'s asynchronous X3DH + ML-KEM-1024 establishment.

Each file's header states what it models, what it doesn't (above all, wire
encoding and primitive hardness) and its queries. Read that scope before the
results.

## Status

**Both models have been run** with ProVerif 2.05:

- `handshake.pv`: all 5 queries (secrecy and 4 injective authentication
  correspondences) returned the predicted result.
- `x3dh.pv`: the secrecy / forward-secrecy query returned the predicted
  result (secret even after the phase-1 long-term key leak).

Running them caught two bugs in the *models*, not the protocols:

1. Both responder roles echoed the decrypted plaintext onto the public
   channel (`out(net, received)`), handing the secret to the attacker;
   ProVerif rightly reported a break. The echo was removed: reaching the
   `sdec` call already shows the responder derived a usable key.
2. The first authentication queries quantified over all identities, including
   attacker-run ones, and flagged the attacker acting as itself. They now
   refer to the two honest, mutually pinned identities, declared as
   `free ... [private]` names.

If you change a `.pv` file, re-run it and update this section and the file's
STATUS note with the real result.

## Installing ProVerif

Not in Homebrew core. Via opam:

```sh
brew install opam
opam init            # slow the first time
opam install proverif
eval $(opam env)
```

Or build from source (OCaml and a C toolchain):
<https://bblanche.gitlabpages.inria.fr/proverif/>.

## Running

```sh
proverif crates/core/formal/proverif/handshake.pv
proverif crates/core/formal/proverif/x3dh.pv
```

Each prints one `RESULT ...` line per query. A secrecy query
(`attacker(secretApplicationData)`) reads `false` when the secret holds; a
correspondence query (`inj-event(...) ==> inj-event(...)`) reads `true` when it
holds.

## What this verifies, and what it doesn't

These are protocol-logic models: an attacker who can intercept, replay and
recombine messages but not break primitives. A clean result is real evidence
against logic-level flaws (reflection attacks, unbound signatures, unkeyed
confirmations), which have broken deployed protocols with sound primitives.

It is **not** evidence that:

- X25519, ML-KEM-1024, ML-DSA-87, ChaCha20-Poly1305 or HKDF-SHA256 are secure
  (assumed);
- `handshake.rs`/`x3dh.rs` match these models: the models were translated
  from the Rust by hand, not extracted from it;
- X3DH is deniable, or anything else ProVerif's query language can't express
  (see the file headers).

## hax / F\* verification: not attempted

Signal's SPQR is checked with [hax](https://github.com/cryspen/hax), which
extracts the real Rust into F\* and proves refinement types about the actual
implementation, plus ProVerif models: "the code that runs is the code that was
verified." This workspace doesn't attempt that, deliberately:

- hax needs source written in the subset it can translate; retrofitting
  existing modules is a rewrite, not annotation.
- F\* proof engineering is specialist work, often weeks to months per module
  for experts.
- A token extraction that runs but proves nothing, presented as verification,
  would be the overclaiming this workspace's standards exist to prevent.

If it is ever attempted, it should be a dedicated effort one module at a time,
starting with `crates/core/src/ratchet.rs`, the closest analogue to SPQR.
