# ProVerif protocol models

Two Dolev-Yao models of this crate's session-establishment protocols,
checked with [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/):

- `handshake.pv` — `crate::handshake`'s live, 3-message mutually
  authenticated handshake.
- `x3dh.pv` — `crate::x3dh`'s asynchronous, deniable X3DH+ML-KEM-1024
  session establishment.

Each file's own header explains exactly what it models, what it
deliberately doesn't (most importantly: neither models the wire encoding
or concrete algorithm hardness — see below), and the queries it runs. Read
those before the query results; a query result without the model's scope
next to it is not meaningful on its own.

## Status

**Both models have been executed**, with ProVerif 2.05 (installed via
`opam`, since it isn't in Homebrew core — see "Installing ProVerif"
below). Results:

- `handshake.pv`: all 5 queries (secrecy + 4 injective authentication
  correspondences) returned the predicted result.
- `x3dh.pv`: the secrecy/forward-secrecy query returned the predicted
  result (secret even after the phase-1 long-term-key leak).

Getting there caught two real bugs in the *models* (not the protocols —
worth being precise about that distinction):

1. Both `Responder`/`ResponderX3DH` roles originally echoed their
   decrypted plaintext back onto the public network channel
   (`out(net, received)`), intended as "prove the responder can use `sk`"
   but actually just handing the secret to the attacker directly,
   independent of anything the real protocol does. ProVerif's secrecy
   query correctly reported this as a break — because it was one, in the
   model. Fixed by deleting the echo; successfully reaching the `sdec`
   call is already sufficient evidence the responder derived a usable key.
2. The first attempt at the authentication correspondence queries
   quantified over *all* identities (`query a: bitstring, b: bitstring, ...`),
   which includes identities the attacker registers and runs themselves
   — a self-impersonation the queries correctly flagged as "no matching
   honest signing event," which is true but not a protocol flaw (nobody
   claims the attacker can't act as themselves). Fixed by restricting
   the queries to the two concrete, honest, mutually-pinned identities
   declared as top-level `free ... [private]` names specifically so the
   queries can reference them directly.

Both are exactly the kind of mistake formal tooling exists to catch
early and cheaply, in a model, rather than the hard way, in running code
— which is the actual case for having this directory at all, distinct
from (and smaller in scope than) what full hax/F* verification of the
real implementation would give you (see below).

If you change either `.pv` file, re-run it and update this section (and
the file's own STATUS note) with the real result — don't just edit the
"expected" comments and assume.

## Installing ProVerif

Not currently packaged in Homebrew core. Two practical routes:

**Via opam (OCaml's package manager):**

```sh
brew install opam
opam init            # bootstraps an OCaml switch; slow the first time
opam install proverif
eval $(opam env)
```

**From source**, if opam isn't an option:
<https://bblanche.gitlabpages.inria.fr/proverif/> has release tarballs and
build instructions (requires OCaml + a C toolchain).

## Running

```sh
proverif crates/core/formal/proverif/handshake.pv
proverif crates/core/formal/proverif/x3dh.pv
```

Each prints one `RESULT ...` line per `query` in the file, in order. A
secrecy query (`attacker(secretApplicationData)`) reads `false` when the
property holds (the attacker cannot derive it); a correspondence query
(`inj-event(...) ==> inj-event(...)`) reads `true` when it holds.

## What "formal verification" means here, and what it doesn't

These are protocol-*logic* models: an idealized Dolev-Yao attacker who can
intercept, replay, and recombine messages but cannot break the underlying
primitives directly (forge a signature without the key, invert a hash,
decrypt without the key). A clean ProVerif result is real evidence the
protocol's *message flow* doesn't have a logic-level flaw — the kind of
bug that has broken real, deployed protocols (reflection attacks, missing
binding between a signature and its context, unkeyed confirmation
messages) even when every primitive underneath was sound.

It is **not** evidence about:

- Whether X25519, ML-KEM-1024, ML-DSA-87, ChaCha20-Poly1305, or
  HKDF-SHA256 are themselves secure — ProVerif takes that as a given
  (Dolev-Yao attackers can't break primitives, only misuse protocols).
- Whether `crates/core/src/handshake.rs`/`x3dh.rs`'s actual Rust
  *implementation* matches these `.pv` models faithfully. Nothing here
  extracts from or is checked against the real source the way hax/F\*
  verification would be (see below) — these models were written by
  reading the Rust and translating it by hand, which is exactly the kind
  of step a source-extraction tool exists to remove the risk from.
- Deniability (x3dh.pv) or anything ProVerif's reachability/correspondence
  query language can't express — see that file's own header for specifics.

That's a real, useful, and honestly-bounded thing to have — not a
substitute for what the next section describes.

## hax / F\* / SPQR-level verification: out of reach here, and why

Signal's own post-quantum ratchet, SPQR, goes a level deeper than anything
in this directory: it's checked with
[hax](https://github.com/cryspen/hax) (which extracts real Rust source
into F\* and proves refinement types against the *actual implementation*,
not a hand-written model of it) plus separate ProVerif models of the
protocol logic. That combination is what lets a project credibly claim
"the code that runs is the code that was verified" — the gap this
directory's hand-translated `.pv` models explicitly do not close (previous
section).

This workspace does not attempt hax/F\* verification of any module, and
that's a deliberate scope boundary, not an oversight:

- hax extraction requires the Rust source to be written in a subset hax
  can actually translate (no arbitrary trait objects, limited generic
  bounds, careful handling of anything hax's extraction doesn't support
  yet) — retrofitting that onto existing modules not written with hax in
  mind is a real rewrite, not an annotation pass.
- F\* proof engineering is its own specialized skill, distinct from Rust
  systems programming — writing refinement types that actually capture
  the security property you want, and getting F\*'s SMT-backed prover to
  discharge them, routinely takes domain experts weeks to months per
  module, not something to attempt as a side effect of an otherwise
  Rust-focused change.
- Overclaiming this — a token `#[hax::exclude]`-riddled extraction that
  technically runs but proves nothing meaningful, presented as "hax
  verification" — would be exactly the kind of overclaiming
  `ENGINEERING-STANDARDS.md` and every module's own "honest scope"
  section in this workspace exist to avoid. Naming the gap here plainly is
  the same standard applied to this question instead of the code.

If this workspace ever takes on hax/F\* verification for real, it belongs
as its own dedicated, multi-session effort scoped around one module at a
time (`crates/core/src/ratchet.rs` — mirroring SPQR most directly — is the
natural first candidate), not folded into an unrelated change.
