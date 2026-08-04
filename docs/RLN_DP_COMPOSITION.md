# Do `novachannel-rln` and `novachannel-dp` compose safely?

**Status: a written analysis, not a code change.** The question was: does
RLN's rate limit — which gives a user a real incentive to suppress a
second real send within an epoch, to avoid leaking their key via Shamir
reconstruction — create a signal that `novachannel-dp`'s cover-traffic
scheduler doesn't account for? This document works the question out
formally rather than asserting an answer.

## The concern, stated precisely

`novachannel-dp` protects a per-slot bit: "did this time slot carry a real
message," hidden behind randomized response with likelihood ratio bounded
by `e^ε` (module docs, `crates/dp/src/lib.rs`). `novachannel-rln` gives a
user a reason to make their *true* send/no-send pattern non-independent
across slots within an epoch — specifically, to send at most once. If the
DP scheduler's per-slot randomness doesn't know about this correlation,
does the epsilon bound still hold once you compose many slots, or does the
RLN-induced pattern leak through the composition?

## Setup

Model an epoch as `T` slots, each with a ground-truth bit `b_t ∈ {0,1}`
("real message queued this slot"). `novachannel-dp`'s mechanism `M_t`
looks at `b_t` alone: if `b_t = 1`, output `o_t = 1` always; if `b_t = 0`,
output `o_t = 1` with probability `q = e^{-ε}`, using a fresh CSPRNG draw
independent of every other slot's coin (already a stated precondition in
the module docs). RLN's rate limit induces some joint distribution `D`
over `(b_1, ..., b_T)` — e.g. "at most one 1 per epoch" — which may be
arbitrarily complex and may even be chosen *adaptively*, including in
response to the mechanism's own past outputs. The analysis below doesn't
need to know what `D` actually is; that's the point.

## Claim

The per-slot `e^ε` bound, and the sequential/advanced composition bounds
`novachannel-dp` already implements (`sequential_epsilon`,
`advanced_composition_epsilon`), hold for **any** joint distribution `D`
over `(b_1, ..., b_T)` — including one shaped by RLN's rate-limit
avoidance — with no additional privacy loss and no new analysis required
beyond what's already in the crate.

## Argument

**Per-slot bound is structurally immune to cross-slot correlation.**
`M_t` is a function of `b_t` alone — it never reads `b_1, ..., b_{t-1},
b_{t+1}, ..., b_T`. So for two "databases" that agree everywhere except
slot `t`, `M_t`'s output distribution depends only on the value at `t`;
the existing single-slot proof (`Pr[o=1|b=1]/Pr[o=1|b=0] = e^ε`, module
docs) goes through *unconditionally* on whatever the other coordinates are
or how they were generated. RLN's correlation lives entirely in "the other
coordinates" from `M_t`'s point of view, so it cannot appear anywhere in
that mechanism's own privacy analysis.

**Composition is a statement about mechanism randomness, not about the
input's structure.** The standard DP composition theorem (Dwork & Roth,
*The Algorithmic Foundations of Differential Privacy*, the sequential/
adaptive composition results in their Ch. 3) is proved by a hybrid
argument over the mechanisms' own independent coins, treating the
underlying database as fixed and arbitrary — the proof never assumes
anything about how the database's coordinates relate to each other. That's
exactly why DP composition is described as robust to *adaptive* adversaries
and correlated inputs in the first place: the guarantee has to survive an
adversary who picks the worst-case database, which subsumes an
adversary who picks one shaped like RLN's rate-limit behavior. Concretely,
composing `T` independent-randomness mechanisms `M_1, ..., M_T` gives
`(Σ ε_t)`-DP (or the tighter advanced-composition bound) for the *full*
vector `(b_1, ..., b_T)` under arbitrary-differing adjacency — i.e., it
bounds an adversary's ability to distinguish the true vector from *any*
other vector, which includes distinguishing "no real message all epoch"
from "exactly one real message, wherever RLN placed it." That is precisely
the question of interest, and it's already covered by the existing bound
with zero extra terms.

**So:** composing RLN with `novachannel-dp` costs nothing beyond the
epsilon `novachannel-dp` already spends, and needs no new mechanism,
because the composition theorem it already implements was never relying on
independence of the true send pattern to begin with — only on
independence of the *coin flips*, which the module docs already require
("the composition bounds assume the dummy-injection coin flips are drawn
independently per slot").

## What this does *not* show

This argument bounds what an adversary watching **one epoch's** slot-level
transmit/silent bits can learn. It says nothing about an adversary who
compares patterns **across** epochs or users — e.g. noticing that a
particular identity's traffic always shows exactly one real send per
epoch, at a roughly similar point in the window, and using that shape as a
fingerprint independent of any single epoch's content. That's a
longitudinal/unlinkability question, not a presence-in-a-slot question,
and `novachannel-dp`'s own module docs already scope it out explicitly
("timing/latency correlation ... explicitly out of scope"). Composing
with RLN doesn't introduce this gap — RLN's rate limit doesn't change
*what class* of signal is at risk here — but it doesn't close it either,
and a system that wanted that property would need a mechanism actually
built for it (e.g. randomizing epoch-relative send timing, not just
per-slot presence).

## Confidence level

This is a from-first-principles derivation using a standard, named
composition theorem, applied carefully to this specific mechanism — not
a novel result, and not independently peer reviewed. Treat it with the
same confidence as a careful referee report, not a published proof.
