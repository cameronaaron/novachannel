//! `NovaRescue`: a small Rescue-style, STARK-friendly one-way permutation
//! used as the in-circuit hash for the Merkle-membership AIR in this crate.
//!
//! # Why a new permutation instead of a vetted one
//! Winterfell's own hash implementations (`Rp64_256`, `Blake3_256`, ...) are
//! used *outside* the circuit, for the STARK protocol's own Merkle/FRI
//! commitments — that part of this crate is unmodified, audited code.
//! What's needed *inside* the circuit is different: a permutation whose
//! round function is cheap to express as a low-degree AIR transition
//! constraint, over the specific field this crate's AIR uses
//! (`winterfell::math::fields::f128`). No published implementation fits
//! that combination directly, so this module defines one, following the
//! public Rescue-Prime design (alternating additive round constants,
//! power-map S-box, MDS mixing) with parameters generated deterministically
//! in code rather than hand-copied from a paper (see [`round_constants`]).
//!
//! # Honest security status
//! **This is a from-scratch algebraic hash and has not been independently
//! cryptanalyzed.** Rescue/Poseidon/Griffin-class permutations required
//! years of public scrutiny before their round counts were trusted; this
//! one has had none. Treat `NovaRescue` as demonstrating the *shape* of a
//! ZK-STARK-friendly RLN circuit, not as a hash suitable for a production
//! deployment without an independent security review of the round count,
//! S-box exponent, and MDS matrix below.

use winterfell::math::{fields::f128::BaseElement, FieldElement};

/// Permutation state width, in field elements.
pub const WIDTH: usize = 4;
/// Number of rounds. Chosen conservatively relative to the S-box degree,
/// but see the module-level caveat: this has not been cryptanalyzed.
pub const ROUNDS: usize = 7;
/// S-box exponent (`x^5`); computed by repeated squaring, not `FieldElement::exp`,
/// so the degree is easy to read directly off the code.
#[inline]
fn sbox(x: BaseElement) -> BaseElement {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Round constants, generated deterministically from a fixed seed via a
/// simple splitmix64-style generator. Being *public* and *fixed* is the
/// only requirement for Rescue-style round constants (they don't need to be
/// secret); generating them in code rather than embedding a literal table
/// makes the derivation auditable and keeps this module self-contained.
fn round_constants() -> [[BaseElement; WIDTH]; ROUNDS] {
    const SEED: u64 = 0x4e6f_7661_5253_5443; // "NovaRSTC" as bytes, arbitrary fixed domain tag.
    let mut state = SEED;
    let mut next_u64 = move || {
        // splitmix64
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    };

    let mut rc = [[BaseElement::ZERO; WIDTH]; ROUNDS];
    for round in rc.iter_mut() {
        for slot in round.iter_mut() {
            // Combine two 64-bit draws into a 128-bit value, then reduce
            // into the field by construction (`BaseElement::new` reduces
            // mod p internally).
            let hi = next_u64() as u128;
            let lo = next_u64() as u128;
            *slot = BaseElement::new((hi << 64) | lo);
        }
    }
    rc
}

/// The MDS (maximum-distance-separable) mixing matrix, built as a Cauchy
/// matrix: `M[i][j] = 1 / (x_i - y_j)` for distinct `x_i`, `y_j`. Any Cauchy
/// matrix built this way is guaranteed MDS by construction (a standard,
/// checkable algebraic fact), so this is provably a valid choice without
/// needing to hand-verify a hardcoded matrix.
fn mds_matrix() -> [[BaseElement; WIDTH]; WIDTH] {
    let xs: [BaseElement; WIDTH] = core::array::from_fn(|i| BaseElement::new(i as u128));
    let ys: [BaseElement; WIDTH] = core::array::from_fn(|j| BaseElement::new((WIDTH + j) as u128));

    core::array::from_fn(|i| core::array::from_fn(|j| (xs[i] - ys[j]).inv()))
}

fn mds_multiply(
    mds: &[[BaseElement; WIDTH]; WIDTH],
    state: &[BaseElement; WIDTH],
) -> [BaseElement; WIDTH] {
    core::array::from_fn(|i| {
        let mut acc = BaseElement::ZERO;
        for j in 0..WIDTH {
            acc += mds[i][j] * state[j];
        }
        acc
    })
}

/// One full round: add constants, apply the S-box to every element, mix
/// with the MDS matrix. Used identically by trace generation (here) and by
/// the AIR's transition constraint (`air.rs`) — the two are written from
/// this single shared function so they cannot drift out of sync.
pub fn apply_round(
    state: &[BaseElement; WIDTH],
    round_constants: &[BaseElement; WIDTH],
    mds: &[[BaseElement; WIDTH]; WIDTH],
) -> [BaseElement; WIDTH] {
    let added: [BaseElement; WIDTH] = core::array::from_fn(|i| state[i] + round_constants[i]);
    let boxed: [BaseElement; WIDTH] = core::array::from_fn(|i| sbox(added[i]));
    mds_multiply(mds, &boxed)
}

pub struct Params {
    pub round_constants: [[BaseElement; WIDTH]; ROUNDS],
    pub mds: [[BaseElement; WIDTH]; WIDTH],
}

impl Params {
    pub fn new() -> Self {
        Params {
            round_constants: round_constants(),
            mds: mds_matrix(),
        }
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the full `ROUNDS`-round permutation on a state, returning every
/// intermediate state (`ROUNDS + 1` states total, including the input).
/// The trace builder needs every intermediate value; the plain "just give
/// me the output" case is `full_permutation(..).last()`.
pub fn trace_permutation(
    params: &Params,
    input: [BaseElement; WIDTH],
) -> Vec<[BaseElement; WIDTH]> {
    let mut states = Vec::with_capacity(ROUNDS + 1);
    states.push(input);
    let mut cur = input;
    for r in 0..ROUNDS {
        cur = apply_round(&cur, &params.round_constants[r], &params.mds);
        states.push(cur);
    }
    states
}

/// 2-to-1 compression: `Hash(left, right) -> field element`, used to build
/// the Merkle tree. Capacity lanes (state[2], state[3]) are fixed to zero,
/// matching the sponge convention used inside the AIR.
pub fn compress2(params: &Params, left: BaseElement, right: BaseElement) -> BaseElement {
    let input = [left, right, BaseElement::ZERO, BaseElement::ZERO];
    *trace_permutation(params, input)
        .last()
        .expect("trace_permutation always returns ROUNDS + 1 states")
        .first()
        .expect("each state is a non-empty [BaseElement; WIDTH] array")
}

/// `Hash(sk, epoch) -> a1`, using the same permutation with a distinct
/// input shape (no third/fourth input needed; capacity lanes zeroed).
pub fn hash2(params: &Params, a: BaseElement, b: BaseElement) -> BaseElement {
    compress2(params, a, b)
}
