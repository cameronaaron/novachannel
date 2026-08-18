//! Poseidon2 over the Goldilocks field (`winterfell::math::fields::f64`),
//! width 8 — the in-circuit permutation for the Merkle-membership AIR in
//! this crate.
//!
//! # Why this, not a from-scratch design
//! This module previously defined `NovaRescue`, a from-scratch Rescue-style
//! permutation with invented round constants and an invented MDS matrix,
//! honestly documented as never having had independent cryptanalysis. That
//! is the actual gap this module now closes: every constant below (the
//! external round constants, the internal round constants, the internal
//! diffusion matrix) is copied verbatim from `p3-goldilocks` 0.6.3
//! (Plonky3's own Goldilocks Poseidon2 instantiation — the hash underlying
//! multiple independently audited production STARK provers, e.g. Succinct's
//! SP1 and RISC Zero), and the round structure below is a direct port of
//! `p3-poseidon2` 0.6.3's generic algorithm, not a reinterpretation of it.
//! [`tests::matches_official_poseidon2_goldilocks_width8_test_vector`]
//! checks this port against `p3-goldilocks`'s own `#[test]` vector
//! byte-for-byte — the thing that actually matters here is that this is
//! *the same permutation*, not merely "inspired by" one.
//!
//! # Why width 8, not this crate's previous width 4
//! No production Poseidon2/RPO instance publishes parameters at width 4 —
//! checked directly against `p3-goldilocks`'s source, which only ships
//! constants for widths 8, 12, 16, and 20. Width 8 is the smallest
//! published, audited instance, so it's what this module ports, even
//! though it costs a wider AIR trace than the previous from-scratch width-4
//! design.
//!
//! # What's still this crate's own design, not Plonky3's
//! Only the *permutation* is ported verbatim. How it's wrapped into a
//! 2-to-1 Merkle compression function ([`compress2`]: two active lanes,
//! six lanes fixed to zero, output taken from lane 0) is this crate's own
//! sponge-usage choice, same shape the previous `NovaRescue`-based
//! `compress2` used — a standard, well-understood way to build a
//! compression function from a permutation, not a novel primitive in its
//! own right the way the permutation itself would be.
//!
//! # Remaining honest caveat
//! Porting the *permutation* closes the "invented, uncryptanalyzed
//! construction" gap. It does not, on its own, constitute an independent
//! review of *this port* — a transcription error in any of the constants
//! below would be a real bug. That's exactly what the test-vector check
//! above exists to catch: if this file's constants or round structure ever
//! drifted from `p3-goldilocks`'s, that test fails.

use winterfell::math::{fields::f64::BaseElement, FieldElement};

/// Permutation state width, in field elements.
pub const WIDTH: usize = 8;
/// Forward S-box exponent. `x^7` is a permutation of the Goldilocks field
/// because `gcd(7, p - 1) = 1` — unlike `x^5`, which is *not* a permutation
/// here (`p - 1 = 2^32 * (2^32 - 1)` and `5 | (2^32 - 1)`), which is why
/// Goldilocks-based Poseidon2/RPO instances use degree 7, not the degree-5
/// S-box the previous `NovaRescue` design (over a different field, where
/// degree 5 was fine) used.
pub const SBOX_DEGREE: u32 = 7;
/// Full rounds, split evenly before and after the partial rounds (`RF / 2`
/// each), matching `p3-goldilocks`'s `GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS`.
pub const HALF_FULL_ROUNDS: usize = 4;
/// Partial rounds, matching `p3-goldilocks`'s
/// `GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8`.
pub const PARTIAL_ROUNDS: usize = 22;
/// Total round-function applications per permutation call: one "linear
/// only" initial mixing step (Poseidon2's extra external-linear layer
/// before the first full round), `2 * HALF_FULL_ROUNDS` full rounds, and
/// `PARTIAL_ROUNDS` partial rounds.
pub const ROUNDS: usize = 1 + 2 * HALF_FULL_ROUNDS + PARTIAL_ROUNDS;

/// Which mixing/S-box shape a given step in [`ROUNDS`] uses. Exposed so the
/// AIR (`air.rs`) can build matching periodic selector columns without
/// this module and the AIR silently drifting apart on the round schedule.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StepKind {
    /// Poseidon2's initial external-linear mixing: [`mds_light`] only, no
    /// round constants, no S-box.
    LinearOnly,
    /// A full round: add constants to every lane, S-box every lane,
    /// [`mds_light`].
    Full,
    /// A partial round: add a constant to lane 0 only, S-box lane 0 only,
    /// [`internal_diffuse`].
    Partial,
}

/// The [`StepKind`] of each of the [`ROUNDS`] steps, in order.
pub fn step_kinds() -> [StepKind; ROUNDS] {
    core::array::from_fn(step_kind_at)
}

#[inline]
fn sbox<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}

/// The fixed 4x4 MDS matrix Poseidon2 uses for its external linear layer
/// (`p3-poseidon2`'s `MDSMat4` / `apply_mat4`):
/// `[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`, computed with
/// multiplications unrolled into additions exactly as the reference does.
#[inline]
fn mds4<E: FieldElement>(x: [E; 4]) -> [E; 4] {
    let t01 = x[0] + x[1];
    let t23 = x[2] + x[3];
    let t0123 = t01 + t23;
    let t01123 = t0123 + x[1];
    let t01233 = t0123 + x[3];
    [
        t01123 + t01,         // 2x0 + 3x1 + x2 + x3
        t01123 + x[2] + x[2], // x0 + 2x1 + 3x2 + x3
        t01233 + t23,         // x0 + x1 + 2x2 + 3x3
        t01233 + x[0] + x[0], // 3x0 + x1 + x2 + 2x3
    ]
}

/// Poseidon2's external ("light") linear layer for width 8: apply [`mds4`]
/// to each half of the state, then mix the two halves via the circulant
/// `[[2M4, M4], [M4, 2M4]]` block structure (`p3-poseidon2`'s
/// `mds_light_permutation`).
#[inline]
pub fn mds_light<E: FieldElement>(state: [E; WIDTH]) -> [E; WIDTH] {
    let lo = mds4([state[0], state[1], state[2], state[3]]);
    let hi = mds4([state[4], state[5], state[6], state[7]]);
    let sums: [E; 4] = core::array::from_fn(|k| lo[k] + hi[k]);
    [
        lo[0] + sums[0],
        lo[1] + sums[1],
        lo[2] + sums[2],
        lo[3] + sums[3],
        hi[0] + sums[0],
        hi[1] + sums[1],
        hi[2] + sums[2],
        hi[3] + sums[3],
    ]
}

/// The internal (partial-round) diffusion matrix for width 8:
/// `state[i] <- sum(state) + diag[i] * state[i]`, with `diag` =
/// [`INTERNAL_DIAG`] (`p3-goldilocks`'s `MATRIX_DIAG_8_GOLDILOCKS`).
#[inline]
pub fn internal_diffuse<E: FieldElement + From<BaseElement>>(state: [E; WIDTH]) -> [E; WIDTH] {
    let sum = state.iter().copied().fold(E::ZERO, |a, b| a + b);
    core::array::from_fn(|i| sum + E::from(INTERNAL_DIAG[i]) * state[i])
}

/// One full round: add `rc` to every lane, S-box every lane, [`mds_light`].
#[inline]
pub fn full_round<E: FieldElement + From<BaseElement>>(
    state: [E; WIDTH],
    rc: [E; WIDTH],
) -> [E; WIDTH] {
    let added: [E; WIDTH] = core::array::from_fn(|i| state[i] + rc[i]);
    let boxed: [E; WIDTH] = core::array::from_fn(|i| sbox(added[i]));
    mds_light(boxed)
}

/// One partial round: add `rc` to lane 0 only, S-box lane 0 only,
/// [`internal_diffuse`].
#[inline]
pub fn partial_round<E: FieldElement + From<BaseElement>>(
    state: [E; WIDTH],
    rc_lane0: E,
) -> [E; WIDTH] {
    let mut added = state;
    added[0] += rc_lane0;
    added[0] = sbox(added[0]);
    internal_diffuse(added)
}

/// Round constants for the four initial full rounds (`p3-goldilocks`'s
/// `GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL`).
pub const EXTERNAL_INITIAL: [[BaseElement; WIDTH]; HALF_FULL_ROUNDS] = [
    hex_row([
        0xdd5743e7f2a5a5d9,
        0xcb3a864e58ada44b,
        0xffa2449ed32f8cdc,
        0x42025f65d6bd13ee,
        0x7889175e25506323,
        0x34b98bb03d24b737,
        0xbdcc535ecc4faa2a,
        0x5b20ad869fc0d033,
    ]),
    hex_row([
        0xf1dda5b9259dfcb4,
        0x27515210be112d59,
        0x4227d1718c766c3f,
        0x26d333161a5bd794,
        0x49b938957bf4b026,
        0x4a56b5938b213669,
        0x1120426b48c8353d,
        0x6b323c3f10a56cad,
    ]),
    hex_row([
        0xce57d6245ddca6b2,
        0xb1fc8d402bba1eb1,
        0xb5c5096ca959bd04,
        0x6db55cd306d31f7f,
        0xc49d293a81cb9641,
        0x1ce55a4fe979719f,
        0xa92e60a9d178a4d1,
        0x002cc64973bcfd8c,
    ]),
    hex_row([
        0xcea721cce82fb11b,
        0xe5b55eb8098ece81,
        0x4e30525c6f1ddd66,
        0x43c6702827070987,
        0xaca68430a7b5762a,
        0x3674238634df9c93,
        0x88cee1c825e33433,
        0xde99ae8d74b57176,
    ]),
];

/// Round constants for the four terminal full rounds (`p3-goldilocks`'s
/// `GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL`).
pub const EXTERNAL_FINAL: [[BaseElement; WIDTH]; HALF_FULL_ROUNDS] = [
    hex_row([
        0x014ef1197d341346,
        0x9725e20825d07394,
        0xfdb25aef2c5bae3b,
        0xbe5402dc598c971e,
        0x93a5711f04cdca3d,
        0xc45a9a5b2f8fb97b,
        0xfe8946a924933545,
        0x2af997a27369091c,
    ]),
    hex_row([
        0xaa62c88e0b294011,
        0x058eb9d810ce9f74,
        0xb3cb23eced349ae4,
        0xa3648177a77b4a84,
        0x43153d905992d95d,
        0xf4e2a97cda44aa4b,
        0x5baa2702b908682f,
        0x082923bdf4f750d1,
    ]),
    hex_row([
        0x98ae09a325893803,
        0xf8a6475077968838,
        0xceb0735bf00b2c5f,
        0x0a1a5d953888e072,
        0x2fcb190489f94475,
        0xb5be06270dec69fc,
        0x739cb934b09acf8b,
        0x537750b75ec7f25b,
    ]),
    hex_row([
        0xe9dd318bae1f3961,
        0xf7462137299efe1a,
        0xb1f6b8eee9adb940,
        0xbdebcc8a809dfe6b,
        0x40fc1f791b178113,
        0x3ac1c3362d014864,
        0x9a016184bdb8aeba,
        0x95f2394459fbc25e,
    ]),
];

/// Round constants for the 22 partial rounds, one scalar per round, applied
/// to lane 0 only (`p3-goldilocks`'s `GOLDILOCKS_POSEIDON2_RC_8_INTERNAL`).
pub const INTERNAL: [BaseElement; PARTIAL_ROUNDS] = [
    BaseElement::new(0x488897d85ff51f56),
    BaseElement::new(0x1140737ccb162218),
    BaseElement::new(0xa7eeb9215866ed35),
    BaseElement::new(0x9bd2976fee49fcc9),
    BaseElement::new(0xc0c8f0de580a3fcc),
    BaseElement::new(0x4fb2dae6ee8fc793),
    BaseElement::new(0x343a89f35f37395b),
    BaseElement::new(0x223b525a77ca72c8),
    BaseElement::new(0x56ccb62574aaa918),
    BaseElement::new(0xc4d507d8027af9ed),
    BaseElement::new(0xa080673cf0b7e95c),
    BaseElement::new(0xf0184884eb70dcf8),
    BaseElement::new(0x044f10b0cb3d5c69),
    BaseElement::new(0xe9e3f7993938f186),
    BaseElement::new(0x1b761c80e772f459),
    BaseElement::new(0x606cec607a1b5fac),
    BaseElement::new(0x14a0c2e1d45f03cd),
    BaseElement::new(0x4eace8855398574f),
    BaseElement::new(0xf905ca7103eff3e6),
    BaseElement::new(0xf8c8f8d20862c059),
    BaseElement::new(0xb524fe8bdd678e5a),
    BaseElement::new(0xfbb7865901a1ec41),
];

/// The internal diffusion matrix's diagonal, `[-2, 1, 2, 1/2, 3, -1/2, -3,
/// -4]` as reduced field elements (`p3-goldilocks`'s
/// `MATRIX_DIAG_8_GOLDILOCKS`).
pub const INTERNAL_DIAG: [BaseElement; WIDTH] = hex_row([
    0xfffffffeffffffff, // -2
    0x0000000000000001, // 1
    0x0000000000000002, // 2
    0x7fffffff80000001, // 1/2
    0x0000000000000003, // 3
    0x7fffffff80000000, // -1/2
    0xfffffffefffffffe, // -3
    0xfffffffefffffffd, // -4
]);

const fn hex_row(vals: [u64; WIDTH]) -> [BaseElement; WIDTH] {
    [
        BaseElement::new(vals[0]),
        BaseElement::new(vals[1]),
        BaseElement::new(vals[2]),
        BaseElement::new(vals[3]),
        BaseElement::new(vals[4]),
        BaseElement::new(vals[5]),
        BaseElement::new(vals[6]),
        BaseElement::new(vals[7]),
    ]
}

/// The round constants used by the `Full` steps only, keyed by step index
/// (0..[`ROUNDS`]) — zero for `LinearOnly`/`Partial` steps. Paired with
/// [`internal_rc_lane0`] so the AIR can build one uniform per-step,
/// per-lane periodic round-constant table (zero where a given step/lane
/// combination doesn't add a constant there) without hand-tracking which
/// step index maps to which of `EXTERNAL_INITIAL`/`INTERNAL`/
/// `EXTERNAL_FINAL` more than once.
pub fn step_round_constants() -> [[BaseElement; WIDTH]; ROUNDS] {
    core::array::from_fn(|i| match step_kind_at(i) {
        StepKind::LinearOnly => [BaseElement::ZERO; WIDTH],
        StepKind::Full => {
            if i <= HALF_FULL_ROUNDS {
                EXTERNAL_INITIAL[i - 1]
            } else {
                EXTERNAL_FINAL[i - (HALF_FULL_ROUNDS + PARTIAL_ROUNDS) - 1]
            }
        }
        StepKind::Partial => {
            let mut row = [BaseElement::ZERO; WIDTH];
            row[0] = INTERNAL[i - HALF_FULL_ROUNDS - 1];
            row
        }
    })
}

fn step_kind_at(i: usize) -> StepKind {
    if i == 0 {
        StepKind::LinearOnly
    } else if i <= HALF_FULL_ROUNDS {
        StepKind::Full
    } else if i <= HALF_FULL_ROUNDS + PARTIAL_ROUNDS {
        StepKind::Partial
    } else {
        StepKind::Full
    }
}

/// Precomputed, shared parameters: just the per-step round-constant table
/// (the MDS/diffusion matrices are fixed, not parameterized, so unlike the
/// previous `NovaRescue` design there is nothing else to precompute or
/// carry around). Kept as a struct — rather than calling
/// [`step_round_constants`] directly everywhere — so `air.rs` can hold it
/// the same way it held the old `NovaRescue` `Params`.
pub struct Params {
    pub round_constants: [[BaseElement; WIDTH]; ROUNDS],
}

impl Params {
    pub fn new() -> Self {
        Params {
            round_constants: step_round_constants(),
        }
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

/// Applies one step of the permutation, dispatching on [`StepKind`].
pub fn apply_step<E: FieldElement + From<BaseElement>>(
    state: [E; WIDTH],
    kind: StepKind,
    rc: [E; WIDTH],
) -> [E; WIDTH] {
    match kind {
        StepKind::LinearOnly => mds_light(state),
        StepKind::Full => full_round(state, rc),
        StepKind::Partial => partial_round(state, rc[0]),
    }
}

/// Run the full permutation on a state, returning every intermediate state
/// (`ROUNDS + 1` states total, including the input) — the trace builder
/// needs every intermediate value; the plain "just give me the output"
/// case is `trace_permutation(..).last()`.
pub fn trace_permutation(
    params: &Params,
    input: [BaseElement; WIDTH],
) -> Vec<[BaseElement; WIDTH]> {
    let kinds = step_kinds();
    let mut states = Vec::with_capacity(ROUNDS + 1);
    states.push(input);
    let mut cur = input;
    for (kind, rc) in kinds.iter().zip(params.round_constants.iter()) {
        cur = apply_step(cur, *kind, *rc);
        states.push(cur);
    }
    states
}

/// 2-to-1 compression: `Hash(left, right) -> field element`, used to build
/// the Merkle tree. Lanes 2..8 (unused rate capacity) are fixed to zero,
/// matching the sponge convention used inside the AIR.
pub fn compress2(params: &Params, left: BaseElement, right: BaseElement) -> BaseElement {
    let input = [
        left,
        right,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
    ];
    *trace_permutation(params, input)
        .last()
        .expect("trace_permutation always returns ROUNDS + 1 states")
        .first()
        .expect("each state is a non-empty [BaseElement; WIDTH] array")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `p3-goldilocks` 0.6.3's own
    /// `poseidon2::tests::test_default_goldilocks_poseidon2_width_8`,
    /// transcribed input and expected output — the whole point of this
    /// test is that this module's port produces bit-identical output to
    /// the reference implementation, not just "a permutation that looks
    /// like Poseidon2".
    #[test]
    fn matches_official_poseidon2_goldilocks_width8_test_vector() {
        let params = Params::new();
        let input: [BaseElement; WIDTH] = core::array::from_fn(|i| BaseElement::new(i as u64));
        let expected: [BaseElement; WIDTH] = hex_row([
            0x020cf04a1b214d14,
            0x84e14aaaeacaed25,
            0x1ae0f640e81c7457,
            0xa4d204cbaeb0d8a5,
            0x0cf637b627b3a7ff,
            0x788d304d948b486b,
            0x7327133ea1949af4,
            0xf415abb924da395b,
        ]);

        let output = *trace_permutation(&params, input)
            .last()
            .expect("trace_permutation always returns ROUNDS + 1 states");
        assert_eq!(output, expected);
    }

    /// [`sbox`]'s hand-unrolled repeated-squaring implementation (`x2, x4,
    /// x6, x7`) is only ever *claimed* to compute `x^SBOX_DEGREE` in a
    /// doc comment -- nothing ties the two together mechanically. This
    /// checks that claim directly, over the field this module actually
    /// uses, rather than trusting the doc comment and the arithmetic to
    /// have stayed in sync by inspection.
    #[test]
    fn sbox_computes_x_to_the_sbox_degree() {
        for x in [0u64, 1, 2, 3, 5, 1000, u64::MAX / 3].map(BaseElement::new) {
            assert_eq!(sbox(x), x.exp(u64::from(SBOX_DEGREE)));
        }
    }

    /// The module docs claim `x^SBOX_DEGREE` is a permutation of the
    /// Goldilocks field because `gcd(SBOX_DEGREE, p - 1) == 1` -- a
    /// necessary and sufficient condition for `x -> x^k` to be a bijection
    /// on a finite field's multiplicative group. Checked computationally
    /// against the field's actual modulus rather than left as an
    /// unverified comment (the same failure mode `SBOX_DEGREE` being
    /// otherwise-unread code would have let slip by silently if the field
    /// or exponent ever changed).
    #[test]
    fn sbox_degree_is_coprime_with_the_field_order_minus_one() {
        use winterfell::math::StarkField;

        fn gcd(a: u128, b: u128) -> u128 {
            if b == 0 {
                a
            } else {
                gcd(b, a % b)
            }
        }
        let p_minus_1 = u128::from(BaseElement::MODULUS) - 1;
        assert_eq!(gcd(u128::from(SBOX_DEGREE), p_minus_1), 1);
    }

    #[test]
    fn default_matches_new() {
        let a = Params::default();
        let b = Params::new();
        assert_eq!(a.round_constants, b.round_constants);
    }

    #[test]
    fn trace_permutation_returns_rounds_plus_one_states_starting_with_the_input() {
        let params = Params::new();
        let input: [BaseElement; WIDTH] = core::array::from_fn(|i| BaseElement::new(i as u64 + 1));
        let states = trace_permutation(&params, input);
        assert_eq!(states.len(), ROUNDS + 1);
        assert_eq!(states[0], input);
    }

    #[test]
    fn compress2_is_deterministic_and_input_sensitive() {
        let params = Params::new();
        let a = BaseElement::new(1);
        let b = BaseElement::new(2);

        assert_eq!(compress2(&params, a, b), compress2(&params, a, b));
        // The construction isn't symmetric -- swapping inputs changes the
        // output, which is exactly what makes it usable as a Merkle
        // combiner (a tree can't tell left from right otherwise).
        assert_ne!(compress2(&params, a, b), compress2(&params, b, a));
    }
}
