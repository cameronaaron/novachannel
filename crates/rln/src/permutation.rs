//! Poseidon2 over the Goldilocks field (`winterfell::math::fields::f64`),
//! width 8: the in-circuit permutation for this crate's Merkle-membership
//! AIR.
//!
//! # Ported, not designed here
//! This replaced `NovaRescue`, a from-scratch Rescue-style permutation with
//! invented constants and no cryptanalysis. Every constant below (external
//! and internal round constants, internal diffusion diagonal) is copied from
//! `p3-goldilocks` 0.6.3, Plonky3's Goldilocks Poseidon2 (used by audited
//! provers such as SP1 and RISC Zero), and the round structure is a direct
//! port of `p3-poseidon2` 0.6.3. Two tests tie it to the reference:
//! `tests::matches_official_poseidon2_goldilocks_width8_test_vector`
//! (byte-for-byte on Plonky3's own vector) and
//! `tests::matches_the_real_upstream_crate_on_many_random_inputs` (10,000
//! random inputs against the published crate).
//!
//! # Why width 8
//! Plonky3 publishes Goldilocks constants only for widths 8, 12, 16 and 20;
//! no production instance exists at the old width 4. Width 8 is the smallest
//! audited one, at the cost of a wider trace.
//!
//! # What is this crate's own design
//! Only the permutation is ported. Wrapping it as a 2-to-1 Merkle
//! compression ([`compress2`]: two active lanes, six fixed to zero, output
//! from lane 0) is a standard construction chosen here.
//!
//! # Remaining caveat
//! The tests above are strong evidence against a transcription error, but
//! they are not an independent human review of this port.

use winterfell::math::{fields::f64::BaseElement, FieldElement};

/// Permutation state width, in field elements.
pub const WIDTH: usize = 8;
/// Forward S-box exponent. `x^7` permutes Goldilocks because
/// `gcd(7, p - 1) = 1`; `x^5` does not, since `p - 1 = 2^32 * (2^32 - 1)`
/// and `5 | (2^32 - 1)`. Hence degree 7 rather than the old design's 5.
pub const SBOX_DEGREE: u32 = 7;
/// Full rounds, split evenly before and after the partial rounds (`RF / 2`
/// each), matching `p3-goldilocks`'s `GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS`.
pub const HALF_FULL_ROUNDS: usize = 4;
/// Partial rounds, matching `p3-goldilocks`'s
/// `GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8`.
pub const PARTIAL_ROUNDS: usize = 22;
/// Round-function applications per permutation: one linear-only initial
/// mixing step (Poseidon2's extra external layer), `2 * HALF_FULL_ROUNDS`
/// full rounds and `PARTIAL_ROUNDS` partial rounds.
pub const ROUNDS: usize = 1 + 2 * HALF_FULL_ROUNDS + PARTIAL_ROUNDS;

/// Which mixing/S-box shape each step in [`ROUNDS`] uses. Public so the AIR
/// (`air.rs`) builds its selector columns from the same schedule.
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

/// Poseidon2's fixed 4x4 MDS matrix for the external layer (`p3-poseidon2`'s
/// `MDSMat4` / `apply_mat4`), `[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`,
/// with multiplications unrolled into additions as the reference does.
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

/// Poseidon2's external ("light") layer for width 8: `mds4` on each half,
/// then the circulant `[[2M4, M4], [M4, 2M4]]` mix (`p3-poseidon2`'s
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

/// The internal diffusion diagonal `[-2, 1, 2, 1/2, 3, -1/2, -3, -4]` as
/// field elements (`p3-goldilocks`'s `MATRIX_DIAG_8_GOLDILOCKS`).
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

/// Round constants for `Full` steps, by step index (0..[`ROUNDS`]); zero for
/// `LinearOnly`/`Partial` steps. With `internal_rc_lane0` this gives the AIR
/// one uniform per-step, per-lane constant table, so the step-to-constant-set
/// mapping lives in one place.
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

/// Precomputed parameters: the per-step round-constant table (the matrices
/// are fixed). A struct rather than direct [`step_round_constants`] calls so
/// `air.rs` can hold it as one value.
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

/// Runs the permutation, returning every intermediate state (`ROUNDS + 1`,
/// including the input) for the trace builder. For just the output use
/// `trace_permutation(..).last()`.
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

/// 2-to-1 compression `Hash(left, right) -> field element` for the Merkle
/// tree. Lanes 2..8 are fixed to zero, matching the AIR's convention.
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

    /// `p3-goldilocks` 0.6.3's
    /// `poseidon2::tests::test_default_goldilocks_poseidon2_width_8`, input and
    /// expected output transcribed: the port must be bit-identical to the
    /// reference.
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

    /// [`sbox`]'s unrolled squaring chain (`x2, x4, x6, x7`) must compute
    /// `x^SBOX_DEGREE`; checked here over the real field rather than trusted.
    #[test]
    fn sbox_computes_x_to_the_sbox_degree() {
        for x in [0u64, 1, 2, 3, 5, 1000, u64::MAX / 3].map(BaseElement::new) {
            assert_eq!(sbox(x), x.exp(u64::from(SBOX_DEGREE)));
        }
    }

    /// Checks the module-level claim that `x^SBOX_DEGREE` is a bijection,
    /// `gcd(SBOX_DEGREE, p - 1) == 1`, against the field's actual modulus, so a
    /// change of field or exponent can't silently break it.
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

    /// Property test against the published `p3-goldilocks` crate on many random
    /// inputs; one fixed vector can miss a wrong constant it doesn't exercise.
    /// It checks the port rather than replacing it: winterfell's `FieldElement`
    /// and Plonky3's `p3-field::Field` are unrelated traits with no adapter, so
    /// the in-circuit permutation must stay this crate's own code.
    #[test]
    fn matches_the_real_upstream_crate_on_many_random_inputs() {
        use p3_field::PrimeField64;
        use p3_symmetric::Permutation;
        use rand::{RngExt, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        let params = Params::new();
        let upstream = p3_goldilocks::default_goldilocks_poseidon2_8();
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);

        for trial in 0..10_000u32 {
            let raw: [u64; WIDTH] = core::array::from_fn(|_| rng.random::<u64>());

            let this_crate_input: [BaseElement; WIDTH] = raw.map(BaseElement::new);
            let this_crate_output = *trace_permutation(&params, this_crate_input)
                .last()
                .expect("trace_permutation always returns ROUNDS + 1 states");

            let mut upstream_state = p3_goldilocks::Goldilocks::new_array(raw);
            upstream.permute_mut(&mut upstream_state);

            for lane in 0..WIDTH {
                assert_eq!(
                    this_crate_output[lane].as_int(),
                    upstream_state[lane].as_canonical_u64(),
                    "trial {trial}, lane {lane} diverged from the real p3-goldilocks/\
                     p3-poseidon2 permutation on input {raw:?}"
                );
            }
        }
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
