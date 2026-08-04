//! The AIR (algebraic intermediate representation) for RLN membership +
//! rate-limit binding, and the [`winterfell::Prover`] that builds proofs
//! against it.
//!
//! # What the proof shows
//! Given public `(root, epoch, x, y, nullifier)`, the proof shows the
//! prover knows a secret `sk` such that:
//!
//! 1. `Hash(sk, 0)` is a leaf of the Merkle tree with the given `root`
//!    (anonymous membership — the path and leaf position stay hidden).
//! 2. `nullifier = Hash(sk, epoch)` (call this `a1`).
//! 3. `y = sk + a1 * x`.
//!
//! (3) is the Shamir-style rate-limit share: reusing the same `epoch` for a
//! second message forces a second `(x, y)` pair on the *same* line
//! `y = sk + a1*x`, and two points on a degree-1 line let anyone recover
//! `sk` — that's the "slashing" mechanism that makes exceeding the rate
//! limit costly, implemented in [`crate::share`].
//!
//! Binding all three inside one proof (rather than proving membership and
//! computing the share as two separate steps) is what stops a prover from
//! using a *different* secret for the share than the one whose commitment
//! is actually in the tree — see the module docs in `lib.rs` for why that
//! matters.
//!
//! # Trace layout
//! `DEPTH` Merkle levels, each one `NovaRescue` permutation call
//! ([`crate::permutation`]), followed by one more permutation call for
//! `a1 = Hash(sk, epoch)`, followed by one arithmetic-only block computing
//! `sk + a1*x`. Each block occupies [`BLOCK_LEN`] rows (one row per
//! permutation round, plus one row for the block's injected input).
//! Columns: `[state0..state3, sk, sibling_in, selector]`.

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree as WinterMerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

use crate::merkle::{PathStep, Side};
use crate::permutation::{apply_round, Params, ROUNDS, WIDTH as STATE_WIDTH};

/// Rows per block: one injection row plus [`ROUNDS`] round rows.
pub const BLOCK_LEN: usize = ROUNDS + 1;
/// Merkle tree depth (number of levels / path steps). The Merkle portion of
/// the trace needs `DEPTH + 1` hash-permutation blocks — one for the leaf
/// hash, plus one per combine step — so total blocks are
/// `(DEPTH + 1) + 1 (a1) + 1 (linear-check) = DEPTH + 3`. Chosen so
/// `(DEPTH + 3) * BLOCK_LEN` is a power of two, as required by the STARK
/// trace domain.
pub const DEPTH: usize = 5;
pub const NUM_MERKLE_BLOCKS: usize = DEPTH + 1;
pub const NUM_BLOCKS: usize = NUM_MERKLE_BLOCKS + 2;
pub const TRACE_LENGTH: usize = NUM_BLOCKS * BLOCK_LEN;

const COL_STATE0: usize = 0;
const COL_STATE1: usize = 1;
const COL_STATE2: usize = 2;
const COL_STATE3: usize = 3;
const COL_SK: usize = 4;
const COL_SIBLING: usize = 5;
const COL_SELECTOR: usize = 6;
const TRACE_WIDTH: usize = 7;

const A1_TRANSITION_ROW: usize = NUM_MERKLE_BLOCKS * BLOCK_LEN - 1;
const LINEARCHECK_TRANSITION_ROW: usize = (NUM_MERKLE_BLOCKS + 1) * BLOCK_LEN - 1;
const ROOT_ROW: usize = A1_TRANSITION_ROW;
const A1_OUTPUT_ROW: usize = LINEARCHECK_TRANSITION_ROW;
const Y_ROW: usize = LINEARCHECK_TRANSITION_ROW + 1;
const A1_INPUT_ROW: usize = A1_TRANSITION_ROW + 1;

#[doc(hidden)]
pub const ROOT_ROW_PUB: usize = ROOT_ROW;

const _: () = assert!(TRACE_LENGTH.is_power_of_two());

#[derive(Clone)]
pub struct PublicInputs {
    pub root: BaseElement,
    pub epoch: BaseElement,
    pub x: BaseElement,
    pub y: BaseElement,
    pub nullifier: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.root, self.epoch, self.x, self.y, self.nullifier]
    }
}

pub struct RlnAir {
    context: AirContext<BaseElement>,
    pub_inputs: PublicInputs,
    params: Params,
}

fn round_result(
    params: &Params,
    row_in_block: usize,
    state: [BaseElement; STATE_WIDTH],
) -> [BaseElement; STATE_WIDTH] {
    let rc = if row_in_block < ROUNDS {
        params.round_constants[row_in_block]
    } else {
        [BaseElement::ZERO; STATE_WIDTH]
    };
    apply_round(&state, &rc, &params.mds)
}

impl Air for RlnAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width());

        // Degrees, in the order constraints are pushed in `evaluate_transition`.
        let degrees = vec![
            // D1..D4: state0 update (internal round / merkle-boundary / a1 / linearcheck).
            TransitionConstraintDegree::with_cycles(6, vec![BLOCK_LEN, BLOCK_LEN]), // D1 (sbox degree 5 * (1-flag) deg1)
            TransitionConstraintDegree::with_cycles(2, vec![BLOCK_LEN, TRACE_LENGTH, TRACE_LENGTH]), // D2
            TransitionConstraintDegree::with_cycles(1, vec![TRACE_LENGTH]), // D3
            TransitionConstraintDegree::with_cycles(2, vec![TRACE_LENGTH]), // D4
            // E1..E3: state1..3 internal round.
            TransitionConstraintDegree::with_cycles(6, vec![BLOCK_LEN, BLOCK_LEN]),
            TransitionConstraintDegree::with_cycles(6, vec![BLOCK_LEN, BLOCK_LEN]),
            TransitionConstraintDegree::with_cycles(6, vec![BLOCK_LEN, BLOCK_LEN]),
            // F1..F3: state1..3 boundary injection.
            TransitionConstraintDegree::with_cycles(2, vec![BLOCK_LEN]),
            TransitionConstraintDegree::with_cycles(1, vec![BLOCK_LEN]),
            TransitionConstraintDegree::with_cycles(1, vec![BLOCK_LEN]),
            // sk constancy.
            TransitionConstraintDegree::new(1),
            // selector boolean.
            TransitionConstraintDegree::new(2),
            // row0 seeding.
            TransitionConstraintDegree::with_cycles(1, vec![TRACE_LENGTH]),
        ];
        let num_assertions = 8;

        RlnAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
            params: Params::new(),
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let is_last_in_block = periodic_values[0];
        let rc: [E; STATE_WIDTH] = [
            periodic_values[1],
            periodic_values[2],
            periodic_values[3],
            periodic_values[4],
        ];
        let is_a1_transition = periodic_values[5];
        let is_linearcheck_transition = periodic_values[6];
        let is_row0 = periodic_values[7];

        let one = E::ONE;
        let not_last = one - is_last_in_block;

        // Internal-round result for the current row, computed with the same
        // round function as trace generation (see `permutation::apply_round`),
        // inlined here over the extension field `E`.
        let added: [E; STATE_WIDTH] = core::array::from_fn(|i| current[i] + rc[i]);
        let boxed: [E; STATE_WIDTH] = core::array::from_fn(|i| {
            let x = added[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            x4 * x
        });
        let mds: [[E; STATE_WIDTH]; STATE_WIDTH] =
            core::array::from_fn(|i| core::array::from_fn(|j| E::from(self.params.mds[i][j])));
        let round_out: [E; STATE_WIDTH] = core::array::from_fn(|i| {
            (0..STATE_WIDTH).fold(E::ZERO, |acc, j| acc + mds[i][j] * boxed[j])
        });

        let not_a1_or_linear = one - is_a1_transition - is_linearcheck_transition;

        // D1: internal round, slot 0.
        let d1 = not_last * (next[COL_STATE0] - round_out[COL_STATE0]);
        // D2: generic merkle-boundary injection, slot 0.
        let generic0 = next[COL_SELECTOR] * next[COL_SIBLING]
            + (one - next[COL_SELECTOR]) * current[COL_STATE0];
        let d2 = is_last_in_block * not_a1_or_linear * (next[COL_STATE0] - generic0);
        // D3: a1-block seeding, slot 0 <- sk.
        let d3 = is_a1_transition * (next[COL_STATE0] - current[COL_SK]);
        // D4: linear-check row, slot 0 <- sk + a1 * x.
        let x_const = E::from(self.pub_inputs.x);
        let d4 = is_linearcheck_transition
            * (next[COL_STATE0] - (current[COL_SK] + current[COL_STATE0] * x_const));

        result[0] = d1;
        result[1] = d2;
        result[2] = d3;
        result[3] = d4;

        // E1..E3 / F1..F3: slots 1..3.
        for (k, &col) in [COL_STATE1, COL_STATE2, COL_STATE3].iter().enumerate() {
            let e = not_last * (next[col] - round_out[col]);
            let generic = if col == COL_STATE1 {
                next[COL_SELECTOR] * current[COL_STATE0]
                    + (one - next[COL_SELECTOR]) * next[COL_SIBLING]
            } else {
                E::ZERO
            };
            let f = is_last_in_block * (next[col] - generic);
            result[4 + k] = e;
            result[7 + k] = f;
        }

        // sk constancy.
        result[10] = next[COL_SK] - current[COL_SK];
        // selector boolean.
        result[11] = current[COL_SELECTOR] * (current[COL_SELECTOR] - one);
        // row0 seeding: state0 == sk at row 0.
        result[12] = is_row0 * (current[COL_STATE0] - current[COL_SK]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            Assertion::single(COL_STATE1, 0, BaseElement::ZERO),
            Assertion::single(COL_STATE2, 0, BaseElement::ZERO),
            Assertion::single(COL_STATE3, 0, BaseElement::ZERO),
            Assertion::single(COL_STATE0, ROOT_ROW, self.pub_inputs.root),
            Assertion::single(COL_STATE0, A1_OUTPUT_ROW, self.pub_inputs.nullifier),
            Assertion::single(COL_STATE0, Y_ROW, self.pub_inputs.y),
            Assertion::single(COL_SIBLING, A1_INPUT_ROW, self.pub_inputs.epoch),
            Assertion::single(COL_SELECTOR, A1_INPUT_ROW, BaseElement::ZERO),
        ]
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut is_last_in_block = vec![BaseElement::ZERO; BLOCK_LEN];
        is_last_in_block[BLOCK_LEN - 1] = BaseElement::ONE;

        let mut rc_cols = vec![vec![BaseElement::ZERO; BLOCK_LEN]; STATE_WIDTH];
        for (r, round_constants) in self.params.round_constants.iter().enumerate().take(ROUNDS) {
            for (col, &rc) in rc_cols.iter_mut().zip(round_constants.iter()) {
                col[r] = rc;
            }
        }

        let mut is_a1_transition = vec![BaseElement::ZERO; TRACE_LENGTH];
        is_a1_transition[A1_TRANSITION_ROW] = BaseElement::ONE;

        let mut is_linearcheck_transition = vec![BaseElement::ZERO; TRACE_LENGTH];
        is_linearcheck_transition[LINEARCHECK_TRANSITION_ROW] = BaseElement::ONE;

        let mut is_row0 = vec![BaseElement::ZERO; TRACE_LENGTH];
        is_row0[0] = BaseElement::ONE;

        vec![
            is_last_in_block,
            rc_cols[0].clone(),
            rc_cols[1].clone(),
            rc_cols[2].clone(),
            rc_cols[3].clone(),
            is_a1_transition,
            is_linearcheck_transition,
            is_row0,
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

/// Everything the prover needs to know that isn't public: the secret key
/// and the Merkle authentication path for its commitment.
pub struct Witness {
    pub sk: BaseElement,
    pub path: Vec<PathStep>,
}

/// Builds the execution trace for one RLN proof. `witness.path.len()` must
/// equal [`DEPTH`].
pub fn build_trace(
    params: &Params,
    witness: &Witness,
    epoch: BaseElement,
    x: BaseElement,
) -> TraceTable<BaseElement> {
    assert_eq!(witness.path.len(), DEPTH, "path length must equal DEPTH");

    let mut cols: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; TRACE_LENGTH]; TRACE_WIDTH];

    // sk is constant across the whole trace.
    for row in cols[COL_SK].iter_mut() {
        *row = witness.sk;
    }

    // Row 0: leaf hash input = (sk, 0, 0, 0).
    let mut state: [BaseElement; STATE_WIDTH] = [
        witness.sk,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
    ];
    write_state(&mut cols, 0, state);

    let mut row = 0usize;
    // Merkle blocks.
    for step in &witness.path {
        for r in 0..ROUNDS {
            state = round_result(params, r, state);
            row += 1;
            write_state(&mut cols, row, state);
        }
        // Boundary injection into the next block's row 0.
        let (sibling, selector) = match step.side {
            Side::Left => (step.sibling, BaseElement::ZERO),
            Side::Right => (step.sibling, BaseElement::ONE),
        };
        cols[COL_SIBLING][row + 1] = sibling;
        cols[COL_SELECTOR][row + 1] = selector;
        let (left, right) = match step.side {
            Side::Left => (state[0], sibling),
            Side::Right => (sibling, state[0]),
        };
        state = [left, right, BaseElement::ZERO, BaseElement::ZERO];
        row += 1;
        write_state(&mut cols, row, state);
    }
    // The loop above ran DEPTH times (rounds-then-inject per path step),
    // which finishes DEPTH blocks of rounds (the leaf hash plus the first
    // DEPTH-1 combines) and seeds DEPTH+1 blocks total. The very last
    // merkle block — the final combine, whose seed the loop just wrote —
    // still needs its own rounds run to actually produce the root.
    for r in 0..ROUNDS {
        state = round_result(params, r, state);
        row += 1;
        write_state(&mut cols, row, state);
    }
    debug_assert_eq!(row, ROOT_ROW);
    row += 1;
    debug_assert_eq!(row, A1_INPUT_ROW);

    // a1 block: input (sk, epoch, 0, 0), set directly (mirrors constraint D3/F1).
    cols[COL_SIBLING][A1_INPUT_ROW] = epoch;
    cols[COL_SELECTOR][A1_INPUT_ROW] = BaseElement::ZERO;
    state = [witness.sk, epoch, BaseElement::ZERO, BaseElement::ZERO];
    write_state(&mut cols, A1_INPUT_ROW, state);
    for r in 0..ROUNDS {
        state = round_result(params, r, state);
        row += 1;
        write_state(&mut cols, row, state);
    }
    debug_assert_eq!(row, A1_OUTPUT_ROW);
    let a1 = state[0];

    // Linear-check block: row Y_ROW's state0 = sk + a1 * x (matches D4).
    row += 1;
    debug_assert_eq!(row, Y_ROW);
    let y_state: [BaseElement; STATE_WIDTH] = [
        witness.sk + a1 * x,
        BaseElement::ZERO,
        BaseElement::ZERO,
        BaseElement::ZERO,
    ];
    write_state(&mut cols, Y_ROW, y_state);
    // Remaining rows of the final block are unused padding; keep applying
    // the round function so the (unread) internal-round constraint is
    // still satisfied uniformly.
    state = y_state;
    for r in 0..ROUNDS {
        state = round_result(params, r, state);
        row += 1;
        if row < TRACE_LENGTH {
            write_state(&mut cols, row, state);
        }
    }

    TraceTable::init(cols)
}

fn write_state(cols: &mut [Vec<BaseElement>], row: usize, state: [BaseElement; STATE_WIDTH]) {
    cols[COL_STATE0][row] = state[0];
    cols[COL_STATE1][row] = state[1];
    cols[COL_STATE2][row] = state[2];
    cols[COL_STATE3][row] = state[3];
}

pub struct RlnProver {
    options: ProofOptions,
    pub_inputs: PublicInputs,
}

impl RlnProver {
    /// The caller must supply the exact public inputs the trace was built
    /// against — `Prover::get_pub_inputs` returns these verbatim rather
    /// than trying to recover them from trace cells, since not every
    /// public input (`x`, notably) has a natural home in the trace.
    pub fn new(options: ProofOptions, pub_inputs: PublicInputs) -> Self {
        RlnProver {
            options,
            pub_inputs,
        }
    }
}

impl Prover for RlnProver {
    type BaseField = BaseElement;
    type Air = RlnAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = WinterMerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Standard proof options for this AIR: ~96-bit conjectured security,
/// matching the parameters used in winterfell's own reference example.
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// # Errors
/// Fails only if the trace itself is malformed (a bug in [`build_trace`] or
/// in this crate's degree bookkeeping, not something a caller's inputs can
/// trigger) — returned as `Err` rather than panicking so that a proving
/// hiccup on our side degrades one caller's request instead of aborting
/// their process.
pub fn prove(
    witness: &Witness,
    epoch: BaseElement,
    x: BaseElement,
    y: BaseElement,
    nullifier: BaseElement,
) -> Result<(Proof, PublicInputs), String> {
    let params = Params::new();
    let trace = build_trace(&params, witness, epoch, x);
    let root = trace.get(COL_STATE0, ROOT_ROW);
    let pub_inputs = PublicInputs {
        root,
        epoch,
        x,
        y,
        nullifier,
    };

    let prover = RlnProver::new(default_proof_options(), pub_inputs.clone());
    let proof = prover.prove(trace).map_err(|e| e.to_string())?;
    Ok((proof, pub_inputs))
}

pub fn verify(proof: Proof, pub_inputs: PublicInputs) -> Result<(), String> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<
        RlnAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        WinterMerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    .map_err(|e| e.to_string())
}
