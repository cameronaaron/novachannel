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
//! `DEPTH` Merkle levels, each one Poseidon2 permutation call
//! ([`crate::permutation`]), followed by one more permutation call for
//! `a1 = Hash(sk, epoch)`, followed by one arithmetic-only block computing
//! `sk + a1*x`. Each block occupies [`BLOCK_LEN`] rows (one row per
//! permutation step, plus one row for the block's injected input).
//! Columns: `[state0..state7, sk, sibling_in, selector]`.
//!
//! Every row's internal-round transition blends three possible outputs —
//! [`permutation::mds_light`] (Poseidon2's linear-only step),
//! [`permutation::full_round`] (S-box on every lane), and
//! [`permutation::partial_round`] (S-box on lane 0 only) — by the periodic
//! `is_linear_only`/`is_full`/`is_partial` selectors, calling the exact
//! same generic functions [`crate::permutation::trace_permutation`] uses
//! for trace generation, so the two cannot drift out of sync the way two
//! independently hand-written copies of the round function could.

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree as WinterMerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

use crate::merkle::{PathStep, Side};
use crate::permutation::{
    self, apply_step, step_kinds, Params, StepKind, ROUNDS, WIDTH as STATE_WIDTH,
};

/// Rows per block: one injection row plus [`ROUNDS`] round-step rows.
pub const BLOCK_LEN: usize = ROUNDS + 1;
/// This crate's default Merkle tree depth (number of levels / path steps),
/// used by this crate's own tests/examples where no other depth is called
/// for -- not a hard limit. Any `depth` for which [`is_valid_depth`] holds
/// works: [`Witness::path`]'s length *is* the depth (nothing else needs to
/// be told what it is), [`build_trace`] sizes the trace to match, and
/// [`RlnAir::new`] recovers `depth` from the trace length winterfell hands
/// it, so a caller picks a depth simply by handing over a path of that
/// length.
pub const DEPTH: usize = 5;

/// The Merkle portion of the trace needs `depth + 1` hash-permutation
/// blocks -- one for the leaf hash, plus one per combine step.
pub fn num_merkle_blocks(depth: usize) -> usize {
    depth + 1
}

/// Total blocks: the Merkle blocks, plus one for `a1 = Hash(sk, epoch)`,
/// plus one for the linear-check row.
pub fn num_blocks(depth: usize) -> usize {
    num_merkle_blocks(depth) + 2
}

/// Total trace length for a tree of the given `depth`.
pub fn trace_length(depth: usize) -> usize {
    num_blocks(depth) * BLOCK_LEN
}

/// Whether `depth` is usable at all: the STARK trace domain requires
/// [`trace_length`] to be a power of two, and since [`BLOCK_LEN`] already
/// is one, that reduces to [`num_blocks`] being a power of two -- true for
/// `depth` in `{1, 5, 13, 29, 61, ...}` (`num_blocks` in
/// `{4, 8, 16, 32, 64, ...}`; `num_blocks` of `1` or `2` are excluded
/// separately since a Merkle tree needs at least one block of its own on
/// top of the `a1`/linear-check blocks).
pub fn is_valid_depth(depth: usize) -> bool {
    let blocks = num_blocks(depth);
    blocks > 2 && blocks.is_power_of_two()
}

fn a1_transition_row(depth: usize) -> usize {
    num_merkle_blocks(depth) * BLOCK_LEN - 1
}

fn linearcheck_transition_row(depth: usize) -> usize {
    (num_merkle_blocks(depth) + 1) * BLOCK_LEN - 1
}

/// The row holding the Merkle root, for a tree of the given `depth` --
/// e.g. `trace.get(0, air::root_row(depth))` after [`build_trace`].
pub fn root_row(depth: usize) -> usize {
    a1_transition_row(depth)
}

fn a1_output_row(depth: usize) -> usize {
    linearcheck_transition_row(depth)
}

fn y_row(depth: usize) -> usize {
    linearcheck_transition_row(depth) + 1
}

fn a1_input_row(depth: usize) -> usize {
    a1_transition_row(depth) + 1
}

const COL_STATE0: usize = 0;
const COL_STATE1: usize = 1;
const COL_STATE2: usize = 2;
const COL_STATE3: usize = 3;
const COL_STATE4: usize = 4;
const COL_STATE5: usize = 5;
const COL_STATE6: usize = 6;
const COL_STATE7: usize = 7;
const COL_SK: usize = 8;
const COL_SIBLING: usize = 9;
const COL_SELECTOR: usize = 10;
const TRACE_WIDTH: usize = 11;

/// The other-than-lane-0 state columns, in order — used everywhere the
/// generalized "every non-lane-0 lane behaves the same way" logic needs to
/// iterate over all seven of them without repeating the list.
const OTHER_STATE_COLS: [usize; STATE_WIDTH - 1] = [
    COL_STATE1, COL_STATE2, COL_STATE3, COL_STATE4, COL_STATE5, COL_STATE6, COL_STATE7,
];

// Periodic column indices, shared between `evaluate_transition` and
// `get_periodic_column_values` so the two can't silently disagree on
// layout.
const PC_IS_LAST_IN_BLOCK: usize = 0;
const PC_RC0: usize = 1; // rc0..rc7 occupy indices 1..=8.
const PC_IS_LINEAR_ONLY: usize = 9;
const PC_IS_FULL: usize = 10;
const PC_IS_PARTIAL: usize = 11;
const PC_IS_A1_TRANSITION: usize = 12;
const PC_IS_LINEARCHECK_TRANSITION: usize = 13;
const PC_IS_ROW0: usize = 14;
const NUM_PERIODIC_COLUMNS: usize = 15;

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
    /// Recovered from the trace length winterfell hands [`RlnAir::new`]
    /// (see [`trace_length`]) rather than stored redundantly -- there is
    /// exactly one `depth` consistent with a given trace length, so
    /// there's nothing to keep in sync by tracking it any other way.
    depth: usize,
}

fn step_result(
    params: &Params,
    row_in_block: usize,
    state: [BaseElement; STATE_WIDTH],
) -> [BaseElement; STATE_WIDTH] {
    if row_in_block >= ROUNDS {
        return state;
    }
    let kinds = step_kinds();
    apply_step(
        state,
        kinds[row_in_block],
        params.round_constants[row_in_block],
    )
}

impl Air for RlnAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width());

        let trace_len = trace_info.length();
        assert!(
            trace_len.is_multiple_of(BLOCK_LEN),
            "trace length {trace_len} is not a multiple of BLOCK_LEN ({BLOCK_LEN})"
        );
        let blocks = trace_len / BLOCK_LEN;
        assert!(
            blocks > 2,
            "trace length {trace_len} is too short for even a zero-depth tree"
        );
        let depth = blocks - 3;
        assert!(
            is_valid_depth(depth),
            "trace length {trace_len} implies depth {depth}, which is invalid \
             (depth + 3 must be a power of two)"
        );

        // Every internal-round constraint (D1, E1..E7) blends
        // mds_light/full_round/partial_round by three mutually-exclusive
        // periodic selectors (summed, not multiplied together -- only one
        // branch is ever live on a given row), on top of the per-lane
        // periodic round constant. Winterfell's declared
        // `TransitionConstraintDegree` must equal the constraint's *exact*
        // measured degree (its debug-mode `validate_transition_degrees`
        // check, in `evaluation_table.rs`, is an equality assertion, not a
        // ceiling), so this is calibrated against that check rather than
        // hand-derived from an informal "worst case" reading of the
        // formula -- see the two-point fit in the PR/commit that added
        // this comment for the derivation. The dominant term is
        // `not_last * is_full * sbox(state + rc)`: base degree 7 (the
        // S-box), against two periodic factors of period BLOCK_LEN
        // (`not_last`, the live selector -- the per-lane `rc` column does
        // not add a third, since it's summed into the trace column before
        // the S-box rather than an independent multiplicative factor).
        let round_cycles = vec![BLOCK_LEN; 2];
        let round_degree = TransitionConstraintDegree::with_cycles(7, round_cycles);

        let mut degrees = vec![
            // D1: state0 internal round (blended mds_light/full/partial).
            round_degree.clone(),
            // D2: generic merkle-boundary injection, state0. Degree-2
            // trace-column product (`selector * sibling`) times
            // `is_last_in_block` (period BLOCK_LEN); the `not_a1_or_linear`
            // factor does not add a further periodic factor in the exact
            // measured degree (see the D1 comment above on why this is
            // fit against the equality check rather than derived by a
            // naive worst-case count).
            TransitionConstraintDegree::with_cycles(3, vec![BLOCK_LEN]),
            // D3: a1-block seeding, state0 <- sk.
            TransitionConstraintDegree::with_cycles(1, vec![trace_len]),
            // D4: linear-check row, state0 <- sk + a1 * x. Degree 2 in
            // trace columns (`state0 * x_const`) with no further periodic
            // factor in the exact measured degree, matching D3's pattern.
            TransitionConstraintDegree::new(2),
        ];
        // E1..E7: state1..7 internal round (same blended formula as D1).
        for _ in OTHER_STATE_COLS {
            degrees.push(round_degree.clone());
        }
        // F1: state1 boundary injection (sibling/selector merge logic).
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![BLOCK_LEN]));
        // F2..F7: state2..7 boundary injection (always zero).
        for _ in &OTHER_STATE_COLS[1..] {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![BLOCK_LEN]));
        }
        // sk constancy.
        degrees.push(TransitionConstraintDegree::new(1));
        // selector boolean.
        degrees.push(TransitionConstraintDegree::new(2));
        // row0 seeding.
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![trace_len]));

        let num_assertions = (STATE_WIDTH - 1) + 5;

        RlnAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
            params: Params::new(),
            depth,
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

        let is_last_in_block = periodic_values[PC_IS_LAST_IN_BLOCK];
        let rc: [E; STATE_WIDTH] = core::array::from_fn(|i| periodic_values[PC_RC0 + i]);
        let is_linear_only = periodic_values[PC_IS_LINEAR_ONLY];
        let is_full = periodic_values[PC_IS_FULL];
        let is_partial = periodic_values[PC_IS_PARTIAL];
        let is_a1_transition = periodic_values[PC_IS_A1_TRANSITION];
        let is_linearcheck_transition = periodic_values[PC_IS_LINEARCHECK_TRANSITION];
        let is_row0 = periodic_values[PC_IS_ROW0];

        let one = E::ONE;
        let not_last = one - is_last_in_block;

        // The current row's state, fed through all three possible round
        // steps -- calling the exact same generic functions trace
        // generation uses (see `step_result`/`permutation::apply_step`),
        // so this can't drift from what the trace actually computes.
        let current_state: [E; STATE_WIDTH] = core::array::from_fn(|i| current[i]);
        let linear_out = permutation::mds_light(current_state);
        let full_out = permutation::full_round(current_state, rc);
        let partial_out = permutation::partial_round(current_state, rc[0]);
        let round_out: [E; STATE_WIDTH] = core::array::from_fn(|i| {
            is_linear_only * linear_out[i] + is_full * full_out[i] + is_partial * partial_out[i]
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

        // E1..E7 / F1..F7: slots 1..7.
        for (k, &col) in OTHER_STATE_COLS.iter().enumerate() {
            let e = not_last * (next[col] - round_out[col]);
            let generic = if col == COL_STATE1 {
                next[COL_SELECTOR] * current[COL_STATE0]
                    + (one - next[COL_SELECTOR]) * next[COL_SIBLING]
            } else {
                E::ZERO
            };
            let f = is_last_in_block * (next[col] - generic);
            result[4 + k] = e;
            result[4 + OTHER_STATE_COLS.len() + k] = f;
        }

        let after_ef = 4 + 2 * OTHER_STATE_COLS.len();
        // sk constancy.
        result[after_ef] = next[COL_SK] - current[COL_SK];
        // selector boolean.
        result[after_ef + 1] = current[COL_SELECTOR] * (current[COL_SELECTOR] - one);
        // row0 seeding: state0 == sk at row 0.
        result[after_ef + 2] = is_row0 * (current[COL_STATE0] - current[COL_SK]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions: Vec<Assertion<Self::BaseField>> = OTHER_STATE_COLS
            .iter()
            .map(|&col| Assertion::single(col, 0, BaseElement::ZERO))
            .collect();
        assertions.extend([
            Assertion::single(COL_STATE0, root_row(self.depth), self.pub_inputs.root),
            Assertion::single(
                COL_STATE0,
                a1_output_row(self.depth),
                self.pub_inputs.nullifier,
            ),
            Assertion::single(COL_STATE0, y_row(self.depth), self.pub_inputs.y),
            Assertion::single(COL_SIBLING, a1_input_row(self.depth), self.pub_inputs.epoch),
            Assertion::single(COL_SELECTOR, a1_input_row(self.depth), BaseElement::ZERO),
        ]);
        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let mut is_last_in_block = vec![BaseElement::ZERO; BLOCK_LEN];
        is_last_in_block[BLOCK_LEN - 1] = BaseElement::ONE;

        let kinds = step_kinds();
        let mut rc_cols = vec![vec![BaseElement::ZERO; BLOCK_LEN]; STATE_WIDTH];
        let mut is_linear_only = vec![BaseElement::ZERO; BLOCK_LEN];
        let mut is_full = vec![BaseElement::ZERO; BLOCK_LEN];
        let mut is_partial = vec![BaseElement::ZERO; BLOCK_LEN];
        for (r, &kind) in kinds.iter().enumerate() {
            for (col, &rc) in rc_cols
                .iter_mut()
                .zip(self.params.round_constants[r].iter())
            {
                col[r] = rc;
            }
            match kind {
                StepKind::LinearOnly => is_linear_only[r] = BaseElement::ONE,
                StepKind::Full => is_full[r] = BaseElement::ONE,
                StepKind::Partial => is_partial[r] = BaseElement::ONE,
            }
        }

        let trace_len = trace_length(self.depth);
        let mut is_a1_transition = vec![BaseElement::ZERO; trace_len];
        is_a1_transition[a1_transition_row(self.depth)] = BaseElement::ONE;

        let mut is_linearcheck_transition = vec![BaseElement::ZERO; trace_len];
        is_linearcheck_transition[linearcheck_transition_row(self.depth)] = BaseElement::ONE;

        let mut is_row0 = vec![BaseElement::ZERO; trace_len];
        is_row0[0] = BaseElement::ONE;

        let mut cols = vec![is_last_in_block];
        cols.extend(rc_cols);
        cols.push(is_linear_only);
        cols.push(is_full);
        cols.push(is_partial);
        cols.push(is_a1_transition);
        cols.push(is_linearcheck_transition);
        cols.push(is_row0);
        debug_assert_eq!(cols.len(), NUM_PERIODIC_COLUMNS);
        cols
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

/// Builds the execution trace for one RLN proof. The tree depth is simply
/// `witness.path.len()` -- any depth for which [`is_valid_depth`] holds is
/// usable, not just [`DEPTH`].
pub fn build_trace(
    params: &Params,
    witness: &Witness,
    epoch: BaseElement,
    x: BaseElement,
) -> TraceTable<BaseElement> {
    let depth = witness.path.len();
    assert!(
        is_valid_depth(depth),
        "path length {depth} is invalid: depth + 3 must be a power of two \
         (valid depths: 1, 5, 13, 29, 61, ...)"
    );
    let root_row = root_row(depth);
    let a1_input_row = a1_input_row(depth);
    let a1_output_row = a1_output_row(depth);
    let y_row = y_row(depth);
    let trace_len = trace_length(depth);

    let mut cols: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; trace_len]; TRACE_WIDTH];

    // sk is constant across the whole trace.
    for row in cols[COL_SK].iter_mut() {
        *row = witness.sk;
    }

    // Row 0: leaf hash input = (sk, 0, 0, 0, 0, 0, 0, 0).
    let mut state: [BaseElement; STATE_WIDTH] = core::array::from_fn(|i| {
        if i == 0 {
            witness.sk
        } else {
            BaseElement::ZERO
        }
    });
    write_state(&mut cols, 0, state);

    let mut row = 0usize;
    // Merkle blocks.
    for step in &witness.path {
        for r in 0..ROUNDS {
            state = step_result(params, r, state);
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
        state = core::array::from_fn(|i| match i {
            0 => left,
            1 => right,
            _ => BaseElement::ZERO,
        });
        row += 1;
        write_state(&mut cols, row, state);
    }
    // The loop above ran `depth` times (rounds-then-inject per path step),
    // which finishes `depth` blocks of rounds (the leaf hash plus the
    // first `depth - 1` combines) and seeds `depth + 1` blocks total. The
    // very last merkle block — the final combine, whose seed the loop
    // just wrote — still needs its own rounds run to actually produce the
    // root.
    for r in 0..ROUNDS {
        state = step_result(params, r, state);
        row += 1;
        write_state(&mut cols, row, state);
    }
    debug_assert_eq!(row, root_row);
    row += 1;
    debug_assert_eq!(row, a1_input_row);

    // a1 block: input (sk, epoch, 0, ..., 0), set directly (mirrors constraint D3/F1).
    cols[COL_SIBLING][a1_input_row] = epoch;
    cols[COL_SELECTOR][a1_input_row] = BaseElement::ZERO;
    state = core::array::from_fn(|i| match i {
        0 => witness.sk,
        1 => epoch,
        _ => BaseElement::ZERO,
    });
    write_state(&mut cols, a1_input_row, state);
    for r in 0..ROUNDS {
        state = step_result(params, r, state);
        row += 1;
        write_state(&mut cols, row, state);
    }
    debug_assert_eq!(row, a1_output_row);
    let a1 = state[0];

    // Linear-check block: row y_row's state0 = sk + a1 * x (matches D4).
    row += 1;
    debug_assert_eq!(row, y_row);
    let y_state: [BaseElement; STATE_WIDTH] = core::array::from_fn(|i| {
        if i == 0 {
            witness.sk + a1 * x
        } else {
            BaseElement::ZERO
        }
    });
    write_state(&mut cols, y_row, y_state);
    // Remaining rows of the final block are unused padding; keep applying
    // the round function so the (unread) internal-round constraint is
    // still satisfied uniformly.
    state = y_state;
    for r in 0..ROUNDS {
        state = step_result(params, r, state);
        row += 1;
        if row < trace_len {
            write_state(&mut cols, row, state);
        }
    }

    TraceTable::init(cols)
}

fn write_state(cols: &mut [Vec<BaseElement>], row: usize, state: [BaseElement; STATE_WIDTH]) {
    for (col, &val) in cols.iter_mut().take(STATE_WIDTH).zip(state.iter()) {
        col[row] = val;
    }
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

/// Proof options targeting 128+ bits of conjectured security.
///
/// Winterfell's own `ProofOptions` docs give the formula this is built
/// from: conjectured soundness is bounded by `num_queries *
/// log2(blowup_factor) + grinding_factor`, i.e. `32 * log2(16) + 20 =
/// 32*4 + 20 = 148` bits here — comfortably past 128 with margin, not
/// pinned exactly to the line. `FieldExtension::Quadratic` (bumped from
/// `None`) addresses the separate caveat those same docs raise: even a
/// ~128-bit base field can fall short of ~100+ bits of *field-related*
/// soundness (as opposed to query-based soundness) without an extension,
/// since that margin depends on the field size relative to the evaluation
/// domain, not on `num_queries`/`blowup_factor` at all -- and now matters
/// more than before, since the base field itself shrank from f128 to the
/// 64-bit Goldilocks field.
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        16,
        20,
        FieldExtension::Quadratic,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// # Errors
/// Fails if the trace itself is malformed (a bug in [`build_trace`] or in
/// this crate's degree bookkeeping, not something a caller's inputs can
/// trigger) — returned as `Err` rather than panicking so that a proving
/// hiccup on our side degrades one caller's request instead of aborting
/// their process.
///
/// Also fails — via the same `catch_unwind` pattern [`verify`] uses, for
/// the same upstream reason — for a small, identifiable class of witnesses:
/// a leaf whose Merkle path is every-left or every-right (indices `0` and
/// `2^depth - 1`) makes the trace's `selector` column *literally* constant
/// across every row, not merely satisfying the boolean constraint at each
/// sample point. Winterfell's debug-mode `validate_transition_degrees`
/// check (only compiled into non-release builds) measures a transition
/// constraint's degree from the actual trace polynomial rather than
/// trusting our declared upper bound, so a column that's constant by
/// witness-driven coincidence — not by construction — legitimately
/// measures a lower degree than any single fixed declaration can commit to
/// in advance, and its equality assertion panics. This never runs in
/// release builds (proofs for these two leaves are exactly as sound and
/// verify identically to any other leaf there); the `catch_unwind` here
/// only protects a caller building this crate in dev/test mode, which
/// would otherwise crash on those two leaves out of every `2^depth`.
pub fn prove(
    witness: &Witness,
    epoch: BaseElement,
    x: BaseElement,
    y: BaseElement,
    nullifier: BaseElement,
) -> Result<(Proof, PublicInputs), String> {
    let params = Params::new();
    let trace = build_trace(&params, witness, epoch, x);
    let root = trace.get(COL_STATE0, root_row(witness.path.len()));
    let pub_inputs = PublicInputs {
        root,
        epoch,
        x,
        y,
        nullifier,
    };

    let prover = RlnProver::new(default_proof_options(), pub_inputs.clone());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
    let proof = match result {
        Ok(inner) => inner.map_err(|e| e.to_string())?,
        Err(_) => return Err("proving panicked on a degenerate witness".to_string()),
    };
    Ok((proof, pub_inputs))
}

/// # Panics-as-`Err`
/// A malformed-but-parseable [`Proof`] can drive winterfell's own
/// constraint evaluator into an internal panic rather than a clean
/// rejection (see [`crate::Message::from_proof_bytes`]'s doc comment for
/// a concrete example found by this crate's own fuzzing — that one's in
/// deserialization, not here, but the same untrusted-input surface
/// applies to verification itself). `catch_unwind` turns any such panic
/// into an `Err` so a caller verifying attacker-supplied proofs degrades
/// gracefully instead of crashing.
pub fn verify(proof: Proof, pub_inputs: PublicInputs) -> Result<(), String> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        winterfell::verify::<
            RlnAir,
            Blake3_256<BaseElement>,
            DefaultRandomCoin<Blake3_256<BaseElement>>,
            WinterMerkleTree<Blake3_256<BaseElement>>,
        >(proof, pub_inputs, &min_opts)
    }));
    match result {
        Ok(inner) => inner.map_err(|e| e.to_string()),
        Err(_) => Err("verification panicked on malformed proof".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pub_inputs() -> PublicInputs {
        PublicInputs {
            root: BaseElement::ZERO,
            epoch: BaseElement::ZERO,
            x: BaseElement::ZERO,
            y: BaseElement::ZERO,
            nullifier: BaseElement::ZERO,
        }
    }

    /// `RlnAir::new` is normally only ever invoked by `winterfell::verify`
    /// itself, fed a `TraceInfo` reconstructed from a genuine proof -- so
    /// none of its three malformed-input guards (width, length-not-a-
    /// multiple-of-`BLOCK_LEN`, and too-short-for-any-tree) are exercised
    /// by proving/verifying a real proof. Calling it directly is the only
    /// way to confirm those guards actually fire rather than silently
    /// accepting (and then presumably panicking somewhere less legible
    /// downstream) a `TraceInfo` that couldn't have come from a real trace.
    #[test]
    #[should_panic(expected = "not a multiple of BLOCK_LEN")]
    fn new_panics_on_trace_length_not_a_multiple_of_block_len() {
        // Must stay a power of two (winterfell's own `TraceInfo::new`
        // enforces that before this crate's code ever runs) while still
        // not being a multiple of `BLOCK_LEN` (32) -- 16 is the largest
        // power of two smaller than `BLOCK_LEN` itself.
        let trace_info = TraceInfo::new(TRACE_WIDTH, 16);
        RlnAir::new(trace_info, dummy_pub_inputs(), default_proof_options());
    }

    #[test]
    #[should_panic(expected = "too short for even a zero-depth tree")]
    fn new_panics_on_a_trace_too_short_for_any_tree() {
        // A single block (BLOCK_LEN rows) is a multiple of BLOCK_LEN but
        // fewer than the minimum three blocks (merkle + a1 + linear-check)
        // any valid tree needs.
        let trace_info = TraceInfo::new(TRACE_WIDTH, BLOCK_LEN);
        RlnAir::new(trace_info, dummy_pub_inputs(), default_proof_options());
    }

    // A third guard in `RlnAir::new` -- `is_valid_depth(depth)`, covering a
    // block count that's `> 2` but not itself a power of two -- has no
    // reachable test here: `BLOCK_LEN` (32) is itself a power of two, and
    // `TraceInfo::new` already rejects any non-power-of-two length before
    // this crate's code runs, so a length that's both a power of two *and*
    // a multiple of `BLOCK_LEN` always yields a power-of-two block count.
    // That branch is only reachable via `build_trace`'s direct
    // `is_valid_depth` check on `witness.path.len()`, exercised by
    // `invalid_depths_are_rejected_by_is_valid_depth` in `tests/rln.rs`.

    #[test]
    fn a1_and_linearcheck_transition_rows_are_the_last_row_of_their_block() {
        // Both rows are defined as "last row of a specific block" -- confirm
        // that arithmetic actually lands where the trace layout doc comment
        // (module docs, "Trace layout") claims, since every assertion row
        // getter (`root_row`, `a1_output_row`, `y_row`, `a1_input_row`)
        // is derived from these two and would silently misalign if they drifted.
        let depth = DEPTH;
        assert_eq!((a1_transition_row(depth) + 1) % BLOCK_LEN, 0);
        assert_eq!((linearcheck_transition_row(depth) + 1) % BLOCK_LEN, 0);
        assert!(linearcheck_transition_row(depth) > a1_transition_row(depth));
    }
}
