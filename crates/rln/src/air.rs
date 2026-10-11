//! The AIR (algebraic intermediate representation) for RLN membership plus
//! rate-limit binding, and the [`winterfell::Prover`] that proves against it.
//!
//! # What the proof shows
//! Given public `(root, epoch, x, y, nullifier)`, the prover knows `sk` with:
//!
//! 1. `Hash(sk, 0)` a leaf of the tree with root `root` (anonymous
//!    membership: path and position stay hidden);
//! 2. `nullifier = Hash(sk, epoch)` (call it `a1`);
//! 3. `y = sk + a1 * x`.
//!
//! (3) is the Shamir-style share: a second message in the same `epoch` puts
//! a second point on the line `y = sk + a1*x`, and two points recover `sk`
//! ([`crate::share`]). Proving all three in one proof stops a prover from
//! using a different secret for the share than the one committed in the
//! tree.
//!
//! # Trace layout
//! `DEPTH` Merkle levels, one Poseidon2 call each ([`crate::permutation`]),
//! then one call for `a1 = Hash(sk, epoch)`, then one arithmetic block for
//! `sk + a1*x`. Each block is [`BLOCK_LEN`] rows (one per permutation step
//! plus one for the injected input). Columns:
//! `[state0..state7, sk, sibling_in, selector]`.
//!
//! Each row's round transition blends the three possible steps,
//! [`permutation::mds_light`] (linear only), [`permutation::full_round`]
//! (S-box on every lane) and [`permutation::partial_round`] (S-box on lane
//! 0), by the periodic `is_linear_only`/`is_full`/`is_partial` selectors. It
//! calls the same functions [`crate::permutation::trace_permutation`] uses
//! to build the trace, so constraints and trace cannot drift apart.

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
/// Default Merkle depth for this crate's tests and examples; not a limit.
/// Any `depth` with [`is_valid_depth`] works: [`Witness::path`]'s length is
/// the depth, [`build_trace`] sizes the trace from it, and [`RlnAir::new`]
/// recovers it from the trace length.
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

/// Whether `depth` is usable. The trace length must be a power of two and
/// [`BLOCK_LEN`] is one, so [`num_blocks`] must be too: `depth` in
/// `{1, 5, 13, 29, 61, ...}` (`num_blocks` in `{4, 8, 16, 32, 64, ...}`).
/// `num_blocks` of 1 or 2 is excluded because the tree needs at least one
/// block besides the `a1` and linear-check blocks.
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

/// The state columns other than lane 0, for the logic shared by all seven.
const OTHER_STATE_COLS: [usize; STATE_WIDTH - 1] = [
    COL_STATE1, COL_STATE2, COL_STATE3, COL_STATE4, COL_STATE5, COL_STATE6, COL_STATE7,
];

// Periodic column indices, shared by `evaluate_transition` and
// `get_periodic_column_values` so they agree on layout.
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
    /// Recovered from the trace length passed to [`RlnAir::new`] (see
    /// [`trace_length`]); exactly one depth fits a given length, so it isn't
    /// stored separately.
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

/// Whether `trace_info` is a shape this AIR could have produced, as a
/// `Result` instead of the panic [`RlnAir::new`] would raise.
///
/// [`RlnAir::new`] must panic (winterfell's `Air::new` returns `Self`), and
/// `TraceInfo` comes from attacker-supplied proof bytes. [`verify`]'s
/// `catch_unwind` guards that in a normal build but not at all under
/// `panic = "abort"`, common in size-optimized and embedded builds, where a
/// malformed proof would abort the process. So the check runs here first.
/// Found by the `rln_verify` fuzz target with a 5-byte input
/// (`ENGINEERING-STANDARDS.md` §6.31).
fn validate_trace_info(trace_info: &TraceInfo) -> Result<(), String> {
    if trace_info.width() != TRACE_WIDTH {
        return Err(format!(
            "proof declares a trace width of {}, not this AIR's {TRACE_WIDTH}",
            trace_info.width()
        ));
    }
    let trace_len = trace_info.length();
    if !trace_len.is_multiple_of(BLOCK_LEN) {
        return Err(format!(
            "proof declares a trace length of {trace_len}, not a multiple of BLOCK_LEN ({BLOCK_LEN})"
        ));
    }
    let blocks = trace_len / BLOCK_LEN;
    if blocks <= 2 {
        return Err(format!(
            "proof declares a trace length of {trace_len}, too short for even a zero-depth tree"
        ));
    }
    let depth = blocks - 3;
    if !is_valid_depth(depth) {
        return Err(format!(
            "proof declares a trace length of {trace_len}, implying depth {depth}, \
             which is invalid (depth + 3 must be a power of two)"
        ));
    }
    Ok(())
}

impl Air for RlnAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    /// # Panics
    /// Panics on a `TraceInfo` this AIR could not have produced.
    ///
    /// It must panic: winterfell's `Air::new` returns `Self`, so there is no
    /// error channel, and `TraceInfo` comes from attacker-supplied bytes.
    /// [`verify`] runs the same checks as a `Result` first, so this is
    /// unreachable through it; its `catch_unwind` alone would be no guard under
    /// `panic = "abort"`.
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

        // Every internal-round constraint (D1, E1..E7) sums mds_light,
        // full_round and partial_round weighted by three mutually exclusive
        // periodic selectors, plus the per-lane periodic round constant.
        // Winterfell's debug-mode `validate_transition_degrees` asserts that the
        // declared degree *equals* the measured one, so these are calibrated to
        // the measured degree on ordinary witnesses rather than a hand-derived
        // worst case (degenerate witnesses measure lower; see `prove`). The
        // dominant term is `not_last * is_full * sbox(state + rc)`: degree 7 from
        // the S-box against two period-BLOCK_LEN factors (`not_last` and the
        // selector). `rc` is summed in before the S-box, so it adds no factor.
        let round_cycles = vec![BLOCK_LEN; 2];
        let round_degree = TransitionConstraintDegree::with_cycles(7, round_cycles);

        let mut degrees = vec![
            // D1: state0 internal round (blended mds_light/full/partial).
            round_degree.clone(),
            // D2: Merkle-boundary injection into state0. Degree-2 trace product
            // (`selector * sibling`) times `is_last_in_block` (period BLOCK_LEN);
            // `not_a1_or_linear` adds no factor to the measured degree (see D1).
            TransitionConstraintDegree::with_cycles(3, vec![BLOCK_LEN]),
            // D3: a1-block seeding, state0 <- sk.
            TransitionConstraintDegree::with_cycles(1, vec![trace_len]),
            // D4: linear-check row, state0 <- sk + a1 * x. Degree 2 in trace columns
            // (`state0 * x_const`) with no periodic factor, like D3.
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

        // The current row's state through all three possible round steps, using
        // the same functions trace generation does (`step_result` /
        // `permutation::apply_step`).
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

/// Builds the execution trace for one RLN proof. The depth is
/// `witness.path.len()`; any depth with [`is_valid_depth`] works.
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
    // The loop ran `depth` times (rounds, then inject), completing `depth`
    // blocks of rounds (leaf hash plus the first `depth - 1` combines) and
    // seeding `depth + 1`. The last Merkle block, seeded by the final
    // iteration, still needs its rounds to produce the root.
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
    // The final block's remaining rows are padding; keep applying the round
    // function so the round constraint holds uniformly.
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
    /// Takes the exact public inputs the trace was built against, which
    /// `Prover::get_pub_inputs` returns as-is; not all of them (`x`, notably)
    /// live in a trace cell.
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

/// Proof options giving 127 bits of conjectured security, the maximum this
/// field and extension degree allow. Measured with
/// `cargo run -p novachannel-rln --release --example proof_size`, which
/// reads winterfell's own `Proof::conjectured_security`.
///
/// # Why 127, not 148
/// This previously claimed 148 bits from the query term alone,
/// `num_queries * log2(blowup_factor) + grinding_factor = 32*4 + 20`.
/// Winterfell (`winter-air`'s `ConjecturedSecurity::compute`) actually
/// computes
///
/// ```text
/// min(min(field_security, query_security) - 1, hash_collision_resistance)
/// ```
///
/// with `field_security = base_field_bits * field_extension_degree`, which
/// for Goldilocks with a quadratic extension is `64 * 2 = 128`. So the
/// result is `min(min(128, 148) - 1, 128) = 127`: the field binds, and 148
/// was never reachable. §6.20 of `ENGINEERING-STANDARDS.md` had the same
/// error and is corrected there. Likewise the pre-hardening default (24
/// queries, `FieldExtension::None`), described as ~96-bit, gave
/// `min(64, 96) - 1 = 63`; hardening went from 63 to 127, not 96 to 148.
///
/// # Why not a cubic extension for 128
/// Rejected on measurement. `FieldExtension::Cubic` reaches exactly 128
/// (`min(min(192, 148) - 1, 128)`, now capped by `Blake3_256`), and every
/// test passes, but on the machine that ran `examples/proving_time` it cost
/// **5.6x the proving time** (5.4ms to 29.8ms median) and 18% more proof
/// bytes (27.0KB to 31.8KB) for one bit, paid on every message and more on
/// a mobile prover. Recorded so it isn't retried blind
/// (`ENGINEERING-STANDARDS.md` §0.3).
///
/// More than 32 queries buys nothing: with field and hash terms at 128, the
/// query term (148) is already slack. `examples/proof_size`'s last row
/// shows it: 48 queries, same cap, 41% more proof bytes.
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
/// Fails if the trace is malformed (a bug in [`build_trace`] or the degree
/// bookkeeping, not reachable from caller input), as `Err` rather than a
/// panic so one bad request doesn't abort the caller's process.
///
/// In debug builds it also fails for two leaves out of every `2^depth`:
/// indices `0` and `2^depth - 1`, whose all-left or all-right path makes
/// the `selector` column constant. Winterfell's debug-only
/// `validate_transition_degrees` measures the actual polynomial, finds a
/// lower degree than declared, and panics; the same `catch_unwind` pattern
/// [`verify`] uses turns that into `Err`. Release builds don't run that
/// check, and proofs for those leaves are as sound as any other.
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

/// The conjectured-security floor a proof must clear to be accepted.
///
/// This verifier-side value is the one that matters: a proof carries the
/// [`ProofOptions`] it was made with, so a prover (including a malicious
/// one) picks its own security level, and only this floor rejects a weak
/// one.
///
/// It was 95 while `ENGINEERING-STANDARDS.md` §6.20 described the crate as
/// raised to the workspace's 128-bit bar, so a 96-bit proof would have been
/// accepted. It is now 127, exactly what [`default_proof_options`]
/// produces and the ceiling for Goldilocks with a quadratic extension: it
/// admits the default and rejects anything weaker, including the 63-bit
/// no-extension configurations `examples/proof_size` measures. A round 128
/// would reject this crate's own proofs unless the default paid the 5.6x
/// proving-time cost described at [`default_proof_options`].
pub const MIN_CONJECTURED_SECURITY_BITS: u32 = 127;

/// Verifies `proof` against `pub_inputs`.
///
/// # Panics-as-`Err`
/// A malformed but parseable [`Proof`] can make winterfell's constraint
/// evaluator panic instead of rejecting cleanly (compare the deserializer
/// panic documented at [`crate::Message::from_proof_bytes`]).
/// `catch_unwind` turns such panics into `Err`.
///
/// # A known remote denial of service this function cannot prevent
/// **A malformed proof can abort the calling process.** `winterfell`
/// 0.13.1's `BatchMerkleProof::read_from` passes an attacker-controlled
/// count straight to `Vec::with_capacity` (and again per node vector via
/// `read_many`). A six-byte mutation of a genuine proof makes a release
/// build request ~2.5 petabytes and die with SIGABRT; measured and pinned by
/// `a_known_unbounded_allocation_in_winterfells_verifier_still_aborts_the_process`
/// in `crates/rln/tests/rln.rs`.
///
/// `catch_unwind` does **not** contain this: allocation failure calls
/// `handle_alloc_error`, which aborts instead of unwinding. The parse also
/// happens inside `winterfell::verify`, after every guard this crate has.
///
/// It can't be fixed here. `Queries`' raw bytes are private, so the only
/// in-crate fix is re-implementing winterfell's wire format to pre-scan it,
/// which would drift on every upgrade, and 0.13.1 is the latest release.
/// It is the class this workspace fixed three times in its own parsers
/// (`ENGINEERING-STANDARDS.md` §6.29: bound a declared count by the bytes
/// remaining), here in a dependency.
///
/// **A deployment that must not abort on a hostile proof has to isolate this
/// call** in a supervised process or a memory-limited sandbox. Whoever
/// supplies proof bytes can kill any caller of this function.
pub fn verify(proof: Proof, pub_inputs: PublicInputs) -> Result<(), String> {
    // Reject a malformed trace shape here, before winterfell sees it, rather
    // than via a panic in `RlnAir::new` that `catch_unwind` won't catch under
    // `panic = "abort"`. See `validate_trace_info`.
    validate_trace_info(proof.trace_info())?;

    let min_opts =
        winterfell::AcceptableOptions::MinConjecturedSecurity(MIN_CONJECTURED_SECURITY_BITS);
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

    /// Real proofs never reach `RlnAir::new`'s three malformed-input guards
    /// (width, length not a multiple of `BLOCK_LEN`, too short for any tree),
    /// since winterfell only calls it with a `TraceInfo` from a genuine proof.
    /// Calling it directly is the only way to show they fire.
    #[test]
    #[should_panic(expected = "not a multiple of BLOCK_LEN")]
    fn new_panics_on_trace_length_not_a_multiple_of_block_len() {
        // A power of two (`TraceInfo::new` requires it) that isn't a multiple of
        // `BLOCK_LEN` (32): 16 is the largest such value.
        let trace_info = TraceInfo::new(TRACE_WIDTH, 16);
        RlnAir::new(trace_info, dummy_pub_inputs(), default_proof_options());
    }

    #[test]
    #[should_panic(expected = "too short for even a zero-depth tree")]
    fn new_panics_on_a_trace_too_short_for_any_tree() {
        // One block is a multiple of BLOCK_LEN but fewer than the three blocks
        // (merkle, a1, linear-check) any tree needs.
        let trace_info = TraceInfo::new(TRACE_WIDTH, BLOCK_LEN);
        RlnAir::new(trace_info, dummy_pub_inputs(), default_proof_options());
    }

    // The third guard, `is_valid_depth(depth)` (a block count `> 2` that isn't
    // a power of two), is unreachable here: `BLOCK_LEN` is a power of two and
    // `TraceInfo::new` rejects non-power-of-two lengths, so any accepted
    // length gives a power-of-two block count. That branch is reached through
    // `build_trace`'s own check, tested by
    // `invalid_depths_are_rejected_by_is_valid_depth` in `tests/rln.rs`.

    #[test]
    fn a1_and_linearcheck_transition_rows_are_the_last_row_of_their_block() {
        // Both rows are "last row of a given block". Every assertion-row getter
        // (`root_row`, `a1_output_row`, `y_row`, `a1_input_row`) derives from
        // these, so confirm they land where the module's "Trace layout" docs say.
        let depth = DEPTH;
        assert_eq!((a1_transition_row(depth) + 1) % BLOCK_LEN, 0);
        assert_eq!((linearcheck_transition_row(depth) + 1) % BLOCK_LEN, 0);
        assert!(linearcheck_transition_row(depth) > a1_transition_row(depth));
    }
}
