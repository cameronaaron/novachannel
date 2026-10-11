//! Cover traffic for the "did this user send anything?" metadata signal.
//!
//! # The mechanism
//! Time is divided into fixed slots. Let `b ∈ {0,1}` be whether the user has
//! a real message queued this slot, and `o ∈ {0,1}` the observable "a packet
//! (real or dummy, indistinguishable from outside) was sent this slot":
//!
//! - `b = 1`: send the real message, so `o = 1` always (real traffic is
//!   never delayed or dropped; the budget goes into dummy traffic).
//! - `b = 0`: send a dummy with independent probability `q = e^{-ε}`.
//!
//! # Security limitation: not epsilon-DP for positive epsilon
//! The send event has likelihood ratio `1/q = exp(epsilon)`, but DP needs
//! the bound in both directions for every event. Silence has probability
//! `1-q` in an empty slot and zero in a busy one, so
//! `1-q <= exp(epsilon) * 0` fails whenever `q < 1`: silence reveals that
//! nothing was queued. The empirical send-event test does not establish DP.
//!
//! `epsilon = 0` sends every slot and hides the presence bit, provided real
//! and dummy packets match in size, framing and timing. Positive epsilon only
//! tunes cover bandwidth; it is NOT a DP budget. [`sequential_epsilon`],
//! [`advanced_composition_epsilon`] and [`Budget`] are calculators for
//! mechanisms independently shown to be DP; they don't certify this
//! scheduler or its queued variant.
//!
//! See Dwork and Roth, Definition 2.4:
//! <https://www.cis.upenn.edu/~aaroth/Papers/privacybook.pdf>.
//!
//! # What this doesn't cover
//! - **System-wide timing.** [`GridScheduler`] quantizes this scheduler's
//!   own send times to a grid. Timing elsewhere (application processing,
//!   request/response patterns, anything downstream) is the caller's
//!   pipeline to audit.
//! - **Composition.** No pure-DP composition bound applies to
//!   positive-epsilon scheduling, even with independent draws.
//!
//! [`SizeBucketer`] handles the size side channel: pad plaintext to one of a
//! fixed set of sizes before encrypting, so ciphertext length reveals only
//! the bucket. It is a separate, simple length-hiding pad/unpad (no
//! epsilon); pad first, then seal the padded bytes (e.g. with
//! `novachannel`), so only the bucket size is ever visible.

#![forbid(unsafe_code)]
// Each `.unwrap()` must become an `.expect("why it can't fail")` or is a
// bug (libsignal's `protocol`/`zkgroup` crates enforce the same lint).
// Allowed in tests, on values the test just built.
#![warn(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use rand::{Rng, RngExt};

/// Per-slot cover-traffic scheduler. Positive epsilon is NOT a DP guarantee;
/// see the module security limitation.
#[derive(Clone, Copy, Debug)]
pub struct DummyScheduler {
    epsilon: f64,
    /// `q = e^{-epsilon}`: probability of sending a dummy in an empty slot.
    dummy_probability: f64,
}

impl DummyScheduler {
    /// # Panics
    /// Panics unless `epsilon` is finite and non-negative. `epsilon = 0` is
    /// legal: a dummy in every empty slot (full hiding, maximum bandwidth).
    pub fn new(epsilon: f64) -> Self {
        assert!(
            epsilon.is_finite() && epsilon >= 0.0,
            "epsilon must be finite and >= 0"
        );
        DummyScheduler {
            epsilon,
            dummy_probability: (-epsilon).exp(),
        }
    }

    pub fn epsilon(&self) -> f64 {
        self.epsilon
    }

    /// Probability a dummy is sent when there's no real message this slot.
    pub fn dummy_probability(&self) -> f64 {
        self.dummy_probability
    }

    /// Whether to transmit this slot: always if `has_real_message`, otherwise
    /// with probability [`Self::dummy_probability`]. When it returns `true` for
    /// an empty slot the caller must build a dummy indistinguishable from a
    /// real packet; any distinguishing signal (size, timing jitter, ...) voids
    /// even the zero-epsilon guarantee.
    pub fn decide(&self, has_real_message: bool, rng: &mut impl Rng) -> bool {
        // Draw unconditionally and discard it when a real message is queued.
        // `has_real_message || rng.random_bool(..)` returns the same value but
        // short-circuits, making the number of random values consumed depend on
        // the bit being hidden. That leaks whenever the `rng` is observable (shared
        // across users or streams, seeded and replayed, or reasoned about by
        // consumption count); one discarded sample per slot removes the question.
        let dummy = rng.random_bool(self.dummy_probability);
        has_real_message || dummy
    }
}

/// What one [`GridScheduler::tick`] call transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOutput<M> {
    /// A real, queued message went out this slot.
    Real(M),
    /// No real message was queued and a dummy went out. The caller must make it
    /// indistinguishable from a real packet; see [`DummyScheduler::decide`].
    Dummy,
    /// Nothing transmitted this slot.
    Silent,
}

/// Closes the within-slot timing gap: with [`DummyScheduler::decide`]
/// alone a real message goes out the instant it's ready, so an observer
/// with finer timing than a slot learns when it arrived. `GridScheduler`
/// buffers instead: [`Self::enqueue`] only adds to a FIFO, and
/// [`Self::tick`], called once per grid boundary by the caller's clock, is
/// the only thing that transmits. Send times are always on the grid,
/// whatever the enqueue time, by construction.
///
/// This crate does no I/O and starts no timer; `GridScheduler` is a state
/// machine the caller ticks, the same boundary `novachannel-mpc`'s `Dealer`
/// and `novachannel-oram`'s `ServerStorage` draw.
///
/// Several messages enqueued in one slot go out one per tick, oldest first,
/// with the same positive-epsilon silence leakage described above. That
/// delay is the cost: hiding *when* costs latency, as hiding *whether*
/// costs bandwidth. Messages that can't wait need a different mechanism,
/// not a smaller epsilon.
pub struct GridScheduler<M> {
    scheduler: DummyScheduler,
    queue: std::collections::VecDeque<M>,
}

impl<M> GridScheduler<M> {
    pub fn new(epsilon: f64) -> Self {
        GridScheduler {
            scheduler: DummyScheduler::new(epsilon),
            queue: std::collections::VecDeque::new(),
        }
    }

    pub fn epsilon(&self) -> f64 {
        self.scheduler.epsilon()
    }

    /// Queues a real message for the next grid slot. Never transmits; see the
    /// type docs.
    pub fn enqueue(&mut self, message: M) {
        self.queue.push_back(message);
    }

    /// How many real messages are waiting for a future grid slot.
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Advances one grid slot: dequeues the oldest message, if any, and applies
    /// the same presence decision as [`DummyScheduler::decide`]. Call once per
    /// fixed tick of your own clock, never in response to [`Self::enqueue`], or
    /// the hidden timing leaks through the call pattern.
    pub fn tick(&mut self, rng: &mut impl Rng) -> SlotOutput<M> {
        let queued = self.queue.pop_front();
        let has_real = queued.is_some();
        if self.scheduler.decide(has_real, rng) {
            match queued {
                Some(message) => SlotOutput::Real(message),
                None => SlotOutput::Dummy,
            }
        } else {
            SlotOutput::Silent
        }
    }
}

/// Basic sequential composition: `k` independent epsilon-DP slots cost at
/// most `k * epsilon`. Exact, but loose for large `k`; see
/// [`advanced_composition_epsilon`].
pub fn sequential_epsilon(epsilon_per_slot: f64, num_slots: u64) -> f64 {
    epsilon_per_slot * num_slots as f64
}

/// Advanced composition (Dwork, Rothblum, Vadhan 2010): `k`-fold
/// composition of epsilon-DP mechanisms is `(eps', k*delta + delta')`-DP for
/// any `delta' > 0`, with
///
/// ```text
/// eps' = sqrt(2k * ln(1/delta')) * eps + k * eps * (e^eps - 1)
/// ```
///
/// Tighter than [`sequential_epsilon`] beyond a handful of slots, at the
/// cost of failure probability `delta_prime`. Choose it cryptographically
/// small (e.g. `1e-9`); it is the chance the tail bound fails, not a
/// privacy/utility knob.
pub fn advanced_composition_epsilon(
    epsilon_per_slot: f64,
    num_slots: u64,
    delta_prime: f64,
) -> f64 {
    assert!(
        delta_prime > 0.0 && delta_prime < 1.0,
        "delta_prime must be in (0, 1)"
    );
    let k = num_slots as f64;
    let eps = epsilon_per_slot;
    (2.0 * k * (1.0 / delta_prime).ln()).sqrt() * eps + k * eps * (eps.exp() - 1.0)
}

/// A privacy odometer: tracks epsilon spent across slots via
/// [`sequential_epsilon`] and how many slots remain in the budget.
///
/// For independently established DP mechanisms only, not positive-epsilon
/// [`DummyScheduler`] or [`GridScheduler`].
pub struct Budget {
    epsilon_per_slot: f64,
    total_budget: f64,
    slots_spent: u64,
}

impl Budget {
    pub fn new(epsilon_per_slot: f64, total_budget: f64) -> Self {
        assert!(epsilon_per_slot > 0.0, "epsilon_per_slot must be positive");
        assert!(total_budget > 0.0, "total_budget must be positive");
        Budget {
            epsilon_per_slot,
            total_budget,
            slots_spent: 0,
        }
    }

    pub fn spent(&self) -> f64 {
        sequential_epsilon(self.epsilon_per_slot, self.slots_spent)
    }

    pub fn remaining(&self) -> f64 {
        (self.total_budget - self.spent()).max(0.0)
    }

    pub fn slots_remaining(&self) -> u64 {
        (self.remaining() / self.epsilon_per_slot).floor() as u64
    }

    /// Records one more slot's mechanism.
    ///
    /// Returns `false` without recording if that would exceed the budget; fall
    /// back to a lower-epsilon scheduler or stop sending rather than exceed the
    /// declared guarantee.
    #[must_use]
    pub fn spend_slot(&mut self) -> bool {
        if self.spent() + self.epsilon_per_slot > self.total_budget {
            return false;
        }
        self.slots_spent += 1;
        true
    }
}

// SIZE BUCKETING
// ================================================================================================
//
// Independent of the presence-bit mechanism above: pad plaintext to one of
// a fixed set of lengths before encryption, so ciphertext length reveals
// only the bucket.

const LENGTH_PREFIX_LEN: usize = 4;

/// Returned by [`SizeBucketer::pad`]/[`SizeBucketer::unpad`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingError {
    /// The plaintext plus `pad`'s 4-byte length prefix exceeds every bucket.
    /// Use a larger bucket or split the message.
    MessageTooLargeForAnyBucket,
    /// `unpad`'s input is shorter than the length prefix, or the prefix claims
    /// more bytes than the buffer holds. Behind an authenticated channel (the
    /// intended use) this means a caller bug: tampering already fails the
    /// channel's AEAD before `unpad` runs.
    Malformed,
}

impl std::fmt::Display for PaddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaddingError::MessageTooLargeForAnyBucket => write!(
                f,
                "message plus its length prefix exceeds every configured padding bucket"
            ),
            PaddingError::Malformed => write!(
                f,
                "padded input is too short, or its length prefix is inconsistent with its size"
            ),
        }
    }
}

impl std::error::Error for PaddingError {}

/// Pads plaintext to fixed size buckets so ciphertext length reveals only
/// the bucket. See the module docs for scope and how it composes with
/// encryption.
#[derive(Clone, Debug)]
pub struct SizeBucketer {
    /// Strictly increasing, deduplicated bucket sizes in bytes.
    buckets: Vec<usize>,
}

impl SizeBucketer {
    /// `bucket_sizes` is sorted and deduplicated here. Buckets smaller than
    /// `pad`'s length prefix are dropped, since nothing fits in them.
    ///
    /// # Panics
    /// Panics if no usable bucket remains.
    pub fn new(bucket_sizes: impl IntoIterator<Item = usize>) -> Self {
        let mut buckets: Vec<usize> = bucket_sizes
            .into_iter()
            .filter(|&b| b >= LENGTH_PREFIX_LEN)
            .collect();
        buckets.sort_unstable();
        buckets.dedup();
        assert!(
            !buckets.is_empty(),
            "SizeBucketer needs at least one bucket >= the length-prefix overhead ({LENGTH_PREFIX_LEN} bytes)"
        );
        SizeBucketer { buckets }
    }

    /// Powers of two from `2^min_log2` to `2^max_log2` bytes inclusive, the
    /// conventional choice (as in Tor cell padding) without an application size
    /// distribution to tune against.
    ///
    /// # Panics
    /// Panics if `min_log2 > max_log2`.
    pub fn power_of_two_buckets(min_log2: u32, max_log2: u32) -> Self {
        assert!(min_log2 <= max_log2, "min_log2 must be <= max_log2");
        Self::new((min_log2..=max_log2).map(|k| 1usize << k))
    }

    /// The configured bucket sizes, sorted ascending.
    pub fn buckets(&self) -> &[usize] {
        &self.buckets
    }

    /// Pads `plaintext` to the smallest bucket fitting it plus the length
    /// prefix. Encrypt the result, not `plaintext`, or the padding hides
    /// nothing.
    pub fn pad(&self, plaintext: &[u8]) -> Result<Vec<u8>, PaddingError> {
        if plaintext.len() > u32::MAX as usize {
            return Err(PaddingError::MessageTooLargeForAnyBucket);
        }
        let needed = plaintext
            .len()
            .checked_add(LENGTH_PREFIX_LEN)
            .ok_or(PaddingError::MessageTooLargeForAnyBucket)?;
        let bucket = self
            .buckets
            .iter()
            .find(|&&b| b >= needed)
            .copied()
            .ok_or(PaddingError::MessageTooLargeForAnyBucket)?;

        let mut out = Vec::with_capacity(bucket);
        out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        out.extend_from_slice(plaintext);
        out.resize(bucket, 0u8);
        Ok(out)
    }

    /// Inverse of [`Self::pad`]: recovers the original plaintext, dropping
    /// the trailing pad bytes.
    pub fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, PaddingError> {
        if padded.len() < LENGTH_PREFIX_LEN {
            return Err(PaddingError::Malformed);
        }
        let len = u32::from_be_bytes(
            padded[..LENGTH_PREFIX_LEN]
                .try_into()
                .expect("checked length"),
        ) as usize;
        let end = LENGTH_PREFIX_LEN
            .checked_add(len)
            .ok_or(PaddingError::Malformed)?;
        if end > padded.len() {
            return Err(PaddingError::Malformed);
        }
        Ok(padded[LENGTH_PREFIX_LEN..end].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Randomness consumption must not depend on the presence bit: a
    /// short-circuiting `decide` drew only in empty slots, so a shared or
    /// replayed `rng` leaked the hidden value. Identically seeded generators
    /// driven through opposite ground truths must end in the same state.
    #[test]
    fn the_scheduler_consumes_the_same_randomness_whether_or_not_a_message_is_queued() {
        let scheduler = DummyScheduler::new(0.5);
        let mut all_real = ChaCha20Rng::seed_from_u64(4242);
        let mut none_real = ChaCha20Rng::seed_from_u64(4242);

        for _ in 0..100 {
            assert!(scheduler.decide(true, &mut all_real));
            let _ = scheduler.decide(false, &mut none_real);
        }

        // Same seed and number of draws, so the next values match. They wouldn't
        // if the busy run had skipped draws.
        assert_eq!(
            all_real.random_range(0..u64::MAX),
            none_real.random_range(0..u64::MAX),
            "the two runs consumed different amounts of randomness"
        );
    }

    /// The same property through `GridScheduler::tick`, which is the API a
    /// caller actually drives once per slot.
    #[test]
    fn the_grid_scheduler_consumes_the_same_randomness_whether_or_not_a_message_is_queued() {
        let mut busy: GridScheduler<u32> = GridScheduler::new(0.5);
        let mut idle: GridScheduler<u32> = GridScheduler::new(0.5);
        let mut busy_rng = ChaCha20Rng::seed_from_u64(7);
        let mut idle_rng = ChaCha20Rng::seed_from_u64(7);

        for i in 0..100u32 {
            busy.enqueue(i);
            let _ = busy.tick(&mut busy_rng);
            let _ = idle.tick(&mut idle_rng);
        }

        assert_eq!(
            busy_rng.random_range(0..u64::MAX),
            idle_rng.random_range(0..u64::MAX)
        );
    }

    #[test]
    fn grid_scheduler_never_transmits_a_real_message_the_same_tick_it_was_enqueued_unless_ticked() {
        // A message enqueued mid-slot goes out only on a later `tick()`, never as
        // a side effect of `enqueue`; that is the property this type guarantees.
        let mut s: GridScheduler<u32> = GridScheduler::new(0.0);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert_eq!(s.queue_len(), 0);
        s.enqueue(42);
        assert_eq!(s.queue_len(), 1, "enqueue must not transmit by itself");
        let out = s.tick(&mut rng);
        assert_eq!(out, SlotOutput::Real(42));
        assert_eq!(s.queue_len(), 0);
    }

    #[test]
    fn grid_scheduler_ticks_are_indistinguishable_regardless_of_when_within_the_slot_enqueue_happened(
    ) {
        // Enqueueing at different points relative to the ticks gives the same
        // observable sequence: `tick()` sees only whether the queue is non-empty,
        // never a timestamp.
        let epsilon = 1.0;
        let mut early: GridScheduler<u32> = GridScheduler::new(epsilon);
        let mut late: GridScheduler<u32> = GridScheduler::new(epsilon);
        let mut rng_a = ChaCha20Rng::seed_from_u64(7);
        let mut rng_b = ChaCha20Rng::seed_from_u64(7);

        early.enqueue(1); // "arrives" right at the start of the slot
        let out_a = early.tick(&mut rng_a);

        // Arrives at the last instant of the slot: enqueue immediately before
        // `tick`.
        late.enqueue(1);
        let out_b = late.tick(&mut rng_b);

        assert_eq!(out_a, out_b);
        assert_eq!(out_a, SlotOutput::Real(1));
    }

    #[test]
    fn grid_scheduler_queues_multiple_messages_fifo_across_ticks() {
        let mut s: GridScheduler<&str> = GridScheduler::new(0.0);
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        s.enqueue("first");
        s.enqueue("second");
        assert_eq!(s.queue_len(), 2);
        assert_eq!(s.tick(&mut rng), SlotOutput::Real("first"));
        assert_eq!(s.tick(&mut rng), SlotOutput::Real("second"));
        // Empty queue, epsilon = 0 -> dummy_probability = 1 -> always Dummy.
        assert_eq!(s.tick(&mut rng), SlotOutput::Dummy);
    }

    #[test]
    fn grid_scheduler_empty_queue_follows_the_same_dummy_probability_as_dummy_scheduler() {
        let epsilon = 0.5f64;
        let mut s: GridScheduler<u32> = GridScheduler::new(epsilon);
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        let trials = 200_000;
        let mut sent = 0u64;
        for _ in 0..trials {
            match s.tick(&mut rng) {
                SlotOutput::Dummy => sent += 1,
                SlotOutput::Silent => {}
                SlotOutput::Real(_) => unreachable!("queue is always empty in this test"),
            }
        }
        let p_send = sent as f64 / trials as f64;
        let expected = DummyScheduler::new(epsilon).dummy_probability();
        assert!(
            (p_send - expected).abs() < 0.01,
            "empirical dummy-send rate {p_send} too far from expected {expected}"
        );
    }

    #[test]
    fn silence_is_a_counterexample_to_positive_epsilon_pure_dp() {
        let scheduler = DummyScheduler::new(1.0);
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let mut witnessed_silence = false;
        for _ in 0..1000 {
            let mut real_rng = rng.clone();
            assert!(scheduler.decide(true, &mut real_rng));
            witnessed_silence |= !scheduler.decide(false, &mut rng);
        }
        assert!(witnessed_silence);
        // Test the missing ordered pair and event from the former proof.
        let silence_given_empty = 1.0 - scheduler.dummy_probability();
        let silence_given_real = 0.0;
        assert!(silence_given_empty > scheduler.epsilon().exp() * silence_given_real);
    }

    #[test]
    fn dummy_probability_matches_e_neg_epsilon() {
        let s = DummyScheduler::new(1.0);
        assert!((s.dummy_probability() - std::f64::consts::E.recip()).abs() < 1e-12);
    }

    #[test]
    fn zero_epsilon_always_sends() {
        let s = DummyScheduler::new(0.0);
        assert_eq!(s.dummy_probability(), 1.0);
    }

    #[test]
    fn epsilon_getter_returns_the_constructed_value() {
        let s = DummyScheduler::new(2.5);
        assert_eq!(s.epsilon(), 2.5);
    }

    #[test]
    fn empirical_likelihood_ratio_matches_bound() {
        let epsilon = 0.5f64;
        let s = DummyScheduler::new(epsilon);
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let trials = 200_000;
        let mut send_given_real = 0u64;
        let mut send_given_empty = 0u64;
        for _ in 0..trials {
            if s.decide(true, &mut rng) {
                send_given_real += 1;
            }
            if s.decide(false, &mut rng) {
                send_given_empty += 1;
            }
        }

        let p_send_given_real = send_given_real as f64 / trials as f64;
        let p_send_given_empty = send_given_empty as f64 / trials as f64;
        assert!((p_send_given_real - 1.0).abs() < 1e-6);

        let empirical_ratio = p_send_given_real / p_send_given_empty;
        // Should be close to e^epsilon; allow generous slack for sampling noise.
        assert!(
            (empirical_ratio - epsilon.exp()).abs() < 0.05,
            "empirical ratio {empirical_ratio} too far from e^epsilon={}",
            epsilon.exp()
        );
    }

    #[test]
    fn sequential_composition_is_linear() {
        assert_eq!(sequential_epsilon(0.1, 10), 1.0);
    }

    #[test]
    fn advanced_composition_beats_sequential_for_many_slots() {
        let eps = 0.01;
        let k = 10_000;
        let seq = sequential_epsilon(eps, k);
        let adv = advanced_composition_epsilon(eps, k, 1e-9);
        assert!(
            adv < seq,
            "advanced composition ({adv}) should beat sequential ({seq}) for large k"
        );
    }

    #[test]
    fn budget_tracks_spend_and_refuses_overspend() {
        let mut b = Budget::new(0.1, 1.0);
        for _ in 0..10 {
            assert!(b.spend_slot());
        }
        assert!((b.spent() - 1.0).abs() < 1e-9);
        assert_eq!(b.slots_remaining(), 0);
        assert!(!b.spend_slot());
    }

    #[test]
    fn pad_then_unpad_round_trips_for_a_range_of_lengths() {
        let bucketer = SizeBucketer::power_of_two_buckets(4, 13);
        for len in [0usize, 1, 15, 16, 17, 255, 4000, 4092] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let padded = bucketer.pad(&plaintext).unwrap();
            assert_eq!(bucketer.unpad(&padded).unwrap(), plaintext);
        }
    }

    #[test]
    fn padded_output_length_always_matches_a_configured_bucket() {
        let bucketer = SizeBucketer::power_of_two_buckets(4, 12);
        for len in [0usize, 1, 100, 4092] {
            let padded = bucketer.pad(&vec![0u8; len]).unwrap();
            assert!(
                bucketer.buckets().contains(&padded.len()),
                "padded length {} is not one of the configured buckets",
                padded.len()
            );
        }
    }

    /// The property that matters: plaintexts of different lengths in the same
    /// bucket pad to the same size.
    #[test]
    fn messages_in_the_same_bucket_produce_identical_padded_lengths() {
        let bucketer = SizeBucketer::power_of_two_buckets(4, 12);
        // Both need a bucket >= len + 4: 130 -> 256, 250 -> 256 — same
        // bucket, different plaintext lengths.
        let short = bucketer.pad(&[0xAAu8; 130]).unwrap();
        let long = bucketer.pad(&[0xBBu8; 250]).unwrap();
        assert_eq!(short.len(), long.len());
        assert_eq!(short.len(), 256);
        assert_ne!(short, long);
    }

    #[test]
    fn a_message_larger_than_every_bucket_is_rejected() {
        let bucketer = SizeBucketer::power_of_two_buckets(4, 8); // largest bucket: 256 bytes
        let plaintext = vec![0u8; 10_000];
        assert_eq!(
            bucketer.pad(&plaintext),
            Err(PaddingError::MessageTooLargeForAnyBucket)
        );
    }

    #[test]
    fn unpad_rejects_a_too_short_buffer_not_panicked_on() {
        let bucketer = SizeBucketer::power_of_two_buckets(4, 8);
        assert_eq!(bucketer.unpad(&[]), Err(PaddingError::Malformed));
        assert_eq!(bucketer.unpad(&[1, 2, 3]), Err(PaddingError::Malformed));
    }

    #[test]
    fn unpad_rejects_a_length_prefix_claiming_more_than_the_buffer_holds() {
        let bucketer = SizeBucketer::power_of_two_buckets(4, 8);
        // A length prefix claiming 1000 content bytes, in a 16-byte buffer.
        let mut forged = 1000u32.to_be_bytes().to_vec();
        forged.resize(16, 0);
        assert_eq!(bucketer.unpad(&forged), Err(PaddingError::Malformed));
    }

    #[test]
    fn duplicate_and_unsorted_bucket_sizes_are_normalized() {
        let bucketer = SizeBucketer::new([64, 16, 64, 32, 16]);
        assert_eq!(bucketer.buckets(), &[16, 32, 64]);
    }

    #[test]
    fn buckets_smaller_than_the_length_prefix_are_dropped() {
        let bucketer = SizeBucketer::new([1, 2, 3, 64]);
        assert_eq!(bucketer.buckets(), &[64]);
    }

    #[test]
    #[should_panic(expected = "needs at least one bucket")]
    fn no_usable_buckets_panics_rather_than_silently_accepting_nothing() {
        SizeBucketer::new([1, 2, 3]);
    }

    #[test]
    fn padding_error_has_a_human_readable_display() {
        assert!(PaddingError::MessageTooLargeForAnyBucket
            .to_string()
            .contains("bucket"));
        assert!(PaddingError::Malformed.to_string().contains("length"));
    }
}
