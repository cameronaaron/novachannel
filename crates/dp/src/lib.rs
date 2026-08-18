//! Formal differential privacy for the "did this user send anything?"
//! metadata signal, via calibrated dummy traffic.
//!
//! # The guarantee, precisely
//! Time is divided into fixed-length slots. In each slot, let `b ∈ {0,1}`
//! be ground truth: "does the user have a real message queued this slot?"
//! The scheduler's *observable* output `o ∈ {0,1}` ("a packet — real or
//! dummy, indistinguishable to an outside observer — was transmitted this
//! slot") is produced by:
//!
//! - if `b = 1`: transmit the real message, so `o = 1` with probability 1
//!   (real traffic is never delayed or dropped — all the privacy budget
//!   goes to calibrating the *dummy* side, not to withholding real sends).
//! - if `b = 0`: transmit a dummy packet independently with probability
//!   `q = e^{-ε}`, so `o = 1` with probability `q`.
//!
//! This is randomized response, and it gives **exact ε-differential
//! privacy** for the single-slot presence bit — not an approximation:
//!
//! ```text
//! Pr[o=1 | b=1] / Pr[o=1 | b=0] = 1 / q = e^ε
//! Pr[o=0 | b=1] / Pr[o=0 | b=0] = 0 / (1-q) = 0 ≤ e^ε
//! ```
//!
//! Both ratios are bounded by `e^ε`, which is the definition of
//! ε-differential privacy for this binary mechanism. An adversary who sees
//! one slot's transmit/silent bit and tries to guess whether it was
//! triggered by a real message gains, at most, likelihood ratio `e^ε` —
//! matching the guarantee in the module-level claim: *"an adversary
//! monitoring the channel has bounded statistical advantage in
//! distinguishing a real send from cover traffic."*
//!
//! # Composing across many slots
//! Watching one slot bounds an adversary by `e^ε`; watching `k`
//! independent slots (e.g. an entire session) composes. [`sequential_epsilon`]
//! gives the simple (loose, exact, no failure probability) bound; for
//! anything beyond a handful of slots, [`advanced_composition_epsilon`]
//! gives the standard tighter Dwork-Rothblum-Vadhan bound at the cost of
//! an explicit `delta` failure probability. [`Budget`] wraps this into a
//! stateful "how many more slots can I spend before crossing my target
//! total ε" tracker (a privacy odometer), so callers don't have to
//! re-derive the composition math at every call site.
//!
//! # What this doesn't cover
//! - **Timing/latency side channels.** A real message is sent immediately;
//!   this crate says nothing about correlating queueing delay or
//!   request/response timing across the wider system. Unlike the size
//!   side channel below, closing this would mean actually scheduling
//!   traffic (real sends delayed to a grid, not just padded) — a materially
//!   larger, separate undertaking than a padding function, and not
//!   attempted here.
//! - **Non-independent slots.** The composition bounds assume the
//!   dummy-injection coin flips are drawn independently per slot with a
//!   fresh CSPRNG draw each time; reusing randomness across slots breaks
//!   the guarantee.
//!
//! [`SizeBucketer`] closes the other side channel this module used to
//! leave open: padding a message's *content* to one of a fixed set of
//! sizes before it's encrypted, so an observer of ciphertext length learns
//! only which bucket a message fell into, not its exact size. This is a
//! genuinely separate, much simpler mechanism than the presence-bit DP
//! above — no epsilon, no composition math, just a length-hiding pad/unpad
//! pair — composed by the caller with whatever does the actual encryption
//! (`novachannel`, most naturally): pad the plaintext first, then seal the
//! padded bytes, so the padding itself is never visible to an observer,
//! only the resulting bucket size is.

#![forbid(unsafe_code)]
// Every `.unwrap()` this catches either gets replaced with a
// `.expect("reason")` documenting why it can't actually fail, or is a
// bug — the same discipline libsignal's own crates enforce
// (`#![warn(clippy::unwrap_used)]` in their `protocol`/`zkgroup` crate
// roots), turning a one-time manual audit into a standing, compiler-
// checked one. Exempted in test code, where `.unwrap()` on a value the
// test itself just constructed is the normal, idiomatic thing to do.
#![warn(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use rand::{Rng, RngExt};

/// Per-slot dummy-traffic scheduler calibrated to a target epsilon.
#[derive(Clone, Copy, Debug)]
pub struct DummyScheduler {
    epsilon: f64,
    /// `q = e^{-epsilon}`: probability of sending a dummy in an empty slot.
    dummy_probability: f64,
}

impl DummyScheduler {
    /// # Panics
    /// Panics if `epsilon` is not finite and non-negative. `epsilon = 0`
    /// is legal and means "always send a dummy in every empty slot" (perfect
    /// hiding, maximum bandwidth cost).
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

    /// Decides whether to transmit this slot. Always `true` if
    /// `has_real_message`; otherwise `true` with probability
    /// [`Self::dummy_probability`]. The caller is responsible for actually
    /// constructing an indistinguishable dummy packet (same size/framing as
    /// a real one) when this returns `true` and `has_real_message` was
    /// `false` — the DP guarantee is about the *decision bit*, and is void
    /// if a passive observer can tell real and dummy packets apart by any
    /// other signal (size, timing jitter, ...).
    pub fn decide(&self, has_real_message: bool, rng: &mut impl Rng) -> bool {
        has_real_message || rng.random_bool(self.dummy_probability)
    }
}

/// Basic sequential composition: watching `k` independent epsilon-DP slots
/// costs at most `k * epsilon` total. Exact, no failure probability, but
/// loose for large `k` — see [`advanced_composition_epsilon`] for a
/// tighter bound.
pub fn sequential_epsilon(epsilon_per_slot: f64, num_slots: u64) -> f64 {
    epsilon_per_slot * num_slots as f64
}

/// Advanced composition (Dwork, Rothblum, Vadhan 2010): for `k`-fold
/// composition of epsilon-DP mechanisms, the composed mechanism is
/// `(eps', k*delta + delta')`-DP for any `delta' > 0`, where
///
/// ```text
/// eps' = sqrt(2k * ln(1/delta')) * eps + k * eps * (e^eps - 1)
/// ```
///
/// This is tighter than [`sequential_epsilon`] once `k` is more than a
/// handful of slots, at the cost of accepting a small failure probability
/// `delta_prime` (the guarantee holds except with probability `delta_prime`).
/// `delta_prime` should be chosen cryptographically small (e.g. `1e-9`) —
/// it is not a tunable privacy/utility knob so much as "the chance the
/// tail bound itself fails."
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

/// A stateful privacy odometer: tracks how much of a total epsilon budget
/// has been spent across slots via [`sequential_epsilon`], and reports how
/// many more slots can be spent before the budget is exhausted.
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

    /// Records that one more slot's mechanism was applied.
    ///
    /// Returns `false` (budget exhausted, spend not recorded) if this slot
    /// would push total spend over the budget — the caller should fall
    /// back to a lower-epsilon (higher dummy-rate) scheduler, or stop
    /// sending, rather than silently exceeding the declared guarantee.
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
// A separate, independent mechanism from the presence-bit DP above (module
// docs): closes the size-correlation side channel by padding plaintext
// content up to one of a fixed set of byte-length "buckets" before
// encryption, so ciphertext length reveals only which bucket a message
// fell into, not its exact size.

const LENGTH_PREFIX_LEN: usize = 4;

/// Returned by [`SizeBucketer::pad`]/[`SizeBucketer::unpad`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingError {
    /// The plaintext, plus the 4-byte length prefix `pad` adds, is larger
    /// than every configured bucket — there is no bucket size that would
    /// hide it. The caller needs either a larger bucket or to split the
    /// message.
    MessageTooLargeForAnyBucket,
    /// `unpad`'s input is shorter than the length prefix, or the prefix
    /// claims more content bytes than the padded buffer actually holds.
    /// Composed with an authenticated channel (the documented intended
    /// use — module docs), this should only ever be reachable via a
    /// caller bug: a genuinely tampered message already fails that
    /// channel's own AEAD verification before its plaintext ever reaches
    /// `unpad`.
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

/// Pads plaintext up to a fixed set of size buckets so a passive observer
/// of ciphertext length learns only which bucket a message fell into —
/// see the module docs' "What this doesn't cover" section for the full
/// scope and how this composes with an actual encrypted channel.
#[derive(Clone, Debug)]
pub struct SizeBucketer {
    /// Strictly increasing, deduplicated bucket sizes in bytes.
    buckets: Vec<usize>,
}

impl SizeBucketer {
    /// `bucket_sizes` need not be sorted or deduplicated — both happen
    /// here. Any bucket smaller than the length-prefix overhead `pad`
    /// itself adds is dropped first, since no plaintext (not even an
    /// empty one) could ever fit in it.
    ///
    /// # Panics
    /// Panics if this leaves zero usable buckets.
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

    /// Powers of two from `2^min_log2` through `2^max_log2` bytes
    /// inclusive — the conventional choice (the same shape Tor cell
    /// padding uses) when there's no application-specific size
    /// distribution to tune buckets against instead.
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

    /// Pads `plaintext` up to the smallest configured bucket that fits
    /// `plaintext.len()` plus the length prefix. Encrypt the *result*, not
    /// `plaintext` directly, for the padding to hide anything — an
    /// observer who only ever sees the padded bytes in the clear learns
    /// nothing this function was meant to hide.
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

    /// The actual property that matters: two plaintexts of different
    /// lengths that land in the *same* bucket produce identically-sized
    /// padded output — an observer of ciphertext length alone cannot
    /// distinguish them.
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
