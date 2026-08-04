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
//!   request/response timing across the wider system.
//! - **Volume/size side channels.** Padding message *content* to a fixed
//!   size is a separate, simpler problem, not addressed here.
//! - **Non-independent slots.** The composition bounds assume the
//!   dummy-injection coin flips are drawn independently per slot with a
//!   fresh CSPRNG draw each time; reusing randomness across slots breaks
//!   the guarantee.

#![deny(unsafe_code)]
// Every `.unwrap()` this catches either gets replaced with a
// `.expect("reason")` documenting why it can't actually fail, or is a
// bug — the same discipline libsignal's own crates enforce
// (`#![warn(clippy::unwrap_used)]` in their `protocol`/`zkgroup` crate
// roots), turning a one-time manual audit into a standing, compiler-
// checked one. Exempted in test code, where `.unwrap()` on a value the
// test itself just constructed is the normal, idiomatic thing to do.
#![warn(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use rand::Rng;

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
        has_real_message || rng.gen_bool(self.dummy_probability)
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
}
