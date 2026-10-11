//! The rate-limiting mechanism: linear algebra over the STARK's field. Two
//! shares from the *same* nullifier (same `epoch`, so the same `a1`) with
//! different `x` reveal the secret key that produced them: spend twice in
//! one epoch and your key is extracted.
//!
//! One share alone reveals nothing: `y = sk + a1 * x` has a solution `sk`
//! for every `a1`, so a single point is information-theoretically hiding (a
//! 1-of-1 Shamir share). The second point on the line pins the intercept.

use winterfell::math::fields::f64::BaseElement;

#[derive(Clone, Copy, Debug)]
pub struct Share {
    pub nullifier: BaseElement,
    pub x: BaseElement,
    pub y: BaseElement,
}

/// Attempts to recover `sk` from two shares. `None` if they don't share a
/// nullifier (different epochs, no violation) or have the same `x`
/// (degenerate: division by zero).
pub fn recover_secret(a: &Share, b: &Share) -> Option<BaseElement> {
    if a.nullifier != b.nullifier {
        return None;
    }
    if a.x == b.x {
        return None;
    }
    // Two points (x1,y1), (x2,y2) on y = sk + a1*x:
    //   a1 = (y1 - y2) / (x1 - x2)
    //   sk = y1 - a1*x1
    let a1 = (a.y - b.y) / (a.x - b.x);
    Some(a.y - a1 * a.x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_sk_from_two_points_on_the_same_line() {
        let sk = BaseElement::new(1234);
        let a1 = BaseElement::new(777);
        let nullifier = BaseElement::new(1); // shares must agree on this
        let x1 = BaseElement::new(10);
        let x2 = BaseElement::new(20);

        let share_a = Share {
            nullifier,
            x: x1,
            y: sk + a1 * x1,
        };
        let share_b = Share {
            nullifier,
            x: x2,
            y: sk + a1 * x2,
        };

        assert_eq!(recover_secret(&share_a, &share_b), Some(sk));
    }

    #[test]
    fn different_nullifiers_do_not_recover_anything() {
        let share_a = Share {
            nullifier: BaseElement::new(1),
            x: BaseElement::new(10),
            y: BaseElement::new(20),
        };
        let share_b = Share {
            nullifier: BaseElement::new(2),
            x: BaseElement::new(30),
            y: BaseElement::new(40),
        };
        assert_eq!(recover_secret(&share_a, &share_b), None);
    }

    #[test]
    fn identical_x_is_the_degenerate_case_and_recovers_nothing() {
        // Equal `x` would divide by zero, and is not a real second observation
        // (both shares bind the same message value), so recovering nothing is
        // correct, not just safe.
        let nullifier = BaseElement::new(1);
        let x = BaseElement::new(10);
        let share_a = Share {
            nullifier,
            x,
            y: BaseElement::new(20),
        };
        let share_b = Share {
            nullifier,
            x,
            y: BaseElement::new(999),
        };
        assert_eq!(recover_secret(&share_a, &share_b), None);
    }
}
