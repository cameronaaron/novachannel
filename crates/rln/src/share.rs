//! The rate-limiting mechanism itself: plain linear algebra over the same
//! field the STARK operates on. Given two shares from the *same* nullifier
//! (i.e. the same `epoch`, meaning the same `a1`) but different `x`, the
//! secret key that produced them is recoverable — that's the "spend twice
//! in one epoch, get your key extracted" property RLN is named for.
//!
//! One share alone reveals nothing about `sk`: `y = sk + a1 * x` for a
//! single `(x, y)` pair has a solution `sk` for every possible `a1`, so it's
//! information-theoretically hiding on its own (this is exactly a 1-of-1
//! Shamir share). It's only the *second* point on the same line that pins
//! down the line's intercept.

use winterfell::math::fields::f64::BaseElement;

#[derive(Clone, Copy, Debug)]
pub struct Share {
    pub nullifier: BaseElement,
    pub x: BaseElement,
    pub y: BaseElement,
}

/// Attempts to recover `sk` from two shares. Returns `None` if the shares
/// don't share a nullifier (different epochs — no violation), or if `x`
/// values coincide (degenerate, division by zero).
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
        // Same x on the same line would divide by zero deriving the slope;
        // it's also not a real two-point observation (both shares came
        // from the same message-binding value), so refusing to "recover"
        // anything from it is correct, not just safe.
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
