//! Threshold key generation and decryption for mixnode operators: `t` of
//! `n` operators must cooperate to decrypt under the group key, and no
//! coalition smaller than `t` ever holds or can reconstruct the secret.
//!
//! # Where this fits
//! A conventional mixnode has one operator with one key, who can be
//! coerced, subpoenaed or malicious. Splitting the key across `n`
//! independent operators with [`Dealer`] (a joint-Feldman DKG) means
//! compromising the node takes `t` of them at once.
//!
//! # Protocol
//! 1. **Distributed key generation** ([`Dealer`]): each participant runs a
//!    Feldman VSS of its own random contribution, and everyone sums the
//!    shares and commitments received from all dealers. The result is a
//!    `(t, n)` Shamir sharing of a group secret `s` nobody computes, and a
//!    public key `Y = s*G`.
//! 2. **Threshold decryption** ([`partial_decrypt`], [`combine_partials`]):
//!    given an ephemeral point `R` (e.g. from an ElGamal-style encapsulation
//!    to `Y`), each of `t` participants computes `s_i*R` from its share;
//!    Lagrange interpolation in the exponent over any `t` valid partials
//!    gives `s*R`, what a full-key holder would compute, without ever
//!    reconstructing `s`.
//!
//! # Commit-reveal and complaint resolution
//! Each dealer's `a_0` coefficient (its contribution to the group key) is
//! exchanged by **commit, then reveal** ([`Dealer::commitment_hash`] before
//! [`Dealer::reveal`]), so a rushing adversary can't choose its
//! contribution after seeing everyone else's and bias the key.
//!
//! A faulty dealer no longer aborts the run. Two paths, at two scales:
//!
//! - [`identify_faulty_dealers`]: when one process sees every dealer's
//!   shares (this crate's tests, or a trusted coordinator), it computes
//!   directly which dealers sent anyone an invalid share, the outcome the
//!   complaint protocol reaches without the network round trip.
//! - [`Complaint`]/[`Dealer::share_for`]/[`resolve_complaint`]: the
//!   per-accusation building block for a network where nobody sees every
//!   share. A participant whose share fails [`verify_share`] broadcasts a
//!   [`Complaint`] naming the dealer and showing the share received; the
//!   dealer broadcasts the true share ([`Dealer::share_for`]); and
//!   [`resolve_complaint`] reaches a [`ComplaintVerdict`] from the dealer's
//!   public commitments, the complaint and the disclosure, which anyone can
//!   recompute.
//!
//!   **A dealer is disqualified only if the share it broadcasts in response
//!   fails [`verify_share`] against its own published commitments.** That
//!   is Gennaro et al.'s rule, and the only judgement derivable from values
//!   the dealer itself published. A complaint's `received_share` is an
//!   unauthenticated claim about a message nobody else saw: "the dealer
//!   sent me the wrong share" and "I am lying about what I received" look
//!   identical. Treating that as dealer fault (as this crate once did) let
//!   one malicious participant disqualify every honest dealer and decide
//!   the group key alone. It is now
//!   [`ComplaintVerdict::DisclosureIsValidButContradictsTheAccusersClaim`],
//!   not a fault; see that variant for what to do with it and what
//!   authenticated delivery would be needed to attribute it.
//!
//!   `examples/networked_complaint.rs` drives this decision procedure over a
//!   real broadcast transport; a production deployment will likely use its
//!   own transport.
//!
//! Either path feeds [`finalize_key_share_excluding_faulty`], so a proven
//! faulty dealer costs only its own contribution.
//!
//! # No networking in the crate; a networked example exists
//! [`Dealer`] is a state machine producing messages (broadcast commitments,
//! point-to-point shares, complaints and disclosures) for the caller to
//! transport, most naturally over `novachannel` sessions. Delivering the
//! same broadcast values to every honest participant, so all reach the same
//! [`ComplaintVerdict`], is the caller's job. In
//! `examples/networked_complaint.rs`, five participants, each an OS thread
//! with its own TCP socket to a small broadcast relay, exchange a real
//! [`Complaint`] and [`Dealer::share_for`] disclosure, and each computes the
//! same verdict from what it received. The relay only forwards complaints
//! and disclosures (safe to broadcast) and never sees a dealer's polynomial
//! or the per-dealer shares from the reveal round, which stay local to
//! `main()`.

#![forbid(unsafe_code)]
// Each `.unwrap()` must become an `.expect("why it can't fail")` or is a
// bug (libsignal's `protocol`/`zkgroup` crates enforce the same lint).
// Allowed in tests, on values the test just built.
#![warn(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::collections::BTreeMap;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use getrandom::{rand_core::UnwrapErr, SysRng};
use rand_core::Rng;
use sha2::{Digest, Sha256};

pub type ParticipantId = u32;
pub mod frost;
pub mod threshold_kem;

/// `rand_core` 0.10 (shared by the workspace's dalek and ML-KEM/ML-DSA
/// crates) no longer ships `OsRng`; `getrandom`'s `SysRng`, wrapped as
/// infallible, replaces it. Same pattern and rationale as
/// `novachannel::rng`.
pub(crate) fn csprng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Whether `id` may be a Shamir evaluation point.
///
/// **Zero is not a participant id.** Every secret here is a polynomial's
/// constant term: `f(0)` *is* the secret, for a [`Dealer`]'s contribution
/// and for [`threshold_kem::encrypt_to_group`]'s master secret. Evaluating
/// at zero yields the secret, not a share. RFC 9591 excludes zero from FROST
/// identifiers for the same reason.
///
/// This was exploitable: [`Dealer::share_for`] is the network-facing answer
/// to a [`Complaint`], which carries the accuser's id. Before this check,
/// `Complaint { accuser: 0, .. }` made an honest dealer broadcast `f(0)`,
/// its whole contribution; repeated against every dealer, that reconstructs
/// the group secret.
pub const fn is_valid_participant_id(id: ParticipantId) -> bool {
    id != 0
}

pub(crate) fn scalar_from_id(id: ParticipantId) -> Scalar {
    debug_assert!(
        is_valid_participant_id(id),
        "participant id 0 is the secret's own evaluation point, never a share's"
    );
    Scalar::from(id as u64)
}

/// Evaluates Feldman commitments `[C_0, C_1, ..., C_{t-1}]` at `id`:
/// `sum_k(id^k * C_k)`, i.e. `f(id) * G` for the hidden polynomial `f`.
/// Shared by [`verify_share`] (one dealer) and
/// [`frost::public_verification_share`] (summed over surviving dealers) so
/// they agree on what evaluating a commitment means.
pub(crate) fn evaluate_commitment(commitments: &[RistrettoPoint], id: Scalar) -> RistrettoPoint {
    let mut expected = RistrettoPoint::default();
    let mut power = Scalar::ONE;
    for c in commitments {
        expected += power * c;
        power *= id;
    }
    expected
}

/// One participant's Feldman VSS dealing of their own random contribution
/// to the group secret.
pub struct Dealer {
    threshold: u32,
    num_participants: u32,
    coefficients: Vec<Scalar>,
    commitments: Vec<RistrettoPoint>,
}

impl Drop for Dealer {
    fn drop(&mut self) {
        for c in self.coefficients.iter_mut() {
            *c = Scalar::ZERO;
        }
    }
}

impl Dealer {
    /// Generates a random degree-`(threshold - 1)` polynomial and its Feldman
    /// commitments. `threshold` participants are needed to reconstruct
    /// anything derived from this contribution.
    pub fn new(threshold: u32, num_participants: u32) -> Self {
        assert!(threshold >= 1 && threshold <= num_participants);
        let mut rng = csprng();
        let coefficients: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(&mut rng)).collect();
        let commitments = coefficients
            .iter()
            .map(|c| c * RISTRETTO_BASEPOINT_POINT)
            .collect();
        Dealer {
            threshold,
            num_participants,
            coefficients,
            commitments,
        }
    }

    /// Commit-round message: a hash binding this dealer to its commitments
    /// without revealing them. Collect all `n` dealers' hashes *before* any
    /// dealer calls [`Dealer::reveal`]; that ordering prevents the rushing bias
    /// attack (module docs).
    pub fn commitment_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for c in &self.commitments {
            hasher.update(c.compress().as_bytes());
        }
        hasher.finalize().into()
    }

    /// Reveal round: the actual commitments (broadcast to everyone) and the
    /// per-participant shares (each sent only to that participant).
    pub fn reveal(&self) -> (Vec<RistrettoPoint>, BTreeMap<ParticipantId, Scalar>) {
        let shares = (1..=self.num_participants)
            .map(|id| (id, evaluate(&self.coefficients, scalar_from_id(id))))
            .collect();
        (self.commitments.clone(), shares)
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Recomputes this dealer's share for `participant_id`, identical to what
    /// [`Self::reveal`] sent. This is the dealer's answer to a [`Complaint`]:
    /// broadcast with its public `commitments`, it lets everyone run
    /// [`resolve_complaint`] and reach the same verdict without trusting either
    /// side's word.
    ///
    /// Returns `None` for any id this dealer never dealt to, including `0`. The
    /// id comes from an attacker-supplied [`Complaint`], and evaluating at zero
    /// would disclose the dealer's whole contribution (see
    /// [`is_valid_participant_id`]). `None` means the complaint was malformed
    /// and the dealer should publish nothing.
    pub fn share_for(&self, participant_id: ParticipantId) -> Option<Scalar> {
        if !is_valid_participant_id(participant_id) || participant_id > self.num_participants {
            return None;
        }
        Some(evaluate(&self.coefficients, scalar_from_id(participant_id)))
    }
}

/// A participant's public accusation that dealer `dealer_index`'s reveal to
/// them (`received_share`) failed [`verify_share`] against the dealer's
/// broadcast commitments. Safe to broadcast: any `threshold - 1` Feldman
/// shares are information-theoretically independent of the polynomial, so
/// showing one's own disputed share reveals nothing new.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Complaint {
    pub accuser: ParticipantId,
    pub dealer_index: usize,
    pub received_share: Scalar,
}

/// The outcome of [`resolve_complaint`]. Anyone with the same three public
/// values (the dealer's commitments, the [`Complaint`], and the
/// [`Dealer::share_for`] disclosure) reaches the same verdict, which is what
/// makes it a resolution rather than one party's word against another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplaintVerdict {
    /// The complaint can't be answered: its `accuser` is not a valid
    /// participant id (see [`is_valid_participant_id`]), so the dealer must
    /// publish nothing. The fault, if any, is the accuser's.
    MalformedComplaint,
    /// The disclosed share doesn't verify against the dealer's own commitments:
    /// the polynomial used to deal doesn't match the one committed to. Faulty
    /// whatever the accuser claims. **The only verdict that disqualifies a
    /// dealer**, and the only one that can, since it alone is decided purely
    /// from values the dealer published.
    DealerCannotProduceAValidShare,
    /// The disclosed share verifies against the dealer's commitments but
    /// differs from what the accuser says it received.
    ///
    /// **Attributable to neither party.** `Complaint::received_share` is an
    /// unauthenticated claim about a message nobody else saw: "the dealer sent
    /// me something wrong" and "I am lying about what I received" produce
    /// identical evidence. Calling this dealer fault, as this crate once did,
    /// let any participant disqualify any honest dealer, and one who
    /// disqualified them all would decide the group key alone. Gennaro et
    /// al.'s DKG has no such rule: disqualify iff the broadcast share fails
    /// verification.
    ///
    /// The useful outcome is repair: the disclosure is public and verified, so
    /// the accuser adopts it as its share and the run continues. Attributing
    /// this case would need an authenticated record of the original delivery
    /// (a dealer signature on each share, or shares encrypted to each
    /// recipient's published key and broadcast), which this crate doesn't
    /// provide because it does no networking.
    DisclosureIsValidButContradictsTheAccusersClaim,
    /// The disclosure verifies and equals what the accuser claims to have
    /// received (so that verifies too). The complaint was mistaken or
    /// malicious; the dealer is exonerated.
    ComplaintWasUnfounded,
}

impl ComplaintVerdict {
    /// `true` only for [`Self::DealerCannotProduceAValidShare`], the one verdict
    /// decided from the dealer's own published values and so the only basis
    /// for exclusion. This is what [`finalize_key_share_excluding_faulty`]
    /// needs.
    pub fn is_faulty(&self) -> bool {
        matches!(self, ComplaintVerdict::DealerCannotProduceAValidShare)
    }
}

/// Resolves one [`Complaint`] using `dealer_commitments` (the dealer's
/// broadcast Feldman commitments from [`Dealer::reveal`]) and
/// `disclosed_share` (its [`Dealer::share_for`] answer for the accuser).
/// Every honest participant computes this from the same broadcast values
/// and reaches the same [`ComplaintVerdict`]; see the module docs.
pub fn resolve_complaint(
    dealer_commitments: &[RistrettoPoint],
    complaint: &Complaint,
    disclosed_share: &Scalar,
) -> ComplaintVerdict {
    // Checked first, so a complaint naming an impossible accuser is never
    // scored against the dealer: the dealer rightly refuses to disclose
    // ([`Dealer::share_for`] returns `None`), and that refusal must not read as
    // "could not produce a valid share".
    if !is_valid_participant_id(complaint.accuser) {
        return ComplaintVerdict::MalformedComplaint;
    }
    if !verify_share(dealer_commitments, complaint.accuser, disclosed_share) {
        return ComplaintVerdict::DealerCannotProduceAValidShare;
    }
    if disclosed_share != &complaint.received_share {
        return ComplaintVerdict::DisclosureIsValidButContradictsTheAccusersClaim;
    }
    ComplaintVerdict::ComplaintWasUnfounded
}

fn evaluate(coefficients: &[Scalar], x: Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, c| acc * x + c)
}

/// Feldman verification: `share` is consistent with `commitments` for
/// `participant_id`, i.e. `share * G == sum_k(id^k * C_k)`. Run on every
/// share from every dealer; a failure identifies that dealer as faulty (see
/// [`identify_faulty_dealers`]) instead of aborting the DKG.
pub fn verify_share(
    commitments: &[RistrettoPoint],
    participant_id: ParticipantId,
    share: &Scalar,
) -> bool {
    // Not a participant id, so not a share to verify (see
    // [`is_valid_participant_id`]). [`resolve_complaint`], the only caller that
    // must tell "invalid id" from "invalid share", checks the id first.
    if !is_valid_participant_id(participant_id) {
        return false;
    }
    let expected = evaluate_commitment(commitments, scalar_from_id(participant_id));
    share * RISTRETTO_BASEPOINT_POINT == expected
}

/// A participant's final DKG output: their share of the (never assembled)
/// group secret, and the group's public key.
pub struct KeyShare {
    pub participant_id: ParticipantId,
    pub secret_share: Scalar,
    pub group_public_key: RistrettoPoint,
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        self.secret_share = Scalar::ZERO;
    }
}

/// Combines every dealer's verified share for this participant and every
/// dealer's `C_0` commitment into this participant's [`KeyShare`].
///
/// # Panics
/// Panics if `participant_id` is not valid (see
/// [`is_valid_participant_id`]). A `KeyShare` carries the id into [`frost`]
/// signing and [`combine_partials`], so refusing here keeps id zero out of
/// every Lagrange interpolation downstream. This is a caller configuration
/// error: the id is this participant's own, never adversary-supplied.
pub fn finalize_key_share(
    participant_id: ParticipantId,
    verified_shares_from_each_dealer: &[Scalar],
    each_dealers_c0: &[RistrettoPoint],
) -> KeyShare {
    assert!(
        is_valid_participant_id(participant_id),
        "participant id 0 is the group secret's own evaluation point, not a participant"
    );
    let secret_share = verified_shares_from_each_dealer
        .iter()
        .fold(Scalar::ZERO, |acc, s| acc + s);
    let group_public_key = each_dealers_c0
        .iter()
        .fold(RistrettoPoint::default(), |acc, c| acc + c);
    KeyShare {
        participant_id,
        secret_share,
        group_public_key,
    }
}

/// Identifies dealers who sent any participant a share failing
/// [`verify_share`] against their own commitments: the complaint
/// resolution from the module docs, computed directly instead of over a
/// broadcast exchange. `dealer_commitments[d]`/`dealer_shares[d]` must be
/// dealer `d`'s [`Dealer::reveal`] outputs, in matching order.
///
/// Returns the indices of every proven-faulty dealer, for
/// [`finalize_key_share_excluding_faulty`].
pub fn identify_faulty_dealers(
    dealer_commitments: &[Vec<RistrettoPoint>],
    dealer_shares: &[BTreeMap<ParticipantId, Scalar>],
) -> Vec<usize> {
    dealer_commitments
        .iter()
        .zip(dealer_shares)
        .enumerate()
        .filter_map(|(dealer_index, (commitments, shares))| {
            let all_valid = shares
                .iter()
                .all(|(&pid, s)| verify_share(commitments, pid, s));
            (!all_valid).then_some(dealer_index)
        })
        .collect()
}

/// Like [`finalize_key_share`], but drops every dealer in `excluded` (from
/// [`identify_faulty_dealers`]) from both the secret share and the group
/// public key, for every participant, so honest participants converge on
/// the same smaller but sound key.
pub fn finalize_key_share_excluding_faulty(
    participant_id: ParticipantId,
    dealer_commitments: &[Vec<RistrettoPoint>],
    dealer_shares: &[BTreeMap<ParticipantId, Scalar>],
    excluded: &[usize],
) -> KeyShare {
    let surviving_shares: Vec<Scalar> = dealer_shares
        .iter()
        .enumerate()
        .filter(|(d, _)| !excluded.contains(d))
        .map(|(_, shares)| shares[&participant_id])
        .collect();
    let surviving_c0: Vec<RistrettoPoint> = dealer_commitments
        .iter()
        .enumerate()
        .filter(|(d, _)| !excluded.contains(d))
        .map(|(_, c)| c[0])
        .collect();
    finalize_key_share(participant_id, &surviving_shares, &surviving_c0)
}

/// Lagrange coefficient for `participant_id` at `x = 0`, over the set of
/// participant ids in this reconstruction.
pub(crate) fn lagrange_coefficient_at_zero(
    participant_id: ParticipantId,
    all_ids: &[ParticipantId],
) -> Scalar {
    let xi = scalar_from_id(participant_id);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &other in all_ids {
        if other == participant_id {
            continue;
        }
        let xj = scalar_from_id(other);
        num *= xj;
        den *= xj - xi;
    }
    num * den.invert()
}

/// One participant's contribution to a threshold decryption: `s_i * R`.
pub fn partial_decrypt(share: &KeyShare, r: &RistrettoPoint) -> RistrettoPoint {
    share.secret_share * r
}

/// Combines `t` partial decryptions into `s * R` by Lagrange interpolation
/// in the exponent. `partials` needs at least `threshold` entries, all from
/// participants in the same DKG.
pub fn combine_partials(partials: &[(ParticipantId, RistrettoPoint)]) -> RistrettoPoint {
    let ids: Vec<ParticipantId> = partials.iter().map(|(id, _)| *id).collect();
    partials
        .iter()
        .fold(RistrettoPoint::default(), |acc, (id, p)| {
            acc + lagrange_coefficient_at_zero(*id, &ids) * p
        })
}

/// Derives a symmetric key from a shared secret point: the last step of
/// both a sender's encapsulation and a quorum's threshold decryption, which
/// must yield the same 32 bytes.
pub fn derive_symmetric_key(shared_point: &RistrettoPoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"novachannel-mpc shared secret v1");
    hasher.update(shared_point.compress().as_bytes());
    hasher.finalize().into()
}

/// Encapsulates to a group public key: pick ephemeral `r`, publish
/// `R = r*G`, derive the key from `r*Y`. Only a `threshold` quorum can
/// derive the same key, via [`partial_decrypt`] + [`combine_partials`] +
/// [`derive_symmetric_key`].
pub fn encapsulate(group_public_key: &RistrettoPoint) -> (RistrettoPoint, [u8; 32]) {
    let mut rng = csprng();
    let mut r_bytes = [0u8; 64];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order_wide(&r_bytes);
    let big_r = r * RISTRETTO_BASEPOINT_POINT;
    let shared = r * group_public_key;
    (big_r, derive_symmetric_key(&shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a full `t`-of-`n` DKG in-process (no networking — see module
    /// docs) and returns every participant's final key share.
    fn run_dkg(threshold: u32, n: u32) -> Vec<KeyShare> {
        let dealers: Vec<Dealer> = (0..n).map(|_| Dealer::new(threshold, n)).collect();

        // Commit round.
        let _hashes: Vec<_> = dealers.iter().map(|d| d.commitment_hash()).collect();

        // Reveal round.
        let revealed: Vec<(Vec<RistrettoPoint>, BTreeMap<ParticipantId, Scalar>)> =
            dealers.iter().map(|d| d.reveal()).collect();

        let c0s: Vec<RistrettoPoint> = revealed.iter().map(|(c, _)| c[0]).collect();

        (1..=n)
            .map(|pid| {
                let shares: Vec<Scalar> = revealed
                    .iter()
                    .map(|(commitments, shares)| {
                        let s = shares[&pid];
                        assert!(
                            verify_share(commitments, pid, &s),
                            "bad share for participant {pid}"
                        );
                        s
                    })
                    .collect();
                finalize_key_share(pid, &shares, &c0s)
            })
            .collect()
    }

    #[test]
    fn all_participants_agree_on_group_public_key() {
        let shares = run_dkg(3, 5);
        let y0 = shares[0].group_public_key;
        for s in &shares {
            assert_eq!(s.group_public_key, y0);
        }
    }

    #[test]
    fn dealer_threshold_getter_returns_the_constructed_value() {
        let dealer = Dealer::new(3, 5);
        assert_eq!(dealer.threshold(), 3);
    }

    #[test]
    fn threshold_quorum_recovers_the_shared_secret() {
        let (threshold, n) = (3, 5);
        let shares = run_dkg(threshold, n);

        let (r, sender_key) = encapsulate(&shares[0].group_public_key);

        // Any 3 of the 5 participants should be able to reconstruct it.
        for quorum in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
            let partials: Vec<(ParticipantId, RistrettoPoint)> = quorum
                .iter()
                .map(|&i| (shares[i].participant_id, partial_decrypt(&shares[i], &r)))
                .collect();
            let combined = combine_partials(&partials);
            assert_eq!(derive_symmetric_key(&combined), sender_key);
        }
    }

    #[test]
    fn below_threshold_quorum_does_not_recover_the_secret() {
        let (threshold, n) = (3, 5);
        let shares = run_dkg(threshold, n);
        let (r, sender_key) = encapsulate(&shares[0].group_public_key);

        // Only 2 participants — below the threshold of 3.
        let partials: Vec<(ParticipantId, RistrettoPoint)> = [0, 1]
            .iter()
            .map(|&i| (shares[i].participant_id, partial_decrypt(&shares[i], &r)))
            .collect();
        let combined = combine_partials(&partials);
        assert_ne!(derive_symmetric_key(&combined), sender_key);
    }

    #[test]
    fn tampered_share_fails_feldman_verification() {
        let dealer = Dealer::new(2, 3);
        let (commitments, mut shares) = dealer.reveal();
        let bad = shares.get_mut(&1).unwrap();
        *bad += Scalar::ONE;
        assert!(!verify_share(&commitments, 1, bad));
    }

    #[test]
    fn a_faulty_dealer_is_identified_and_excluded_without_aborting_the_dkg() {
        let (threshold, n) = (3, 5);
        let dealers: Vec<Dealer> = (0..n).map(|_| Dealer::new(threshold, n)).collect();
        let _hashes: Vec<_> = dealers.iter().map(|d| d.commitment_hash()).collect();

        let mut dealer_commitments: Vec<Vec<RistrettoPoint>> = Vec::new();
        let mut dealer_shares: Vec<BTreeMap<ParticipantId, Scalar>> = Vec::new();
        for d in &dealers {
            let (c, s) = d.reveal();
            dealer_commitments.push(c);
            dealer_shares.push(s);
        }

        // Dealer 2 sends participant 4 a corrupted share — simulating a
        // faulty (or malicious) dealer, without changing anything else.
        let faulty_dealer = 2usize;
        *dealer_shares[faulty_dealer].get_mut(&4).unwrap() += Scalar::ONE;

        let excluded = identify_faulty_dealers(&dealer_commitments, &dealer_shares);
        assert_eq!(excluded, vec![faulty_dealer]);

        // Every honest participant excludes the same dealer and converges on the
        // same smaller but sound key; the DKG didn't abort.
        let shares: Vec<KeyShare> = (1..=n)
            .map(|pid| {
                finalize_key_share_excluding_faulty(
                    pid,
                    &dealer_commitments,
                    &dealer_shares,
                    &excluded,
                )
            })
            .collect();
        let y0 = shares[0].group_public_key;
        for s in &shares {
            assert_eq!(s.group_public_key, y0);
        }

        // The key differs from naively including every dealer, so exclusion
        // changed something.
        let naive_c0s: Vec<RistrettoPoint> = dealer_commitments.iter().map(|c| c[0]).collect();
        let naive_key = naive_c0s
            .iter()
            .fold(RistrettoPoint::default(), |acc, c| acc + c);
        assert_ne!(y0, naive_key);

        // And the excluded group key still works end-to-end for a
        // threshold quorum of the honest participants.
        let (r, sender_key) = encapsulate(&y0);
        let partials: Vec<(ParticipantId, RistrettoPoint)> = [0, 1, 3]
            .iter()
            .map(|&i| (shares[i].participant_id, partial_decrypt(&shares[i], &r)))
            .collect();
        let combined = combine_partials(&partials);
        assert_eq!(derive_symmetric_key(&combined), sender_key);
    }

    #[test]
    fn an_honest_dealer_disclosure_exonerates_against_an_unfounded_complaint() {
        let dealer = Dealer::new(3, 5);
        let (commitments, shares) = dealer.reveal();
        // Participant 4's honestly received share, complained about anyway. The
        // claim is the real share, so this is the unfounded-complaint branch, not
        // corruption in transit.
        let complaint = Complaint {
            accuser: 4,
            dealer_index: 0,
            received_share: shares[&4],
        };
        let disclosed = dealer.share_for(4).unwrap();
        assert_eq!(
            resolve_complaint(&commitments, &complaint, &disclosed),
            ComplaintVerdict::ComplaintWasUnfounded
        );
        assert!(!resolve_complaint(&commitments, &complaint, &disclosed).is_faulty());
    }

    /// `received_share` is an unauthenticated claim about an unwitnessed
    /// message, so a disagreement with the dealer's verified disclosure is
    /// reported but never blamed on the dealer. This crate used to return a
    /// faulty verdict here, enabling the eviction attack in the next test.
    #[test]
    fn a_disagreement_the_evidence_cannot_attribute_is_reported_without_blaming_the_dealer() {
        let dealer = Dealer::new(3, 5);
        let (commitments, shares) = dealer.reveal();
        let mut claimed = shares[&4];
        claimed += Scalar::ONE;
        let complaint = Complaint {
            accuser: 4,
            dealer_index: 0,
            received_share: claimed,
        };

        // Confronted, the dealer discloses the real share: it verifies against
        // the dealer's commitments but doesn't match the accuser's claim.
        let disclosed = dealer.share_for(4).unwrap();
        let verdict = resolve_complaint(&commitments, &complaint, &disclosed);
        assert_eq!(
            verdict,
            ComplaintVerdict::DisclosureIsValidButContradictsTheAccusersClaim
        );
        assert!(
            !verdict.is_faulty(),
            "an honest dealer must not be excludable on an unverifiable claim"
        );
        // ...and the disclosure is a usable repair: it verifies, so the
        // accuser can simply adopt it and the run continues.
        assert!(verify_share(&commitments, 4, &disclosed));
    }

    /// The attack the rule above closes: one participant fabricating
    /// complaints must not be able to exclude every honest dealer and decide
    /// the group key alone.
    #[test]
    fn a_lying_accuser_cannot_disqualify_a_single_honest_dealer_let_alone_all_of_them() {
        let dealers: Vec<Dealer> = (0..5).map(|_| Dealer::new(3, 5)).collect();
        let liar: ParticipantId = 2;

        for (index, dealer) in dealers.iter().enumerate() {
            let (commitments, _) = dealer.reveal();
            let complaint = Complaint {
                accuser: liar,
                dealer_index: index,
                // Pure fabrication: never anything this dealer dealt.
                received_share: Scalar::from(999_999u64),
            };
            let disclosed = dealer
                .share_for(liar)
                .expect("a real participant id always has a share");
            assert!(
                !resolve_complaint(&commitments, &complaint, &disclosed).is_faulty(),
                "dealer {index} was excluded on a fabricated complaint"
            );
        }
    }

    /// The dealer's secret lives at evaluation point 0, so answering a
    /// complaint naming participant 0 would publish it. The dealer must refuse,
    /// and the refusal must not count against it.
    #[test]
    fn a_complaint_naming_participant_zero_neither_discloses_a_secret_nor_blames_the_dealer() {
        let dealer = Dealer::new(3, 5);
        let (commitments, _) = dealer.reveal();

        assert_eq!(
            dealer.share_for(0),
            None,
            "evaluating the dealing polynomial at zero returns the secret, not a share"
        );
        assert_eq!(
            dealer.share_for(6),
            None,
            "no share was ever dealt to a participant outside the group"
        );

        let complaint = Complaint {
            accuser: 0,
            dealer_index: 0,
            received_share: Scalar::ZERO,
        };
        let verdict = resolve_complaint(&commitments, &complaint, &Scalar::ZERO);
        assert_eq!(verdict, ComplaintVerdict::MalformedComplaint);
        assert!(!verdict.is_faulty());
    }

    #[test]
    fn a_dealer_who_cannot_produce_any_share_matching_their_own_commitments_is_faulty() {
        // Two independent dealers simulate a disclosure that doesn't match the
        // broadcast commitments: dealer B's honest share against dealer A's
        // honest commitments. The API can't build an inconsistent `Dealer` (a
        // real one always deals shares matching its commitments), so the
        // mismatch has to come from outside.
        let dealer_a = Dealer::new(3, 5);
        let dealer_b = Dealer::new(3, 5);
        let (commitments_a, _) = dealer_a.reveal();
        let mismatched_disclosure = dealer_b.share_for(4).unwrap();

        let complaint = Complaint {
            accuser: 4,
            dealer_index: 0,
            received_share: mismatched_disclosure,
        };
        let verdict = resolve_complaint(&commitments_a, &complaint, &mismatched_disclosure);
        assert_eq!(verdict, ComplaintVerdict::DealerCannotProduceAValidShare);
        assert!(verdict.is_faulty());
    }

    /// End to end: per-accusation `Complaint`/`resolve_complaint` reaches the
    /// same exclusion as `identify_faulty_dealers` (the single-process batch
    /// path) for the same fault. Two ways to compute one outcome.
    #[test]
    fn complaint_resolution_agrees_with_the_batch_identify_faulty_dealers_path() {
        let (threshold, n) = (3, 5);
        let dealers: Vec<Dealer> = (0..n).map(|_| Dealer::new(threshold, n)).collect();

        let mut dealer_commitments: Vec<Vec<RistrettoPoint>> = Vec::new();
        let mut dealer_shares: Vec<BTreeMap<ParticipantId, Scalar>> = Vec::new();
        for d in &dealers {
            let (c, s) = d.reveal();
            dealer_commitments.push(c);
            dealer_shares.push(s);
        }

        // The fault must be decidable from public values on both paths: a dealing
        // inconsistent with the dealer's own broadcast commitments. A corrupted
        // delivered share would only be visible to the batch path, which gets the
        // dealer's real output; the complaint path sees only the accuser's
        // unverifiable claim and rightly doesn't blame the dealer (see
        // `a_disagreement_the_evidence_cannot_attribute_is_reported_without_blaming_the_dealer`).
        let faulty_dealer = 2usize;
        dealer_commitments[faulty_dealer][1] += RISTRETTO_BASEPOINT_POINT;

        let batch_excluded = identify_faulty_dealers(&dealer_commitments, &dealer_shares);
        assert_eq!(batch_excluded, vec![faulty_dealer]);

        // Participant 4 finds dealer 2's share invalid and complains; dealer 2
        // discloses; the verdict must match the batch path.
        let received = dealer_shares[faulty_dealer][&4];
        assert!(!verify_share(
            &dealer_commitments[faulty_dealer],
            4,
            &received
        ));
        let complaint = Complaint {
            accuser: 4,
            dealer_index: faulty_dealer,
            received_share: received,
        };
        let disclosed = dealers[faulty_dealer]
            .share_for(4)
            .expect("a real participant id always has a share");
        let verdict = resolve_complaint(&dealer_commitments[faulty_dealer], &complaint, &disclosed);
        assert_eq!(verdict, ComplaintVerdict::DealerCannotProduceAValidShare);
        assert!(verdict.is_faulty());
    }
}
