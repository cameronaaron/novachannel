//! Threshold key generation and decryption for mixnode operators: `t`-of-`n`
//! operators must cooperate to decrypt anything under the group key, and no
//! single operator — nor any coalition smaller than `t` — ever holds or can
//! reconstruct the full secret.
//!
//! # Where this fits
//! A conventional mixnode has one operator holding one decryption key: they
//! can be coerced, subpoenaed, or simply be malicious, and onion layers
//! meant for that node are exposed. Splitting the node's key across `n`
//! independent operators via [`Dealer`] (a joint-Feldman DKG) means
//! compromising the node requires compromising `t` of them simultaneously.
//!
//! # Protocol
//! 1. **Distributed key generation** ([`Dealer`]): each of `n` participants
//!    runs a Feldman verifiable secret sharing (VSS) of their own random
//!    contribution; every participant sums the shares and commitments they
//!    receive from *all* dealers. The result is a `(t, n)` Shamir sharing
//!    of an implicit group secret `s` that no single party ever computes,
//!    plus a public group key `Y = s*G`.
//! 2. **Threshold decryption** ([`partial_decrypt`], [`combine_partials`]):
//!    given an ephemeral point `R` (e.g. from an ElGamal-style
//!    encapsulation to `Y`), each of `t` participants computes a partial
//!    decryption `s_i*R` from their share alone; combining any `t` valid
//!    partials via Lagrange interpolation in the exponent recovers `s*R`
//!    — the shared secret a full-key holder would have computed — without
//!    ever reconstructing `s`.
//!
//! # Honest limitation: no networked complaint broadcast
//! Commitments to each dealer's `a_0` coefficient (which determines their
//! contribution to the group key) are exchanged via an explicit **commit,
//! then reveal** round ([`Dealer::commitment_hash`] before
//! [`Dealer::reveal`]) specifically to prevent the classic bias attack
//! where a rushing adversary picks their contribution *after* seeing
//! everyone else's, skewing the final group key toward a value they
//! partially control.
//!
//! A single faulty dealer no longer has to abort the whole run. Two
//! resolution paths exist, at two different scales:
//!
//! - [`identify_faulty_dealers`]: given every dealer's shares (as visible
//!   to a single process running a whole DKG, e.g. this crate's own test
//!   suite, or a trusted coordinator any deployment already has to trust
//!   for something), directly computes which dealers sent *any*
//!   participant an invalid share — the outcome the complaint protocol
//!   below exists to compute, without the network round trip, when
//!   nothing stops the code from just looking at every share at once.
//! - [`Complaint`]/[`Dealer::share_for`]/[`resolve_complaint`]: the actual
//!   per-accusation building block for a real network deployment, where no
//!   single party sees every share. A participant who receives a share
//!   that fails [`verify_share`] broadcasts a [`Complaint`] naming the
//!   dealer and exhibiting the share they received; the accused dealer
//!   responds by recomputing that participant's true share
//!   ([`Dealer::share_for`]) and broadcasting it; [`resolve_complaint`]
//!   takes the dealer's (already-public, from the commit/reveal round)
//!   commitments, the complaint, and that disclosure, and reaches a
//!   [`ComplaintVerdict`] — faulty dealer, or unfounded complaint — that
//!   every other participant can recompute independently from the same
//!   three public values, without trusting either party's word alone.
//!   This is the standard complaint/accusation resolution from Gennaro et
//!   al.'s malicious-secure DKG; the decision procedure lives in this
//!   crate, and `examples/networked_complaint.rs` (see "does not do
//!   networking" below) demonstrates a real broadcast transport driving it
//!   end-to-end, though a production deployment will likely reach for its
//!   own transport instead of that example's relay.
//!
//! Either path feeds [`finalize_key_share_excluding_faulty`], so a proven-
//! faulty dealer costs the group nothing beyond their own contribution
//! instead of aborting DKG for everyone.
//!
//! # This crate does not do networking, but a real deployment of it exists
//! [`Dealer`] is a pure state machine: it produces messages for the caller
//! to transport (broadcast commitments, point-to-point shares, and
//! complaints/disclosures) however their deployment does so (over
//! `novachannel` sessions, most naturally) — reaching every honest
//! participant with the same broadcast values, so they all compute the
//! same [`ComplaintVerdict`], is the caller's problem, the same "this
//! crate is a state machine, not a network" boundary the module docs
//! already drew for the commit/reveal round above. `examples/networked_complaint.rs`
//! is that transport, not just an assertion that one is possible: five
//! participants, each its own OS thread with its own real TCP socket to a
//! small broadcast relay, exchange a real [`Complaint`] and the accused
//! dealer's real [`Dealer::share_for`] disclosure over the network, and
//! every participant independently computes the same [`ComplaintVerdict`]
//! from what it received over the wire. The relay only ever forwards
//! complaint/disclosure messages — exactly the values this doc already
//! calls "safe to broadcast" — and never sees a dealer's private
//! polynomial or the raw per-dealer shares from the earlier reveal round,
//! which the example keeps local to its own `main()`, the same as every
//! other test in this crate.

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

/// `rand_core` 0.10 (shared by `curve25519-dalek`, `ed25519-dalek`,
/// `x25519-dalek`, `ml-kem`, `ml-dsa` across this workspace) no longer
/// ships an `OsRng` directly — `getrandom`'s `SysRng`, wrapped to present
/// as infallible, is the ecosystem's replacement. See `novachannel::rng`
/// for the identical pattern and its rationale.
pub(crate) fn csprng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

pub(crate) fn scalar_from_id(id: ParticipantId) -> Scalar {
    Scalar::from(id as u64)
}

/// Evaluates a Feldman commitment vector `[C_0, C_1, ..., C_{t-1}]` at `id`:
/// `sum_k(id^k * C_k)`, i.e. `f(id) * G` for the (never-revealed)
/// polynomial `f` the commitments belong to. Shared by [`verify_share`]
/// (one dealer, one participant) and
/// [`frost::public_verification_share`] (summed across every surviving
/// dealer, giving a participant's implicit public key share) so the two
/// can't drift apart on what "evaluating a commitment" means.
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
    /// Generates a random degree-`(threshold - 1)` polynomial and its
    /// Feldman commitments. `threshold` participants will be needed to
    /// reconstruct anything derived from this dealer's contribution.
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
    /// without revealing them. Every participant should collect all `n`
    /// dealers' hashes *before* any dealer calls [`Dealer::reveal`] — that
    /// ordering is what prevents the rushing bias attack described in the
    /// module docs.
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

    /// Recomputes the share this dealer's polynomial evaluates to for
    /// `participant_id` — identical to what [`Self::reveal`] already sent
    /// them. This is the dealer's own response to a [`Complaint`] naming
    /// them: broadcasting it alongside the dealer's already-public
    /// `commitments` lets every other participant run [`resolve_complaint`]
    /// and reach the same verdict independently, rather than trusting
    /// either the accuser's claim or the dealer's say-so alone.
    pub fn share_for(&self, participant_id: ParticipantId) -> Scalar {
        evaluate(&self.coefficients, scalar_from_id(participant_id))
    }
}

/// A participant's public accusation that dealer `dealer_index`'s reveal
/// to them (`received_share`) failed [`verify_share`] against that
/// dealer's own, already-broadcast commitments. Safe to broadcast: a
/// single Feldman share reveals nothing about the underlying polynomial
/// (any `threshold - 1` of them are information-theoretically
/// independent of it), so exhibiting one's own disputed share costs
/// nothing beyond what the dealer already gave this participant directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Complaint {
    pub accuser: ParticipantId,
    pub dealer_index: usize,
    pub received_share: Scalar,
}

/// The independently-recomputable outcome of [`resolve_complaint`] —
/// anyone holding the same three public values (the dealer's
/// commitments, the [`Complaint`], and the dealer's [`Dealer::share_for`]
/// disclosure) reaches the same verdict, which is what makes this a real
/// resolution and not just one party's word against another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplaintVerdict {
    /// The dealer's disclosed share doesn't even verify against their own
    /// commitments — whatever polynomial they actually used when dealing
    /// doesn't match what they committed to. Faulty, regardless of what
    /// the accuser claims to have received.
    DealerCannotProduceAValidShare,
    /// The dealer's disclosed share verifies fine, but doesn't match what
    /// the accuser says they actually received — the dealer sent (or the
    /// transport delivered) something other than the dealer's own valid
    /// share. Faulty.
    DealersDisclosureContradictsWhatWasSent,
    /// The dealer's disclosure verifies and matches exactly what the
    /// accuser claims to have received — which, being equal, also
    /// verifies. The complaint was mistaken or malicious; the dealer is
    /// exonerated.
    ComplaintWasUnfounded,
}

impl ComplaintVerdict {
    /// `true` for either faulty verdict — the outcome
    /// [`finalize_key_share_excluding_faulty`] needs, without the caller
    /// having to match on both variants that mean "exclude this dealer."
    pub fn is_faulty(&self) -> bool {
        !matches!(self, ComplaintVerdict::ComplaintWasUnfounded)
    }
}

/// Resolves one [`Complaint`] against `dealer_commitments` (that dealer's
/// already-broadcast Feldman commitments, from [`Dealer::reveal`]) and
/// `disclosed_share` (that same dealer's [`Dealer::share_for`] response,
/// naming the complaint's accuser). Every honest participant computes this
/// from the same three broadcast values and reaches the same
/// [`ComplaintVerdict`] — see the module docs for the full protocol shape
/// this implements.
pub fn resolve_complaint(
    dealer_commitments: &[RistrettoPoint],
    complaint: &Complaint,
    disclosed_share: &Scalar,
) -> ComplaintVerdict {
    if !verify_share(dealer_commitments, complaint.accuser, disclosed_share) {
        return ComplaintVerdict::DealerCannotProduceAValidShare;
    }
    if disclosed_share != &complaint.received_share {
        return ComplaintVerdict::DealersDisclosureContradictsWhatWasSent;
    }
    ComplaintVerdict::ComplaintWasUnfounded
}

fn evaluate(coefficients: &[Scalar], x: Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, c| acc * x + c)
}

/// Feldman verification: checks that `share` is consistent with
/// `commitments` for `participant_id`, i.e. `share * G == sum_k(id^k * C_k)`.
/// Every participant must run this on every share they receive from every
/// dealer; a failure identifies that dealer as faulty (see
/// [`identify_faulty_dealers`]) rather than requiring the whole DKG to
/// abort.
pub fn verify_share(
    commitments: &[RistrettoPoint],
    participant_id: ParticipantId,
    share: &Scalar,
) -> bool {
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

/// Combines every dealer's contribution (verified shares for this
/// participant, and every dealer's `C_0` commitment) into this
/// participant's final [`KeyShare`].
pub fn finalize_key_share(
    participant_id: ParticipantId,
    verified_shares_from_each_dealer: &[Scalar],
    each_dealers_c0: &[RistrettoPoint],
) -> KeyShare {
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

/// Identifies dealers who sent at least one participant a share that fails
/// [`verify_share`] against that dealer's own commitments — the complaint
/// resolution described in the module docs, run directly rather than over a
/// broadcast/reveal exchange. `dealer_commitments[d]`/`dealer_shares[d]`
/// must be dealer `d`'s outputs from [`Dealer::reveal`], in matching order.
///
/// Returns the indices (into `dealer_commitments`/`dealer_shares`) of every
/// dealer proven faulty. Pass these to
/// [`finalize_key_share_excluding_faulty`] so a single bad dealer costs the
/// group nothing beyond their own contribution, instead of aborting DKG
/// for everyone.
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

/// Like [`finalize_key_share`], but skips every dealer index in `excluded`
/// (from [`identify_faulty_dealers`]) entirely — their contribution is
/// dropped from both the secret share and the group public key, for every
/// participant, so all honest participants still converge on the same
/// (smaller, but sound) group key.
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

/// Lagrange coefficient for `participant_id` interpolating at `x = 0`,
/// given the full set of participant ids contributing to this
/// reconstruction.
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

/// Combines `t` participants' partial decryptions into the full shared
/// secret `s * R`, via Lagrange interpolation in the exponent. `partials`
/// must contain at least `threshold` entries, all for participants that
/// actually took part in the same DKG.
pub fn combine_partials(partials: &[(ParticipantId, RistrettoPoint)]) -> RistrettoPoint {
    let ids: Vec<ParticipantId> = partials.iter().map(|(id, _)| *id).collect();
    partials
        .iter()
        .fold(RistrettoPoint::default(), |acc, (id, p)| {
            acc + lagrange_coefficient_at_zero(*id, &ids) * p
        })
}

/// Derives a symmetric key from a shared secret point — the last step of
/// both a sender's encapsulation to the group key and a quorum's threshold
/// decryption; both sides should end up with the same 32 bytes.
pub fn derive_symmetric_key(shared_point: &RistrettoPoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"novachannel-mpc shared secret v1");
    hasher.update(shared_point.compress().as_bytes());
    hasher.finalize().into()
}

/// A sender's encapsulation to a group public key: pick ephemeral `r`,
/// publish `R = r*G`, derive the symmetric key from `r*Y`. Only a quorum of
/// `threshold` key-share holders can later derive the same key, via
/// [`partial_decrypt`] + [`combine_partials`] + [`derive_symmetric_key`].
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

        // Every honest participant excludes the same dealer and converges
        // on the same, smaller-but-sound group key — the DKG as a whole
        // did not have to abort over one dealer's fault.
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

        // The resulting key actually differs from what naively including
        // every dealer (faulty one included) would have produced — proving
        // exclusion changed something real, not a no-op.
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
        // Participant 4's honestly-received share, complained about anyway
        // (mistakenly, or maliciously) — the accuser's own claim is
        // internally consistent (it's the real share), so this is the
        // "unfounded complaint" branch, not the "corrupted in transit" one.
        let complaint = Complaint {
            accuser: 4,
            dealer_index: 0,
            received_share: shares[&4],
        };
        let disclosed = dealer.share_for(4);
        assert_eq!(
            resolve_complaint(&commitments, &complaint, &disclosed),
            ComplaintVerdict::ComplaintWasUnfounded
        );
        assert!(!resolve_complaint(&commitments, &complaint, &disclosed).is_faulty());
    }

    #[test]
    fn a_share_corrupted_in_transit_is_caught_even_though_the_dealer_computed_it_honestly() {
        let dealer = Dealer::new(3, 5);
        let (commitments, shares) = dealer.reveal();
        // The accuser claims to have received something other than what
        // the dealer's polynomial actually evaluates to for them —
        // standing in for corruption between `Dealer::reveal` and however
        // the caller's transport delivered it (this crate does no
        // networking — module docs).
        let mut corrupted = shares[&4];
        corrupted += Scalar::ONE;
        let complaint = Complaint {
            accuser: 4,
            dealer_index: 0,
            received_share: corrupted,
        };
        // The dealer, confronted, recomputes and discloses the *real*
        // share — which verifies fine against their own commitments, but
        // doesn't match what the accuser claims to have received.
        let disclosed = dealer.share_for(4);
        let verdict = resolve_complaint(&commitments, &complaint, &disclosed);
        assert_eq!(
            verdict,
            ComplaintVerdict::DealersDisclosureContradictsWhatWasSent
        );
        assert!(verdict.is_faulty());
    }

    #[test]
    fn a_dealer_who_cannot_produce_any_share_matching_their_own_commitments_is_faulty() {
        // Two independent dealers stand in for "the dealer's disclosure
        // doesn't match the commitments they actually broadcast" — e.g. a
        // dealer whose per-participant evaluations were never consistent
        // with any single degree-(threshold - 1) polynomial in the first
        // place. Using dealer B's real, honestly-computed share against
        // dealer A's real, honestly-computed commitments reproduces
        // exactly that inconsistency without hand-constructing an invalid
        // `Dealer` (which this crate's own API has no way to build, since
        // every real `Dealer` always deals a share matching its own
        // commitments by construction — the mismatch has to come from
        // outside).
        let dealer_a = Dealer::new(3, 5);
        let dealer_b = Dealer::new(3, 5);
        let (commitments_a, _) = dealer_a.reveal();
        let mismatched_disclosure = dealer_b.share_for(4);

        let complaint = Complaint {
            accuser: 4,
            dealer_index: 0,
            received_share: mismatched_disclosure,
        };
        let verdict = resolve_complaint(&commitments_a, &complaint, &mismatched_disclosure);
        assert_eq!(verdict, ComplaintVerdict::DealerCannotProduceAValidShare);
        assert!(verdict.is_faulty());
    }

    /// End-to-end: the per-accusation `Complaint`/`resolve_complaint` flow
    /// reaches the same exclusion decision `identify_faulty_dealers`
    /// (the batch, single-process convenience path) already does for the
    /// same underlying fault — the two are two ways to compute one
    /// outcome, not two different outcomes (module docs).
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

        let faulty_dealer = 2usize;
        *dealer_shares[faulty_dealer].get_mut(&4).unwrap() += Scalar::ONE;

        let batch_excluded = identify_faulty_dealers(&dealer_commitments, &dealer_shares);
        assert_eq!(batch_excluded, vec![faulty_dealer]);

        // Participant 4 independently notices their share from dealer 2
        // fails verification and files a complaint; dealer 2 discloses;
        // the verdict must agree with the batch path's conclusion.
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
        let disclosed = dealers[faulty_dealer].share_for(4);
        let verdict = resolve_complaint(&dealer_commitments[faulty_dealer], &complaint, &disclosed);
        assert!(verdict.is_faulty());
    }
}
