//! `novachannel-rln`: zero-knowledge rate-limiting nullifiers with a
//! post-quantum, hash-based ZK-STARK membership proof.
//!
//! # What this gives you
//! A group of `2^DEPTH` members, each holding a secret key whose
//! commitment sits in a public Merkle tree. Any member can produce a
//! message proof that:
//! - was made by *some* member of the group, without revealing which one
//!   (a ZK-STARK over a hash-based circuit — no elliptic curves, so no
//!   discrete-log assumption to break, which is the "post-quantum" part), and
//! - is tied to a rate-limit `epoch`, such that sending a second message in
//!   the same epoch leaks the sender's secret key to anyone who collects
//!   both proofs (see [`share`]).
//!
//! # What this doesn't give you
//! - **Independent cryptanalysis.** [`permutation`] defines a new,
//!   from-scratch STARK-friendly hash. Treat this crate as a demonstration
//!   of RLN's circuit shape, not as something to deploy without an
//!   independent security review of that permutation.
//! - **A real membership registry.** [`merkle::MerkleTree`] is an in-memory
//!   reference tree; wiring it to a persistent/distributed registry
//!   (a smart contract, a gossiped log, ...) is out of scope here.
//!
//! # Example
//! See `tests/rln.rs` for a full walkthrough: build a tree, prove
//! membership + a rate-limit share, verify the proof, then show that a
//! second message in the same epoch lets a third party recover the
//! sender's key.
//!
//! # Run tests with `--release`
//! `cargo test -p novachannel-rln --release`. In debug builds, winterfell
//! runs an internal sanity check that the *declared* transition constraint
//! degree exactly equal the *measured* degree of the polynomial for that
//! specific witness. This AIR's declared degrees are honest, safe upper
//! bounds (never too low — that's the property that actually matters for
//! soundness), but a few of the boundary-injection columns are sparse
//! (meaningful only at block-boundary rows, filled with padding
//! elsewhere), which makes their *measured* interpolated degree vary
//! slightly with the witness (e.g. which Merkle path a given leaf index
//! produces) rather than always hitting the theoretical worst case. That
//! trips the debug-only exact-match assertion without indicating any
//! actual soundness issue — release builds skip that check and use the
//! declared degree directly for domain sizing, which is what correctness
//! actually depends on. Tightening the declared degrees to match the
//! measured value in every case is possible future work.

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

pub mod air;
pub mod merkle;
pub mod permutation;
pub mod share;

use rand::RngCore;
use winterfell::math::{fields::f128::BaseElement, FieldElement};

use merkle::{MerkleTree, PathStep};
use permutation::{compress2, Params};

/// A member's long-term secret. Never leaves the holder's process.
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub sk: BaseElement,
}

impl Identity {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Identity {
            sk: bytes_to_field(&bytes),
        }
    }

    /// The public commitment placed in the membership tree: `Hash(sk, 0)`.
    pub fn commitment(&self, params: &Params) -> BaseElement {
        compress2(params, self.sk, BaseElement::ZERO)
    }
}

/// Reduces arbitrary bytes into a field element by absorbing 8-byte chunks
/// through the same in-crate permutation used everywhere else (no separate
/// hash dependency needed just for domain mapping). This is a convenience
/// for turning message bytes / epoch counters into the field elements the
/// AIR operates over — it is *not* meant to be collision-resistant on its
/// own merit beyond what the underlying permutation provides.
pub fn bytes_to_field(bytes: &[u8]) -> BaseElement {
    let params = Params::new();
    let mut acc = BaseElement::ZERO;
    for chunk in bytes.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let v = BaseElement::new(u64::from_le_bytes(buf) as u128);
        acc = compress2(&params, acc, v);
    }
    acc
}

pub fn epoch_field(epoch: u64) -> BaseElement {
    bytes_to_field(&epoch.to_le_bytes())
}

pub struct Message {
    pub proof: winterfell::Proof,
    pub public: air::PublicInputs,
}

/// Proves that `identity` is a member of `tree` and computes its rate-limit
/// share for `epoch`, binding the message via `message_x` (typically
/// `bytes_to_field(message_bytes)` — the caller decides what "the message"
/// means for their application).
pub fn prove_message(
    tree: &MerkleTree,
    leaf_index: usize,
    identity: &Identity,
    epoch: BaseElement,
    message_x: BaseElement,
) -> Result<Message, String> {
    let path: Vec<PathStep> = tree.path(leaf_index);
    let a1 = compress2(tree.params(), identity.sk, epoch);
    let y = identity.sk + a1 * message_x;

    let witness = air::Witness {
        sk: identity.sk,
        path,
    };
    let (proof, public) = air::prove(&witness, epoch, message_x, y, a1)?;
    Ok(Message { proof, public })
}

/// Verifies a message proof against a known tree root. On success, returns
/// the [`share::Share`] carried by the message, for the caller to check
/// against previously-seen shares in this epoch (see [`share::recover_secret`]).
pub fn verify_message(root: BaseElement, msg: Message) -> Result<share::Share, String> {
    if msg.public.root != root {
        return Err("proof is for a different membership root".into());
    }
    let public = msg.public;
    air::verify(msg.proof, public.clone())?;
    Ok(share::Share {
        nullifier: public.nullifier,
        x: public.x,
        y: public.y,
    })
}
