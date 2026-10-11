//! `novachannel-rln`: zero-knowledge rate-limiting nullifiers with a
//! post-quantum, hash-based ZK-STARK membership proof.
//!
//! # What this gives you
//! A group of `2^depth` members (any `depth` for which
//! [`air::is_valid_depth`] holds; [`air::DEPTH`] is the default), each
//! holding a secret key whose commitment sits in a public Merkle tree. Any
//! member can produce a message proof that:
//! - was made by *some* member, without revealing which (a STARK over a
//!   hash-based circuit: no discrete-log assumption, hence post-quantum), and
//! - is tied to a rate-limit `epoch`, so a second message in the same epoch
//!   leaks the sender's secret key to anyone holding both proofs (see
//!   [`share`]).
//!
//! # What this doesn't give you
//! - **Independent review of this port.** [`permutation`] is a hand-port of
//!   `p3-goldilocks`/`p3-poseidon2`'s Poseidon2-over-Goldilocks (the hash
//!   behind several audited production STARK provers) and matches that
//!   reference's test vector byte-for-byte. A transcription error elsewhere in
//!   the port is still a risk the vector doesn't rule out. Treat this crate as
//!   a demonstration of RLN's circuit shape, not something to deploy without
//!   an independent review.
//! - **A real membership registry.** [`merkle::MerkleTree`] is an in-memory
//!   reference tree; a persistent or distributed registry is out of scope.
//! - **A verifier safe to run in-process on hostile input.** A malformed
//!   proof can abort the process through an unbounded allocation in
//!   `winterfell`'s query parser, which nothing in this crate can contain and
//!   which has no fixed upstream release. Stated at [`air::verify`] and
//!   pinned by a test; isolate that call if a hostile sender must not be able
//!   to kill your process.
//!
//! # Example
//! `tests/rln.rs` walks through it: build a tree, prove membership and a
//! rate-limit share, verify, then recover the key from a second message in
//! the same epoch.
//!
//! # Run tests with `--release`
//! `cargo test -p novachannel-rln --release`. Debug builds of winterfell
//! assert that each declared constraint degree equals the degree measured on
//! the witness. Ours are upper bounds (what soundness needs), but sparse
//! boundary-injection columns measure lower on some witnesses, so that
//! debug-only check fails. Release builds size domains from the declared
//! degree. Tightening the declarations to always match is possible future
//! work.

#![forbid(unsafe_code)]
// Each `.unwrap()` must become an `.expect("why it can't fail")` or is a
// bug (libsignal's `protocol`/`zkgroup` crates enforce the same lint).
// Allowed in tests, on values the test just built.
#![warn(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod air;
pub mod merkle;
pub mod permutation;
pub mod share;

use rand::Rng;
use winterfell::math::{fields::f64::BaseElement, FieldElement};

use merkle::{MerkleTree, PathStep};
use permutation::{compress2, Params};

/// A member's long-term secret. Never leaves the holder's process.
///
/// No `Debug` impl: unlike [`share::Share`] (hiding by construction), a bare
/// `sk` is the secret itself. Not `Copy`, which would conflict with `Drop`
/// and let the secret spread through implicit copies; the `Drop` impl below
/// best-effort-clears it, as `novachannel::identity::Identity` does.
#[derive(Clone)]
pub struct Identity {
    pub sk: BaseElement,
}

impl Identity {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Identity {
            sk: bytes_to_field(&bytes),
        }
    }

    /// The public commitment placed in the membership tree: `Hash(sk, 0)`.
    pub fn commitment(&self, params: &Params) -> BaseElement {
        compress2(params, self.sk, BaseElement::ZERO)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.sk = BaseElement::ZERO;
    }
}

/// Bytes packed per field element by [`bytes_to_field`]. Seven, not eight:
/// any 7-byte value is below the Goldilocks modulus `2^64 - 2^32 + 1`, so
/// the packing is injective. Eight bytes was not; see [`bytes_to_field`].
pub const BYTES_PER_ELEMENT: usize = 7;

/// Absorbs bytes into a field element with this crate's permutation. This
/// is how message bytes and epochs enter the AIR, including the
/// message-binding `x` of a [`share::Share`], so collision resistance here
/// is security-critical.
///
/// # Two collision classes this used to have
/// The old construction absorbed zero-padded 8-byte chunks seeded from
/// `ZERO`, which collided without any cryptanalysis:
///
/// - **No length separation.** Padding was indistinguishable from trailing
///   zero bytes: `b"a"` and `b"a\0"` absorbed identically.
/// - **Non-injective packing.** A chunk read as a `u64` reduced mod `p`, so
///   `v` and `v + p` collided (`2^32 - 1` such pairs, e.g. `0` and
///   `0xFFFFFFFF00000001`).
///
/// Either breaks the rate limit. A key is only recoverable from two shares on
/// one nullifier with *different* `x`; colliding messages give identical
/// shares, from which [`share::recover_secret`] learns nothing. A member
/// could send a second message per epoch by appending a zero byte.
///
/// Now the byte length is absorbed first and [`BYTES_PER_ELEMENT`] bytes are
/// packed per element, so the input-to-elements map is injective and
/// collision resistance rests on the permutation alone. This changed every
/// output: nullifiers, `x` values and identity commitments differ from
/// earlier versions (a breaking proof-format change).
pub fn bytes_to_field(bytes: &[u8]) -> BaseElement {
    let params = Params::new();
    // Seeding with the length separates `b"a"` from `b"a\0"`: the absorbed
    // sequences differ in their first element.
    let mut acc = BaseElement::new(bytes.len() as u64);
    for chunk in bytes.chunks(BYTES_PER_ELEMENT) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let v = BaseElement::new(u64::from_le_bytes(buf));
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

impl Message {
    /// Parses `proof_bytes` from an untrusted peer into a [`Message`] paired
    /// with `public`, catching panics instead of crashing the caller.
    ///
    /// Callers have to deserialize proofs before [`verify_message`], and this
    /// crate's fuzz target (`crates/core/fuzz/fuzz_targets/rln_verify.rs`)
    /// found a 4-byte input (`[0xdd, 0x00, 0x03, 0xdd]`) that makes winterfell
    /// 0.13.1's `Proof::from_bytes` panic ("attempt to exponentiate with
    /// overflow") on an attacker-controlled trace-length exponent, before any
    /// verification runs. It reproduces under this workspace's
    /// `overflow-checks = true` release profile, so it is a remote DoS for code
    /// that parses proofs directly. The bug is upstream; parse through here
    /// instead of calling `winterfell::Proof::from_bytes`.
    pub fn from_proof_bytes(proof_bytes: &[u8], public: air::PublicInputs) -> Result<Self, String> {
        let parsed = std::panic::catch_unwind(|| winterfell::Proof::from_bytes(proof_bytes))
            .map_err(|_| "malformed proof bytes: parser panicked".to_string())?;
        let proof = parsed.map_err(|e| e.to_string())?;
        Ok(Message { proof, public })
    }
}

/// Proves `identity` is a member of `tree` and computes its rate-limit share
/// for `epoch`, binding the message via `message_x` (typically
/// `bytes_to_field(message_bytes)`; the caller defines "the message").
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

/// Verifies a message proof against a known tree root. Returns the
/// [`share::Share`] it carries, to check against shares already seen this
/// epoch (see [`share::recover_secret`]).
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
