//! `novachannel`: a hybrid classical/post-quantum secure channel.
//!
//! This crate is a small, from-first-principles building block — not a
//! drop-in TLS replacement. It composes vetted primitives (X25519,
//! Ed25519, ML-KEM-768, ML-DSA-65, ChaCha20-Poly1305, HKDF-SHA256) rather
//! than implementing any cryptographic primitive itself, and it
//! deliberately leaves out things a general-purpose transport protocol
//! needs and this does not attempt: certificate authorities / PKI (peer
//! identities are pinned by the caller), version/ciphersuite negotiation
//! (there is exactly one suite), and record compression or padding.
//!
//! # What it gives you
//! - **Mutual authentication** via a hybrid (Ed25519 + ML-DSA-65)
//!   signature over the full handshake transcript.
//! - **Forward secrecy** via ephemeral X25519 + ML-KEM-768, discarded after
//!   one handshake.
//! - **Post-quantum confidentiality and authentication**, composed with
//!   the classical primitives so that breaking only one leg (classical or
//!   post-quantum) does not break the session.
//! - **An AEAD transport** (ChaCha20-Poly1305) with per-direction keys and
//!   a replay-checked, explicit sequence number, safe to run over an
//!   unreliable/reordering transport.
//!
//! See [`handshake`] for the protocol description and [`transport`] for
//! the record layer.
//!
//! # 2024 PQC standard, not the round-3 submissions
//! This crate originally used `pqcrypto-kyber`/`pqcrypto-dilithium` — C
//! (PQClean) implementations of the pre-standardization NIST round-3
//! submissions. It now uses RustCrypto's `ml-kem`/`ml-dsa`: pure Rust, and
//! implementing the algorithms NIST actually ratified as FIPS 203 (ML-KEM)
//! and FIPS 204 (ML-DSA) in 2024 — not an earlier draft of them. The wire
//! format changed accordingly (see [`identity`] and [`kex`]); this is a
//! breaking change from any earlier version of this crate, not a
//! transparent upgrade.
//!
//! # Example
//! See `examples/echo.rs` for a full client/server handshake and
//! encrypted exchange over TCP.

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

mod erasure;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod kex;
pub mod multidevice;
pub mod prekey;
pub mod ratchet;
mod rng;
pub mod sealed_sender;
pub mod transport;
mod wire;
pub mod x3dh;

pub use error::{Error, Result};
pub use handshake::{
    initiator_start, responder_respond, EstablishedSession, InitiatorHandshakeState, PeerInfo,
    ResponderHandshakeState,
};
pub use identity::{HybridSignature, Identity, PublicIdentity};
pub use multidevice::{
    DeviceId, DeviceListEntry, MultiDeviceSession, ReceivingDevice, RemoteAccount, SignedDeviceList,
};
pub use prekey::{
    DhIdentity, OneTimePreKey, OneTimePreKeyStore, PreKeyBundle, SealingPublicKey, SignedPreKey,
};
pub use ratchet::{ChunkOutcome, ChunkProgress, Opened, RatchetedSession};
pub use sealed_sender::{SealedEnvelope, SenderCertificate, UnsealedMessage};
pub use transport::{Receiver, Sender};
pub use x3dh::{initiate, respond, InitMessage, InitiatedSession, RespondedSession};
