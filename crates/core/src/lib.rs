//! `novachannel`: a hybrid classical/post-quantum secure channel.
//!
//! A small building block, not a TLS replacement. It composes vetted
//! primitives (X25519, Ed25519, ML-KEM-1024, ML-DSA-87, ChaCha20-Poly1305,
//! HKDF-SHA256) and implements none itself. It deliberately omits a CA/PKI
//! (callers pin peer identities), version or ciphersuite negotiation (there
//! is one suite), and record compression or padding.
//!
//! # What it gives you
//! - **Mutual authentication** by a hybrid (Ed25519 + ML-DSA-87) signature
//!   over the full handshake transcript.
//! - **Forward secrecy** from ephemeral X25519 + ML-KEM-1024, discarded
//!   after one handshake.
//! - **Post-quantum confidentiality and authentication**, combined with the
//!   classical primitives so breaking one leg doesn't break the session.
//! - **An AEAD transport** (ChaCha20-Poly1305) with per-direction keys and
//!   an explicit, replay-checked sequence number, safe over unreliable or
//!   reordering transports.
//!
//! See [`handshake`] for the protocol and [`transport`] for the record
//! layer.
//!
//! # The 2024 standards, not the round-3 submissions
//! This crate once used `pqcrypto-kyber`/`pqcrypto-dilithium` (PQClean C
//! implementations of the round-3 submissions). It now uses RustCrypto's
//! pure-Rust `ml-kem`/`ml-dsa`, implementing FIPS 203 and FIPS 204 as
//! ratified in 2024. The wire format changed accordingly (see [`identity`]
//! and [`kex`]): a breaking change from earlier versions.
//!
//! # Example
//! `examples/echo.rs` runs a full client/server handshake and encrypted
//! exchange over TCP.

#![forbid(unsafe_code)]
// Each `.unwrap()` must become an `.expect("why it can't fail")` or is a
// bug (libsignal's `protocol`/`zkgroup` crates enforce the same lint).
// Allowed in tests, on values the test just built.
#![warn(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod erasure;
pub mod error;
pub mod group;
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
pub use group::{Commit, Group, GroupOp, LeafKeyPackage, MyLeafKeyPackage, Welcome};
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
