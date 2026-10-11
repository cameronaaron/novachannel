//! An opt-in ratchet layered on [`crate::handshake`] and
//! [`crate::transport`], seeded from
//! [`crate::handshake::EstablishedSession::ratchet_root`]. It adds two
//! properties the plain session lacks:
//!
//! - **Per-message forward secrecy.** Each record is sealed under a fresh
//!   single-use AEAD key from a one-way hash chain (`ChainKey::advance`,
//!   HMAC-SHA256) and discarded after use. The chain's current state
//!   doesn't recover past message keys, unlike the plain transport's one
//!   static key per session.
//! - **Post-compromise security.** Either party can call
//!   [`RatchetedSession::initiate_ratchet`] to mix a fresh hybrid X25519 +
//!   ML-KEM-1024 exchange ([`crate::kex`]) into an HKDF root key, moving to
//!   a new epoch with fresh chains. A compromised session regains
//!   confidentiality once a step completes on both sides.
//!
//! # Scope relative to Signal's production ratchet
//! Signal's Double Ratchet now uses
//! [`signalapp/SparsePostQuantumRatchet`](https://github.com/signalapp/SparsePostQuantumRatchet)
//! ("SPQR"). Its source (`src/v1/unchunked/send_ek.rs` and others) shows
//! the step is not a plain ML-KEM exchange but an **incremental**
//! re-encoding of ML-KEM-768 (`incremental_mlkem768`) that splits the
//! ~1.1KB key and ~1KB ciphertext into `header`/`ek`/`ct1`/`ct2` pieces
//! sent over several round trips by a `KeysUnsampled -> HeaderSent ->
//! EkSent -> EkSentCt1Received` state machine (with Reed-Solomon erasure
//! coding in `src/v1/chunked/`), so no message carries a full KEM payload.
//! It is machine-verified: `hax_lib` refinement types checked with F*, plus
//! ProVerif models.
//!
//! This module's default is a **synchronous one-shot** hybrid re-key
//! ([`RatchetedSession::initiate_ratchet`]): a full X25519 key and ML-KEM-1024
//! encapsulation key in one message, a full ciphertext in the reply, the
//! same shapes [`crate::kex`] uses in the handshake. The alternative,
//! [`RatchetedSession::initiate_incremental_ratchet`], splits that material
//! into small chunks plus parity chunks (`crate::erasure`, on
//! `reed_solomon_simd`) so the exchange survives losing some. That is
//! closer in shape to SPQR's chunked, loss-tolerant design, but much
//! smaller:
//!
//! - **Chunked and erasure-coded, not re-encoded.** SPQR re-encodes
//!   ML-KEM-768's internal structure, so each piece means something to the
//!   algorithm. This splits the ordinary serialized ML-KEM-768 key and
//!   ciphertext bytes from [`crate::kex`] into interchangeable shards. Loss
//!   tolerance is real; SPQR's per-chunk size savings are not reproduced.
//! - **Caller-chosen `(data_shards, parity_shards)`**, trading chunk size
//!   against loss tolerance for the caller's transport.
//! - **A checksum over the reconstructed payload**, checked before use
//!   (`ENGINEERING-STANDARDS.md` §6.4, assert properties). Forgery is
//!   already excluded (each chunk is an AEAD-sealed ratchet record), but a
//!   bad reconstruction from the wrong shards is caught instead of feeding
//!   a wrong KEX result into the next epoch.
//! - **No formal verification of the erasure-coding use.** Coding is
//!   `reed_solomon_simd`'s; framing and reassembly are this workspace's own
//!   (see `crate::erasure`).
//!
//! Chunks of one step may arrive in any order (only which `data_shards`
//! arrive matters); ordering relative to other records is covered below.
//!
//! Both variants share these constraints:
//!
//! - **Out-of-order and lost application records are tolerated, within a
//!   bound.** Like real Double Ratchet implementations, each `RecvChain`
//!   caches message keys skipped while catching up: a `seq` ahead of
//!   `expected_seq` derives and stores the keys in between (never
//!   rewinding the one-way chain) instead of rejecting, and a late arrival
//!   for a skipped `seq` decrypts from the cache instead of `Error::Replay`.
//!   At most [`MAX_SKIPPED_KEYS`] per chain, so an injected far-future
//!   `seq` can't force unbounded memory; exceeding it is
//!   [`Error::TooManySkippedKeys`], not silent truncation. A cached key is
//!   deleted when looked up, whether or not decryption succeeds, so a true
//!   replay of that `seq` fails. This covers [`RatchetedSession::seal`] /
//!   [`RatchetedSession::open`] records; incremental-ratchet chunks have
//!   their own reordering tolerance (above).
//! - **Ratchet initiation must not race.** If both sides call
//!   [`RatchetedSession::initiate_ratchet`] before seeing the other's step,
//!   it fails with [`Error::RatchetInProgress`] rather than diverging.
//!   Callers needing concurrent initiation must coordinate (e.g. only the
//!   handshake initiator ratchets) or retry on error.
//! - **No formal verification of this module.** SPQR is hax/F*-checked with
//!   ProVerif models. `crates/core/formal/proverif` has executed ProVerif
//!   models of `crate::handshake` and `crate::x3dh` but not of this
//!   ratchet-step protocol, and nothing here has hax/F* verification; that
//!   directory's README says what is covered and why hax/F* remains out of
//!   reach. This module has the workspace's usual adversarial tests
//!   (`ENGINEERING-STANDARDS.md`) and nothing more.
//!
//! The result is real forward secrecy and hybrid PQ post-compromise
//! security from a much smaller, fully understood mechanism, not a
//! reimplementation of SPQR.

use std::cmp::Ordering;
use std::collections::HashMap;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use kem::KeyExport;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::handshake::EstablishedSession;
use crate::kex::{self, InitiatorKex};
use crate::wire::{Reader, Writer};

type HmacSha256 = Hmac<Sha256>;

/// `(chunks received, data_shards needed)` for an in-progress incremental
/// reconstruction, or `None`. See
/// [`RatchetedSession::incremental_ratchet_progress`].
pub type ChunkProgress = Option<(usize, usize)>;

/// The most message keys one `RecvChain` caches for out-of-order delivery
/// (see module docs). 1000 is the order of magnitude Signal's
/// `libsignal-protocol` uses (`MAX_FORWARD_JUMPS` / skipped-key caps).
pub const MAX_SKIPPED_KEYS: u64 = 1000;

const MSG_APPLICATION: u8 = 0;
const MSG_RATCHET_STEP1: u8 = 1;
const MSG_RATCHET_STEP2: u8 = 2;
const MSG_RATCHET_STEP1_CHUNK: u8 = 3;
const MSG_RATCHET_STEP2_CHUNK: u8 = 4;

const LABEL_MESSAGE_KEY: &[u8] = &[0x01];
const LABEL_NEXT_CHAIN: &[u8] = &[0x02];

const LABEL_INIT_SEND: &[u8] = b"novachannel ratchet v1 epoch0 initiator->responder";
const LABEL_INIT_RECV: &[u8] = b"novachannel ratchet v1 epoch0 responder->initiator";
const LABEL_STEP_ROOT: &[u8] = b"novachannel ratchet v1 step root";
const LABEL_STEP_I2R: &[u8] = b"novachannel ratchet v1 step initiator->responder";
const LABEL_STEP_R2I: &[u8] = b"novachannel ratchet v1 step responder->initiator";

/// One position in a one-way hash chain: `advance` consumes `self` and
/// yields the next state and a one-time message key, so a compromised chain
/// key walks forward, never backward.
#[derive(Clone)]
struct ChainKey([u8; 32]);

impl Drop for ChainKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ChainKey {
    fn advance(&self) -> (ChainKey, [u8; 32]) {
        (
            ChainKey(hmac32(&self.0, LABEL_NEXT_CHAIN)),
            hmac32(&self.0, LABEL_MESSAGE_KEY),
        )
    }
}

fn hmac32(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

/// Seals `plaintext` (including the leading message-type byte) under a
/// single-use key with an all-zero nonce. AEAD needs each (key, nonce) pair
/// unique, which a never-reused key guarantees whatever the nonce.
fn seal_with_message_key(message_key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, Payload},
        ChaCha20Poly1305, Key, KeyInit, Nonce,
    };
    let cipher = ChaCha20Poly1305::new(&Key::from(*message_key));
    cipher
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn open_with_message_key(message_key: &[u8; 32], aad: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, Payload},
        ChaCha20Poly1305, Key, KeyInit, Nonce,
    };
    let cipher = ChaCha20Poly1305::new(&Key::from(*message_key));
    cipher
        .decrypt(&Nonce::from([0u8; 12]), Payload { msg: record, aad })
        .map_err(|_| Error::Decrypt)
}

/// One receive chain: its epoch, the next expected sequence number, and
/// cached keys for skipped lower sequence numbers (see module docs).
struct RecvChain {
    epoch: u32,
    chain: ChainKey,
    expected_seq: u64,
    skipped: HashMap<u64, [u8; 32]>,
}

impl Drop for RecvChain {
    fn drop(&mut self) {
        for key in self.skipped.values_mut() {
            key.zeroize();
        }
    }
}

/// A [`crate::handshake::EstablishedSession`] with per-message forward
/// secrecy and an explicit, coordinated hybrid-PQ ratchet step. The module
/// docs compare it with Signal's SPQR.
pub struct RatchetedSession {
    root_key: [u8; 32],
    send_epoch: u32,
    send_chain: ChainKey,
    send_seq: u64,
    recv_current: RecvChain,
    recv_previous: Option<RecvChain>,
    pending: Option<InitiatorKex>,
    pending_epoch: u32,
    /// Reconstruction of the peer's incremental step-1 chunks (this side is
    /// responding), or `None`.
    incoming_step1_chunks: Option<ChunkAccumulator>,
    /// Reconstruction of the peer's incremental step-2 reply chunks (this side
    /// initiated and is waiting), or `None`.
    incoming_step2_chunks: Option<ChunkAccumulator>,
    /// `attempt_nonce` of the last *completed* step-1 reconstruction. Chunks
    /// may be lost or reordered, so stragglers from a finished attempt can
    /// arrive after `root_key` has moved on. Recognizing them lets
    /// [`Self::open_ratchet_chunk`] ignore them rather than fail to decrypt
    /// with the new key.
    last_completed_step1_attempt: Option<[u8; 32]>,
    /// The step-2 counterpart of `last_completed_step1_attempt`.
    last_completed_step2_attempt: Option<[u8; 32]>,
}

/// Accumulates erasure-coded chunks for one incremental ratchet step, in
/// either direction (only the holding field of [`RatchetedSession`]
/// differs).
struct ChunkAccumulator {
    attempt_nonce: [u8; 32],
    data_shards: usize,
    parity_shards: usize,
    original_len: usize,
    checksum: [u8; 8],
    shards: Vec<Option<Vec<u8>>>,
}

impl ChunkAccumulator {
    fn received_count(&self) -> usize {
        self.shards.iter().filter(|s| s.is_some()).count()
    }
}

fn truncated_checksum(data: &[u8]) -> [u8; 8] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

const LABEL_CHUNK_KEY_STEP1: &[u8] = b"novachannel ratchet v1 incremental chunk key step1";
const LABEL_CHUNK_KEY_STEP2: &[u8] = b"novachannel ratchet v1 incremental chunk key step2";

/// Derives the AEAD key for one incremental-ratchet attempt (shared by that
/// direction's chunks) from the current `root_key`, which both sides agree
/// on, mixed with a fresh random `attempt_nonce`. Each attempt, retries
/// included, therefore gets an independent, effectively single-use key,
/// which makes the fixed shard-index nonce ([`chunk_nonce`]) safe.
fn derive_chunk_key(
    root_key: &[u8; 32],
    attempt_nonce: &[u8; 32],
    label: &[u8],
) -> Result<[u8; 32]> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(root_key.as_slice()), attempt_nonce);
    let hk = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| Error::Malformed("HKDF PRK too short"))?;
    let mut key = [0u8; 32];
    hk.expand(label, &mut key)
        .map_err(|_| Error::Malformed("HKDF expand failed"))?;
    Ok(key)
}

/// `shard_index` as the low byte of an otherwise zero nonce. Safe because
/// each `chunk_key` covers one attempt ([`derive_chunk_key`]) and each shard
/// is sealed once ([`build_chunk_records`]).
fn chunk_nonce(shard_index: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[11] = shard_index;
    nonce
}

fn seal_chunk(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, Payload},
        ChaCha20Poly1305, Key, KeyInit, Nonce,
    };
    ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn open_chunk(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, Payload},
        ChaCha20Poly1305, Key, KeyInit, Nonce,
    };
    ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&Nonce::from(*nonce), Payload { msg: record, aad })
        .map_err(|_| Error::Decrypt)
}

/// An incremental-ratchet chunk's header, parsed before decryption:
/// `attempt_nonce` and `msg_type` (direction) are needed to derive the key,
/// so they can't be encrypted.
struct ChunkHeader {
    msg_type: u8,
    attempt_nonce: [u8; 32],
    shard_index: u8,
    data_shards: u8,
    parity_shards: u8,
    original_len: u32,
    checksum: [u8; 8],
    header_len: usize,
}

fn parse_chunk_header(bytes: &[u8]) -> Result<(ChunkHeader, &[u8])> {
    let mut r = Reader::new(bytes);
    let msg_type = r.get_fixed(1)?[0];
    let attempt_nonce: [u8; 32] = r
        .get_fixed(32)?
        .try_into()
        .expect("get_fixed(32) already guarantees the length");
    let counts = r.get_fixed(3)?;
    let (shard_index, data_shards, parity_shards) = (counts[0], counts[1], counts[2]);
    let original_len = u32::from_be_bytes(
        r.get_fixed(4)?
            .try_into()
            .expect("get_fixed(4) already guarantees the length"),
    );
    let checksum: [u8; 8] = r
        .get_fixed(8)?
        .try_into()
        .expect("get_fixed(8) already guarantees the length");
    let header_len = r.consumed();
    let ciphertext = r.get_var()?;
    if !r.finished() {
        return Err(Error::Malformed("trailing bytes in ratchet chunk"));
    }
    Ok((
        ChunkHeader {
            msg_type,
            attempt_nonce,
            shard_index,
            data_shards,
            parity_shards,
            original_len,
            checksum,
            header_len,
        },
        ciphertext,
    ))
}

struct ChunkFields {
    shard_index: u8,
    data_shards: u8,
    parity_shards: u8,
    original_len: u32,
    checksum: [u8; 8],
    shard: Vec<u8>,
}

/// Erasure-encodes `payload` into `data_shards + parity_shards`
/// individually AEAD-sealed chunk records. Unlike
/// [`RatchetedSession::seal`]'s output they are outside the strict
/// per-record sequence, so they may arrive in any order, interleaved, with
/// up to `parity_shards` missing. They deliberately bypass
/// [`RatchetedSession::open`] (module docs).
fn build_chunk_records(
    msg_type: u8,
    chunk_key: &[u8; 32],
    attempt_nonce: &[u8; 32],
    payload: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<Vec<u8>>> {
    let checksum = truncated_checksum(payload);
    // The payload is always this module's own KEX material (~1.6KB), but the
    // length is sent as a `u32` and silent truncation is undetectable by the
    // reader, so refuse rather than assume.
    let original_len = u32::try_from(payload.len()).map_err(|_| Error::TooLarge)?;
    let (shards, _shard_len) = crate::erasure::encode(payload, data_shards, parity_shards)?;

    let mut out = Vec::with_capacity(shards.len());
    for (i, shard) in shards.iter().enumerate() {
        let mut header = Writer::new();
        header.put_fixed(&[msg_type]);
        header.put_fixed(attempt_nonce);
        header.put_fixed(&[i as u8, data_shards as u8, parity_shards as u8]);
        header.put_fixed(&original_len.to_be_bytes());
        header.put_fixed(&checksum);
        let header_bytes = header.into_bytes();

        let ciphertext = seal_chunk(chunk_key, &chunk_nonce(i as u8), &header_bytes, shard)?;
        let mut record = Writer::new();
        record.put_fixed(&header_bytes);
        record.put_var(&ciphertext);
        out.push(record.into_bytes());
    }
    Ok(out)
}

/// A fresh random 32-byte attempt id, so a retry gets its own
/// [`derive_chunk_key`] output instead of colliding with a stale, partly
/// received earlier attempt.
fn generate_attempt_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).expect("OS randomness source failed");
    nonce
}

/// What [`RatchetedSession::open_ratchet_chunk`] reports.
pub enum ChunkOutcome {
    /// The chunk was filed and fewer than `data_shards` have arrived, *or* it
    /// is a harmless straggler from a completed attempt. Callers handle both
    /// the same; [`RatchetedSession::incremental_ratchet_progress`]
    /// distinguishes them if needed.
    StillAccumulating,
    /// A step-1 attempt reconstructed and this (responder) side has advanced
    /// its epoch. Send `reply_records` to the peer; each is a complete chunk
    /// record for [`RatchetedSession::open_ratchet_chunk`].
    Step1Complete { reply_records: Vec<Vec<u8>> },
    /// A step-2 reply reconstructed successfully; the epoch has already
    /// advanced on this (initiator) side. Nothing further to send.
    Step2Complete,
}

/// A record decoded by [`RatchetedSession::open`]: application data to
/// deliver, or a ratchet-control message already fully handled.
pub enum Opened {
    Application(Vec<u8>),
    /// A ratchet-control message was processed, including the epoch switch.
    /// `reply` is `Some` for the peer's step 1 (a step-2 reply sealed under the
    /// *old* epoch, which the caller must send) and `None` for step 2.
    RatchetAdvanced {
        reply: Option<Vec<u8>>,
    },
}

impl RatchetedSession {
    /// Builds epoch-0 chains directly from the handshake's `ratchet_root`
    /// — no KEX needed yet, since the handshake itself already did one.
    pub fn new(session: &EstablishedSession, is_initiator: bool) -> Self {
        let (send_label, recv_label) = if is_initiator {
            (LABEL_INIT_SEND, LABEL_INIT_RECV)
        } else {
            (LABEL_INIT_RECV, LABEL_INIT_SEND)
        };
        let send_chain = ChainKey(hmac32(&session.ratchet_root, send_label));
        let recv_chain = ChainKey(hmac32(&session.ratchet_root, recv_label));

        RatchetedSession {
            root_key: session.ratchet_root,
            send_epoch: 0,
            send_chain,
            send_seq: 0,
            recv_current: RecvChain {
                epoch: 0,
                chain: recv_chain,
                expected_seq: 0,
                skipped: HashMap::new(),
            },
            recv_previous: None,
            pending: None,
            pending_epoch: 0,
            incoming_step1_chunks: None,
            incoming_step2_chunks: None,
            last_completed_step1_attempt: None,
            last_completed_step2_attempt: None,
        }
    }

    /// Seals one application record. Safe at any time, including while a
    /// ratchet step is pending (see module docs).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut payload = Vec::with_capacity(1 + plaintext.len());
        payload.push(MSG_APPLICATION);
        payload.extend_from_slice(plaintext);
        self.seal_payload(&payload)
    }

    /// Starts a ratchet step: fresh hybrid KEX material, sealed as a control
    /// message under the current send chain; the epoch changes when
    /// [`Self::open`] processes the peer's reply.
    pub fn initiate_ratchet(&mut self) -> Result<Vec<u8>> {
        if self.pending.is_some() {
            return Err(Error::RatchetInProgress);
        }
        let kex = InitiatorKex::generate();

        let mut w = Writer::new();
        w.put_fixed(kex.x25519_public().as_bytes());
        w.put_var(&kex.ml_kem_public().to_bytes());

        let mut payload = Vec::with_capacity(1 + w.0.len());
        payload.push(MSG_RATCHET_STEP1);
        payload.extend_from_slice(&w.0);

        let record = self.seal_payload(&payload)?;
        self.pending = Some(kex);
        self.pending_epoch = self.send_epoch;
        Ok(record)
    }

    /// The incremental, erasure-coded alternative to [`Self::initiate_ratchet`]
    /// (module docs). Splits the KEX material into `data_shards + parity_shards`
    /// AEAD-sealed chunks; any `data_shards` of them reaching the peer, in any
    /// order and interleaved with anything else, let
    /// [`Self::open_ratchet_chunk`] complete the step. Requires
    /// `data_shards >= 1` and `data_shards + parity_shards <= 255` (see
    /// `crate::erasure`).
    ///
    /// These chunks do **not** go through [`Self::seal`]/[`Self::open`]'s strict
    /// sequence, which is what makes loss and reorder tolerance real. The peer
    /// handles each with [`Self::open_ratchet_chunk`].
    pub fn initiate_incremental_ratchet(
        &mut self,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if self.pending.is_some() {
            return Err(Error::RatchetInProgress);
        }
        let kex = InitiatorKex::generate();

        let mut w = Writer::new();
        w.put_fixed(kex.x25519_public().as_bytes());
        w.put_var(&kex.ml_kem_public().to_bytes());
        let payload = w.into_bytes();

        let attempt_nonce = generate_attempt_nonce();
        let chunk_key = derive_chunk_key(&self.root_key, &attempt_nonce, LABEL_CHUNK_KEY_STEP1)?;
        let records = build_chunk_records(
            MSG_RATCHET_STEP1_CHUNK,
            &chunk_key,
            &attempt_nonce,
            &payload,
            data_shards,
            parity_shards,
        )?;

        self.pending = Some(kex);
        self.pending_epoch = self.send_epoch;
        Ok(records)
    }

    /// Chunks received so far as `(received, needed)`, for step 1 (responding to
    /// the peer's incremental initiation) and step 2 (awaiting the reply to
    /// ours). `None` where nothing is in progress.
    pub fn incremental_ratchet_progress(&self) -> (ChunkProgress, ChunkProgress) {
        (
            self.incoming_step1_chunks
                .as_ref()
                .map(|a| (a.received_count(), a.data_shards)),
            self.incoming_step2_chunks
                .as_ref()
                .map(|a| (a.received_count(), a.data_shards)),
        )
    }

    fn seal_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let (next_chain, message_key) = self.send_chain.advance();
        let epoch = self.send_epoch;
        let seq = self.send_seq;
        self.send_seq = self
            .send_seq
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;

        let aad = header_bytes(epoch, seq);
        let ciphertext = seal_with_message_key(&message_key, &aad, payload)?;
        self.send_chain = next_chain;

        let mut out = Vec::with_capacity(aad.len() + ciphertext.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens one record. Ratchet-control messages (steps 1 and 2) are handled
    /// internally, including the epoch switch, and reported as
    /// [`Opened::RatchetAdvanced`].
    pub fn open(&mut self, record: &[u8]) -> Result<Opened> {
        if record.len() < 12 {
            return Err(Error::Malformed("ratchet record shorter than header"));
        }
        let epoch = u32::from_be_bytes(
            record[..4]
                .try_into()
                .expect("length already checked above"),
        );
        let seq = u64::from_be_bytes(
            record[4..12]
                .try_into()
                .expect("length already checked above"),
        );
        let aad = &record[..12];
        let ciphertext = &record[12..];

        let plaintext = if epoch == self.recv_current.epoch {
            self.open_on(RecvSlot::Current, seq, aad, ciphertext)?
        } else if self
            .recv_previous
            .as_ref()
            .is_some_and(|p| p.epoch == epoch)
        {
            self.open_on(RecvSlot::Previous, seq, aad, ciphertext)?
        } else {
            return Err(Error::UnknownEpoch);
        };

        if plaintext.is_empty() {
            return Err(Error::Malformed("empty ratchet payload"));
        }
        match plaintext[0] {
            MSG_APPLICATION => Ok(Opened::Application(plaintext[1..].to_vec())),
            MSG_RATCHET_STEP1 => {
                let reply = self.handle_step1(epoch, &plaintext[1..])?;
                Ok(Opened::RatchetAdvanced { reply: Some(reply) })
            }
            MSG_RATCHET_STEP2 => {
                self.handle_step2(epoch, &plaintext[1..])?;
                Ok(Opened::RatchetAdvanced { reply: None })
            }
            _ => Err(Error::Malformed("unknown ratchet message type")),
        }
    }

    fn recv_mut(&mut self, slot: RecvSlot) -> &mut RecvChain {
        match slot {
            RecvSlot::Current => &mut self.recv_current,
            RecvSlot::Previous => self
                .recv_previous
                .as_mut()
                .expect("caller only reaches Previous when recv_previous is Some"),
        }
    }

    /// Opens a record against `slot`'s chain. `seq == expected_seq` is the
    /// normal step; `seq < expected_seq` uses (and removes) a cached skipped
    /// key; `seq > expected_seq` derives and caches the keys in between first,
    /// never rewinding (module docs).
    fn open_on(
        &mut self,
        slot: RecvSlot,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let recv = self.recv_mut(slot);
        match seq.cmp(&recv.expected_seq) {
            Ordering::Less => {
                // Remove the cached key on lookup whatever the decrypt result: every
                // message key is used once, and this makes a replay of the same `seq`
                // fail.
                let key = recv.skipped.remove(&seq).ok_or(Error::Replay)?;
                open_with_message_key(&key, aad, ciphertext)
            }
            Ordering::Equal => {
                let (next_chain, message_key) = recv.chain.advance();
                let plaintext = open_with_message_key(&message_key, aad, ciphertext)?;
                // Advance the chain only after decryption succeeds, so a forged record
                // can't desync the receive chain.
                recv.chain = next_chain;
                recv.expected_seq += 1;
                Ok(plaintext)
            }
            Ordering::Greater => {
                let skip_count = seq - recv.expected_seq;
                if skip_count > MAX_SKIPPED_KEYS
                    || recv.skipped.len() as u64 + skip_count > MAX_SKIPPED_KEYS
                {
                    return Err(Error::TooManySkippedKeys);
                }
                let mut chain = recv.chain.clone();
                let mut newly_skipped = Vec::with_capacity(skip_count as usize);
                for s in recv.expected_seq..seq {
                    let (next, key) = chain.advance();
                    newly_skipped.push((s, key));
                    chain = next;
                }
                let (next_chain, message_key) = chain.advance();
                let plaintext = open_with_message_key(&message_key, aad, ciphertext)?;

                // Commit the skipped keys and chain advance only after `seq` decrypts, so
                // a forged far-future `seq` can't force state changes or memory use.
                recv.skipped.extend(newly_skipped);
                recv.chain = next_chain;
                recv.expected_seq = seq + 1;
                Ok(plaintext)
            }
        }
    }

    fn handle_step1(&mut self, epoch: u32, payload: &[u8]) -> Result<Vec<u8>> {
        if self.pending.is_some() {
            return Err(Error::RatchetInProgress);
        }
        // A step 1 is only legitimate on the current epoch's chain. `Self::open`
        // also accepts the previous epoch's chain (so in-flight records survive a
        // transition), and a peer holding that chain's keys could seal a step 1 on
        // it. `advance_epoch(epoch)` would then derive `epoch + 1`, a number
        // already used, leaving two differently keyed chains with one epoch label
        // and a send chain the peer can't read. The `current`/`previous` scheme
        // needs monotonic epochs, so reject.
        if epoch != self.send_epoch {
            return Err(Error::WrongState);
        }
        let mut r = Reader::new(payload);
        let peer_x25519 = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let peer_ml_kem = kex::ml_kem_public_from_bytes(r.get_var()?)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in ratchet step1"));
        }

        let kex_out = kex::responder_exchange(&peer_x25519, &peer_ml_kem)?;

        let mut w = Writer::new();
        w.put_fixed(kex_out.x25519_public.as_bytes());
        w.put_var(&kex_out.ml_kem_ciphertext);
        let mut reply_payload = Vec::with_capacity(1 + w.0.len());
        reply_payload.push(MSG_RATCHET_STEP2);
        reply_payload.extend_from_slice(&w.0);

        // The reply itself must still go out under the *old* send chain —
        // the epoch only switches once it's on the wire.
        let reply = self.seal_payload(&reply_payload)?;

        let (new_root, new_send, new_recv) =
            derive_next_epoch(&self.root_key, &kex_out.shared_secret, false);
        self.advance_epoch(epoch, new_root, new_send, new_recv);

        Ok(reply)
    }

    fn handle_step2(&mut self, epoch: u32, payload: &[u8]) -> Result<()> {
        let kex = match self.pending.take() {
            Some(kex) if self.pending_epoch == epoch => kex,
            Some(kex) => {
                self.pending = Some(kex);
                return Err(Error::WrongState);
            }
            None => return Err(Error::WrongState),
        };

        let mut r = Reader::new(payload);
        let peer_x25519 = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
        let ml_kem_ct = kex::ml_kem_ciphertext_from_bytes(r.get_var()?)?;
        if !r.finished() {
            return Err(Error::Malformed("trailing bytes in ratchet step2"));
        }

        let shared_secret = kex.finish(&peer_x25519, &ml_kem_ct)?;
        let (new_root, new_send, new_recv) =
            derive_next_epoch(&self.root_key, &shared_secret, true);
        self.advance_epoch(epoch, new_root, new_send, new_recv);
        Ok(())
    }

    /// Processes one incremental-ratchet chunk: a peer's step 1 from
    /// [`Self::initiate_incremental_ratchet`], or a peer's step 2 from a
    /// [`ChunkOutcome::Step1Complete`]'s `reply_records`. Kept apart from
    /// [`Self::open`] because chunks must bypass its strict sequence (module
    /// docs).
    pub fn open_ratchet_chunk(&mut self, bytes: &[u8]) -> Result<ChunkOutcome> {
        let (header, ciphertext) = parse_chunk_header(bytes)?;
        let header_bytes = &bytes[..header.header_len];

        match header.msg_type {
            MSG_RATCHET_STEP1_CHUNK => {
                // A straggler from an already reconstructed attempt (see
                // `last_completed_step1_attempt`): ignore it. `root_key` has moved to the
                // epoch this attempt produced, so deriving a chunk key now would use the
                // wrong key.
                if self.last_completed_step1_attempt == Some(header.attempt_nonce) {
                    return Ok(ChunkOutcome::StillAccumulating);
                }
                // Same guard as `handle_step1`: with our own ratchet pending we can't
                // accept the peer's step 1, one-shot or incremental, until ours resolves.
                if self.pending.is_some() {
                    return Err(Error::RatchetInProgress);
                }
                let chunk_key =
                    derive_chunk_key(&self.root_key, &header.attempt_nonce, LABEL_CHUNK_KEY_STEP1)?;
                let shard = open_chunk(
                    &chunk_key,
                    &chunk_nonce(header.shard_index),
                    header_bytes,
                    ciphertext,
                )?;
                let fields = ChunkFields {
                    shard_index: header.shard_index,
                    data_shards: header.data_shards,
                    parity_shards: header.parity_shards,
                    original_len: header.original_len,
                    checksum: header.checksum,
                    shard,
                };
                let (reconstructed, data_shards, parity_shards) = match accumulate_chunk(
                    &mut self.incoming_step1_chunks,
                    header.attempt_nonce,
                    fields,
                )? {
                    Some(result) => result,
                    None => return Ok(ChunkOutcome::StillAccumulating),
                };

                let mut r = Reader::new(&reconstructed);
                let peer_x25519 = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
                let peer_ml_kem = kex::ml_kem_public_from_bytes(r.get_var()?)?;
                if !r.finished() {
                    return Err(Error::Malformed(
                        "trailing bytes in reconstructed ratchet step1",
                    ));
                }

                let kex_out = kex::responder_exchange(&peer_x25519, &peer_ml_kem)?;

                let mut w = Writer::new();
                w.put_fixed(kex_out.x25519_public.as_bytes());
                w.put_var(&kex_out.ml_kem_ciphertext);
                let reply_payload = w.into_bytes();

                // Derive from `self.root_key` before `advance_epoch` overwrites it, so the
                // reply uses the *old* epoch's key, as `handle_step1`'s one-shot reply
                // does via `seal_payload`.
                let reply_attempt_nonce = generate_attempt_nonce();
                let reply_chunk_key =
                    derive_chunk_key(&self.root_key, &reply_attempt_nonce, LABEL_CHUNK_KEY_STEP2)?;
                // The peer's step-1 split; the decode that just succeeded proves it works
                // for a payload this size.
                let reply_records = build_chunk_records(
                    MSG_RATCHET_STEP2_CHUNK,
                    &reply_chunk_key,
                    &reply_attempt_nonce,
                    &reply_payload,
                    data_shards,
                    parity_shards,
                )?;

                let (new_root, new_send, new_recv) =
                    derive_next_epoch(&self.root_key, &kex_out.shared_secret, false);
                self.advance_epoch(self.send_epoch, new_root, new_send, new_recv);
                self.last_completed_step1_attempt = Some(header.attempt_nonce);

                Ok(ChunkOutcome::Step1Complete { reply_records })
            }
            MSG_RATCHET_STEP2_CHUNK => {
                // Same straggler-from-a-finished-attempt short circuit as
                // the step-1 arm above.
                if self.last_completed_step2_attempt == Some(header.attempt_nonce) {
                    return Ok(ChunkOutcome::StillAccumulating);
                }
                if self.pending.is_none() {
                    return Err(Error::WrongState);
                }
                let chunk_key =
                    derive_chunk_key(&self.root_key, &header.attempt_nonce, LABEL_CHUNK_KEY_STEP2)?;
                let shard = open_chunk(
                    &chunk_key,
                    &chunk_nonce(header.shard_index),
                    header_bytes,
                    ciphertext,
                )?;
                let fields = ChunkFields {
                    shard_index: header.shard_index,
                    data_shards: header.data_shards,
                    parity_shards: header.parity_shards,
                    original_len: header.original_len,
                    checksum: header.checksum,
                    shard,
                };
                let (reconstructed, _data_shards, _parity_shards) = match accumulate_chunk(
                    &mut self.incoming_step2_chunks,
                    header.attempt_nonce,
                    fields,
                )? {
                    Some(result) => result,
                    None => return Ok(ChunkOutcome::StillAccumulating),
                };

                // Parse and complete the exchange before consuming `self.pending`: taking
                // it first meant any failure below destroyed this side's ephemeral KEX
                // material and stranded a step a retried reply could have completed.
                let mut r = Reader::new(&reconstructed);
                let peer_x25519 = kex::x25519_public_from_bytes(r.get_fixed(32)?)?;
                let ml_kem_ct = kex::ml_kem_ciphertext_from_bytes(r.get_var()?)?;
                if !r.finished() {
                    return Err(Error::Malformed(
                        "trailing bytes in reconstructed ratchet step2",
                    ));
                }

                let kex = self.pending.take().expect("checked Some above");
                let shared_secret = kex.finish(&peer_x25519, &ml_kem_ct)?;
                let (new_root, new_send, new_recv) =
                    derive_next_epoch(&self.root_key, &shared_secret, true);
                self.advance_epoch(self.send_epoch, new_root, new_send, new_recv);
                self.last_completed_step2_attempt = Some(header.attempt_nonce);
                Ok(ChunkOutcome::Step2Complete)
            }
            _ => Err(Error::Malformed("unknown ratchet chunk message type")),
        }
    }

    fn advance_epoch(
        &mut self,
        old_epoch: u32,
        new_root: [u8; 32],
        new_send: [u8; 32],
        new_recv: [u8; 32],
    ) {
        let new_epoch = old_epoch + 1;
        self.root_key = new_root;
        self.send_epoch = new_epoch;
        self.send_chain = ChainKey(new_send);
        self.send_seq = 0;

        let old_current = std::mem::replace(
            &mut self.recv_current,
            RecvChain {
                epoch: new_epoch,
                chain: ChainKey(new_recv),
                expected_seq: 0,
                skipped: HashMap::new(),
            },
        );
        self.recv_previous = Some(old_current);
    }
}

enum RecvSlot {
    Current,
    Previous,
}

/// Files one chunk into `slot` (starting an accumulator on a new attempt's
/// first chunk, or checking it against the one in progress). Once
/// `data_shards` have arrived, reconstructs, verifies the checksum, and
/// returns `Some((payload, data_shards, parity_shards))`, clearing `slot`
/// on success or failure (partial state from a failed reconstruction is
/// worthless). `Ok(None)` while waiting.
fn accumulate_chunk(
    slot: &mut Option<ChunkAccumulator>,
    attempt_nonce: [u8; 32],
    fields: ChunkFields,
) -> Result<Option<(Vec<u8>, usize, usize)>> {
    let data_shards = fields.data_shards as usize;
    let parity_shards = fields.parity_shards as usize;
    let total = data_shards + parity_shards;
    if fields.shard_index as usize >= total {
        return Err(Error::Malformed("chunk shard index out of range"));
    }

    // A chunk from a different attempt starts fresh rather than erroring, so a
    // retry isn't blocked by an abandoned attempt's stale state.
    let is_new_attempt = match slot {
        Some(acc) => acc.attempt_nonce != attempt_nonce,
        None => true,
    };
    if is_new_attempt {
        *slot = Some(ChunkAccumulator {
            attempt_nonce,
            data_shards,
            parity_shards,
            original_len: fields.original_len as usize,
            checksum: fields.checksum,
            shards: vec![None; total],
        });
    }
    let accumulator = slot.as_mut().expect("just ensured Some immediately above");

    // Within one attempt, every chunk must agree on the shape. The AEAD tag
    // proves a chunk came from a holder of `root_key`, not that it belongs to
    // this attempt's payload.
    if accumulator.data_shards != data_shards
        || accumulator.parity_shards != parity_shards
        || accumulator.original_len != fields.original_len as usize
        || accumulator.checksum != fields.checksum
    {
        return Err(Error::Malformed(
            "chunk parameters do not match the in-progress reconstruction",
        ));
    }

    accumulator.shards[fields.shard_index as usize] = Some(fields.shard);

    if accumulator.received_count() < data_shards {
        return Ok(None);
    }

    let reconstructed = crate::erasure::decode(&accumulator.shards, data_shards, parity_shards);
    let original_len = accumulator.original_len;
    let checksum = accumulator.checksum;
    *slot = None; // a completed attempt, successful or not, is done either way

    let reconstructed = reconstructed?;
    if original_len > reconstructed.len() {
        return Err(Error::Malformed(
            "chunk reconstruction shorter than its declared length",
        ));
    }
    let truncated = &reconstructed[..original_len];
    if truncated_checksum(truncated) != checksum {
        return Err(Error::Malformed("chunk reconstruction checksum mismatch"));
    }

    Ok(Some((truncated.to_vec(), data_shards, parity_shards)))
}

fn header_bytes(epoch: u32, seq: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&epoch.to_be_bytes());
    out[4..].copy_from_slice(&seq.to_be_bytes());
    out
}

/// Derives the next epoch's root key and both chain keys from the previous
/// root key and a fresh shared secret, in the shape of
/// `handshake::finalize_keys`.
fn derive_next_epoch(
    root_key: &[u8; 32],
    shared_secret: &kex::SharedSecret,
    is_initiator: bool,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(root_key.as_slice()), &shared_secret.0);
    let hk = Hkdf::<Sha256>::from_prk(&prk).expect("HKDF PRK is always the SHA-256 output length");

    let mut new_root = [0u8; 32];
    hk.expand(LABEL_STEP_ROOT, &mut new_root)
        .expect("32-byte output is within HKDF-SHA256's expand limit");
    let mut i2r = [0u8; 32];
    hk.expand(LABEL_STEP_I2R, &mut i2r)
        .expect("32-byte output is within HKDF-SHA256's expand limit");
    let mut r2i = [0u8; 32];
    hk.expand(LABEL_STEP_R2I, &mut r2i)
        .expect("32-byte output is within HKDF-SHA256's expand limit");

    if is_initiator {
        (new_root, i2r, r2i)
    } else {
        (new_root, r2i, i2r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{initiator_start, responder_respond};
    use crate::identity::Identity;

    fn pair() -> (RatchetedSession, RatchetedSession) {
        let server_identity = Identity::generate();
        let client_identity = Identity::generate();

        let (init_state, msg1) = initiator_start(None);
        let (resp_state, msg2) = responder_respond(&server_identity, None, &msg1).unwrap();
        let (msg3, client_session) = init_state.complete(&client_identity, &msg2).unwrap();
        let server_session = resp_state.complete(&msg3).unwrap();

        (
            RatchetedSession::new(&client_session, true),
            RatchetedSession::new(&server_session, false),
        )
    }

    // These four tests reach internal error branches (a too-short ratchet
    // record, an empty payload, an unknown message type, trailing bytes in a
    // control payload) that the public API never produces, since `seal` and
    // `initiate_ratchet` always write well-formed payloads. They need the
    // private `seal_payload`, so they live in this module.

    #[test]
    fn a_record_shorter_than_the_header_is_rejected() {
        let (_client, mut server) = pair();
        assert!(matches!(server.open(&[0u8; 4]), Err(Error::Malformed(_))));
    }

    #[test]
    fn an_empty_decrypted_payload_is_rejected() {
        let (mut client, mut server) = pair();
        let record = client.seal_payload(&[]).unwrap();
        assert!(matches!(server.open(&record), Err(Error::Malformed(_))));
    }

    #[test]
    fn an_unrecognized_message_type_is_rejected() {
        let (mut client, mut server) = pair();
        let record = client.seal_payload(&[99u8]).unwrap();
        assert!(matches!(server.open(&record), Err(Error::Malformed(_))));
    }

    #[test]
    fn trailing_bytes_in_a_ratchet_step1_payload_are_rejected() {
        let (mut client, mut server) = pair();

        let kex = InitiatorKex::generate();
        let mut w = Writer::new();
        w.put_fixed(kex.x25519_public().as_bytes());
        w.put_var(&kex.ml_kem_public().to_bytes());
        let mut payload = Vec::new();
        payload.push(MSG_RATCHET_STEP1);
        payload.extend_from_slice(&w.0);
        payload.push(0xFF); // trailing garbage

        let record = client.seal_payload(&payload).unwrap();
        assert!(matches!(server.open(&record), Err(Error::Malformed(_))));
    }

    #[test]
    fn trailing_bytes_in_a_ratchet_step2_payload_are_rejected() {
        let (mut client, mut server) = pair();
        // Client has a real pending ratchet at epoch 0, matching the forged
        // reply's epoch tag below.
        client.initiate_ratchet().unwrap();

        let decoy_initiator = InitiatorKex::generate();
        let responder_kex_out = kex::responder_exchange(
            decoy_initiator.x25519_public(),
            decoy_initiator.ml_kem_public(),
        )
        .unwrap();
        let mut w = Writer::new();
        w.put_fixed(responder_kex_out.x25519_public.as_bytes());
        w.put_var(&responder_kex_out.ml_kem_ciphertext);
        let mut payload = Vec::new();
        payload.push(MSG_RATCHET_STEP2);
        payload.extend_from_slice(&w.0);
        payload.push(0xFF); // trailing garbage

        // Sealed under the server's still-current epoch-0 send chain, which
        // the client's epoch-0 recv chain can decrypt.
        let record = server.seal_payload(&payload).unwrap();
        assert!(matches!(client.open(&record), Err(Error::Malformed(_))));
    }

    #[test]
    fn a_step2_reply_at_an_epoch_other_than_the_pending_one_is_rejected_and_pending_survives() {
        let (mut client, _server) = pair();
        client.initiate_ratchet().unwrap();
        assert_eq!(client.pending_epoch, 0);

        let result = client.handle_step2(1, &[0u8; 32]);
        assert!(matches!(result, Err(Error::WrongState)));
        // The mismatched reply must not have consumed the real pending
        // ratchet — a later, correctly-tagged reply should still work.
        assert!(client.pending.is_some());
    }

    /// `Self::open` accepts the previous epoch's chain so in-flight records
    /// survive a transition, so a peer holding that chain could seal a step 1
    /// on it. Before the fix, `advance_epoch(epoch)` then reused an epoch
    /// number, leaving two chains with one label and a send chain the peer
    /// couldn't read. Reached through private `handle_step1`, like the
    /// `handle_step2` tests, since honest public-API use never produces it.
    #[test]
    fn a_step1_tagged_with_a_stale_epoch_is_rejected_and_leaves_the_epoch_untouched() {
        let (mut client, mut server) = pair();

        // One real ratchet, so the server sits at epoch 1 with a live
        // epoch-0 chain still in its `previous` slot.
        let step1 = client.initiate_ratchet().unwrap();
        let reply = match server.open(&step1).unwrap() {
            Opened::RatchetAdvanced { reply: Some(reply) } => reply,
            _ => panic!("the server's first step 1 must produce a reply"),
        };
        client.open(&reply).unwrap();
        assert_eq!(server.send_epoch, 1);
        assert_eq!(server.recv_previous.as_ref().map(|p| p.epoch), Some(0));

        let kex = InitiatorKex::generate();
        let mut w = Writer::new();
        w.put_fixed(kex.x25519_public().as_bytes());
        w.put_var(&kex.ml_kem_public().to_bytes());

        assert!(matches!(
            server.handle_step1(0, &w.0),
            Err(Error::WrongState)
        ));
        assert_eq!(server.send_epoch, 1, "a rejected step 1 must not advance");
        assert_eq!(server.recv_current.epoch, 1);

        // The same step 1 tagged with the current epoch is still accepted, so the
        // check rejects the stale epoch, not step 1.
        assert!(server.handle_step1(1, &w.0).is_ok());
        assert_eq!(server.send_epoch, 2);
    }

    /// A reconstruction that decrypts (genuinely from the peer) but doesn't
    /// parse must leave the pending KEX material intact; consuming it on
    /// failure stranded a step a retried reply could have completed.
    #[test]
    fn a_malformed_incremental_step2_reconstruction_leaves_the_pending_ratchet_intact() {
        let (mut client, _server) = pair();
        client.initiate_incremental_ratchet(2, 1).unwrap();
        assert!(client.pending.is_some());

        // Chunks sealed under the key the client will derive, so they
        // authenticate, but with an invalid step-2 body: 32 bytes of x25519 and no
        // ML-KEM ciphertext length prefix.
        let attempt_nonce = generate_attempt_nonce();
        let chunk_key =
            derive_chunk_key(&client.root_key, &attempt_nonce, LABEL_CHUNK_KEY_STEP2).unwrap();
        let records = build_chunk_records(
            MSG_RATCHET_STEP2_CHUNK,
            &chunk_key,
            &attempt_nonce,
            &[0xAAu8; 32],
            2,
            1,
        )
        .unwrap();

        // Exactly `data_shards` chunks: the second triggers reconstruction. A
        // third would start a fresh accumulator, since completion clears the slot.
        assert!(matches!(
            client.open_ratchet_chunk(&records[0]),
            Ok(ChunkOutcome::StillAccumulating)
        ));
        assert!(matches!(
            client.open_ratchet_chunk(&records[1]),
            Err(Error::Malformed(_))
        ));
        assert!(
            client.pending.is_some(),
            "a failed reconstruction must not consume the pending KEX material"
        );
    }

    #[test]
    fn a_step2_reply_with_no_pending_ratchet_is_rejected() {
        let (_client, mut server) = pair();
        assert!(server.pending.is_none());
        let result = server.handle_step2(0, &[0u8; 32]);
        assert!(matches!(result, Err(Error::WrongState)));
    }
}
