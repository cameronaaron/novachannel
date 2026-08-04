use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("handshake message malformed: {0}")]
    Malformed(&'static str),
    #[error("identity signature did not verify")]
    BadSignature,
    #[error("post-quantum key encapsulation failed")]
    Kem,
    #[error("peer identity did not match the pinned expected identity")]
    IdentityMismatch,
    #[error("handshake message received out of order")]
    WrongState,
    #[error("AEAD open failed: ciphertext forged or corrupted")]
    Decrypt,
    #[error("record sequence number was replayed or fell outside the receive window")]
    Replay,
    #[error("plaintext or record exceeds the maximum allowed size")]
    TooLarge,
    #[error("record sequence space exhausted; the session must be rekeyed")]
    SequenceExhausted,
    #[error("a ratchet step is already pending; finish it before sending application data")]
    RatchetInProgress,
    #[error("record's epoch is neither the current nor the immediately preceding one")]
    UnknownEpoch,
}

pub type Result<T> = core::result::Result<T, Error>;
