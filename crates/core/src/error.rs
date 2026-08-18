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
    #[error("referenced one-time prekey is unknown or was already consumed")]
    UnknownOneTimePreKey,
    #[error("sender certificate's expiry has passed")]
    CertificateExpired,
    #[error("no session exists for the referenced device")]
    UnknownDevice,
    #[error("device's bundle does not match what the signed device list authorizes")]
    UnauthorizedDevice,
    #[error("signed device list version is not newer than the last one accepted")]
    StaleDeviceList,
    #[error("group has reached its fixed leaf capacity; this module does not support resizing")]
    GroupFull,
    #[error("referenced leaf index is not a current group member")]
    NotAGroupMember,
    #[error("could not locate a decryptable path secret in this commit's update path")]
    CommitNotDecryptable,
    #[error("catching up to this record's sequence number would skip more keys than this session allows")]
    TooManySkippedKeys,
    #[error(
        "a received commit's public path key did not match the key its decrypted secret derives"
    )]
    PathKeyMismatch,
    /// An [`crate::identity::Identity`] backed by an external signing
    /// backend (HSM, cloud KMS, hardware token — see that module's "Key
    /// custody" docs) failed to sign. Never returned for the default,
    /// in-process [`crate::identity::Identity::generate`] case, which
    /// cannot fail this way.
    #[error("external signing backend failed: {0}")]
    SigningBackend(#[source] Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = core::result::Result<T, Error>;
