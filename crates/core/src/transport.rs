//! The post-handshake data plane: ChaCha20-Poly1305 AEAD records with
//! per-direction keys and an explicit, replay-checked sequence number.
//!
//! Each direction gets its own key and base IV (derived via HKDF with
//! distinct labels), so the two peers never encrypt under the same
//! (key, nonce) pair — the one mistake that silently destroys AEAD security.
//! The sequence number is carried on the wire (rather than assumed
//! in-order, as TLS does) and XORed into the base IV to form the nonce, so
//! the same design works unmodified over an unreliable, reordering
//! transport such as UDP/QUIC.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::error::{Error, Result};

pub const MAX_PLAINTEXT_LEN: usize = 16 * 1024;
const TAG_LEN: usize = 16;
const SEQ_LEN: usize = 8;
/// Sliding window width for replay detection, in sequence numbers.
const REPLAY_WINDOW: u64 = 64;

pub struct DirectionalKey {
    cipher: ChaCha20Poly1305,
    base_iv: [u8; 12],
}

impl DirectionalKey {
    pub fn new(key_bytes: &[u8; 32], iv_bytes: &[u8; 12]) -> Self {
        DirectionalKey {
            cipher: ChaCha20Poly1305::new(&Key::from(*key_bytes)),
            base_iv: *iv_bytes,
        }
    }

    fn nonce_for(&self, seq: u64) -> Nonce {
        let mut nonce = self.base_iv;
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        Nonce::from(nonce)
    }
}

/// Sending half of one direction of the channel.
pub struct Sender {
    key: DirectionalKey,
    next_seq: u64,
}

impl Sender {
    pub fn new(key: DirectionalKey) -> Self {
        Sender { key, next_seq: 0 }
    }

    /// Seals `plaintext` into a self-contained record: `seq(8) || ciphertext+tag`.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::TooLarge);
        }
        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;

        let seq_bytes = seq.to_be_bytes();
        let nonce = self.key.nonce_for(seq);
        let ciphertext = self
            .key
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &seq_bytes,
                },
            )
            .map_err(|_| Error::Decrypt)?;

        let mut out = Vec::with_capacity(SEQ_LEN + ciphertext.len());
        out.extend_from_slice(&seq_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

/// Receiving half of one direction of the channel, with a sliding-window
/// replay filter so out-of-order (but not replayed) records are accepted.
pub struct Receiver {
    key: DirectionalKey,
    highest_seq: Option<u64>,
    window: u64, // bit i set => (highest_seq - i) already seen
}

impl Receiver {
    pub fn new(key: DirectionalKey) -> Self {
        Receiver {
            key,
            highest_seq: None,
            window: 0,
        }
    }

    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>> {
        if record.len() < SEQ_LEN + TAG_LEN {
            return Err(Error::Malformed("record shorter than header + tag"));
        }
        if record.len() > SEQ_LEN + TAG_LEN + MAX_PLAINTEXT_LEN {
            return Err(Error::TooLarge);
        }
        let seq_bytes = &record[..SEQ_LEN];
        let seq = u64::from_be_bytes(
            seq_bytes
                .try_into()
                .expect("length already checked by the caller above"),
        );
        self.check_replay(seq)?;

        let nonce = self.key.nonce_for(seq);
        let plaintext = self
            .key
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &record[SEQ_LEN..],
                    aad: seq_bytes,
                },
            )
            .map_err(|_| Error::Decrypt)?;

        self.record_seen(seq);
        Ok(plaintext)
    }

    /// `window` bit `age - 1` records whether `highest_seq - age` has been
    /// seen, for `age` in `1..=REPLAY_WINDOW`. `highest_seq` itself is
    /// always considered seen once set, without needing a bit — it's
    /// exactly the record that most recently moved the window forward.
    fn check_replay(&self, seq: u64) -> Result<()> {
        match self.highest_seq {
            None => Ok(()),
            Some(highest) => {
                if seq > highest {
                    Ok(())
                } else if seq == highest {
                    Err(Error::Replay)
                } else {
                    let age = highest - seq;
                    if age > REPLAY_WINDOW || self.window & (1 << (age - 1)) != 0 {
                        Err(Error::Replay)
                    } else {
                        Ok(())
                    }
                }
            }
        }
    }

    fn record_seen(&mut self, seq: u64) {
        match self.highest_seq {
            None => {
                self.highest_seq = Some(seq);
                self.window = 0;
            }
            Some(highest) if seq > highest => {
                let shift = seq - highest;
                self.window = if shift >= REPLAY_WINDOW {
                    0
                } else {
                    (self.window << shift) | (1 << (shift - 1))
                };
                self.highest_seq = Some(seq);
            }
            Some(highest) => {
                let age = highest - seq;
                self.window |= 1 << (age - 1);
            }
        }
    }
}
