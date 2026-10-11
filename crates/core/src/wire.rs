//! Minimal, explicit (de)serialization for handshake messages.
//!
//! Hand-rolled rather than a general serde format: every field here is
//! security-critical, and an explicit reader makes the exact bytes that are
//! authenticated or fed to a KDF easy to audit.
//!
//! # Why a 64-bit length prefix
//! [`Writer::put_var`] used a `u16` prefix guarded only by `debug_assert!`.
//! In release builds, the only ones this workspace's gate runs
//! (`ENGINEERING-STANDARDS.md` §0.4), a field over 65535 bytes silently
//! wrapped its prefix into an unparseable message. Not hypothetical: a
//! [`crate::group::Commit`] for 32 leaves is ~73KB, so `Commit::to_bytes`
//! silently produced garbage for realistically sized groups.
//!
//! A `u64` prefix makes truncation structurally impossible: `usize` is at
//! most 64 bits on every Rust target, so `bytes.len() as u64` is lossless and
//! `put_var` needs no failure path. A `u32` prefix with a fallible writer was
//! rejected: every `to_bytes` would return `Result` for an unreachable case
//! (a single field over 4GiB). The cost is 6 bytes per variable field, under
//! 1% of the multi-kilobyte PQ key material in every message.
//!
//! This is a breaking wire-format change (§6.11), not a transparent upgrade.

use crate::error::{Error, Result};

/// Width of the length prefix [`Writer::put_var`] writes and
/// [`Reader::get_var`] reads. See the module docs for why it is 8 bytes.
const VAR_LEN_PREFIX: usize = 8;

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Writer(Vec::new())
    }

    pub fn put_fixed(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    /// Length-prefixed (u64 BE) variable field. Cannot truncate: the prefix
    /// holds any `usize` (module docs).
    pub fn put_var(&mut self, bytes: &[u8]) {
        self.0
            .extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        self.0.extend_from_slice(bytes);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn get_fixed(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            return Err(Error::Malformed("unexpected end of message"));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn get_var(&mut self) -> Result<&'a [u8]> {
        let len_bytes: [u8; VAR_LEN_PREFIX] = self
            .get_fixed(VAR_LEN_PREFIX)?
            .try_into()
            .expect("get_fixed(VAR_LEN_PREFIX) already guarantees the length");
        let len = usize::try_from(u64::from_be_bytes(len_bytes))
            .map_err(|_| Error::Malformed("length prefix exceeds this platform's usize"))?;
        self.get_fixed(len)
    }

    /// Bytes consumed so far — used to slice out "everything up to here"
    /// when building a transcript to sign or hash.
    pub fn consumed(&self) -> usize {
        self.pos
    }

    /// Bytes left unread in this message.
    ///
    /// Lets a count-prefixed sequence reject an absurd count *before*
    /// reserving memory: every element costs at least one byte, so a larger
    /// count is unsatisfiable. Without it, an attacker's `u32` count drove
    /// `Vec::with_capacity` toward four billion elements, hundreds of
    /// gigabytes, which aborts the process wherever the reservation fails
    /// (memory cgroups, strict overcommit, a fuzzer's malloc limit) instead of
    /// being a parse error.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_fixed_past_the_end_of_the_buffer_is_rejected() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(r.get_fixed(4).is_err());
        // A failed read must not have consumed anything.
        assert_eq!(r.get_fixed(3).unwrap(), &[1, 2, 3]);
    }

    /// Regression test for the truncation defect in the module docs: a field
    /// longer than a `u16` prefix allows must round-trip exactly.
    #[test]
    fn a_field_larger_than_the_old_u16_prefix_round_trips_exactly() {
        for len in [0usize, 1, 65_535, 65_536, 70_000, 200_000] {
            let payload = vec![0xABu8; len];
            let mut w = Writer::new();
            w.put_var(&payload);
            let bytes = w.into_bytes();

            let mut r = Reader::new(&bytes);
            assert_eq!(r.get_var().unwrap(), &payload[..], "len={len}");
            assert!(r.finished(), "len={len}");
        }
    }

    #[test]
    fn a_length_prefix_longer_than_the_buffer_is_a_parse_error_not_an_allocation() {
        let mut bytes = u64::MAX.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"three");
        let mut r = Reader::new(&bytes);
        assert!(matches!(r.get_var(), Err(Error::Malformed(_))));
    }

    #[test]
    fn remaining_tracks_what_is_left_to_read() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5]);
        assert_eq!(r.remaining(), 5);
        r.get_fixed(2).unwrap();
        assert_eq!(r.remaining(), 3);
        r.get_fixed(3).unwrap();
        assert_eq!(r.remaining(), 0);
        assert!(r.finished());
    }
}
