//! Minimal, explicit (de)serialization for handshake messages.
//!
//! Handshake wire formats are hand-rolled rather than pulled in via a
//! general-purpose serde format: every field on this path is
//! security-critical, and an explicit reader makes the exact bytes that were
//! authenticated or fed into a KDF easy to audit.
//!
//! # Why a 64-bit length prefix
//! [`Writer::put_var`] originally wrote a `u16` length prefix, guarded only
//! by a `debug_assert!`. In a release build — the only build this
//! workspace's own gate actually runs (`ENGINEERING-STANDARDS.md` §0.4) —
//! a field longer than 65535 bytes silently wrapped its length prefix and
//! produced a structurally corrupt message that no reader could ever parse
//! back. That was not hypothetical: a [`crate::group::Commit`] for a group
//! of 32 leaves already measures ~73KB, so `Commit::to_bytes` silently
//! emitted unparseable bytes for any realistically sized group, with no
//! error anywhere.
//!
//! The prefix is now `u64`, which makes the truncation *structurally*
//! impossible rather than merely documented: `usize` is at most 64 bits on
//! every target Rust supports, so `bytes.len() as u64` is lossless by
//! construction and `put_var` needs no failure path at all. A `u32` prefix
//! plus a fallible writer was considered and rejected: it would make every
//! `to_bytes` in this crate return `Result` to report a condition no caller
//! can actually reach (a single field larger than 4GiB), trading a worse
//! public API for no additional safety. The cost of the wider prefix is 6
//! bytes per variable-length field — under 1% on the multi-kilobyte
//! post-quantum key material that dominates every message here.
//!
//! This is a breaking wire-format change, stated as such per §6.11's
//! standard, not a transparent upgrade.

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

    /// Length-prefixed (u64 BE) variable-size field. Cannot truncate: see
    /// the module docs on why the prefix is wide enough to hold any
    /// `usize` on any supported target.
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
    /// Exists so a count-prefixed sequence can reject an absurd count
    /// *before* reserving memory for it: every element of every such
    /// sequence in this crate costs at least one byte on the wire, so a
    /// declared count larger than this is provably unsatisfiable. Without
    /// it, an attacker-chosen `u32` count drove a `Vec::with_capacity` of
    /// up to four billion elements — an allocation of hundreds of
    /// gigabytes, which aborts the process outright wherever a reservation
    /// that size fails (a memory cgroup, strict overcommit, a fuzzer's
    /// malloc limit) rather than failing as a parse error.
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

    /// The regression test for the silent-truncation defect the module
    /// docs describe: a field longer than the old `u16` prefix could
    /// express must round-trip exactly, not wrap its length and become
    /// unparseable.
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
