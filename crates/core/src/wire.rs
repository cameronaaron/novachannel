//! Minimal, explicit (de)serialization for handshake messages.
//!
//! Handshake wire formats are hand-rolled rather than pulled in via a
//! general-purpose serde format: every field on this path is
//! security-critical, and an explicit reader makes the exact bytes that were
//! authenticated or fed into a KDF easy to audit.

use crate::error::{Error, Result};

pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Writer(Vec::new())
    }

    pub fn put_fixed(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    /// Length-prefixed (u16 BE) variable-size field.
    pub fn put_var(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() <= u16::MAX as usize);
        self.0
            .extend_from_slice(&(bytes.len() as u16).to_be_bytes());
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
        let len_bytes = self.get_fixed(2)?;
        let len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        self.get_fixed(len)
    }

    /// Bytes consumed so far — used to slice out "everything up to here"
    /// when building a transcript to sign or hash.
    pub fn consumed(&self) -> usize {
        self.pos
    }

    pub fn finished(&self) -> bool {
        self.pos == self.buf.len()
    }
}
