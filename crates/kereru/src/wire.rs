//! Encoding and decoding of SSH wire types.
//!
//! SSH encodes most values with a 4-byte big-endian length prefix ("string"),
//! and integers as big-endian "mpint" values. Everything a packet needs is
//! built with [`Writer`] and read back with [`Reader`].

use crate::{Error, Result};

/// Builds one SSH packet payload.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A writer whose payload starts with a message number.
    pub fn message(msg: u8) -> Self {
        Self::default().byte(msg)
    }

    pub fn byte(mut self, v: u8) -> Self {
        self.buf.push(v);
        self
    }

    pub fn bool(mut self, v: bool) -> Self {
        self.buf.push(u8::from(v));
        self
    }

    pub fn u32(mut self, v: u32) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// A length-prefixed byte string.
    pub fn string(mut self, v: &[u8]) -> Self {
        self.buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(v);
        self
    }

    /// A length-prefixed UTF-8 string.
    pub fn str(self, v: &str) -> Self {
        self.string(v.as_bytes())
    }

    /// A comma-separated name-list, which is a string on the wire.
    pub fn name_list(self, names: &[&str]) -> Self {
        self.str(&names.join(","))
    }

    /// A multiple-precision integer: big-endian, no leading zero bytes, with a
    /// leading zero when the high bit is set so the value stays unsigned.
    pub fn mpint(mut self, bytes: &[u8]) -> Self {
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        let mag = &bytes[start..];
        if mag.first().is_some_and(|b| b & 0x80 != 0) {
            self.buf
                .extend_from_slice(&(mag.len() as u32 + 1).to_be_bytes());
            self.buf.push(0);
        } else {
            self.buf
                .extend_from_slice(&(mag.len() as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(mag);
        self
    }

    pub fn raw(mut self, v: &[u8]) -> Self {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Reads one SSH packet payload.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| Error::Protocol(format!("packet truncated at byte {}", self.pos)))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Reads exactly `n` bytes without a length prefix.
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.byte()? != 0)
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    pub fn utf8(&mut self) -> Result<&'a str> {
        std::str::from_utf8(self.string()?)
            .map_err(|_| Error::Protocol("expected UTF-8 string".into()))
    }

    /// Reads an mpint, dropping the sign and leading zeros.
    pub fn mpint(&mut self) -> Result<&'a [u8]> {
        let raw = self.string()?;
        let start = raw.iter().position(|b| *b != 0).unwrap_or(raw.len());
        Ok(&raw[start..])
    }

    pub fn name_list(&mut self) -> Result<Vec<&'a str>> {
        let raw = self.string()?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        std::str::from_utf8(raw)
            .map(|s| s.split(',').collect())
            .map_err(|_| Error::Protocol("name-list is not UTF-8".into()))
    }
}

/// Splits a signature blob into its algorithm name and the signature itself.
pub fn split_signature(blob: &[u8]) -> Result<(String, &[u8])> {
    let mut r = Reader::new(blob);
    let alg = r.utf8()?.to_owned();
    let sig = r.string()?;
    Ok((alg, sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mpint_round_trips_unsigned_values() {
        let bytes = Writer::default().mpint(&[0x80, 0x01]).into_vec();
        assert_eq!(bytes, [0, 0, 0, 3, 0, 0x80, 0x01]);

        let mut r = Reader::new(&bytes);
        assert_eq!(r.mpint().unwrap(), [0x80, 0x01]);
    }

    #[test]
    fn mpint_strips_leading_zeros_and_encodes_zero() {
        let bytes = Writer::default()
            .mpint(&[0, 0, 0x2a])
            .mpint(&[0, 0])
            .into_vec();
        assert_eq!(bytes, [0, 0, 0, 1, 0x2a, 0, 0, 0, 0]);
    }

    #[test]
    fn reader_rejects_truncated_packets() {
        let mut r = Reader::new(&[0, 0, 0, 8, 1, 2]);
        assert!(r.string().is_err());
    }

    #[test]
    fn name_lists_are_comma_separated_strings() {
        let bytes = Writer::default().name_list(&["a", "b"]).into_vec();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.name_list().unwrap(), ["a", "b"]);
    }
}
