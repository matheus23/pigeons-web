//! Packet framing over an async byte stream.
//!
//! SSH wraps every message in a length-prefixed packet with randomized padding.
//! Before the first `NEWKEYS` the packets are plaintext; afterwards both
//! directions are AEAD-encrypted with independent keys and sequence numbers.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::{Cipher, Randomness};
use crate::{Error, Result};

/// Upper bound on a single packet, matching OpenSSH's channel data limit.
const MAX_PACKET: usize = 256 * 1024 + 64;

/// Longest banner line accepted from the server.
const MAX_LINE: usize = 1024;

pub(crate) struct Conn<T> {
    io: T,
    buf: Vec<u8>,
    in_cipher: Option<Cipher>,
    out_cipher: Option<Cipher>,
    /// Packet counters. SSH sequence numbers start at zero, increment for every
    /// packet in a direction, and are never reset — not even across `NEWKEYS`.
    seq_in: u32,
    seq_out: u32,
    rng: Box<dyn Randomness>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Conn<T> {
    pub fn new(io: T, rng: Box<dyn Randomness>) -> Self {
        Self {
            io,
            buf: Vec::with_capacity(16 * 1024),
            in_cipher: None,
            out_cipher: None,
            seq_in: 0,
            seq_out: 0,
            rng,
        }
    }

    /// The randomness source, for key exchange and initialization vectors.
    pub fn rng(&mut self) -> &mut dyn Randomness {
        &mut *self.rng
    }

    /// Restarts outgoing sequence numbering, which strict key exchange requires
    /// after NEWKEYS so no packet can be injected or replayed across a rekey.
    pub fn reset_out_sequence(&mut self) {
        self.seq_out = 0;
    }

    /// Restarts incoming sequence numbering, see [`reset_out_sequence`].
    pub fn reset_in_sequence(&mut self) {
        self.seq_in = 0;
    }

    pub fn set_out_cipher(&mut self, cipher: Cipher) {
        self.out_cipher = Some(cipher);
    }

    pub fn set_in_cipher(&mut self, cipher: Cipher) {
        self.in_cipher = Some(cipher);
    }

    /// One read from the transport; `Error::Closed` at EOF.
    async fn fill(&mut self) -> Result<()> {
        let n = self.io.read_buf(&mut self.buf).await?;
        if n == 0 {
            return Err(Error::Closed);
        }
        Ok(())
    }

    /// Reads one CRLF-terminated line, used for the version exchange.
    pub async fn read_line(&mut self) -> Result<String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                let line = String::from_utf8_lossy(&line);
                return Ok(line.trim_end_matches(['\r', '\n']).to_owned());
            }
            if self.buf.len() > MAX_LINE {
                return Err(Error::Protocol("banner line too long".into()));
            }
            self.fill().await?;
        }
    }

    pub async fn write_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.io.write_all(bytes).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Total bytes needed for the next packet, if the length is already known.
    fn next_packet_len(&self) -> Result<Option<usize>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let (len, tag) = match &self.in_cipher {
            None => (
                u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize,
                0,
            ),
            Some(cipher) => (
                cipher.peek_length(self.seq_in, &self.buf)? as usize,
                cipher.kind().tag_len(),
            ),
        };
        if len > MAX_PACKET {
            return Err(Error::Protocol(format!(
                "packet of {len} bytes is too large"
            )));
        }
        Ok(Some(4 + len + tag))
    }

    /// Removes and decrypts the next packet if it is fully buffered.
    ///
    /// The returned payload has the length field, padding length, and padding
    /// stripped: it starts at the message number.
    pub fn take_packet(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(total) = self.next_packet_len()? else {
            return Ok(None);
        };
        if self.buf.len() < total {
            return Ok(None);
        }
        let raw: Vec<u8> = self.buf.drain(..total).collect();
        let plain = match &mut self.in_cipher {
            None => raw[4..].to_vec(),
            Some(cipher) => {
                let packet_len = total - 4 - cipher.kind().tag_len();
                let (packet, tag) = raw.split_at(4 + packet_len);
                cipher.open(self.seq_in, packet, tag)?
            }
        };
        self.seq_in = self.seq_in.wrapping_add(1);
        let Some((&pad, rest)) = plain.split_first() else {
            return Err(Error::Protocol("empty packet".into()));
        };
        let end = rest
            .len()
            .checked_sub(pad as usize)
            .ok_or_else(|| Error::Protocol(format!("padding of {} bytes exceeds packet", pad)))?;
        let payload = rest[..end].to_vec();
        if payload.is_empty() {
            // Every packet starts with a message number, so an empty payload is
            // malformed; indexing it further down would abort the page.
            return Err(Error::Protocol("empty packet payload".into()));
        }
        Ok(Some(payload))
    }

    /// Waits for the next packet, reading from the transport as needed.
    pub async fn read_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some(packet) = self.take_packet()? {
                return Ok(packet);
            }
            self.fill().await?;
        }
    }

    pub async fn write_packet(&mut self, payload: &[u8]) -> Result<()> {
        // Padding aligns the packet to the cipher's block size. Without a cipher
        // the 4-byte length field counts towards the alignment; with an AEAD
        // cipher only the body does (the length is either AAD or encrypted with
        // its own key), which is what OpenSSH's `aadlen = 4` accounts for.
        let (block, aligned) = match &self.out_cipher {
            None => (8, 4 + 1 + payload.len()),
            Some(cipher) => (cipher.kind().block_size(), 1 + payload.len()),
        };
        let mut padding = block - (aligned % block);
        if padding < 4 {
            padding += block;
        }

        let packet_length = 1 + payload.len() + padding;
        let mut packet = Vec::with_capacity(packet_length + 4);
        packet.extend_from_slice(&(packet_length as u32).to_be_bytes());
        packet.push(padding as u8);
        packet.extend_from_slice(payload);
        let pad_start = packet.len();
        packet.resize(pad_start + padding, 0);
        self.rng.fill(&mut packet[pad_start..]);

        match &mut self.out_cipher {
            None => self.write_raw(&packet).await,
            Some(cipher) => {
                let sealed = cipher.seal(self.seq_out, &packet)?;
                self.write_raw(&sealed).await
            }
        }?;
        self.seq_out = self.seq_out.wrapping_add(1);
        Ok(())
    }

    /// Reads more bytes into the buffer. Cancel-safe inside `select!`.
    pub async fn fill_more(&mut self) -> Result<()> {
        self.fill().await
    }
}
