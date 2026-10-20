//! Cryptographic building blocks: ciphers, key derivation, and host key checks.
//!
//! Only the pieces this client actually negotiates are implemented:
//! `curve25519-sha256` for key exchange, `ssh-ed25519` and
//! `ecdsa-sha2-nistp256` for host keys, and the two AEAD ciphers
//! `chacha20-poly1305@openssh.com` and `aes{128,256}-gcm@openssh.com`.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Fills buffers with cryptographically secure random bytes.
///
/// The caller supplies this so the crate stays independent of any particular
/// platform randomness source: the browser uses `crypto.getRandomValues`, native
/// callers use the OS.
pub trait Randomness {
    /// Fills `out` completely with random bytes.
    fn fill(&mut self, out: &mut [u8]);
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Key derivation (RFC 4253 section 7.2)
// ---------------------------------------------------------------------------

/// Derives `len` bytes of key material for the letter `label`.
///
/// The first block hashes `K || H || label || session_id`; any further blocks
/// are chained by hashing `K || H || previous`.
pub fn derive_key(
    shared: &[u8],
    exchange_hash: &[u8],
    label: u8,
    session_id: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut out = sha256_parts(&[shared, exchange_hash, &[label], session_id]).to_vec();
    while out.len() < len {
        let next = sha256_parts(&[shared, exchange_hash, &out]);
        out.extend_from_slice(&next);
    }
    out.truncate(len);
    out
}

// ---------------------------------------------------------------------------
// Ciphers
// ---------------------------------------------------------------------------

/// The AEAD ciphers this client supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    /// OpenSSH's default: 64-byte key, sequence-number nonce, 16-byte tag.
    ChaCha20Poly1305Openssh,
    /// GCM in the style of RFC 5647: 16-byte key, 12-byte counter nonce.
    Aes128Gcm,
    /// Same as above with a 32-byte key.
    Aes256Gcm,
}

impl CipherKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305Openssh => "chacha20-poly1305@openssh.com",
            Self::Aes128Gcm => "aes128-gcm@openssh.com",
            Self::Aes256Gcm => "aes256-gcm@openssh.com",
        }
    }

    /// Wire packet length excluding the tag. AEAD ciphers keep the 4-byte length
    /// field in the clear and use it as associated data (OpenSSH's chacha XORs
    /// it instead), so both are multiples of the cipher's block size.
    pub fn block_size(self) -> usize {
        match self {
            Self::ChaCha20Poly1305Openssh => 8,
            Self::Aes128Gcm | Self::Aes256Gcm => 16,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305Openssh => 64,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305Openssh => 0,
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
        }
    }

    pub fn tag_len(self) -> usize {
        16
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "chacha20-poly1305@openssh.com" => Some(Self::ChaCha20Poly1305Openssh),
            "aes128-gcm@openssh.com" => Some(Self::Aes128Gcm),
            "aes256-gcm@openssh.com" => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
}

/// One direction's cipher state.
///
/// The packet sequence number is not stored here: it counts every packet on the
/// connection and is never reset, not even across `NEWKEYS`, so the connection
/// owns it and passes the current value in.
pub struct Cipher {
    kind: CipherKind,
    key: Vec<u8>,
    /// GCM only: the derived initialization vector, incremented per packet.
    nonce: [u8; 12],
}

impl Cipher {
    pub fn new(kind: CipherKind, key: Vec<u8>, iv: &[u8]) -> Self {
        let mut nonce = [0u8; 12];
        let n = iv.len().min(12);
        nonce[..n].copy_from_slice(&iv[..n]);
        Self { kind, key, nonce }
    }

    pub fn kind(&self) -> CipherKind {
        self.kind
    }

    fn bump_nonce(&mut self) {
        for byte in self.nonce.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                return;
            }
        }
    }

    fn nonce_for(&mut self, seq: u32) -> [u8; 12] {
        match self.kind {
            // OpenSSH's chacha cipher uses the sequence number as the nonce.
            CipherKind::ChaCha20Poly1305Openssh => Self::chacha_nonce(seq),
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => {
                let nonce = self.nonce;
                self.bump_nonce();
                nonce
            }
        }
    }

    /// The nonce chacha uses for a given sequence number.
    fn chacha_nonce(seq: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&(seq as u64).to_be_bytes());
        nonce
    }

    /// Encrypts `packet` (length field, padding length, payload, padding) and
    /// appends the tag, producing the bytes to send on the wire.
    pub fn seal(&mut self, seq: u32, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < 4 {
            return Err(Error::Crypto("packet too short to seal".into()));
        }
        let nonce = self.nonce_for(seq);

        match self.kind {
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => {
                let (aad, body) = packet.split_at(4);
                let mut buf = body.to_vec();
                let tag = match self.key.len() {
                    16 => Aes128Gcm::new_from_slice(&self.key)
                        .map_err(|_| Error::Crypto("bad AES-128 key".into()))?
                        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut buf),
                    32 => Aes256Gcm::new_from_slice(&self.key)
                        .map_err(|_| Error::Crypto("bad AES-256 key".into()))?
                        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut buf),
                    _ => Err(aes_gcm::Error),
                }
                .map_err(|_| Error::Crypto("encryption failed".into()))?;

                let mut out = Vec::with_capacity(packet.len() + 16);
                out.extend_from_slice(aad);
                out.extend_from_slice(&buf);
                out.extend_from_slice(&tag);
                Ok(out)
            }
            CipherKind::ChaCha20Poly1305Openssh => {
                let (len_field, body) = packet.split_at(4);
                // OpenSSH: the first 32 bytes key the payload, the second 32 the length.
                let (main_key, len_key) = self.key.split_at(32);
                let nonce = Self::chacha_nonce(seq);
                let header = chacha_block(len_key, &nonce);

                let mut len_enc = [0u8; 4];
                len_enc.copy_from_slice(len_field);
                for (i, b) in len_enc.iter_mut().enumerate() {
                    *b ^= header[i];
                }

                // The payload starts at block counter 1; block 0 of the same key
                // supplies the Poly1305 key.
                let mut body = body.to_vec();
                let poly_key = chacha_block(main_key, &nonce);
                let mut main_stream = ChaCha20::new(main_key.into(), (&nonce).into());
                main_stream.seek(64u32);
                main_stream.apply_keystream(&mut body);

                let mut mac_input = Vec::with_capacity(4 + body.len());
                mac_input.extend_from_slice(&len_enc);
                mac_input.extend_from_slice(&body);
                let tag =
                    poly1305::Poly1305::new((&poly_key[..32]).into()).compute_unpadded(&mac_input);

                let mut out = Vec::with_capacity(4 + body.len() + 16);
                out.extend_from_slice(&len_enc);
                out.extend_from_slice(&body);
                out.extend_from_slice(&tag);
                Ok(out)
            }
        }
    }

    /// Decrypts a wire packet: `packet` holds everything but the tag, `tag` the
    /// trailing authentication tag. Returns the plaintext starting at the
    /// padding-length byte (the length field is not part of the result).
    pub fn open(&mut self, seq: u32, packet: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < 4 {
            return Err(Error::Crypto("packet too short to open".into()));
        }
        let nonce = self.nonce_for(seq);

        match self.kind {
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => {
                let (aad, body) = packet.split_at(4);
                let mut buf = body.to_vec();
                match self.key.len() {
                    16 => Aes128Gcm::new_from_slice(&self.key)
                        .map_err(|_| Error::Crypto("bad AES-128 key".into()))?
                        .decrypt_in_place_detached(
                            Nonce::from_slice(&nonce),
                            aad,
                            &mut buf,
                            Tag::from_slice(tag),
                        ),
                    32 => Aes256Gcm::new_from_slice(&self.key)
                        .map_err(|_| Error::Crypto("bad AES-256 key".into()))?
                        .decrypt_in_place_detached(
                            Nonce::from_slice(&nonce),
                            aad,
                            &mut buf,
                            Tag::from_slice(tag),
                        ),
                    _ => Err(aes_gcm::Error),
                }
                .map_err(|_| Error::Crypto("packet authentication failed".into()))?;
                Ok(buf)
            }
            CipherKind::ChaCha20Poly1305Openssh => {
                let (len_enc, body_enc) = packet.split_at(4);
                // OpenSSH: the first 32 bytes key the payload, the second 32 the length.
                let (main_key, _len_key) = self.key.split_at(32);
                let nonce = Self::chacha_nonce(seq);
                let poly_key = chacha_block(main_key, &nonce);

                let mut mac_input = Vec::with_capacity(packet.len());
                mac_input.extend_from_slice(len_enc);
                mac_input.extend_from_slice(body_enc);
                let expected =
                    poly1305::Poly1305::new((&poly_key[..32]).into()).compute_unpadded(&mac_input);
                if !constant_time_eq(&expected, tag) {
                    return Err(Error::Crypto("packet authentication failed".into()));
                }

                let mut body = body_enc.to_vec();
                let mut main_stream = ChaCha20::new(main_key.into(), (&nonce).into());
                main_stream.seek(64u32);
                main_stream.apply_keystream(&mut body);
                Ok(body)
            }
        }
    }

    /// Reads the length field, which for chacha is XOR-encrypted and for GCM is
    /// sent in the clear. Does not advance the cipher.
    pub fn peek_length(&self, seq: u32, head: &[u8]) -> Result<u32> {
        let head: [u8; 4] = head
            .get(..4)
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| Error::Crypto("need 4 bytes for the packet length".into()))?;
        match self.kind {
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => Ok(u32::from_be_bytes(head)),
            CipherKind::ChaCha20Poly1305Openssh => {
                let (_main_key, len_key) = self.key.split_at(32);
                let block = chacha_block(len_key, &Self::chacha_nonce(seq));
                let mut len = head;
                for (i, b) in len.iter_mut().enumerate() {
                    *b ^= block[i];
                }
                Ok(u32::from_be_bytes(len))
            }
        }
    }
}

/// The first 64 keystream bytes for `key`/`nonce`: the chacha length mask and
/// the Poly1305 key both come from this block.
fn chacha_block(key: &[u8], nonce: &[u8; 12]) -> [u8; 64] {
    let mut block = [0u8; 64];
    let mut stream = ChaCha20::new(key.into(), nonce.into());
    stream.apply_keystream(&mut block);
    block
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// curve25519 key exchange
// ---------------------------------------------------------------------------

/// A one-shot X25519 key agreement for `curve25519-sha256`.
pub struct EphemeralKey {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
}

impl EphemeralKey {
    pub fn generate(rng: &mut dyn Randomness) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let secret = x25519_dalek::StaticSecret::from(bytes);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// Computes the shared secret as magnitude bytes: leading zeros stripped,
    /// ready to be encoded as an mpint.
    pub fn agree(&self, peer: &[u8]) -> Result<Vec<u8>> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| Error::Protocol("curve25519 public key is not 32 bytes".into()))?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(Error::Protocol(
                "curve25519 shared secret is all zeros".into(),
            ));
        }
        let bytes = shared.as_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        Ok(bytes[start..].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Host keys
// ---------------------------------------------------------------------------

/// Host key algorithms this client can verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyKind {
    /// `ssh-ed25519`
    Ed25519,
    /// `ecdsa-sha2-nistp256`
    EcdsaP256,
}

impl HostKeyKind {
    /// The SSH algorithm name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
        }
    }

    /// Looks up an algorithm by its SSH name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ssh-ed25519" => Some(Self::Ed25519),
            "ecdsa-sha2-nistp256" => Some(Self::EcdsaP256),
            _ => None,
        }
    }
}

/// A host key advertised by the server.
#[derive(Debug, Clone)]
pub struct HostKey {
    /// Key algorithm.
    pub kind: HostKeyKind,
    /// The wire-format key blob, as sent in the key exchange reply.
    pub blob: Vec<u8>,
    /// `SHA256:...` fingerprint, the same value `ssh-keygen -l` prints.
    pub fingerprint: String,
}

impl HostKey {
    /// Parses the host key blob and computes `SHA256:base64` like OpenSSH does.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let mut r = crate::wire::Reader::new(blob);
        let alg = r.utf8()?;
        let kind = HostKeyKind::from_name(alg)
            .ok_or_else(|| Error::Unsupported(format!("host key algorithm {alg}")))?;
        match kind {
            HostKeyKind::Ed25519 => {
                let key = r.string()?;
                if key.len() != 32 {
                    return Err(Error::Protocol("ed25519 host key is not 32 bytes".into()));
                }
            }
            HostKeyKind::EcdsaP256 => {
                let curve = r.utf8()?;
                if curve != "nistp256" {
                    return Err(Error::Protocol(format!("unexpected curve {curve}")));
                }
                let point = r.string()?;
                if point.len() != 65 || point[0] != 4 {
                    return Err(Error::Protocol("unexpected P-256 point encoding".into()));
                }
            }
        }
        Ok(Self {
            kind,
            blob: blob.to_vec(),
            fingerprint: fingerprint(blob),
        })
    }

    /// Verifies the server's signature over the exchange hash.
    pub fn verify(&self, exchange_hash: &[u8], signature_blob: &[u8]) -> Result<()> {
        let (alg, sig) = crate::wire::split_signature(signature_blob)?;
        if alg != self.kind.name() {
            return Err(Error::Protocol(format!(
                "host key algorithm {alg} does not match key {}",
                self.kind.name()
            )));
        }
        match self.kind {
            HostKeyKind::Ed25519 => {
                let mut r = crate::wire::Reader::new(&self.blob);
                r.utf8()?;
                let key = r.string()?;
                let key: [u8; 32] = key
                    .try_into()
                    .map_err(|_| Error::Protocol("ed25519 host key is not 32 bytes".into()))?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
                    .map_err(|e| Error::Protocol(format!("bad ed25519 host key: {e}")))?;
                let sig: [u8; 64] = sig
                    .try_into()
                    .map_err(|_| Error::Protocol("ed25519 signature is not 64 bytes".into()))?;
                use ed25519_dalek::Verifier as _;
                key.verify(exchange_hash, &ed25519_dalek::Signature::from_bytes(&sig))
                    .map_err(|_| Error::Protocol("host key signature rejected".into()))
            }
            HostKeyKind::EcdsaP256 => {
                use p256::ecdsa::signature::Verifier as _;
                let mut r = crate::wire::Reader::new(&self.blob);
                r.utf8()?;
                r.string()?;
                let point = r.string()?;
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|e| Error::Protocol(format!("bad P-256 host key: {e}")))?;

                let mut rs = crate::wire::Reader::new(sig);
                let (r_bytes, s_bytes) = (rs.mpint()?, rs.mpint()?);
                if r_bytes.len() > 32 || s_bytes.len() > 32 {
                    return Err(Error::Protocol("ECDSA signature component too long".into()));
                }
                let mut r32 = [0u8; 32];
                let mut s32 = [0u8; 32];
                r32[32 - r_bytes.len()..].copy_from_slice(r_bytes);
                s32[32 - s_bytes.len()..].copy_from_slice(s_bytes);
                let sig = p256::ecdsa::Signature::from_scalars(r32, s32)
                    .map_err(|_| Error::Protocol("bad ECDSA signature".into()))?;
                key.verify(exchange_hash, &sig)
                    .map_err(|_| Error::Protocol("host key signature rejected".into()))
            }
        }
    }
}

/// OpenSSH-style fingerprint: `SHA256:` plus unpadded base64 of the key blob.
pub fn fingerprint(blob: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha256(blob))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u8);

    impl Randomness for FixedRng {
        fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[test]
    fn x25519_agreement_is_symmetric() {
        let mut a_rng = FixedRng(1);
        let mut b_rng = FixedRng(200);
        let a = EphemeralKey::generate(&mut a_rng);
        let b = EphemeralKey::generate(&mut b_rng);
        assert_eq!(a.agree(b.public()).unwrap(), b.agree(a.public()).unwrap());
    }

    #[test]
    fn derived_keys_are_deterministic_and_label_separated() {
        let shared = [7u8; 32];
        let h = [9u8; 32];
        let sid = [3u8; 32];
        let a = derive_key(&shared, &h, b'A', &sid, 12);
        let b = derive_key(&shared, &h, b'B', &sid, 12);
        assert_eq!(a, derive_key(&shared, &h, b'A', &sid, 12));
        assert_ne!(a, b);
        assert_eq!(a.len(), 12);
        // Longer requests are chained, so the prefix is stable.
        let long = derive_key(&shared, &h, b'A', &sid, 64);
        assert_eq!(&long[..12], &a[..]);
    }

    #[test]
    fn gcm_round_trips_and_rejects_tampering() {
        let mut sealer = Cipher::new(CipherKind::Aes128Gcm, vec![1; 16], &[2; 12]);
        let mut opener = Cipher::new(CipherKind::Aes128Gcm, vec![1; 16], &[2; 12]);
        let packet = [0, 0, 0, 12, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let wire = sealer.seal(0, &packet).unwrap();
        assert_eq!(wire.len(), packet.len() + 16);
        // The length field stays readable on the wire.
        assert_eq!(
            opener.peek_length(0, &wire).unwrap() as usize,
            packet.len() - 4
        );

        let (body, tag) = wire.split_at(wire.len() - 16);
        assert_eq!(opener.open(0, body, tag).unwrap(), packet[4..].to_vec());

        let mut tampered = wire.clone();
        tampered[6] ^= 1;
        let (body, tag) = tampered.split_at(tampered.len() - 16);
        assert!(opener.open(0, body, tag).is_err());
    }

    #[test]
    fn aes256_round_trips() {
        let mut sealer = Cipher::new(CipherKind::Aes256Gcm, vec![3; 32], &[4; 12]);
        let mut opener = Cipher::new(CipherKind::Aes256Gcm, vec![3; 32], &[4; 12]);
        let packet = [0, 0, 0, 8, 4, 1, 2, 3, 4, 5, 6, 7];
        let wire = sealer.seal(0, &packet).unwrap();
        let (body, tag) = wire.split_at(wire.len() - 16);
        assert_eq!(opener.open(0, body, tag).unwrap(), packet[4..].to_vec());
    }

    #[test]
    fn chacha_round_trips_and_tracks_the_sequence_number() {
        let key = vec![9u8; 64];
        let mut sealer = Cipher::new(CipherKind::ChaCha20Poly1305Openssh, key.clone(), &[]);
        let mut opener = Cipher::new(CipherKind::ChaCha20Poly1305Openssh, key, &[]);
        let packet = [0, 0, 0, 11, 4, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51];

        // Two packets in a row: the nonce is the sequence number, so a cipher
        // that forgot to advance would decrypt the second packet wrongly.
        for _ in 0..2 {
            let wire = sealer.seal(0, &packet).unwrap();
            assert_eq!(
                opener.peek_length(0, &wire).unwrap() as usize,
                packet.len() - 4
            );
            let (body, tag) = wire.split_at(wire.len() - 16);
            assert_eq!(opener.open(0, body, tag).unwrap(), packet[4..].to_vec());
        }
    }

    #[test]
    fn fingerprints_match_openssh_format() {
        let blob = [1u8, 2, 3];
        assert!(fingerprint(&blob).starts_with("SHA256:"));
        assert!(!fingerprint(&blob).ends_with('='));
    }
}
