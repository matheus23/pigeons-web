//! Public key identity: the keys a client offers and the signatures it makes.
//!
//! Signing is an async trait method so the browser can delegate to WebCrypto
//! without ever exposing the private key to this crate — or to Wasm memory at
//! all, since the key can stay non-extractable.

use async_trait::async_trait;

use crate::wire::Writer;
use crate::{Error, Result};

/// A public key offered during `publickey` authentication.
#[derive(Debug, Clone)]
pub struct AuthKey {
    blob: Vec<u8>,
    algorithm: &'static str,
    fingerprint: String,
}

impl AuthKey {
    /// An Ed25519 key from its 32-byte public key.
    pub fn ed25519(public: &[u8]) -> Result<Self> {
        if public.len() != 32 {
            return Err(Error::Protocol("ed25519 public key is not 32 bytes".into()));
        }
        let blob = Writer::default().str("ssh-ed25519").string(public);
        Self::from_blob(blob.into_vec(), "ssh-ed25519")
    }

    /// A P-256 key from its 65-byte uncompressed SEC1 point.
    pub fn ecdsa_p256(point: &[u8]) -> Result<Self> {
        if point.len() != 65 || point[0] != 4 {
            return Err(Error::Protocol(
                "P-256 public key is not an uncompressed point".into(),
            ));
        }
        let blob = Writer::default()
            .str("ecdsa-sha2-nistp256")
            .str("nistp256")
            .string(point);
        Self::from_blob(blob.into_vec(), "ecdsa-sha2-nistp256")
    }

    fn from_blob(blob: Vec<u8>, algorithm: &'static str) -> Result<Self> {
        let fingerprint = crate::crypto::fingerprint(&blob);
        Ok(Self {
            blob,
            algorithm,
            fingerprint,
        })
    }

    /// The wire-format public key blob.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The SSH algorithm name used in authentication requests.
    pub fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// `SHA256:...` fingerprint, as shown by `ssh-keygen -l`.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Produces signatures with keys that this crate never sees.
///
/// Implementations return the raw signature value: 64 bytes for Ed25519, or the
/// 64-byte `r || s` pair for P-256. Wrapping it in the SSH signature blob is
/// handled here.
#[async_trait(?Send)]
pub trait Signer {
    /// Keys to try, in order.
    fn keys(&self) -> Vec<AuthKey>;

    /// Signs `data` with `key`.
    async fn sign(&self, key: &AuthKey, data: &[u8]) -> Result<Vec<u8>>;
}

/// Builds the SSH signature blob for a `publickey` request.
pub(crate) fn signature_blob(key: &AuthKey, raw: &[u8]) -> Result<Vec<u8>> {
    let inner = match key.algorithm() {
        "ssh-ed25519" => {
            if raw.len() != 64 {
                return Err(Error::Auth("Ed25519 signature is not 64 bytes".into()));
            }
            // The signature field is `string alg || string <64 bytes>`.
            raw.to_vec()
        }
        "ecdsa-sha2-nistp256" => {
            let (r, s) = raw.split_at(raw.len() / 2);
            if r.len() != 32 {
                return Err(Error::Auth("P-256 signature is not 64 bytes".into()));
            }
            // ECDSA wraps the two integers, still inside a single string.
            Writer::default().mpint(r).mpint(s).into_vec()
        }
        other => return Err(Error::Unsupported(format!("signing with {other}"))),
    };

    Ok(Writer::default()
        .str(key.algorithm())
        .string(&inner)
        .into_vec())
}

/// The data signed for public key authentication (RFC 4252 section 7).
pub(crate) fn signed_data(session_id: &[u8], request: &[u8]) -> Vec<u8> {
    Writer::default().string(session_id).raw(request).into_vec()
}
