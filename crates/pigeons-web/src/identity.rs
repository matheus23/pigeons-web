//! The browser SSH identity.
//!
//! The private key is a WebCrypto key that never becomes extractable, and never
//! enters Wasm memory: signing happens inside the browser's crypto
//! implementation, so this crate only ever holds a `CryptoKey` handle.
//!
//! Keys live in IndexedDB rather than localStorage because `localStorage` only
//! stores strings, while `CryptoKey` objects survive (structured clone) in IDB.
//! The SSH host configuration — the `~/.ssh/config` equivalent — is plain JSON
//! in localStorage.

use base64::Engine as _;
use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::CryptoKey;

use kereru::{AuthKey, Result as SshResult, Signer};

use crate::platform::{self, Result};

const STORAGE_KEY: &str = "identity";

/// PKCS#8 DER prefix for an Ed25519 private key; the 32-byte seed follows it.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Which signature scheme the browser gave us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    EcdsaP256,
}

impl Algorithm {
    fn storage_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "ecdsa-p256",
        }
    }

    fn from_storage_name(name: &str) -> Option<Self> {
        match name {
            "ed25519" => Some(Self::Ed25519),
            "ecdsa-p256" => Some(Self::EcdsaP256),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::EcdsaP256 => "ECDSA P-256",
        }
    }
}

pub struct Identity {
    algorithm: Algorithm,
    key: CryptoKey,
    public: Vec<u8>,
    auth_key: AuthKey,
}

impl Identity {
    /// Loads the stored identity, creating one on first use.
    pub async fn load_or_create() -> Result<Self> {
        if let Some(identity) = Self::load().await? {
            return Ok(identity);
        }
        Self::create().await
    }

    async fn load() -> Result<Option<Self>> {
        let Some(stored) = platform::idb_get(STORAGE_KEY).await? else {
            return Ok(None);
        };
        let algorithm = Reflect::get(&stored, &JsValue::from_str("algorithm"))
            .ok()
            .and_then(|v| v.as_string())
            .and_then(|name| Algorithm::from_storage_name(&name));
        let public = Reflect::get(&stored, &JsValue::from_str("public"))
            .map_err(|_| "stored identity has no public key".to_string())
            .and_then(platform::bytes_of);
        let key = Reflect::get(&stored, &JsValue::from_str("key"))
            .map_err(|_| "stored identity has no private key".to_string())
            .and_then(platform::as_crypto_key);

        match (algorithm, public, key) {
            (Some(algorithm), Ok(public), Ok(key)) => {
                let auth_key = auth_key_for(algorithm, &public)?;
                Ok(Some(Self {
                    algorithm,
                    key,
                    public,
                    auth_key,
                }))
            }
            // A partial or foreign record is not worth repairing: replace it.
            _ => {
                platform::idb_delete(STORAGE_KEY).await.ok();
                Ok(None)
            }
        }
    }

    /// Creates a fresh identity, preferring Ed25519.
    async fn create() -> Result<Self> {
        match Self::create_ed25519().await {
            Ok(identity) => Ok(identity),
            Err(ed25519_error) => {
                platform::log(&format!(
                    "Ed25519 unavailable ({ed25519_error}); falling back to P-256"
                ));
                Self::create_p256().await
            }
        }
    }

    /// Ed25519 from a seed we generate.
    ///
    /// Importing a seed as non-extractable PKCS#8 means no extractable key ever
    /// exists. The public half is derived locally, which is why `ed25519-dalek`
    /// is a dependency here as well as in the SSH crate.
    async fn create_ed25519() -> Result<Self> {
        let mut seed = [0u8; 32];
        {
            use kereru::Randomness as _;
            platform::BrowserRng.fill(&mut seed);
        }
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();

        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
        pkcs8.extend_from_slice(&seed);
        seed.fill(0);

        let key = JsFuture::from(
            platform::subtle()
                .import_key_with_str(
                    "pkcs8",
                    &platform::object(&pkcs8),
                    "Ed25519",
                    false,
                    &platform::array_of(&["sign"]),
                )
                .map_err(|e| format!("importing Ed25519 key: {e:?}"))?,
        )
        .await
        .map_err(|e| format!("importing Ed25519 key: {e:?}"))?;
        pkcs8.fill(0);

        let identity = Self {
            algorithm: Algorithm::Ed25519,
            key: platform::as_crypto_key(key)?,
            auth_key: AuthKey::ed25519(&public).map_err(|e| e.to_string())?,
            public: public.to_vec(),
        };
        identity.save().await?;
        Ok(identity)
    }

    /// P-256 fallback for browsers without WebCrypto Ed25519.
    ///
    /// WebCrypto cannot import a P-256 key from a seed, so this generates an
    /// extractable pair, keeps the public point, then re-imports the private
    /// half as non-extractable and drops the exported bytes. The window in which
    /// an extractable private key exists is one `await`.
    async fn create_p256() -> Result<Self> {
        let params = p256_params();
        let pair = JsFuture::from(
            platform::subtle()
                .generate_key_with_object(&params, true, &platform::array_of(&["sign", "verify"]))
                .map_err(|e| format!("generating P-256 key: {e:?}"))?,
        )
        .await
        .map_err(|e| format!("generating P-256 key: {e:?}"))?;

        let public_key: CryptoKey = Reflect::get(&pair, &JsValue::from_str("publicKey"))
            .map_err(|_| "generated key has no public half".to_string())?
            .unchecked_into();
        let private_key: CryptoKey = Reflect::get(&pair, &JsValue::from_str("privateKey"))
            .map_err(|_| "generated key has no private half".to_string())?
            .unchecked_into();

        let public = JsFuture::from(
            platform::subtle()
                .export_key("raw", &public_key)
                .map_err(|e| format!("exporting P-256 public key: {e:?}"))?,
        )
        .await
        .map_err(|e| format!("exporting P-256 public key: {e:?}"))?
        .unchecked_into::<js_sys::Uint8Array>()
        .to_vec();

        let der = JsFuture::from(
            platform::subtle()
                .export_key("pkcs8", &private_key)
                .map_err(|e| format!("exporting P-256 private key: {e:?}"))?,
        )
        .await
        .map_err(|e| format!("exporting P-256 private key: {e:?}"))?
        .unchecked_into::<js_sys::Uint8Array>()
        .to_vec();

        let key = JsFuture::from(
            platform::subtle()
                .import_key_with_object(
                    "pkcs8",
                    &platform::object(&der),
                    &params,
                    false,
                    &platform::array_of(&["sign"]),
                )
                .map_err(|e| format!("re-importing P-256 key: {e:?}"))?,
        )
        .await
        .map_err(|e| format!("re-importing P-256 key: {e:?}"))?;

        let identity = Self {
            algorithm: Algorithm::EcdsaP256,
            key: platform::as_crypto_key(key)?,
            auth_key: AuthKey::ecdsa_p256(&public).map_err(|e| e.to_string())?,
            public,
        };
        identity.save().await?;
        Ok(identity)
    }

    async fn save(&self) -> Result<()> {
        let record = Object::new();
        let _ = Reflect::set(
            &record,
            &"algorithm".into(),
            &JsValue::from_str(self.algorithm.storage_name()),
        );
        let _ = Reflect::set(
            &record,
            &"public".into(),
            &JsValue::from(js_sys::Uint8Array::from(self.public.as_slice())),
        );
        let _ = Reflect::set(&record, &"key".into(), self.key.as_ref());
        platform::idb_put(STORAGE_KEY, &record).await
    }

    /// Discards the stored key so the next load creates a new one.
    pub async fn forget(&self) -> Result<()> {
        platform::idb_delete(STORAGE_KEY).await
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn fingerprint(&self) -> &str {
        self.auth_key.fingerprint()
    }

    /// The `authorized_keys` line for this identity.
    pub fn public_key_line(&self) -> String {
        format!(
            "{} {}",
            self.auth_key.algorithm(),
            base64::engine::general_purpose::STANDARD.encode(self.auth_key.blob())
        )
    }
}

#[async_trait::async_trait(?Send)]
impl Signer for Identity {
    fn keys(&self) -> Vec<AuthKey> {
        vec![self.auth_key.clone()]
    }

    async fn sign(&self, _key: &AuthKey, data: &[u8]) -> SshResult<Vec<u8>> {
        let promise = match self.algorithm {
            Algorithm::Ed25519 => platform::subtle()
                .sign_with_str_and_buffer_source("Ed25519", &self.key, &platform::object(data))
                .map_err(|e| kereru::Error::Auth(format!("signing failed: {e:?}")))?,
            Algorithm::EcdsaP256 => platform::subtle()
                .sign_with_object_and_buffer_source(
                    &p256_params(),
                    &self.key,
                    &platform::object(data),
                )
                .map_err(|e| kereru::Error::Auth(format!("signing failed: {e:?}")))?,
        };
        let signature = JsFuture::from(promise)
            .await
            .map_err(|e| kereru::Error::Auth(format!("signing failed: {e:?}")))?;
        platform::bytes_of(signature).map_err(kereru::Error::Auth)
    }
}

fn auth_key_for(algorithm: Algorithm, public: &[u8]) -> Result<AuthKey> {
    let key = match algorithm {
        Algorithm::Ed25519 => AuthKey::ed25519(public),
        Algorithm::EcdsaP256 => AuthKey::ecdsa_p256(public),
    };
    key.map_err(|e| format!("invalid stored public key: {e}"))
}

fn p256_params() -> Object {
    let params = Object::new();
    let _ = Reflect::set(&params, &"name".into(), &JsValue::from_str("ECDSA"));
    let _ = Reflect::set(&params, &"namedCurve".into(), &JsValue::from_str("P-256"));
    params
}
