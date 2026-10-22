//! The transport handshake: version exchange, algorithm negotiation,
//! curve25519 key exchange, key derivation, and public key authentication.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::conn::Conn;
use crate::crypto::{Cipher, CipherKind, EphemeralKey, HostKey, derive_key};
use crate::wire::{Reader, Writer};
use crate::{ClientConfig, Error, HostKeyCheck, HostKeyInfo, HostKeyVerdict, Result, Signer};

/// Messages used during the handshake.
mod msg {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const EXT_INFO: u8 = 7;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    pub const KEX_ECDH_INIT: u8 = 30;
    pub const KEX_ECDH_REPLY: u8 = 31;
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_BANNER: u8 = 53;
    pub const USERAUTH_PK_OK: u8 = 60;
}

/// OpenSSH's "strict key exchange" pseudo-algorithm (the Terrapin mitigation).
///
/// When both sides list it, a man-in-the-middle cannot inject packets around the
/// key exchange, because every message is accounted for by the sequence numbers
/// and those are reset to zero when the keys change.
const STRICT_KEX: &str = "kex-strict-c-v00@openssh.com";

const KEX_ALGORITHMS: [&str; 2] = ["curve25519-sha256", "curve25519-sha256@libssh.org"];

/// MACs are not used by the AEAD ciphers this client negotiates, but the
/// protocol still requires the lists to intersect.
const MAC_ALGORITHMS: [&str; 4] = [
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
];

/// What the server offered in its `KEXINIT`.
pub(crate) struct ServerKex {
    kex: Vec<String>,
    host_keys: Vec<String>,
    ciphers_c2s: Vec<String>,
    ciphers_s2c: Vec<String>,
    macs_c2s: Vec<String>,
    macs_s2c: Vec<String>,
    compression_c2s: Vec<String>,
    compression_s2c: Vec<String>,
    first_kex_packet_follows: bool,
}

fn build_kexinit(
    ciphers: &[&'static str],
    host_keys: &[&'static str],
    rng: &mut dyn crate::Randomness,
) -> Vec<u8> {
    let mut cookie = [0u8; 16];
    rng.fill(&mut cookie);
    Writer::message(msg::KEXINIT)
        .raw(&cookie)
        .name_list(&[STRICT_KEX, KEX_ALGORITHMS[0], KEX_ALGORITHMS[1]])
        .name_list(host_keys)
        .name_list(ciphers)
        .name_list(ciphers)
        .name_list(&MAC_ALGORITHMS)
        .name_list(&MAC_ALGORITHMS)
        .name_list(&["none"])
        .name_list(&["none"])
        .name_list(&[])
        .name_list(&[])
        .bool(false)
        .u32(0)
        .into_vec()
}

fn parse_kexinit(payload: &[u8]) -> Result<ServerKex> {
    let mut r = Reader::new(payload);
    r.byte()?; // message number
    r.raw(16)?; // cookie
    let mut names =
        || -> Result<Vec<String>> { Ok(r.name_list()?.into_iter().map(str::to_owned).collect()) };
    let kex = names()?;
    let host_keys = names()?;
    let ciphers_c2s = names()?;
    let ciphers_s2c = names()?;
    let macs_c2s = names()?;
    let macs_s2c = names()?;
    let compression_c2s = names()?;
    let compression_s2c = names()?;
    let _languages_c2s = names()?;
    let _languages_s2c = names()?;
    let first_kex_packet_follows = r.bool()?;
    let _reserved = r.u32()?;
    Ok(ServerKex {
        kex,
        host_keys,
        ciphers_c2s,
        ciphers_s2c,
        macs_c2s,
        macs_s2c,
        compression_c2s,
        compression_s2c,
        first_kex_packet_follows,
    })
}

/// Picks the first client-preferred name the server also supports.
fn negotiate(what: &str, client: &[&str], server: &[String]) -> Result<String> {
    client
        .iter()
        .find(|c| server.iter().any(|s| s == *c))
        .map(|c| (*c).to_owned())
        .ok_or_else(|| {
            Error::Protocol(format!(
                "no shared {what}; the server offers [{}]",
                server.join(", ")
            ))
        })
}

pub(crate) struct Handshake {
    pub host_key: HostKey,
    pub server_version: String,
    pub banners: Vec<String>,
    pub cipher: &'static str,
}

/// Turns a `DISCONNECT` packet into an error.
pub(crate) fn disconnect(packet: &[u8]) -> Error {
    let mut r = Reader::new(packet.get(1..).unwrap_or(&[]));
    let reason = r.u32().unwrap_or(0);
    let message = r
        .string()
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_else(|_| "no reason given".into());
    Error::Disconnected(reason, message)
}

/// Runs the handshake up to and including authentication.
pub(crate) async fn handshake<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<T>,
    cfg: &ClientConfig,
    signer: &dyn Signer,
    check: &dyn HostKeyCheck,
) -> Result<Handshake> {
    let mut banners = Vec::new();

    // 1. Version exchange. The server may send human-readable lines first.
    conn.write_raw(format!("{}\r\n", cfg.client_version).as_bytes())
        .await?;
    let server_version = loop {
        let line = conn.read_line().await?;
        if line.starts_with("SSH-2.0-") || line.starts_with("SSH-1.99-") {
            break line;
        }
    };

    // 2. Algorithm negotiation.
    let i_c = build_kexinit(&cfg.ciphers, &cfg.host_key_algorithms, conn.rng());
    conn.write_packet(&i_c).await?;
    let mut skipped_before_kexinit = 0;
    let i_s = loop {
        let packet = conn.read_packet().await?;
        match packet[0] {
            msg::KEXINIT => break packet,
            msg::IGNORE | msg::DEBUG => {
                skipped_before_kexinit += 1;
                continue;
            }
            msg::DISCONNECT => return Err(disconnect(&packet)),
            other => {
                return Err(Error::Protocol(format!(
                    "expected KEXINIT, got message {other}"
                )));
            }
        }
    };

    let server = parse_kexinit(&i_s)?;
    // Strict key exchange, if the server offers it: the KEXINIT must have been the
    // first packet, nothing else may appear until NEWKEYS, and the sequence
    // numbers restart when the keys change.
    let strict_kex = server.kex.iter().any(|name| name == STRICT_KEX);
    if strict_kex && skipped_before_kexinit > 0 {
        return Err(Error::Protocol(
            "server sent packets before KEXINIT under strict key exchange".into(),
        ));
    }

    let kex_alg = negotiate("key exchange algorithm", &KEX_ALGORITHMS, &server.kex)?;
    let host_key_alg = negotiate(
        "host key algorithm",
        &cfg.host_key_algorithms,
        &server.host_keys,
    )?;
    let cipher_c2s = negotiate("cipher", &cfg.ciphers, &server.ciphers_c2s)?;
    let cipher_s2c = negotiate("cipher", &cfg.ciphers, &server.ciphers_s2c)?;
    negotiate("MAC algorithm", &MAC_ALGORITHMS, &server.macs_c2s)?;
    negotiate("MAC algorithm", &MAC_ALGORITHMS, &server.macs_s2c)?;
    if negotiate("compression", &["none"], &server.compression_c2s)? != "none"
        || negotiate("compression", &["none"], &server.compression_s2c)? != "none"
    {
        return Err(Error::Unsupported("compression".into()));
    }

    // A server may optimistically send its key exchange packet before seeing
    // ours. If its guess was wrong, that packet has to be dropped.
    if server.first_kex_packet_follows {
        let guessed_kex = server.kex.first().is_some_and(|k| *k == kex_alg);
        let guessed_host_key = server.host_keys.first().is_some_and(|k| *k == host_key_alg);
        if !(guessed_kex && guessed_host_key) {
            conn.read_packet().await?;
        }
    }

    // 3. Curve25519 key exchange.
    let ephemeral = EphemeralKey::generate(conn.rng());
    let init = Writer::message(msg::KEX_ECDH_INIT)
        .string(ephemeral.public())
        .into_vec();
    conn.write_packet(&init).await?;

    let reply = loop {
        let packet = conn.read_packet().await?;
        match packet[0] {
            msg::KEX_ECDH_REPLY => break packet,
            msg::IGNORE | msg::DEBUG if !strict_kex => continue,
            msg::DISCONNECT => return Err(disconnect(&packet)),
            other => {
                return Err(Error::Protocol(format!(
                    "expected key exchange reply, got message {other}"
                )));
            }
        }
    };
    let mut r = Reader::new(&reply[1..]);
    let host_key_blob = r.string()?;
    let server_public = r.string()?;
    let signature = r.string()?;
    let shared = ephemeral.agree(server_public)?;

    // 4. Exchange hash over every value exchanged so far (RFC 8731).
    let hash_input = Writer::default()
        .str(&cfg.client_version)
        .str(&server_version)
        .string(&i_c)
        .string(&i_s)
        .string(host_key_blob)
        .string(ephemeral.public())
        .string(server_public)
        .mpint(&shared)
        .into_vec();
    let exchange_hash = crate::crypto::sha256(&hash_input);

    let host_key = HostKey::parse(host_key_blob)?;
    host_key.verify(&exchange_hash, signature)?;
    match check.check(&HostKeyInfo {
        algorithm: host_key_alg.clone(),
        fingerprint: host_key.fingerprint.clone(),
        blob: host_key_blob.to_vec(),
    }) {
        HostKeyVerdict::Trust => {}
        HostKeyVerdict::Reject(reason) => return Err(Error::HostKeyRejected(reason)),
    }

    // 5. Derive keys and switch both directions to the negotiated cipher.
    let k = Writer::default().mpint(&shared).into_vec();
    let session_id = exchange_hash.as_slice();

    let kind_c2s =
        CipherKind::from_name(&cipher_c2s).ok_or_else(|| Error::Unsupported(cipher_c2s.clone()))?;
    let kind_s2c =
        CipherKind::from_name(&cipher_s2c).ok_or_else(|| Error::Unsupported(cipher_s2c.clone()))?;
    let key_c2s = derive_key(&k, session_id, b'C', session_id, kind_c2s.key_len());
    let iv_c2s = derive_key(&k, session_id, b'A', session_id, kind_c2s.iv_len());
    let key_s2c = derive_key(&k, session_id, b'D', session_id, kind_s2c.key_len());
    let iv_s2c = derive_key(&k, session_id, b'B', session_id, kind_s2c.iv_len());

    conn.write_packet(&[msg::NEWKEYS]).await?;
    conn.set_out_cipher(Cipher::new(kind_c2s, key_c2s, &iv_c2s));
    if strict_kex {
        conn.reset_out_sequence();
    }
    loop {
        let packet = conn.read_packet().await?;
        match packet[0] {
            msg::NEWKEYS => break,
            msg::IGNORE | msg::DEBUG if !strict_kex => continue,
            msg::DISCONNECT => return Err(disconnect(&packet)),
            other => {
                return Err(Error::Protocol(format!(
                    "expected NEWKEYS, got message {other}"
                )));
            }
        }
    }
    conn.set_in_cipher(Cipher::new(kind_s2c, key_s2c, &iv_s2c));
    if strict_kex {
        conn.reset_in_sequence();
    }

    // 6. Authenticate with the first identity key the server accepts.
    conn.write_packet(
        &Writer::message(msg::SERVICE_REQUEST)
            .str("ssh-userauth")
            .into_vec(),
    )
    .await?;
    loop {
        let packet = conn.read_packet().await?;
        match packet[0] {
            msg::SERVICE_ACCEPT => break,
            msg::EXT_INFO | msg::IGNORE | msg::DEBUG => continue,
            msg::DISCONNECT => return Err(disconnect(&packet)),
            other => {
                return Err(Error::Protocol(format!(
                    "expected service accept, got message {other}"
                )));
            }
        }
    }

    let keys = signer.keys();
    if keys.is_empty() {
        return Err(Error::Auth("no identity keys configured".into()));
    }

    let mut failure = String::from("no key was accepted");
    for key in &keys {
        let unsigned = Writer::message(msg::USERAUTH_REQUEST)
            .str(&cfg.user)
            .str("ssh-connection")
            .str("publickey")
            .bool(true)
            .str(key.algorithm())
            .string(key.blob())
            .into_vec();

        let signed = crate::auth::signed_data(&exchange_hash, &unsigned);
        let raw_signature = signer.sign(key, &signed).await?;
        let signature_blob = crate::auth::signature_blob(key, &raw_signature)?;

        let packet = Writer::default()
            .raw(&unsigned)
            .string(&signature_blob)
            .into_vec();
        conn.write_packet(&packet).await?;

        loop {
            let packet = conn.read_packet().await?;
            match packet[0] {
                msg::USERAUTH_SUCCESS => {
                    return Ok(Handshake {
                        host_key,
                        server_version,
                        banners,
                        cipher: leak_name(&cipher_c2s),
                    });
                }
                msg::USERAUTH_BANNER => {
                    let mut r = Reader::new(&packet[1..]);
                    banners.push(String::from_utf8_lossy(r.string()?).into_owned());
                }
                msg::USERAUTH_FAILURE => {
                    let mut r = Reader::new(&packet[1..]);
                    let methods = String::from_utf8_lossy(r.string()?).into_owned();
                    failure = format!(
                        "the server rejected {} (it accepts: {}). Is this key in authorized_keys?",
                        key.fingerprint(),
                        if methods.is_empty() {
                            "nothing"
                        } else {
                            &methods
                        }
                    );
                    break;
                }
                msg::USERAUTH_PK_OK => continue,
                msg::EXT_INFO | msg::IGNORE | msg::DEBUG => continue,
                msg::DISCONNECT => return Err(disconnect(&packet)),
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected message {other} during authentication"
                    )));
                }
            }
        }
    }
    Err(Error::Auth(failure))
}

/// The cipher names come from static strings in `CipherKind::name`.
fn leak_name(name: &str) -> &'static str {
    CipherKind::from_name(name).map_or("unknown", |k| k.name())
}
