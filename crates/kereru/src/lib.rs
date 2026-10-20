//! A small SSH client that compiles to WebAssembly.
//!
//! `kereru` speaks enough of the SSH transport and connection protocols to run
//! an interactive shell or a one-shot command over any [`AsyncRead`] +
//! [`AsyncWrite`] stream. In the browser that stream is a WebSocket bridge to
//! the `pigeons` tunnel; on a native host it can be a `TcpStream`.
//!
//! Two design choices follow from running in a browser:
//!
//! * The identity key never enters this crate. Authentication asks a [`Signer`]
//!   for signatures, which lets a page keep a non-extractable WebCrypto key.
//! * Host keys are checked through a [`HostKeyCheck`] callback instead of a
//!   `known_hosts` file, so the caller can store fingerprints wherever it likes.
//!
//! ```no_run
//! # use kereru::{AuthKey, ClientConfig, HostKeyInfo, HostKeyVerdict, Randomness, Signer};
//! # async fn example(
//! #     io: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
//! #     signer: &dyn Signer,
//! #     rng: Box<dyn Randomness>,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let config = ClientConfig {
//!     user: "alice".into(),
//!     ..ClientConfig::default()
//! };
//!
//! let mut session = kereru::connect(
//!     io,
//!     config,
//!     signer,
//!     rng,
//!     &|info: &HostKeyInfo| {
//!         eprintln!("host key: {}", info.fingerprint);
//!         HostKeyVerdict::Trust
//!     },
//! )
//! .await?;
//!
//! let (_input, mut queue) = tokio::sync::mpsc::unbounded_channel();
//! loop {
//!     match session.pump(&mut queue).await? {
//!         kereru::Event::Output(bytes) => print!("{}", String::from_utf8_lossy(&bytes)),
//!         kereru::Event::Closed { .. } => break,
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]

mod auth;
mod conn;
mod crypto;
mod handshake;
mod session;
mod wire;

use tokio::io::{AsyncRead, AsyncWrite};

pub use auth::{AuthKey, Signer};
pub use crypto::{HostKey, HostKeyKind, Randomness};
pub use session::{Event, Input, Session};

/// Everything that can go wrong while connecting or while a session runs.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The underlying byte stream failed.
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
    /// The peer sent something this client could not use.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The peer closed the connection without finishing a message.
    #[error("connection closed")]
    Closed,
    /// The server disconnected and said why.
    #[error("server disconnected ({0}): {1}")]
    Disconnected(u32, String),
    /// The server's host key was rejected by the caller.
    #[error("host key rejected: {0}")]
    HostKeyRejected(String),
    /// Authentication did not succeed.
    #[error("authentication failed: {0}")]
    Auth(String),
    /// The server requested something this client does not implement.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// A cipher or key was invalid.
    #[error("cryptographic error: {0}")]
    Crypto(String),
    /// The server rejected a channel request.
    #[error("the server rejected a channel request")]
    ChannelRefused,
}

/// A result with this crate's error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Settings for one connection.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Remote user name.
    pub user: String,
    /// Value sent as `TERM`.
    pub terminal: String,
    /// Initial terminal width in character cells.
    pub columns: u32,
    /// Initial terminal height in character cells.
    pub rows: u32,
    /// Command to run instead of the user's shell.
    pub command: Option<String>,
    /// Whether to request a pseudo-terminal. Interactive sessions want one;
    /// `ssh host command` normally does not.
    pub request_pty: bool,
    /// Version banner, e.g. `SSH-2.0-Kereru_0.1`.
    pub client_version: String,
    /// Ciphers in preference order.
    pub ciphers: Vec<&'static str>,
    /// Host key algorithms in preference order.
    pub host_key_algorithms: Vec<&'static str>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            user: String::new(),
            terminal: "xterm-256color".into(),
            columns: 80,
            rows: 24,
            command: None,
            request_pty: true,
            client_version: format!("SSH-2.0-Kereru_{}", env!("CARGO_PKG_VERSION")),
            ciphers: vec![
                "chacha20-poly1305@openssh.com",
                "aes256-gcm@openssh.com",
                "aes128-gcm@openssh.com",
            ],
            host_key_algorithms: vec!["ssh-ed25519", "ecdsa-sha2-nistp256"],
        }
    }
}

/// What the caller knows about a server's host key.
#[derive(Debug, Clone)]
pub struct HostKeyInfo {
    /// Algorithm name, e.g. `ssh-ed25519`.
    pub algorithm: String,
    /// `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// The raw key blob, for storing alongside the fingerprint.
    pub blob: Vec<u8>,
}

/// The caller's decision about a host key.
#[derive(Debug, Clone)]
pub enum HostKeyVerdict {
    /// Proceed (and remember this fingerprint).
    Trust,
    /// Abort with this explanation.
    Reject(String),
}

/// Decides whether a host key is acceptable.
pub trait HostKeyCheck {
    /// Called once per connection after the server's signature is verified.
    fn check(&self, info: &HostKeyInfo) -> HostKeyVerdict;
}

impl<F> HostKeyCheck for F
where
    F: Fn(&HostKeyInfo) -> HostKeyVerdict,
{
    fn check(&self, info: &HostKeyInfo) -> HostKeyVerdict {
        self(info)
    }
}

/// Connects, authenticates, and opens a session channel.
///
/// `rng` supplies randomness for key exchange and packet padding; in the browser
/// that is `crypto.getRandomValues`.
pub async fn connect<T: AsyncRead + AsyncWrite + Unpin>(
    io: T,
    cfg: ClientConfig,
    signer: &dyn Signer,
    rng: Box<dyn Randomness>,
    host_key_check: &dyn HostKeyCheck,
) -> Result<Session<T>> {
    let mut conn = conn::Conn::new(io, rng);
    let handshake = handshake::handshake(&mut conn, &cfg, signer, host_key_check).await?;
    let mut session = Session::new(conn, handshake);
    session.open(&cfg).await?;
    Ok(session)
}
