//! A tiny interactive SSH client, mostly for poking at the protocol.
//!
//! ```text
//! cargo run -p kereru --example ssh_shell -- 127.0.0.1:2222 user [command]
//! ```
//!
//! The identity is a fixed development key whose public half is printed on
//! stderr, so a test server can be told to trust it. Nothing here is used by the
//! browser build; it exists so the library can be exercised without a browser.

use std::io::Write as _;

use kereru::{ClientConfig, HostKeyVerdict, Input, Randomness, Result, Signer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::net::TcpStream;

struct DevRng;

impl Randomness for DevRng {
    fn fill(&mut self, out: &mut [u8]) {
        getrandom::getrandom(out).expect("system randomness");
    }
}

struct DevIdentity {
    signing: ed25519_dalek::SigningKey,
    key: kereru::AuthKey,
}

impl DevIdentity {
    fn from_seed() -> Self {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        Self {
            signing,
            key: kereru::AuthKey::ed25519(&public).unwrap(),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Signer for DevIdentity {
    fn keys(&self) -> Vec<kereru::AuthKey> {
        vec![self.key.clone()]
    }

    async fn sign(&self, _key: &kereru::AuthKey, data: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer as _;
        Ok(self.signing.sign(data).to_bytes().to_vec())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2222".into());
    let user = args.next().unwrap_or_else(|| "root".into());
    let command = args.next();

    let identity = DevIdentity::from_seed();
    eprintln!("identity: {}", identity.key.fingerprint());

    let stream = TcpStream::connect(&address).await?;
    let cfg = ClientConfig {
        user,
        command,
        request_pty: std::env::var_os("SSH_PTY").is_some(),
        ..ClientConfig::default()
    };
    let mut session = kereru::connect(
        stream,
        cfg,
        &identity,
        Box::new(DevRng),
        &|info: &kereru::HostKeyInfo| {
            eprintln!("host key: {} {}", info.algorithm, info.fingerprint);
            HostKeyVerdict::Trust
        },
    )
    .await?;

    eprintln!(
        "connected: {} / {}",
        session.server_version(),
        session.cipher()
    );

    let (input, mut queue) = tokio::sync::mpsc::unbounded_channel();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(line)) => {
                    input.send(Input::Data(format!("{line}\r").into_bytes())).ok();
                }
                _ => {
                    input.send(Input::Eof).ok();
                }
            },
            event = session.pump(&mut queue) => match event? {
                kereru::Event::Output(bytes) => {
                    let mut stdout = std::io::stdout();
                    stdout.write_all(&bytes)?;
                    stdout.flush()?;
                }
                kereru::Event::Closed { exit_status } => {
                    eprintln!("\n[closed, status {exit_status:?}]");
                    break;
                }
            },
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn _assert_traits<T: AsyncRead + AsyncWrite + Unpin>(_: T) {}
