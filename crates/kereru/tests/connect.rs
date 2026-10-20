//! End-to-end tests against a real `sshd`.
//!
//! These run only when `KERERU_TEST_SSH` points at a reachable SSH server whose
//! `authorized_keys` we can write, because that is what a real client has to
//! interoperate with. `dev/sshd.sh` starts one.
//!
//! A `sandbox that cannot allocate pseudoterminals (no `/dev/pts` access) still
//! runs most of this file; the PTY tests report a skip instead of failing.

use std::path::PathBuf;

use base64::Engine as _;
use kereru::{
    AuthKey, ClientConfig, HostKeyInfo, HostKeyVerdict, Input, Randomness, Result, Signer,
};
use tokio::net::TcpStream;

struct NativeRng;

impl Randomness for NativeRng {
    fn fill(&mut self, out: &mut [u8]) {
        getrandom::getrandom(out).expect("system randomness");
    }
}

struct TestIdentity {
    signing: ed25519_dalek::SigningKey,
    key: AuthKey,
}

impl TestIdentity {
    /// A fixed, test-only key so parallel tests install the same
    /// `authorized_keys` entry and cannot race each other.
    fn shared() -> Self {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let key = AuthKey::ed25519(&signing.verifying_key().to_bytes()).unwrap();
        Self { signing, key }
    }

    fn authorized_keys_line(&self) -> String {
        format!(
            "ssh-ed25519 {} kereru-test\n",
            base64::engine::general_purpose::STANDARD.encode(self.key.blob())
        )
    }
}

#[async_trait::async_trait(?Send)]
impl Signer for TestIdentity {
    fn keys(&self) -> Vec<AuthKey> {
        vec![self.key.clone()]
    }

    async fn sign(&self, _key: &AuthKey, data: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer as _;
        Ok(self.signing.sign(data).to_bytes().to_vec())
    }
}

/// The identity every test uses, installed in `authorized_keys` exactly once.
fn identity() -> &'static TestIdentity {
    static IDENTITY: std::sync::OnceLock<TestIdentity> = std::sync::OnceLock::new();
    IDENTITY.get_or_init(|| {
        let identity = TestIdentity::shared();
        if server().is_some() {
            let path = PathBuf::from(
                std::env::var("KERERU_TEST_AUTHORIZED_KEYS")
                    .unwrap_or_else(|_| "authorized_keys".into()),
            );
            std::fs::write(&path, identity.authorized_keys_line()).expect("write authorized_keys");
        }
        identity
    })
}

fn server() -> Option<String> {
    std::env::var("KERERU_TEST_SSH").ok()
}

fn user() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".into())
}

fn config(user: &str, command: Option<&str>) -> ClientConfig {
    let defaults = ClientConfig::default();
    // `KERERU_TEST_CIPHERS=aes128-gcm@openssh.com` pins the negotiated cipher.
    let ciphers = std::env::var("KERERU_TEST_CIPHERS").map_or(defaults.ciphers, |list| {
        list.split(',')
            .map(|name| match name {
                "chacha20-poly1305@openssh.com" => "chacha20-poly1305@openssh.com",
                "aes128-gcm@openssh.com" => "aes128-gcm@openssh.com",
                "aes256-gcm@openssh.com" => "aes256-gcm@openssh.com",
                other => panic!("unknown cipher {other}"),
            })
            .collect()
    });
    ClientConfig {
        user: user.to_owned(),
        command: command.map(str::to_owned),
        request_pty: command.is_none(),
        ciphers,
        ..defaults
    }
}

fn accept_any(_info: &HostKeyInfo) -> HostKeyVerdict {
    HostKeyVerdict::Trust
}

/// Collects output until the session ends, optionally reacting to it.
async fn drive(
    session: &mut kereru::Session<TcpStream>,
    input: &tokio::sync::mpsc::UnboundedSender<Input>,
    queue: &mut tokio::sync::mpsc::UnboundedReceiver<Input>,
    mut on_output: impl FnMut(&str) -> Option<Input>,
) -> (String, Option<u32>) {
    let mut output = Vec::new();
    loop {
        match session.pump(queue).await.expect("pump") {
            kereru::Event::Output(bytes) => {
                output.extend_from_slice(&bytes);
                let text = String::from_utf8_lossy(&output).into_owned();
                if let Some(next) = on_output(&text) {
                    input.send(next).expect("send input");
                }
            }
            kereru::Event::Closed { exit_status } => {
                return (String::from_utf8_lossy(&output).into_owned(), exit_status);
            }
        }
    }
}

#[tokio::test]
async fn runs_a_one_shot_command() {
    let Some(address) = server() else {
        return;
    };
    let stream = TcpStream::connect(&address).await.expect("connect");
    let mut session = kereru::connect(
        stream,
        config(
            &user(),
            Some("echo hello-from-kereru; echo err-line >&2; exit 7"),
        ),
        identity(),
        Box::new(NativeRng),
        &accept_any,
    )
    .await
    .expect("handshake");

    let (input, mut queue) = tokio::sync::mpsc::unbounded_channel();
    let (text, exit_status) = drive(&mut session, &input, &mut queue, |_| None).await;

    assert!(text.contains("hello-from-kereru"), "output was: {text:?}");
    assert!(
        text.contains("err-line"),
        "stderr should be merged: {text:?}"
    );
    assert_eq!(exit_status, Some(7));
    assert_eq!(session.host_key().kind, kereru::HostKeyKind::Ed25519);
}

#[tokio::test]
async fn sends_input_and_eof_to_a_command() {
    let Some(address) = server() else {
        return;
    };
    let stream = TcpStream::connect(&address).await.expect("connect");
    let mut session = kereru::connect(
        stream,
        config(&user(), Some("cat")),
        identity(),
        Box::new(NativeRng),
        &accept_any,
    )
    .await
    .expect("handshake");

    let (input, mut queue) = tokio::sync::mpsc::unbounded_channel();
    input
        .send(Input::Data(b"line one\nline two\n".to_vec()))
        .expect("send input");
    input.send(Input::Eof).expect("send eof");

    let (text, _) = drive(&mut session, &input, &mut queue, |_| None).await;
    assert!(text.contains("line one"), "cat did not see input: {text:?}");
    assert!(text.contains("line two"), "cat did not see input: {text:?}");
}

#[tokio::test]
async fn runs_an_interactive_shell_on_a_pty() {
    let Some(address) = server() else {
        return;
    };
    let stream = TcpStream::connect(&address).await.expect("connect");
    let mut session = kereru::connect(
        stream,
        config(&user(), None),
        identity(),
        Box::new(NativeRng),
        &accept_any,
    )
    .await
    .expect("handshake");

    if !session.has_pty() {
        eprintln!("skipping: this server could not allocate a PTY");
        return;
    }

    let (input, mut queue) = tokio::sync::mpsc::unbounded_channel();
    input
        .send(Input::Data(b"echo $((6*7))\r".to_vec()))
        .unwrap();
    input
        .send(Input::Data(b"echo pty-ok-$TERM\r".to_vec()))
        .unwrap();

    let mut asked_to_exit = false;
    let (text, _) = drive(&mut session, &input, &mut queue, |output| {
        if asked_to_exit || !output.contains("pty-ok-") {
            return None;
        }
        asked_to_exit = true;
        Some(Input::Data(b"exit\r".to_vec()))
    })
    .await;

    assert!(
        text.contains("42"),
        "no shell arithmetic in output: {text:?}"
    );
    assert!(
        text.contains("pty-ok-xterm-256color"),
        "TERM was not passed to the shell: {text:?}"
    );
}

#[tokio::test]
async fn a_terminal_resize_reaches_the_shell() {
    let Some(address) = server() else {
        return;
    };
    let stream = TcpStream::connect(&address).await.expect("connect");
    let mut session = kereru::connect(
        stream,
        config(&user(), None),
        identity(),
        Box::new(NativeRng),
        &accept_any,
    )
    .await
    .expect("handshake");

    if !session.has_pty() {
        eprintln!("skipping: this server could not allocate a PTY");
        return;
    }

    let (input, mut queue) = tokio::sync::mpsc::unbounded_channel();
    input
        .send(Input::Resize {
            columns: 120,
            rows: 40,
        })
        .unwrap();
    input
        .send(Input::Data(b"echo tty-$(stty size)\r".to_vec()))
        .unwrap();

    let mut asked_to_exit = false;
    let (text, _) = drive(&mut session, &input, &mut queue, |output| {
        if asked_to_exit || !output.contains("tty-") {
            return None;
        }
        asked_to_exit = true;
        Some(Input::Data(b"exit\r".to_vec()))
    })
    .await;

    assert!(
        text.contains("tty-40 120"),
        "window-change did not reach the shell: {text:?}"
    );
}

#[tokio::test]
async fn a_rejected_host_key_aborts_the_connection() {
    let Some(address) = server() else {
        return;
    };
    let stream = TcpStream::connect(&address).await.expect("connect");
    let error = kereru::connect(
        stream,
        config(&user(), Some("true")),
        identity(),
        Box::new(NativeRng),
        &|_info: &HostKeyInfo| HostKeyVerdict::Reject("fingerprint changed".into()),
    )
    .await
    .expect_err("host key should be rejected");

    assert!(
        matches!(error, kereru::Error::HostKeyRejected(_)),
        "{error:?}"
    );
}

/// Not a protocol test: it keeps the setup honest by proving the key we install
/// is in the format `sshd` expects.
#[test]
fn authorized_keys_line_is_an_openssh_public_key() {
    let line = identity().authorized_keys_line();
    let mut parts = line.trim_end().split(' ');
    assert_eq!(parts.next(), Some("ssh-ed25519"));

    let blob = base64::engine::general_purpose::STANDARD
        .decode(parts.next().expect("key material"))
        .expect("valid base64");
    // A key blob is `string "ssh-ed25519" || string <32 bytes>`.
    assert_eq!(&blob[..4], &[0, 0, 0, 11]);
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert_eq!(&blob[15..19], &[0, 0, 0, 32]);
    assert_eq!(blob.len(), 19 + 32);
}
