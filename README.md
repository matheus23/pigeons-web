# pigeons-web

SSH in your browser, carried over [iroh](https://iroh.computer). One static page,
no backend, no plugin.

```text
  browser tab                                  your machine
┌──────────────────────────────┐            ┌──────────────────┐
│ pigeons-web (wasm)           │            │ roost            │
│   terminal                   │   iroh     │   └─► sshd       │
│   ssh client (kereru)        │◄──────────►│                  │
│   iroh endpoint              │  via relay └──────────────────┘
└──────────────────────────────┘
```

## How a browser can speak iroh

A browser cannot open a UDP socket, so it cannot run QUIC the way a native iroh
endpoint does. iroh's browser build solves that inside the library: it connects
to a relay over a WebSocket and carries the QUIC packets inside the relay's
framing protocol. The page therefore *is* an iroh endpoint — it has an endpoint
id, it resolves peers through the relay, and `Endpoint::connect` works normally.

That means the page can use the `pigeons` protocol directly: dial the roost's
endpoint id with ALPN `/pigeons/0`, open one bi-directional stream, and pipe
bytes. It is exactly what `pigeons fly --stdio` does from a terminal, with no
helper process in between and nothing to deploy next to the static files.

## What is here

| crate | what it is |
| --- | --- |
| `crates/kereru` | A small SSH client. Pure Rust, no I/O assumptions, compiles to wasm. |
| `crates/pigeons-web` | The browser app: terminal, identity, host config, iroh tunnel. |

### `kereru` — the SSH client

There is no maintained Rust SSH client that compiles to wasm and can sign with a
non-extractable WebCrypto key, so this is a from-scratch implementation of the
transport and the parts of the connection protocol a browser shell needs.

- **Key exchange**: `curve25519-sha256` (+ the `@libssh.org` alias).
- **Ciphers**: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`,
  `aes128-gcm@openssh.com`.
- **Host keys**: `ssh-ed25519`, `ecdsa-sha2-nistp256`, verified against the
  exchange hash before anything else happens.
- **Auth**: `publickey`, with Ed25519 or ECDSA P-256.
- **Connection**: one `session` channel, `pty-req`, `shell` or `exec`,
  `window-change`, window management, exit status.

Two traits keep the browser's constraints out of the protocol code:

```rust
#[async_trait(?Send)]
pub trait Signer {
    fn keys(&self) -> Vec<AuthKey>;
    async fn sign(&self, key: &AuthKey, data: &[u8]) -> SshResult<Vec<u8>>;
}

pub trait HostKeyCheck {
    fn check(&self, info: &HostKeyInfo) -> HostKeyVerdict;
}
```

Signing is async so the page can hand the bytes to `crypto.subtle.sign` and never
see the private key. Host key decisions are a callback so the page can do
trust-on-first-use in `localStorage` instead of `known_hosts`.

It runs over any `tokio::io::{AsyncRead, AsyncWrite}`, which is why the same code
is tested natively against a real `sshd` and used in the browser over an iroh
stream.

### `crates/pigeons-web` — the page

- **Tunnel**: one iroh endpoint per page (`tunnel.rs`). The first connection binds
  it; later ones reuse it. The roost's stream is adapted to `AsyncRead`/
  `AsyncWrite` and handed straight to `kereru`.
- **Terminal**: `vt100` for the screen model, painted as DOM rows. Only rows that
  actually changed are rebuilt. 256-colour and truecolour, bold/italic/underline/
  inverse, alternate screen, cursor state, window title.
- **Identity**: an Ed25519 key imported as non-extractable PKCS#8 into WebCrypto;
  the public half is derived locally so the page can show the `authorized_keys`
  line. P-256 is the fallback if a browser lacks WebCrypto Ed25519.
- **Input**: an invisible `textarea` holds focus, because that is the only thing
  a soft keyboard opens for; characters arrive through `input` and composition
  events (so phone keyboards and IME work), while `keydown` handles only control
  keys. The layout follows `visualViewport`, so an open keyboard shrinks the
  terminal instead of hiding the cursor, and the resize is passed to the remote.
- **Storage**: hosts and trusted host keys are JSON in `localStorage` — the
  `~/.ssh/config` equivalent. The key lives in `IndexedDB`, because a `CryptoKey`
  is not a string.
- **Shell**: `ssh [user@]host [command]`, `hosts`, `key`, `forget`, `settings`,
  `disconnect`, `help`, with history. `Ctrl+Shift+C` copies the screen,
  `Ctrl+Shift+D` disconnects, `Ctrl+Shift+`` ` opens settings.

## Running it

Prerequisites: Rust with the `wasm32-unknown-unknown` target, and the
`wasm-bindgen` CLI matching the version pinned in `crates/web/Cargo.toml`
(0.2.122 here).

On the machine you want to reach, with a roost:

```bash
pigeons roost --ssh-port 22
```

Build and serve the page:

```bash
./build.sh                  # writes dist/
dev/serve.sh 8787           # or any static file server
```

Open <http://localhost:8787>, then:

1. `settings` → add a host: name `laptop`, user `alice`, target
   `<roost-endpoint-id>` (the id `pigeons roost` prints; an `iroh:` prefix is
   accepted). A user is required — a browser has no local login name.
2. `key` → copy the `ssh-ed25519 …` line.
3. On the server, append it to `~/.ssh/authorized_keys`.
4. `ssh laptop`.

`dist/` is a plain static directory, deployable anywhere. It has to be served
over HTTPS or from `localhost`: WebCrypto only exists in a secure context.

### Publishing

`.github/workflows/pages.yml` builds `dist/` and deploys it to GitHub Pages on
every push to `main`. Enable it once under *Settings → Pages → Source → GitHub
Actions*. A project page is served from `https://<owner>.github.io/pigeons-web/`;
every asset path is relative, so the subpath needs no configuration, and the
`.wasm` type does not matter because the loader falls back when the server does
not send `application/wasm`.

The workflow pins binaryen 126 because Ubuntu's 116 miscompiles this module, and
`build.sh` runs `dev/check-wasm.mjs`, which fails the build unless the module's
`__wbindgen_externrefs` export is a growable externref table — the thing the
browser grows at startup.

The published page is the only thing to share — there is no service to run
alongside it. If you attach a custom domain, use that address in docs and
elsewhere: it is the link to the live page.

## Tests

```bash
cargo test -p kereru                      # unit tests: wire codec, ciphers, KDF
dev/sshd.sh                               # throwaway sshd on 127.0.0.1:2222
KERERU_TEST_SSH=127.0.0.1:2222 \
KERERU_TEST_AUTHORIZED_KEYS=/tmp/pigeons-web-sshd/authorized_keys \
  cargo test -p kereru --test connect     # against that sshd
```

The integration tests cover a one-shot command with stderr and exit status,
stdin plus EOF, interactive shell on a PTY, `window-change`, and host key
rejection. PTY tests report a skip if the environment cannot allocate a `pty`.

`cargo run -p kereru --example ssh_shell -- 127.0.0.1:2222 $USER` is a small
native client over the same library.

## Verified

- Browser → iroh → `pigeons roost` → `sshd`, from a page served by a plain static
  server: the roost logs `pigeon arrived from …` and the page receives command
  output. No helper process involved.
- Handshake, auth, `exec` and shell sessions against OpenSSH 10.3 with all three
  ciphers, natively.
- Trust on first use: a changed host key is refused with both fingerprints and a
  `forget` hint.

Not verified here: PTY allocation (the development sandbox has no `/dev/pts`, so
full-screen programs were untested end to end), Safari and Firefox WebCrypto
Ed25519, and behaviour when the relay is unreachable.

## Known limits

- **An unreachable roost takes about 30 s to fail**, which is iroh's connect
  timeout; the message names the endpoint id.
- **The page's iroh key is per origin.** It is generated once and kept in
  IndexedDB, so reloads keep the same peer id, but a different host or port is a
  different endpoint.
- **Browser connections are relay-only.** No hole punching: everything goes
  through a relay, which is fine for a shell and not great for bulk transfer.
- **No scrollback.** The screen is the screen; `PageUp` goes to the application.
- **The SSH key is per origin too.** Both the iroh key and the SSH key live in
  per-origin browser storage, so moving the deployment to another host or port
  means trusting a new key on the server.
- **No rekeying.** Fine for a session, not for a multi-gigabyte transfer.
- **No port forwarding, agent forwarding, or `scp`.** One session channel.
- **RSA host keys are not supported** — Ed25519 and P-256 cover modern servers.
- **No IME composition**, and browser shortcuts win over terminal ones.
- The wasm bundle is ~2.9 MB (iroh, rustls, and the SSH stack). It compresses
  well, but it is not a small page.
- Without a PTY the page translates Enter to LF and bare LF to CRLF, because a
  pipe has no line discipline. It warns when the server refuses a PTY.

## Security notes

- The private key is a non-extractable WebCrypto key stored in IndexedDB. It is
  never exported; signing happens inside the browser's crypto implementation.
- SSH is end-to-end between the page and `sshd`: key exchange and encryption run
  in wasm, so the relay and the roost only see ciphertext.
- Host keys are pinned per host name in `localStorage` on first use. There is no
  certificate support and no `known_hosts` import.
- A roost accepts any peer that knows its endpoint id and speaks `/pigeons/0`;
  the SSH server behind it is the thing doing authentication.
