//! The iroh tunnel: the page is its own iroh endpoint.
//!
//! A browser cannot open a QUIC socket, but iroh's browser build reaches a relay
//! over a WebSocket and carries the QUIC packets inside the relay protocol. That
//! makes the page a first-class iroh endpoint: it dials the roost's endpoint id
//! with the `pigeons` ALPN and gets one bi-directional stream, exactly like
//! `pigeons fly --stdio` does from a terminal.
//!
//! The stream is then handed to the SSH client as an ordinary byte stream.

use std::cell::{Cell, RefCell};
use std::pin::Pin;
use std::task::{Context, Poll};

use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::platform;
use crate::platform::Result;

/// The ALPN a `pigeons` roost accepts; one stream is one SSH connection.
const PIGEONS_ALPN: &[u8] = b"/pigeons/0";

thread_local! {
    /// The endpoint, or the reason binding it failed, so concurrent callers
    /// share one outcome instead of each binding their own.
    static ENDPOINT: RefCell<Option<Result<iroh::Endpoint>>> = const { RefCell::new(None) };
    /// True while one caller is inside `bind()`.
    static BINDING: Cell<bool> = const { Cell::new(false) };
}

/// Clears the binding flag however the bind ends, including cancellation.
struct Binding;

impl Drop for Binding {
    fn drop(&mut self) {
        BINDING.with(|flag| flag.set(false));
    }
}

/// The page's iroh endpoint, bound on first use.
///
/// Two callers can arrive before either has finished binding, so the first takes
/// the flag and the others wait for its outcome; otherwise each would bind a
/// separate endpoint with a separate key.
pub async fn endpoint() -> Result<iroh::Endpoint> {
    for _ in 0..750 {
        if let Some(outcome) = ENDPOINT.with(|cell| cell.borrow().clone()) {
            return outcome;
        }
        if !BINDING.with(Cell::get) {
            let binding = Binding;
            BINDING.with(|flag| flag.set(true));
            // The key is generated per page: nothing depends on a stable peer id
            // (SSH authenticates the user), and nothing is written to storage.
            let mut seed = [0u8; 32];
            {
                use kereru::Randomness as _;
                platform::BrowserRng.fill(&mut seed);
            }
            let outcome = iroh::Endpoint::builder(presets::N0)
                .secret_key(iroh::SecretKey::from_bytes(&seed))
                .bind()
                .await
                .map_err(|e| format!("could not start the browser's iroh endpoint: {e}"));
            ENDPOINT.with(|cell| *cell.borrow_mut() = Some(outcome.clone()));
            drop(binding);
            return outcome;
        }
        // Another caller is binding; give it 20ms and look again.
        wasm_bindgen_futures::JsFuture::from(platform::sleep(20))
            .await
            .ok();
    }
    Err("the browser's iroh endpoint did not start".to_owned())
}

/// The id the roost sees for this page, if the endpoint is already up.
pub fn endpoint_id() -> Option<String> {
    ENDPOINT.with(|cell| {
        cell.borrow()
            .as_ref()
            .and_then(|outcome| outcome.as_ref().ok())
            .map(|endpoint| endpoint.id().to_string())
    })
}

/// A roost connection carrying one SSH session.
pub struct RoostStream {
    send: SendStream,
    recv: RecvStream,
    /// Held so the connection outlives the stream.
    _connection: Connection,
}

/// Dials a roost and opens the stream the SSH client will use.
pub async fn connect(roost: &str) -> Result<RoostStream> {
    let endpoint = endpoint().await?;
    // Accept `iroh:<id>` as well as the bare id `pigeons roost` prints.
    let roost = roost.trim();
    let roost = roost.strip_prefix("iroh:").unwrap_or(roost);
    let id: iroh::EndpointId = roost
        .parse()
        .map_err(|e| format!("{roost} is not an iroh endpoint id: {e}"))?;

    let connection = endpoint
        .connect(id, PIGEONS_ALPN)
        .await
        .map_err(|e| format!("could not reach roost {id}: {e}"))?;
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("roost {id} refused a stream: {e}"))?;

    Ok(RoostStream {
        send,
        recv,
        _connection: connection,
    })
}

impl AsyncRead for RoostStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().recv), cx, buf)
    }
}

impl AsyncWrite for RoostStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Finish the QUIC stream so the roost sees a clean end of input.
        let _ = self.get_mut().send.finish();
        Poll::Ready(Ok(()))
    }
}
