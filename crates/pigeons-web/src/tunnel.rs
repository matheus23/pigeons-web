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

use futures::future::{FutureExt, LocalBoxFuture, Shared};
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::platform;
use crate::platform::Result;

/// The ALPN a `pigeons` roost accepts; one stream is one SSH connection.
const PIGEONS_ALPN: &[u8] = b"/pigeons/0";

thread_local! {
    /// The bind in flight or the endpoint it produced, tagged with the attempt
    /// number so a stale failure cannot clear a newer attempt.
    static ENDPOINT: RefCell<Option<(u32, BindFuture)>> = const { RefCell::new(None) };
    static ATTEMPT: Cell<u32> = const { Cell::new(0) };
    /// The bound endpoint, once there is one, for introspection.
    static BOUND: RefCell<Option<iroh::Endpoint>> = const { RefCell::new(None) };
}

/// One bind, shared by everyone waiting on it.
type BindFuture = Shared<LocalBoxFuture<'static, Result<iroh::Endpoint>>>;

/// The page's iroh endpoint, binding it on first use.
///
/// Callers that arrive while a bind is in flight await the same future instead of
/// starting a second endpoint with a second key. A failure is forgotten, so a
/// later attempt — after the network comes back, say — can bind again without a
/// page reload.
pub async fn endpoint() -> Result<iroh::Endpoint> {
    let (attempt, pending) = ENDPOINT.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let generation = ATTEMPT.with(|counter| {
                let next = counter.get().wrapping_add(1);
                counter.set(next);
                next
            });
            let bind = async move {
                // The key is generated per page: nothing depends on a stable peer
                // id (SSH authenticates the user), and nothing is written to storage.
                let mut seed = [0u8; 32];
                {
                    use kereru::Randomness as _;
                    platform::BrowserRng.fill(&mut seed);
                }
                iroh::Endpoint::builder(presets::N0)
                    .secret_key(iroh::SecretKey::from_bytes(&seed))
                    .bind()
                    .await
                    .map_err(|e| format!("could not start the browser's iroh endpoint: {e}"))
            };
            *slot = Some((generation, bind.boxed_local().shared()));
        }
        let (generation, future) = slot.as_ref().expect("just inserted");
        (*generation, future.clone())
    });

    let outcome = pending.await;
    if let Ok(endpoint) = &outcome {
        BOUND.with(|cell| *cell.borrow_mut() = Some(endpoint.clone()));
    }
    if outcome.is_err() {
        ENDPOINT.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot
                .as_ref()
                .is_some_and(|(generation, _)| *generation == attempt)
            {
                *slot = None;
            }
        });
    }
    outcome
}

/// The id the roost sees for this page, if the endpoint is already up.
pub fn endpoint_id() -> Option<String> {
    BOUND.with(|cell| {
        cell.borrow()
            .as_ref()
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
