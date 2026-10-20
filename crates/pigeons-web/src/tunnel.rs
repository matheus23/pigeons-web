//! The iroh tunnel: the page is its own iroh endpoint.
//!
//! A browser cannot open a QUIC socket, but iroh's browser build reaches a relay
//! over a WebSocket and carries the QUIC packets inside the relay protocol. That
//! makes the page a first-class iroh endpoint: it dials the roost's endpoint id
//! with the `pigeons` ALPN and gets one bi-directional stream, exactly like
//! `pigeons fly --stdio` does from a terminal.
//!
//! The stream is then handed to the SSH client as an ordinary byte stream.

use std::cell::RefCell;
use std::pin::Pin;
use std::task::{Context, Poll};

use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasm_bindgen::JsValue;

use crate::platform;
use crate::platform::Result;

/// The ALPN a `pigeons` roost accepts; one stream is one SSH connection.
const PIGEONS_ALPN: &[u8] = b"/pigeons/0";

/// Where the page's iroh key lives, so the roost sees a stable peer id.
const ENDPOINT_KEY: &str = "iroh-endpoint-key";

thread_local! {
    /// One endpoint per page, bound on first use.
    static ENDPOINT: RefCell<Option<iroh::Endpoint>> = const { RefCell::new(None) };
}

/// The page's iroh key, generated once and kept in IndexedDB.
///
/// Without this a reload would be a new peer id, which makes roost-side logs and
/// any future endpoint-id authorisation useless.
async fn endpoint_secret() -> Result<iroh::SecretKey> {
    if let Ok(Some(stored)) = platform::idb_get(ENDPOINT_KEY).await
        && let Ok(bytes) = platform::bytes_of(stored)
        && let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return Ok(iroh::SecretKey::from_bytes(&array));
    }

    let mut bytes = [0u8; 32];
    {
        use kereru::Randomness as _;
        platform::BrowserRng.fill(&mut bytes);
    }
    let key = iroh::SecretKey::from_bytes(&bytes);
    let value = JsValue::from(js_sys::Uint8Array::from(&bytes[..]));
    let _ = platform::idb_put(ENDPOINT_KEY, &value).await;
    Ok(key)
}

/// The page's iroh endpoint, binding it on first use.
pub async fn endpoint() -> Result<iroh::Endpoint> {
    if let Some(endpoint) = ENDPOINT.with(|cell| cell.borrow().clone()) {
        return Ok(endpoint);
    }
    let endpoint = iroh::Endpoint::builder(presets::N0)
        .secret_key(endpoint_secret().await?)
        .bind()
        .await
        .map_err(|e| format!("could not start the browser's iroh endpoint: {e}"))?;
    ENDPOINT.with(|cell| *cell.borrow_mut() = Some(endpoint.clone()));
    Ok(endpoint)
}

/// The id the roost sees for this page, if the endpoint is already up.
pub fn endpoint_id() -> Option<String> {
    ENDPOINT.with(|cell| {
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
