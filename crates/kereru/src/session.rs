//! An authenticated `session` channel: a shell or a command, usually on a PTY.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::conn::Conn;
use crate::crypto::HostKey;
use crate::handshake::disconnect;
use crate::wire::{Reader, Writer};
use crate::{ClientConfig, Error, Result};

/// The channel id we open; the server addresses us by this number.
pub(crate) const LOCAL_CHANNEL: u32 = 0;

/// The window we advertise for terminal output. The server throttles itself to
/// this many unacknowledged bytes.
const LOCAL_WINDOW: u32 = 2 * 1024 * 1024;
/// Largest channel packet we accept, within the protocol's 35000-byte limit.
const MAX_CHANNEL_PACKET: u32 = 32 * 1024;
/// Re-advertise the window once half of it has been consumed.
const WINDOW_THRESHOLD: u32 = LOCAL_WINDOW / 2;

const KEXINIT: u8 = 20;
const DISCONNECT: u8 = 1;
const IGNORE: u8 = 2;
const UNIMPLEMENTED: u8 = 3;
const DEBUG: u8 = 4;
const SERVICE_ACCEPT: u8 = 6;
const EXT_INFO: u8 = 7;
const GLOBAL_REQUEST: u8 = 80;
const REQUEST_FAILURE: u8 = 82;
const CHANNEL_OPEN: u8 = 90;
const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
const CHANNEL_OPEN_FAILURE: u8 = 92;
const CHANNEL_WINDOW_ADJUST: u8 = 93;
const CHANNEL_DATA: u8 = 94;
const CHANNEL_EXTENDED_DATA: u8 = 95;
const CHANNEL_EOF: u8 = 96;
const CHANNEL_CLOSE: u8 = 97;
const CHANNEL_REQUEST: u8 = 98;
const CHANNEL_SUCCESS: u8 = 99;
const CHANNEL_FAILURE: u8 = 100;

/// Something the local side wants to send to the server.
#[derive(Debug, Clone)]
pub enum Input {
    /// Keystrokes or pasted text.
    Data(Vec<u8>),
    /// A new terminal size.
    Resize {
        /// Width in character cells.
        columns: u32,
        /// Height in character cells.
        rows: u32,
    },
    /// No more input will be sent; the server is told the channel's input ended.
    Eof,
    /// Closes the channel outright. A program that ignores EOF (a pager, a
    /// full-screen editor) would otherwise keep the session alive.
    Close,
}

/// Something the server sent that the local side should react to.
#[derive(Debug)]
pub enum Event {
    /// Bytes for the terminal.
    Output(Vec<u8>),
    /// The session is over; exit status if the command reported one.
    Closed {
        /// The command's exit status, when the server sent one.
        exit_status: Option<u32>,
    },
}

/// An open SSH session.
///
/// The session owns the transport. [`Session::pump`] waits for either remote
/// output or local input and returns as soon as there is something to show.
pub struct Session<T> {
    conn: Conn<T>,
    remote_channel: u32,
    /// Bytes the server still accepts.
    remote_window: u32,
    remote_max_packet: u32,
    /// Bytes the server may still send us before a window adjustment.
    local_window: u32,
    output: Vec<u8>,
    pending_input: Vec<u8>,
    host_key: HostKey,
    server_version: String,
    banners: Vec<String>,
    cipher: &'static str,
    exit_status: Option<u32>,
    closed: bool,
    close_sent: bool,
    eof_sent: bool,
    pty: bool,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Session<T> {
    pub(crate) fn new(conn: Conn<T>, handshake: crate::handshake::Handshake) -> Self {
        Self {
            conn,
            remote_channel: 0,
            remote_window: 0,
            remote_max_packet: MAX_CHANNEL_PACKET,
            local_window: LOCAL_WINDOW,
            output: Vec::new(),
            pending_input: Vec::new(),
            host_key: handshake.host_key,
            server_version: handshake.server_version,
            banners: handshake.banners,
            cipher: handshake.cipher,
            exit_status: None,
            closed: false,
            close_sent: false,
            eof_sent: false,
            pty: false,
        }
    }

    /// Opens the session channel, requests a PTY, and starts the shell/command.
    pub(crate) async fn open(&mut self, cfg: &ClientConfig) -> Result<()> {
        let open = Writer::message(CHANNEL_OPEN)
            .str("session")
            .u32(LOCAL_CHANNEL)
            .u32(LOCAL_WINDOW)
            .u32(MAX_CHANNEL_PACKET)
            .into_vec();
        let reply = self.transact(open, CHANNEL_OPEN_CONFIRMATION).await?;

        let mut r = Reader::new(&reply[1..]);
        let _our_channel = r.u32()?;
        self.remote_channel = r.u32()?;
        self.remote_window = r.u32()?;
        self.remote_max_packet = r.u32()?.clamp(1024, MAX_CHANNEL_PACKET);

        if cfg.request_pty {
            let pty = Writer::message(CHANNEL_REQUEST)
                .u32(self.remote_channel)
                .str("pty-req")
                .bool(true)
                .str(&cfg.terminal)
                .u32(cfg.columns)
                .u32(cfg.rows)
                .u32(0) // pixel width; only character cells matter here
                .u32(0) // pixel height
                .string(&[]) // terminal modes: server defaults
                .into_vec();
            // A server may refuse a PTY; a one-shot command still works.
            match self.transact(pty, CHANNEL_SUCCESS).await {
                Ok(_) => self.pty = true,
                Err(Error::ChannelRefused) => self.pty = false,
                Err(e) => return Err(e),
            }
        }

        let start = match &cfg.command {
            Some(command) => Writer::message(CHANNEL_REQUEST)
                .u32(self.remote_channel)
                .str("exec")
                .bool(true)
                .str(command)
                .into_vec(),
            None => Writer::message(CHANNEL_REQUEST)
                .u32(self.remote_channel)
                .str("shell")
                .bool(true)
                .into_vec(),
        };
        match self.transact(start, CHANNEL_SUCCESS).await {
            Ok(_) => Ok(()),
            Err(Error::ChannelRefused) => match &cfg.command {
                Some(command) => Err(Error::Protocol(format!(
                    "the server refused to run `{command}`"
                ))),
                None => Err(Error::Protocol(
                    "the server refused to start a shell".into(),
                )),
            },
            Err(e) => Err(e),
        }
    }

    /// The server's host key, already verified during the handshake.
    pub fn host_key(&self) -> &HostKey {
        &self.host_key
    }

    /// Whether the server granted a pseudo-terminal for this session.
    ///
    /// False when the server refused the request; commands still run, but
    /// line-oriented tools and full-screen programs will not work.
    pub fn has_pty(&self) -> bool {
        self.pty
    }

    /// The server's version banner, e.g. `SSH-2.0-OpenSSH_9.9`.
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Text the server wanted to show before the session started.
    pub fn banners(&self) -> &[String] {
        &self.banners
    }

    /// The negotiated cipher, for display in diagnostics.
    pub fn cipher(&self) -> &'static str {
        self.cipher
    }

    /// The exit status the server reported, if the channel is finished.
    pub fn exit_status(&self) -> Option<u32> {
        self.exit_status
    }

    /// Sends a message and waits for a reply of type `want`.
    async fn transact(&mut self, payload: Vec<u8>, want: u8) -> Result<Vec<u8>> {
        self.conn.write_packet(&payload).await?;
        loop {
            let packet = self.conn.read_packet().await?;
            if packet.first() == Some(&want) {
                return Ok(packet);
            }
            if packet.first() == Some(&CHANNEL_FAILURE) && want == CHANNEL_SUCCESS {
                return Err(Error::ChannelRefused);
            }
            if packet.first() == Some(&CHANNEL_OPEN_FAILURE) {
                let mut r = Reader::new(&packet[1..]);
                let _recipient = r.u32()?;
                let _reason = r.u32()?;
                let description = String::from_utf8_lossy(r.string()?).into_owned();
                return Err(Error::Protocol(format!(
                    "the server refused to open a session: {description}"
                )));
            }
            self.handle_packet(&packet).await?;
        }
    }

    async fn handle_packet(&mut self, packet: &[u8]) -> Result<()> {
        let mut r = Reader::new(packet.get(1..).unwrap_or(&[]));
        match packet[0] {
            KEXINIT => {
                return Err(Error::Unsupported(
                    "the server asked to rekey mid-session; reconnect".into(),
                ));
            }
            DISCONNECT => return Err(disconnect(packet)),
            IGNORE | DEBUG | UNIMPLEMENTED | EXT_INFO | SERVICE_ACCEPT => {}
            GLOBAL_REQUEST => {
                let _name = r.utf8()?;
                if r.bool()? {
                    self.conn
                        .write_packet(&Writer::message(REQUEST_FAILURE).into_vec())
                        .await?;
                }
            }
            CHANNEL_WINDOW_ADJUST => {
                let channel = r.u32()?;
                let increment = r.u32()?;
                if channel == LOCAL_CHANNEL {
                    self.remote_window = self.remote_window.saturating_add(increment);
                }
            }
            CHANNEL_DATA | CHANNEL_EXTENDED_DATA => {
                let channel = r.u32()?;
                if packet[0] == CHANNEL_EXTENDED_DATA {
                    let _data_type = r.u32()?;
                }
                let data = r.string()?;
                if channel == LOCAL_CHANNEL {
                    self.local_window = self.local_window.saturating_sub(data.len() as u32);
                    self.output.extend_from_slice(data);
                    self.maybe_adjust_window().await?;
                }
            }
            CHANNEL_EOF => self.closed = true,
            CHANNEL_CLOSE => {
                if !self.close_sent {
                    self.conn
                        .write_packet(
                            &Writer::message(CHANNEL_CLOSE)
                                .u32(self.remote_channel)
                                .into_vec(),
                        )
                        .await?;
                    self.close_sent = true;
                }
                self.closed = true;
            }
            CHANNEL_REQUEST => {
                let channel = r.u32()?;
                let request = r.utf8()?.to_owned();
                let want_reply = r.bool()?;
                match request.as_str() {
                    "exit-status" => self.exit_status = Some(r.u32()?),
                    "exit-signal" => {
                        let _signal = r.utf8()?;
                    }
                    _ => {}
                }
                if want_reply && channel == LOCAL_CHANNEL {
                    self.conn
                        .write_packet(
                            &Writer::message(CHANNEL_FAILURE)
                                .u32(self.remote_channel)
                                .into_vec(),
                        )
                        .await?;
                }
            }
            CHANNEL_SUCCESS
            | CHANNEL_FAILURE
            | CHANNEL_OPEN_CONFIRMATION
            | CHANNEL_OPEN_FAILURE => {}
            _ => {}
        }
        Ok(())
    }

    async fn maybe_adjust_window(&mut self) -> Result<()> {
        if self.local_window > WINDOW_THRESHOLD {
            return Ok(());
        }
        let increment = LOCAL_WINDOW - self.local_window;
        self.local_window = LOCAL_WINDOW;
        self.conn
            .write_packet(
                &Writer::message(CHANNEL_WINDOW_ADJUST)
                    .u32(self.remote_channel)
                    .u32(increment)
                    .into_vec(),
            )
            .await
    }

    async fn flush_input(&mut self) -> Result<()> {
        if self.close_sent {
            // CHANNEL_CLOSE already went out, so anything still queued has
            // nowhere to go and sending it would be a protocol violation.
            self.pending_input.clear();
            return Ok(());
        }
        while !self.pending_input.is_empty() && self.remote_window > 0 {
            let take = self
                .pending_input
                .len()
                .min(self.remote_window as usize)
                .min(self.remote_max_packet as usize);
            let chunk: Vec<u8> = self.pending_input.drain(..take).collect();
            let packet = Writer::message(CHANNEL_DATA)
                .u32(self.remote_channel)
                .string(&chunk)
                .into_vec();
            self.conn.write_packet(&packet).await?;
            self.remote_window -= take as u32;
        }
        Ok(())
    }

    /// Waits for remote output or local input.
    ///
    /// Returns as soon as there is output to display, or when the session ends.
    pub async fn pump(&mut self, input: &mut mpsc::UnboundedReceiver<Input>) -> Result<Event> {
        loop {
            while let Some(packet) = self.conn.take_packet()? {
                self.handle_packet(&packet).await?;
            }
            self.flush_input().await?;

            if !self.output.is_empty() {
                return Ok(Event::Output(std::mem::take(&mut self.output)));
            }
            if self.closed && self.pending_input.is_empty() {
                self.finish().await?;
                return Ok(Event::Closed {
                    exit_status: self.exit_status,
                });
            }

            let mut queued = None;
            tokio::select! {
                read = self.conn.fill_more() => match read {
                    Ok(()) => {}
                    Err(Error::Closed) => self.closed = true,
                    Err(e) => return Err(e),
                },
                maybe = input.recv() => queued = Some(maybe),
            }

            match queued {
                Some(Some(Input::Data(data))) => self.pending_input.extend_from_slice(&data),
                Some(Some(Input::Resize { columns, rows })) => {
                    self.resize(columns, rows).await?;
                }
                Some(Some(Input::Eof)) | Some(None) => self.send_eof().await?,
                Some(Some(Input::Close)) => self.close().await?,
                None => {}
            }
        }
    }

    /// Tells the server the terminal was resized.
    pub async fn resize(&mut self, columns: u32, rows: u32) -> Result<()> {
        let packet = Writer::message(CHANNEL_REQUEST)
            .u32(self.remote_channel)
            .str("window-change")
            .bool(false)
            .u32(columns)
            .u32(rows)
            .u32(0)
            .u32(0)
            .into_vec();
        self.conn.write_packet(&packet).await
    }

    async fn send_eof(&mut self) -> Result<()> {
        if self.eof_sent {
            return Ok(());
        }
        self.eof_sent = true;
        self.conn
            .write_packet(
                &Writer::message(CHANNEL_EOF)
                    .u32(self.remote_channel)
                    .into_vec(),
            )
            .await
    }

    /// Closes the channel and waits for the server's close.
    pub async fn close(&mut self) -> Result<()> {
        self.send_eof().await?;
        if !self.close_sent {
            self.close_sent = true;
            self.conn
                .write_packet(
                    &Writer::message(CHANNEL_CLOSE)
                        .u32(self.remote_channel)
                        .into_vec(),
                )
                .await?;
        }
        self.closed = true;
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        if !self.close_sent {
            self.close_sent = true;
            self.conn
                .write_packet(
                    &Writer::message(CHANNEL_CLOSE)
                        .u32(self.remote_channel)
                        .into_vec(),
                )
                .await?;
        }
        Ok(())
    }
}

impl<T> std::fmt::Debug for Session<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("server_version", &self.server_version)
            .field("cipher", &self.cipher)
            .field("remote_channel", &self.remote_channel)
            .field("closed", &self.closed)
            .finish()
    }
}
