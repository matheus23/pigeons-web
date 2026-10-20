//! The page: a local prompt, SSH sessions, and a settings sheet.

use std::cell::RefCell;
use std::rc::Rc;

use kereru::{ClientConfig, HostKeyInfo, HostKeyVerdict, Input};
use tokio::sync::mpsc::UnboundedSender;
use wasm_bindgen::JsCast;
use web_sys::{HtmlElement, HtmlInputElement, KeyboardEvent};

use crate::config::{Config, Host};
use crate::identity::Identity;
use crate::platform::{self, Result};
use crate::terminal::{self, Terminal};
use crate::tunnel;

const PROMPT: &str = "\x1b[2mpigeons\x1b[0m \x1b[38;5;110m>\x1b[0m ";
const ACCENT: &str = "\x1b[38;5;110m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

pub async fn run() -> Result<()> {
    let config = Config::load();
    let identity = Rc::new(
        Identity::load_or_create()
            .await
            .map_err(|e| format!("could not prepare an SSH identity: {e}"))?,
    );

    let terminal = Terminal::new(
        platform::by_id::<HtmlElement>("viewport"),
        platform::by_id::<HtmlElement>("grid"),
        platform::by_id::<HtmlElement>("cursor"),
    );

    let app = Rc::new(RefCell::new(App {
        self_ref: std::rc::Weak::new(),
        term: terminal,
        config,
        identity,
        session: None,
        line: String::new(),
        history: Vec::new(),
        history_position: None,
        busy: false,
    }));

    app.borrow_mut().self_ref = Rc::downgrade(&app);
    {
        let mut app = app.borrow_mut();
        app.welcome();
        app.prompt();
    }
    wire(&app);
    update_chrome(&app);
    Ok(())
}

struct ActiveSession {
    input: UnboundedSender<Input>,
    label: String,
    /// Without a pseudo-terminal, characters arrive at the remote through a pipe,
    /// so a line break has to be a plain LF rather than a carriage return.
    pty: bool,
}

struct App {
    /// A handle to the shared app, so a `&mut self` method can spawn work that
    /// needs the `Rc` again once the borrow is released.
    self_ref: std::rc::Weak<RefCell<App>>,
    term: Terminal,
    config: Config,
    identity: Rc<Identity>,
    session: Option<ActiveSession>,
    /// The local prompt's current line.
    line: String,
    history: Vec<String>,
    history_position: Option<usize>,
    busy: bool,
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

fn wire(app: &Rc<RefCell<App>>) {
    let target: web_sys::EventTarget = platform::window().into();

    let handle = app.clone();
    platform::on::<KeyboardEvent>(&target, "keydown", move |event| {
        let action = handle.borrow_mut().on_key(event);
        if matches!(action, Some(Action::OpenSettings)) {
            open_settings(&handle);
        }
    });

    let handle = app.clone();
    platform::on::<web_sys::Event>(&target, "resize", move |_| {
        handle.borrow_mut().relayout();
    });

    let handle = app.clone();
    platform::on::<web_sys::ClipboardEvent>(&platform::document().into(), "paste", move |event| {
        handle.borrow_mut().on_paste(event);
    });

    let handle = app.clone();
    platform::on::<web_sys::MouseEvent>(
        &platform::by_id::<HtmlElement>("terminal").into(),
        "mousedown",
        move |_| {
            handle.borrow_mut().refocus();
        },
    );

    let handle = app.clone();
    platform::on::<web_sys::MouseEvent>(
        &platform::by_id::<HtmlElement>("btn-settings").into(),
        "click",
        move |_| open_settings(&handle),
    );

    let handle = app.clone();
    platform::on::<web_sys::MouseEvent>(
        &platform::by_id::<HtmlElement>("btn-key").into(),
        "click",
        move |_| {
            handle.borrow_mut().print_key();
            update_chrome(&handle);
        },
    );

    platform::on::<web_sys::MouseEvent>(
        &platform::by_id::<HtmlElement>("settings-close").into(),
        "click",
        |_| close_settings(),
    );

    let handle = app.clone();
    platform::on::<web_sys::MouseEvent>(
        &platform::by_id::<HtmlElement>("session-close").into(),
        "click",
        move |_| handle.borrow_mut().disconnect(),
    );
}

impl App {
    fn refocus(&mut self) {
        // Keydown is captured on the window, so there is nothing to focus; this
        // exists so clicking the terminal dismisses an open sheet.
        if is_settings_open() {
            close_settings();
        }
    }

    fn on_key(&mut self, event: KeyboardEvent) -> Option<Action> {
        if is_form_target(&event) {
            return None;
        }

        let ctrl = event.ctrl_key() || event.meta_key();
        if ctrl && event.shift_key() {
            match event.key().to_ascii_lowercase().as_str() {
                "c" => {
                    event.prevent_default();
                    let text = self.term.text();
                    wasm_bindgen_futures::spawn_local(async move {
                        let _ = platform::copy_text(&text).await;
                    });
                    self.toast("screen copied");
                    return None;
                }
                "`" | "~" => {
                    event.prevent_default();
                    if is_settings_open() {
                        close_settings();
                        return None;
                    }
                    return Some(Action::OpenSettings);
                }
                "d" => {
                    event.prevent_default();
                    self.disconnect();
                    return None;
                }
                // Copy what the remote actually sent, for reporting a render bug.
                "b" => {
                    event.prevent_default();
                    let (columns, rows) = self.term.size();
                    let dump = format!("# {columns}x{rows}\n{}\n", self.term.received_dump());
                    platform::log(&dump);
                    wasm_bindgen_futures::spawn_local(async move {
                        let _ = platform::copy_text(&dump).await;
                    });
                    self.toast("received bytes copied");
                    return None;
                }
                _ => {}
            }
        }

        if self.session.is_some() {
            if let Some(mut bytes) = terminal::encode_key(&event, self.term.alternate_screen()) {
                event.prevent_default();
                if let Some(session) = &self.session {
                    if !session.pty {
                        for byte in bytes.iter_mut() {
                            if *byte == b'\r' {
                                *byte = b'\n';
                            }
                        }
                    }
                    let _ = session.input.send(Input::Data(bytes));
                }
            }
            return None;
        }

        self.local_key(event)
    }

    fn local_key(&mut self, event: KeyboardEvent) -> Option<Action> {
        let ctrl = event.ctrl_key() || event.meta_key();
        match event.key().as_str() {
            "Enter" => {
                event.prevent_default();
                return self.submit();
            }
            "Backspace" => {
                event.prevent_default();
                if self.line.pop().is_some() {
                    self.term.write("\x08 \x08");
                }
            }
            "ArrowUp" => {
                event.prevent_default();
                self.recall(-1);
            }
            "ArrowDown" => {
                event.prevent_default();
                self.recall(1);
            }
            "Tab" => event.prevent_default(),
            "c" | "C" if ctrl => {
                event.prevent_default();
                self.line.clear();
                self.term.write("^C");
                self.finish_line();
                self.prompt();
            }
            "l" | "L" if ctrl => {
                event.prevent_default();
                self.term.clear();
                self.line.clear();
                self.prompt();
            }
            "u" | "U" if ctrl => {
                event.prevent_default();
                let width = self.line.chars().count();
                if width > 0 {
                    for _ in 0..width {
                        self.term.write("\x08 \x08");
                    }
                    self.line.clear();
                }
            }
            key => {
                if ctrl || event.alt_key() || event.meta_key() {
                    return None;
                }
                let mut chars = key.chars();
                if let (Some(c), None) = (chars.next(), chars.next())
                    && !c.is_control()
                {
                    event.prevent_default();
                    self.line.push(c);
                    self.term.write(&c.to_string());
                }
            }
        }
        None
    }

    fn on_paste(&mut self, event: web_sys::ClipboardEvent) {
        if is_form_target_event(event.target()) {
            return;
        }
        let Some(data) = event.clipboard_data() else {
            return;
        };
        let text = data.get_data("text/plain").unwrap_or_default();
        if text.is_empty() {
            return;
        }
        event.prevent_default();
        match &self.session {
            Some(session) => {
                let bytes = terminal::encode_paste(&text, false);
                let _ = session.input.send(Input::Data(bytes));
            }
            None => {
                for c in text.chars().filter(|c| !c.is_control()) {
                    self.line.push(c);
                    self.term.write(&c.to_string());
                }
            }
        }
    }

    fn relayout(&mut self) {
        if let Some((columns, rows)) = self.term.fit()
            && let Some(session) = &self.session
        {
            let _ = session.input.send(Input::Resize {
                columns: columns as u32,
                rows: rows as u32,
            });
        }
        self.term.render();
    }

    // -----------------------------------------------------------------------
    // Local command handling
    // -----------------------------------------------------------------------

    fn welcome(&mut self) {
        let hosts = if self.config.hosts.is_empty() {
            format!("{DIM}none yet — add one in settings{RESET}")
        } else {
            self.config
                .hosts
                .iter()
                .map(|host| host.name.clone())
                .collect::<Vec<_>>()
                .join(" · ")
        };
        let key = self.identity.public_key_line();
        let key = shorten(&key, 44);

        self.term.write(&format!(
            "{ACCENT}pigeons-web{RESET}\n\
             {DIM}ssh in your browser, carried over iroh{RESET}\n\n\
             {DIM}hosts {RESET} {hosts}\n\
             {DIM}key   {RESET} {key}\n\n\
             {DIM}ssh <host>  connect · hosts  list · key  identity · help  commands{RESET}\n"
        ));
    }

    fn prompt(&mut self) {
        self.term.write(PROMPT);
    }

    fn finish_line(&mut self) {
        self.term.write("\n");
    }

    fn recall(&mut self, direction: i32) {
        if self.history.is_empty() {
            return;
        }
        let position = match (self.history_position, direction) {
            (None, -1) => Some(self.history.len() - 1),
            (None, _) => return,
            (Some(index), -1) => Some(index.saturating_sub(1)),
            (Some(index), _) => {
                if index + 1 >= self.history.len() {
                    None
                } else {
                    Some(index + 1)
                }
            }
        };
        self.history_position = position;
        let line = position
            .map(|index| self.history[index].clone())
            .unwrap_or_default();

        // Redraw the input line in place.
        self.term.write("\r\x1b[K");
        self.term.write(PROMPT);
        self.term.write(&line);
        self.line = line;
    }

    fn submit(&mut self) -> Option<Action> {
        let line = std::mem::take(&mut self.line);
        self.history_position = None;
        self.finish_line();

        let line = line.trim().to_owned();
        if line.is_empty() {
            self.prompt();
            return None;
        }
        self.history.push(line.clone());

        let words: Vec<&str> = line.split_whitespace().collect();
        match words[0] {
            "help" | "?" => self.print_help(),
            "hosts" | "ls" => self.print_hosts(),
            "key" | "id" => self.print_key(),
            "clear" => {
                self.term.clear();
                self.prompt();
                return None;
            }
            "settings" => return Some(Action::OpenSettings),
            "forget" => match words.get(1) {
                Some(name) => {
                    if self.config.known_hosts.remove(*name).is_some() {
                        self.config.save();
                        self.term
                            .write(&format!("forgot the host key for {name}; the next connection will trust a new one\n"));
                    } else {
                        self.term
                            .write(&format!("no remembered host key for {name}\n"));
                    }
                }
                None => self.term.write("usage: forget <host>\n"),
            },
            "disconnect" => self.disconnect(),
            "ssh" | "connect" => self.start_ssh(&words[1..]),
            other => self
                .term
                .write(&format!("{other}: no such command. try `help`.\n")),
        }
        if self.session.is_none() {
            self.prompt();
        }
        None
    }

    fn print_help(&mut self) {
        self.term.write(&format!(
            "{ACCENT}ssh <host>{RESET} [command]\n\
             {DIM}  connect to a configured host, optionally running one command{RESET}\n\
             {ACCENT}ssh <user>@<host>{RESET}\n\
             {DIM}  connect as a different user{RESET}\n\
             {ACCENT}hosts{RESET}\n\
             {DIM}  list configured hosts{RESET}\n\
             {ACCENT}key{RESET}\n\
             {DIM}  show the public key to add to authorized_keys{RESET}\n\
             {ACCENT}forget <host>{RESET}\n\
             {DIM}  drop the remembered host key after a legitimate server change{RESET}\n\
             {ACCENT}settings{RESET}\n\
             {DIM}  hosts, identity, this browser's endpoint id{RESET}\n\
             {ACCENT}disconnect{RESET}\n\
             {DIM}  or Ctrl+Shift+D, and Ctrl+Shift+C copies the screen{RESET}\n"
        ));
    }

    fn print_hosts(&mut self) {
        if self.config.hosts.is_empty() {
            self.term
                .write("no hosts yet. open `settings` to add one.\n");
            return;
        }
        for host in &self.config.hosts {
            let user = if host.user.is_empty() {
                String::new()
            } else {
                format!("{}@", host.user)
            };
            self.term.write(&format!(
                "{ACCENT}{}{RESET} {DIM}{user}{RESET}{}\n",
                host.name, host.target
            ));
        }
    }

    fn print_key(&mut self) {
        let line = self.identity.public_key_line();
        self.term.write(&format!(
            "\n{ACCENT}your identity{RESET} {DIM}{}{RESET}\n{}\n\n{DIM}fingerprint {}{RESET}\n\
             {DIM}the private half is a non-extractable WebCrypto key: the page can sign with it, never read it{RESET}\n",
            self.identity.algorithm().label(),
            line,
            self.identity.fingerprint(),
        ));
    }

    fn toast(&mut self, message: &str) {
        let node: HtmlElement = platform::by_id("toast");
        node.set_class_name("toast visible");
        platform::set_text(&node, message);
        let node = node.clone();
        platform::on::<web_sys::Event>(&node.clone().into(), "transitionend", move |_| {
            node.set_class_name("toast");
        });
        let node = platform::by_id::<HtmlElement>("toast");
        wasm_bindgen_futures::spawn_local(async move {
            wasm_bindgen_futures::JsFuture::from(platform::sleep(1400))
                .await
                .ok();
            node.set_class_name("toast");
        });
    }

    fn disconnect(&mut self) {
        match &self.session {
            Some(session) => {
                let _ = session.input.send(Input::Eof);
                self.term.write("\r\n");
            }
            None => self.term.write("not connected\n"),
        }
    }

    fn start_ssh(&mut self, args: &[&str]) {
        if self.busy {
            self.term.write("already connecting…\n");
            return;
        }
        if self.session.is_some() {
            self.term
                .write("already connected. `disconnect` first (or Ctrl+Shift+D).\n");
            return;
        }

        let mut user_override = None;
        let mut index = 0;
        if args.first() == Some(&"-l") {
            user_override = args.get(1).map(|value| (*value).to_owned());
            index = 2;
        }
        let Some(destination) = args.get(index) else {
            self.term.write("usage: ssh [user@]<host> [command]\n");
            return;
        };
        // The local prompt splits on whitespace and has no quoting rules of its
        // own, so a single quoted argument keeps its quotes; drop them.
        let command = if args.len() > index + 1 {
            Some(strip_quotes(&args[index + 1..].join(" ")))
        } else {
            None
        };

        let (user_part, name) = match destination.split_once('@') {
            Some((user, name)) => (Some(user.to_owned()), name),
            None => (None, *destination),
        };
        if name.is_empty() {
            self.term.write("usage: ssh [user@]<host> [command]\n");
            return;
        }

        let Some(host) = self.config.host(name).cloned() else {
            self.term.write(&format!(
                "unknown host `{name}`. {DIM}configured: {}{RESET}\n",
                if self.config.hosts.is_empty() {
                    "none — open `settings`".to_owned()
                } else {
                    self.config
                        .hosts
                        .iter()
                        .map(|h| h.name.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
            return;
        };

        let user = user_part
            .or(user_override)
            .unwrap_or_else(|| host.user.clone());

        // A browser has no local login name to fall back on, so an empty user
        // would reach the server as `user ""` and be reported as a bad key.
        if user.trim().is_empty() {
            self.term.write(&format!(
                "{} has no user. {DIM}open `settings` and fill in the user field,\n\
                 or run `ssh <user>@{}`{RESET}\n",
                host.name, host.name
            ));
            return;
        }

        // A host with only a scheme prefix looks configured but is not; catch it
        // here rather than failing later with a parse error.
        let Some(target) = normalized_target(&host.target) else {
            self.term.write(&format!(
                "{} has no endpoint id yet. {DIM}open `settings` and paste the id that\n\
                 `pigeons roost` printed into the target field{RESET}\n",
                host.name
            ));
            return;
        };

        self.busy = true;
        self.term.write(&format!(
            "{DIM}connecting to {} over iroh ({target}){RESET}\n",
            host.name
        ));
        render_chrome(None, true);
        let Some(app) = self.self_ref.upgrade() else {
            return;
        };
        wasm_bindgen_futures::spawn_local(async move {
            connect(app, host, user, command, target).await;
        });
    }

    fn end_session(&mut self, message: Option<String>) {
        let label = self.session.as_ref().map(|session| session.label.clone());
        self.session = None;
        self.busy = false;
        self.term.set_crlf(false);
        match (label, message) {
            (Some(label), Some(error)) => {
                self.term
                    .write(&format!("\r\n\x1b[31m{label}: {error}{RESET}\n"));
            }
            (Some(label), None) => {
                self.term
                    .write(&format!("\r\n{DIM}connection to {label} closed{RESET}\n"));
            }
            (None, Some(error)) => self.term.write(&format!("\x1b[31m{error}{RESET}\n")),
            (None, None) => {}
        }
        self.prompt();
    }
}

// ---------------------------------------------------------------------------
// Connecting
// ---------------------------------------------------------------------------

async fn connect(
    app: Rc<RefCell<App>>,
    host: Host,
    user: String,
    command: Option<String>,
    roost: String,
) {
    let (known, columns, rows) = {
        let state = app.borrow();
        let (columns, rows) = state.term.size();
        (
            state.config.known_hosts.get(&host.name).cloned(),
            columns,
            rows,
        )
    };
    let identity = app.borrow().identity.clone();

    let result = async {
        let stream = tunnel::connect(&roost).await?;

        let config = ClientConfig {
            user,
            terminal: "xterm-256color".into(),
            columns: columns as u32,
            rows: rows as u32,
            command,
            request_pty: true,
            ..ClientConfig::default()
        };

        let check_name = host.name.clone();
        let check = move |info: &HostKeyInfo| -> HostKeyVerdict {
            match &known {
                Some(previous) if previous != &info.fingerprint => HostKeyVerdict::Reject(format!(
                    "the host key for {check_name} changed.\n\
                     known:   {previous}\n\
                     offered: {}\n\
                     If the server was reinstalled deliberately, run `forget {check_name}`.",
                    info.fingerprint
                )),
                _ => HostKeyVerdict::Trust,
            }
        };

        let session = kereru::connect(
            stream,
            config,
            identity.as_ref(),
            Box::new(platform::BrowserRng),
            &check,
        )
        .await
        .map_err(|e| e.to_string())?;

        let fingerprint = session.host_key().fingerprint.clone();
        let summary = format!("{} · {}", session.server_version(), session.cipher());
        let pty = session.has_pty();
        Ok::<_, String>((session, fingerprint, summary, pty))
    }
    .await;

    let (mut session, fingerprint, summary, pty) = match result {
        Ok(value) => value,

        Err(error) => {
            {
                let mut state = app.borrow_mut();
                state.busy = false;
                state.end_session(Some(error));
            }
            update_chrome(&app);
            return;
        }
    };

    let (input, mut queue) = tokio::sync::mpsc::unbounded_channel();
    {
        let mut state = app.borrow_mut();
        if let Some(banners) = session.banners().first() {
            state.term.write(&format!("{DIM}{banners}{RESET}\n"));
        }
        state.term.clear();
        state.term.set_crlf(!pty);
        let label = host.name.clone();
        state
            .term
            .write(&format!("{DIM}connected to {label} · {summary}{RESET}\n"));
        if !pty {
            state.term.write(&format!(
                "{DIM}no pseudo-terminal was granted; full-screen programs will not work{RESET}\n"
            ));
        }
        state.busy = false;
        let is_new = state.config.known_hosts.get(&host.name) != Some(&fingerprint);
        if is_new {
            state
                .config
                .known_hosts
                .insert(host.name.clone(), fingerprint);
            state.config.save();
        }
        state.session = Some(ActiveSession {
            input,
            label: host.name.clone(),
            pty,
        });
    }
    update_chrome(&app);

    // The pump owns the session: it is the only thing that may drive it, so no
    // other code path can borrow the socket while it awaits.
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            match session.pump(&mut queue).await {
                Ok(kereru::Event::Output(bytes)) => {
                    app.borrow_mut().term.process(&bytes);
                }
                Ok(kereru::Event::Closed { .. }) => {
                    app.borrow_mut().end_session(None);
                    update_chrome(&app);
                    break;
                }
                Err(error) => {
                    app.borrow_mut().end_session(Some(error.to_string()));
                    update_chrome(&app);
                    break;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Chrome and settings
// ---------------------------------------------------------------------------

/// Actions that have to happen after the `RefCell` borrow is released, because
/// they borrow the app again (directly or through the settings sheet).
enum Action {
    OpenSettings,
}

fn update_chrome(app: &Rc<RefCell<App>>) {
    let (label, busy) = {
        let state = app.borrow();
        (
            state.session.as_ref().map(|session| session.label.clone()),
            state.busy,
        )
    };
    render_chrome(label.as_deref(), busy);
}

fn render_chrome(label: Option<&str>, busy: bool) {
    let pill: HtmlElement = platform::by_id("session-pill");
    let name: HtmlElement = platform::by_id("session-name");
    let hint: HtmlElement = platform::by_id("hint");

    match label {
        Some(label) => {
            pill.set_class_name("pill connected");
            platform::set_text(&name, label);
            platform::set_text(&hint, "Ctrl+Shift+D disconnects · Ctrl+Shift+C copies");
        }
        None => {
            pill.set_class_name("pill");
            platform::set_text(&name, if busy { "connecting" } else { "local" });
            platform::set_text(&hint, "ssh <host> to connect · Ctrl+Shift+` for settings");
        }
    }
}

fn is_settings_open() -> bool {
    platform::by_id::<HtmlElement>("settings")
        .class_name()
        .contains("open")
}

fn close_settings() {
    platform::by_id::<HtmlElement>("settings").set_class_name("modal");
}

fn open_settings(app: &Rc<RefCell<App>>) {
    platform::by_id::<HtmlElement>("settings").set_class_name("modal open");
    render_settings(app);
}

fn render_settings(app: &Rc<RefCell<App>>) {
    let body: HtmlElement = platform::by_id("settings-body");
    while let Some(child) = body.first_child() {
        body.remove_child(&child).ok();
    }

    let (hosts, identity) = {
        let state = app.borrow();
        (state.config.hosts.clone(), {
            let identity = state.identity.clone();
            (
                identity.public_key_line(),
                identity.fingerprint().to_owned(),
                identity.algorithm().label(),
            )
        })
    };

    // --- hosts -------------------------------------------------------------
    body.append_child(&section_title("hosts", "where your pigeons fly to"))
        .ok();

    for (index, host) in hosts.iter().enumerate() {
        let row = platform::element("div", "host-row");

        let name = text_field("name", &host.name, "name");
        let user = text_field("user", &host.user, "user");
        let target = text_field("target", &host.target, "roost endpoint id");

        // Rows are addressed by position: a row can be renamed while the sheet
        // stays open, and looking it up by its old name loses the edit.
        let field = |input: &HtmlInputElement, change: fn(&mut Host, String)| {
            let app = app.clone();
            let value = input.clone();
            platform::on::<web_sys::Event>(&input.clone().into(), "change", move |_| {
                let mut state = app.borrow_mut();
                if let Some(host) = state.config.hosts.get_mut(index) {
                    change(host, value.value().trim().to_owned());
                }
                state.config.save();
            });
        };
        field(&name, |host, value| {
            if !value.is_empty() {
                host.name = value;
            }
        });
        field(&user, |host, value| host.user = value);
        field(&target, |host, value| host.target = value);

        let remove = platform::element("button", "icon");
        platform::set_text(&remove, "remove");
        {
            let app = app.clone();
            let host_name = host.name.clone();
            platform::on::<web_sys::MouseEvent>(&remove.clone().into(), "click", move |_| {
                app.borrow_mut().config.remove(&host_name);
                app.borrow().config.save();
                render_settings(&app);
            });
        }

        row.append_child(&name).ok();
        row.append_child(&user).ok();
        row.append_child(&target).ok();
        row.append_child(&remove).ok();
        body.append_child(&row).ok();
    }

    let add = platform::element("button", "ghost wide");
    platform::set_text(&add, "add host");
    {
        let app = app.clone();
        platform::on::<web_sys::MouseEvent>(&add.clone().into(), "click", move |_| {
            let count = app.borrow().config.hosts.len() + 1;
            let mut name = format!("host{count}");
            while app.borrow().config.host(&name).is_some() {
                name.push('x');
            }
            app.borrow_mut().config.upsert(Host {
                name,
                user: String::new(),
                target: String::new(),
            });
            app.borrow().config.save();
            render_settings(&app);
        });
    }
    body.append_child(&add).ok();

    // --- identity ----------------------------------------------------------
    body.append_child(&section_title(
        "identity",
        "your SSH key lives in this browser",
    ))
    .ok();

    let identity_box = platform::element("div", "identity");
    let meta = platform::element("div", "meta");
    platform::set_text(
        &meta,
        &format!(
            "{algorithm} · {fingerprint}",
            algorithm = identity.2,
            fingerprint = identity.1
        ),
    );
    let key = platform::element("code", "pubkey");
    platform::set_text(&key, &identity.0);
    identity_box.append_child(&meta).ok();
    identity_box.append_child(&key).ok();

    let actions = platform::element("div", "row-actions");
    let copy = platform::element("button", "ghost");
    platform::set_text(&copy, "copy public key");
    {
        let text = identity.0.clone();
        let app = app.clone();
        platform::on::<web_sys::MouseEvent>(&copy.clone().into(), "click", move |_| {
            let text = text.clone();
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = platform::copy_text(&text).await;
                app.borrow_mut().toast("public key copied");
            });
        });
    }

    let regenerate = platform::element("button", "danger");
    platform::set_text(&regenerate, "replace key");
    {
        let app = app.clone();
        platform::on::<web_sys::MouseEvent>(&regenerate.clone().into(), "click", move |_| {
            let confirmed = platform::window()
                .confirm_with_message(
                    "Replace this browser's SSH key? Hosts that trust the old key will stop accepting it.",
                )
                .unwrap_or(false);
            if !confirmed {
                return;
            }
            let app = app.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let old = app.borrow().identity.clone();
                if old.forget().await.is_err() {
                    return;
                }
                match Identity::load_or_create().await {
                    Ok(fresh) => {
                        app.borrow_mut().identity = Rc::new(fresh);
                        render_settings(&app);
                        update_chrome(&app);
                        app.borrow_mut().print_key();
                    }
                    Err(error) => app
                        .borrow_mut()
                        .toast(&format!("key setup failed: {error}")),
                }
            });
        });
    }
    actions.append_child(&copy).ok();
    actions.append_child(&regenerate).ok();
    identity_box.append_child(&actions).ok();
    body.append_child(&identity_box).ok();

    // --- this browser ------------------------------------------------------
    body.append_child(&section_title(
        "this browser",
        "it is its own iroh endpoint; the roost sees this id",
    ))
    .ok();

    let endpoint_box = platform::element("div", "identity");
    let endpoint_meta = platform::element("div", "meta");
    let endpoint_id = platform::element("code", "pubkey");
    endpoint_box.append_child(&endpoint_meta).ok();
    endpoint_box.append_child(&endpoint_id).ok();
    body.append_child(&endpoint_box).ok();

    {
        let meta = endpoint_meta.clone();
        let value = endpoint_id.clone();
        match tunnel::endpoint_id() {
            Some(id) => {
                platform::set_text(&meta, "iroh endpoint · connected to the relay");
                platform::set_text(&value, &id);
            }
            None => {
                platform::set_text(&meta, "iroh endpoint · starting");
                platform::set_text(&value, "…");
                wasm_bindgen_futures::spawn_local(async move {
                    match tunnel::endpoint().await {
                        Ok(endpoint) => {
                            platform::set_text(&meta, "iroh endpoint · connected to the relay");
                            platform::set_text(&value, &endpoint.id().to_string());
                        }
                        Err(error) => {
                            platform::set_text(
                                &meta,
                                &format!("iroh endpoint · unavailable: {error}"),
                            );
                            platform::set_text(&value, "—");
                        }
                    }
                });
            }
        }
    }

    let note = platform::element("p", "note");
    platform::set_text(
        &note,
        "Hosts and trusted host keys are stored in this browser's localStorage. The SSH key is a \
         non-extractable WebCrypto key kept in IndexedDB, and it is used only to sign \
         authentication requests.",
    );
    body.append_child(&note).ok();
}

fn section_title(title: &str, subtitle: &str) -> HtmlElement {
    let wrapper = platform::element("div", "section-title");
    let heading = platform::element("h2", "");
    platform::set_text(&heading, title);
    let sub = platform::element("span", "sub");
    platform::set_text(&sub, subtitle);
    wrapper.append_child(&heading).ok();
    wrapper.append_child(&sub).ok();
    wrapper
}

fn text_field(name: &str, value: &str, placeholder: &str) -> HtmlInputElement {
    let input: HtmlInputElement = platform::document()
        .create_element("input")
        .expect("input")
        .unchecked_into();
    input.set_class_name("field");
    input.set_name(name);
    input.set_value(value);
    input.set_placeholder(placeholder);
    input.set_spellcheck(false);
    input
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_form_target(event: &KeyboardEvent) -> bool {
    is_form_target_event(event.target())
}

fn is_form_target_event(target: Option<web_sys::EventTarget>) -> bool {
    let Some(target) = target else {
        return false;
    };
    let tag = target
        .dyn_ref::<web_sys::Element>()
        .map(|element| element.tag_name())
        .unwrap_or_default();
    matches!(tag.as_str(), "INPUT" | "TEXTAREA" | "SELECT")
}

fn shorten(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let head: String = text.chars().take(limit - 8).collect();
    let tail: String = text
        .chars()
        .rev()
        .take(6)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{head}…{tail}")
}

/// Removes one layer of matching quotes around a command.
fn strip_quotes(text: &str) -> String {
    let trimmed = text.trim();
    for quote in ['"', '\''] {
        if trimmed.len() >= 2 && trimmed.starts_with(quote) && trimmed.ends_with(quote) {
            return trimmed[1..trimmed.len() - 1].to_owned();
        }
    }
    trimmed.to_owned()
}

/// The roost endpoint id for a host, or `None` when it has not been filled in.
///
/// Accepts the bare id `pigeons roost` prints and an `iroh:` prefix.
fn normalized_target(raw: &str) -> Option<String> {
    let target = raw.trim();
    let id = target.strip_prefix("iroh:").unwrap_or(target);
    if id.is_empty() {
        return None;
    }
    Some(id.to_owned())
}
