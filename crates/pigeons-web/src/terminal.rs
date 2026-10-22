//! Terminal emulation and rendering.
//!
//! `avt` (asciinema's virtual terminal) owns the screen model: escape parsing,
//! insert/delete mode, scroll regions, charsets, wide characters, scrollback.
//! It is a complete emulator rather than a subset, which matters here — a shell
//! editing a prompt that overflows the width uses insert mode and save/restore,
//! and a partial emulator mangles the line.
//!
//! This module paints the grid as DOM rows. A row is only rebuilt when its
//! contents or styling change, so typing stays cheap while a screenful of output
//! still repaints in one pass.

use avt::{Color as AvtColor, Vt};
use wasm_bindgen::JsCast;
use web_sys::{HtmlElement, KeyboardEvent};

use crate::platform;

/// xterm's first sixteen colors, tuned to the page's palette.
const ANSI: [&str; 16] = [
    "#161821", "#e06c75", "#98c379", "#e5c07b", "#61afef", "#c678dd", "#56b6c2", "#cfd3dc",
    "#5c6370", "#ff8087", "#b3e58f", "#ffd68a", "#82c8ff", "#e2a1ff", "#82dbe6", "#ffffff",
];

const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];

/// The emulator's grid size.
///
/// A struct rather than a `(u16, u16)` tuple: `vt100` reports `(rows, cols)` while
/// `avt` reports `(cols, rows)`, and reading one as the other silently announces a
/// transposed terminal to the remote shell, which only misbehaves on a real PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub columns: u16,
    pub rows: u16,
}

/// How many scrollback lines to keep.
const SCROLLBACK: usize = 1000;

pub struct Terminal {
    vt: Vt,
    viewport: HtmlElement,
    grid: HtmlElement,
    cursor: HtmlElement,
    rows: Vec<HtmlElement>,
    /// Per-row signature of what is already painted.
    painted: Vec<String>,
    cell_w: f64,
    cell_h: f64,
    cursor_visible: bool,
    /// Incomplete UTF-8 sequence from the previous chunk.
    pending_utf8: Vec<u8>,
    /// Translate bare LF to CRLF. A session without a pseudo-terminal delivers
    /// plain newlines; a real terminal's line discipline would add the CR, and
    /// without it every line starts where the previous one ended.
    crlf: bool,
    /// Tail of what the remote sent, for the byte dump.
    received: std::collections::VecDeque<u8>,
    /// How many lines the view is scrolled back from the bottom of history.
    scroll: usize,
    /// Shown while the view is not at the bottom; tapping it jumps back.
    scroll_back: HtmlElement,
    /// The DECSET modes the page itself acts on.
    modes: Modes,
    /// Tail of a mode sequence cut off by a chunk boundary.
    mode_tail: Vec<u8>,
}

impl Terminal {
    pub fn new(viewport: HtmlElement, grid: HtmlElement, cursor: HtmlElement) -> Self {
        let (cell_w, cell_h) = measure_cell();
        let mut terminal = Self {
            vt: Vt::builder()
                .size(80, 24)
                .scrollback_limit(SCROLLBACK)
                .build(),
            viewport,
            grid,
            cursor,
            rows: Vec::new(),
            painted: Vec::new(),
            cell_w,
            cell_h,
            cursor_visible: true,
            pending_utf8: Vec::new(),
            crlf: false,
            received: std::collections::VecDeque::new(),
            scroll: 0,
            scroll_back: platform::by_id("scroll-back"),
            modes: Modes::initial(),
            mode_tail: Vec::new(),
        };
        terminal.fit();
        terminal
    }

    /// The emulator's grid size.
    pub fn size(&self) -> Size {
        let (columns, rows) = self.vt.size();
        Size {
            columns: columns as u16,
            rows: rows as u16,
        }
    }

    /// Resizes the screen to the viewport. Returns the new size if it changed.
    pub fn fit(&mut self) -> Option<Size> {
        let rect = self.viewport.get_bounding_client_rect();
        let columns = ((rect.width() / self.cell_w).floor() as u16).clamp(20, 400);
        let rows = ((rect.height() / self.cell_h).floor() as u16).clamp(6, 200);
        let size = Size { columns, rows };
        if size == self.size() {
            return None;
        }

        self.vt.resize(columns as usize, rows as usize);
        self.grid
            .style()
            .set_property("--cell-w", &format!("{}px", self.cell_w))
            .ok();
        self.grid
            .style()
            .set_property("--cell-h", &format!("{}px", self.cell_h))
            .ok();
        // Expose the emulator's own size: it is derived from the same
        // measurement the cursor uses, so it is the value to compare against
        // when the cursor and the text disagree.
        self.viewport
            .set_attribute("data-columns", &columns.to_string())
            .ok();
        self.viewport
            .set_attribute("data-rows", &rows.to_string())
            .ok();
        self.cursor
            .style()
            .set_property("width", &format!("{}px", self.cell_w))
            .ok();
        self.cursor
            .style()
            .set_property("height", &format!("{}px", self.cell_h))
            .ok();

        // Rebuild the row elements to match, then repaint everything. Only the
        // rows are replaced: the grid also holds the hidden probe the cell
        // measurement depends on.
        for row in self.rows.drain(..) {
            row.remove();
        }
        self.painted.clear();

        for _ in 0..rows {
            let row = platform::element("div", "row");
            self.grid.append_child(&row).ok();
            self.rows.push(row);
        }
        Some(size)
    }

    /// Enables or disables newline translation for received bytes.
    pub fn set_crlf(&mut self, crlf: bool) {
        self.crlf = crlf;
    }

    /// Escaped tail of the bytes received from the remote.
    ///
    /// For terminal bugs the byte stream is the only reliable evidence, so this
    /// is what `Ctrl+Shift+B` copies: a rendering oddity can then be reported
    /// exactly instead of described.
    pub fn received_dump(&self) -> String {
        let mut out = String::with_capacity(self.received.len() * 2);
        for byte in &self.received {
            match byte {
                b'\\' => out.push_str("\\\\"),
                0x20..=0x7e => out.push(*byte as char),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                0x1b => out.push_str("\\e"),
                0x07 => out.push_str("\\a"),
                _ => out.push_str(&format!("\\x{byte:02x}")),
            }
        }
        out
    }

    /// The cursor cell the emulator currently reports, for diagnostics.
    pub fn cursor_cell(&self) -> (u16, u16) {
        let cursor = self.vt.cursor();
        (cursor.row as u16, cursor.col as u16)
    }

    pub fn process(&mut self, bytes: &[u8]) {
        self.received.extend(bytes);
        while self.received.len() > 8192 {
            self.received.pop_front();
        }

        let data = if self.crlf {
            normalise_newlines(bytes)
        } else {
            bytes.to_vec()
        };

        // Decode UTF-8 across chunk boundaries: a sequence may be split between
        // two reads, and a truncated character must not be dropped.
        let mut pending = std::mem::take(&mut self.pending_utf8);
        pending.extend_from_slice(&data);
        let mut decoded = String::new();
        let mut consumed = 0;
        loop {
            match std::str::from_utf8(&pending[consumed..]) {
                Ok(text) => {
                    decoded.push_str(text);
                    consumed = pending.len();
                    break;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    // The bytes up to the error are known good.
                    if let Ok(text) = std::str::from_utf8(&pending[consumed..consumed + valid]) {
                        decoded.push_str(text);
                    }
                    consumed += valid;
                    match error.error_len() {
                        // Genuinely invalid: replace it and carry on.
                        Some(length) => {
                            decoded.push('\u{fffd}');
                            consumed += length;
                        }
                        // Incomplete sequence at the end: wait for the next chunk.
                        None => break,
                    }
                }
            }
        }
        self.pending_utf8 = pending[consumed..].to_vec();

        // One parser for every private mode the page acts on; entering the
        // alternate screen drops whatever history the view was reading.
        if scan_modes(&mut self.modes, &mut self.mode_tail, &data) {
            self.scroll = 0;
        }
        let previous_total = self.total_lines();
        let discarded = {
            let changes = self.vt.feed_str(&decoded);
            // Lines this chunk pushed out of the buffer entirely, which happens
            // once history is at its limit.
            changes.scrollback.count()
        };
        if self.scroll > 0 {
            // A scrolled-back view stays on the lines it was showing: every line
            // that leaves the screen moves it back by one, whether the line went
            // into history or was discarded at the limit.
            let advance = pinned_advance(previous_total, self.total_lines(), discarded);
            self.scroll = self.scroll.saturating_add(advance);
        }
        self.render();
    }

    /// Whether a full-screen program is using the alternate screen.
    pub fn alternate_screen(&self) -> bool {
        self.modes.alternate_screen
    }

    /// One character cell's height, for turning a drag into rows.
    pub fn cell_height(&self) -> f64 {
        self.cell_h
    }

    /// How many lines are held in history, including the visible screen.
    fn total_lines(&self) -> usize {
        self.vt.lines().count()
    }

    /// Scrolls the view through history; positive rows go further back.
    pub fn scroll_by(&mut self, rows: i32) {
        let height = self.vt.size().1;
        let furthest = self.total_lines().saturating_sub(height);
        let next = if rows >= 0 {
            self.scroll.saturating_add(rows as usize).min(furthest)
        } else {
            self.scroll.saturating_sub(rows.unsigned_abs() as usize)
        };
        if next != self.scroll {
            self.scroll = next;
            self.render();
        }
    }

    /// Returns the view to the newest output.
    pub fn scroll_to_bottom(&mut self) {
        if self.scroll != 0 {
            self.scroll = 0;
            self.render();
        }
    }

    /// Whether the remote asked for pastes to be wrapped in `CSI 200 ~`.
    pub fn bracketed_paste(&self) -> bool {
        self.modes.bracketed_paste
    }

    /// Writes text with newline translation, for locally generated output.
    pub fn write(&mut self, text: &str) {
        let translated = text.replace('\n', "\r\n");
        self.process(translated.as_bytes());
    }

    pub fn clear(&mut self) {
        let size = self.size();
        self.vt = Vt::builder()
            .size(size.columns as usize, size.rows as usize)
            .scrollback_limit(SCROLLBACK)
            .build();
        self.painted.clear();
        // Input modes and the scroll position belong to the session that set
        // them: a session that dies inside htop must not leave the page sending
        // wheel reports to nobody.
        self.modes = Modes::initial();
        self.mode_tail.clear();
        self.scroll = 0;
    }

    /// Forgets the modes a session set, without touching the screen.
    pub fn reset_input_modes(&mut self) {
        self.modes = Modes::initial();
        self.mode_tail.clear();
    }

    /// Plain text of the visible screen, used for copying.
    pub fn text(&self) -> String {
        self.vt
            .view()
            .map(|line| line.text().trim_end().to_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Whether the application asked for cursor keys in application mode.
    pub fn application_cursor(&self) -> bool {
        self.vt.cursor_key_app_mode()
    }

    pub fn render(&mut self) {
        let (columns, rows) = {
            let (columns, rows) = self.vt.size();
            (columns as u16, rows as u16)
        };

        let total = self.total_lines();
        let window = rows as usize;
        let furthest = total.saturating_sub(window);
        if self.scroll > furthest {
            self.scroll = furthest;
        }
        let start = furthest.saturating_sub(self.scroll);

        let mut painted: Vec<(String, Vec<Run>)> = Vec::with_capacity(window);
        for line in self.vt.lines().skip(start).take(window) {
            painted.push(row_runs(line, columns, self.cell_w));
        }

        for (row, (signature, runs)) in painted.into_iter().enumerate() {
            if self.painted.get(row) == Some(&signature) {
                continue;
            }
            let Some(element) = self.rows.get(row) else {
                continue;
            };
            while let Some(child) = element.first_child() {
                element.remove_child(&child).ok();
            }
            for run in runs {
                let span: HtmlElement = platform::document()
                    .create_element("span")
                    .expect("span")
                    .unchecked_into();
                if !run.css.is_empty() {
                    span.set_attribute("style", &run.css).ok();
                }
                span.set_text_content(Some(&run.text));
                element.append_child(&span).ok();
            }
            if self.painted.len() <= row {
                self.painted.resize(row + 1, String::new());
            }
            self.painted[row] = signature;
        }

        // Cursor. `col == columns` means the line exactly fills the row and the
        // next character will wrap; a real terminal keeps the block on the last
        // cell until then, so clamp instead of drawing past the grid.
        let mut cursor_row = self.vt.cursor().row;
        let mut cursor_column = self.vt.cursor().col;
        if cursor_column >= columns as usize {
            cursor_column = (columns as usize).saturating_sub(1);
        }
        if cursor_row >= rows as usize {
            cursor_row = (rows as usize).saturating_sub(1);
        }
        self.cursor_visible = self.vt.cursor().visible && self.scroll == 0;

        self.scroll_back.set_class_name(if self.scroll == 0 {
            "scroll-back"
        } else {
            "scroll-back visible"
        });
        platform::set_text(&self.scroll_back, &format!("↓ {}", self.scroll));

        let x = cursor_column as f64 * self.cell_w;
        let y = cursor_row as f64 * self.cell_h;
        self.cursor
            .style()
            .set_property("transform", &format!("translate({x}px, {y}px)"))
            .ok();
        self.cursor
            .style()
            .set_property(
                "visibility",
                if self.cursor_visible {
                    "visible"
                } else {
                    "hidden"
                },
            )
            .ok();
    }
    /// Whether the application asked for mouse reports.
    pub fn wants_mouse(&self) -> bool {
        self.modes.mouse_tracking
    }

    /// Whether mouse reports should use the SGR encoding.
    pub fn mouse_sgr(&self) -> bool {
        self.modes.sgr_mouse
    }

    /// Whether wheel and drag become cursor keys on the alternate screen.
    pub fn alternate_scroll(&self) -> bool {
        self.modes.alternate_scroll
    }

    /// The cell under a viewport-relative point, for mouse reports.
    pub fn cell_at(&self, x: f64, y: f64) -> Option<(u16, u16)> {
        let Size { columns, rows } = self.size();
        if x < 0.0 || y < 0.0 {
            return None;
        }
        let column = (x / self.cell_w) as u16;
        let row = (y / self.cell_h) as u16;
        if column >= columns || row >= rows {
            return None;
        }
        Some((column, row))
    }

    /// The grid's position on the page, so pointer coordinates become cells.
    pub fn viewport_origin(&self) -> (f64, f64) {
        let rect = self.viewport.get_bounding_client_rect();
        (rect.left(), rect.top())
    }
}

/// One painted stretch of a row.
struct Run {
    css: String,
    text: String,
}

/// Builds one row's runs plus a signature for change detection.
///
/// Wide glyphs get their own fixed-width box. Left to itself, the text engine
/// lays a fallback CJK glyph out at one em instead of two cells (13px against a
/// 15.6px cell here), so a line containing them drifts left by ~2.6px per glyph
/// and nothing below it lines up. Pinning the advance to the emulator's column
/// count keeps the grid intact whatever font the system picks.
fn row_runs(line: &avt::Line, columns: u16, cell_width: f64) -> (String, Vec<Run>) {
    let mut signature = String::with_capacity(columns as usize * 4);
    let mut runs: Vec<Run> = Vec::new();

    for cell in line.cells() {
        // The second half of a wide glyph is reported with width 0.
        if cell.width() == 0 {
            continue;
        }
        let style = cell_style(cell);
        let text = cell.char().to_string();

        if cell.width() > 1 || !cell.char().is_ascii() {
            let boxed = cell_width * f64::from(cell.width());
            runs.push(Run {
                css: format!("{style}display:inline-block;width:{boxed}px;text-align:center;"),
                text,
            });
            continue;
        }

        match runs.last_mut() {
            Some(last) if last.css == style => last.text.push_str(&text),
            _ => runs.push(Run { css: style, text }),
        }
    }

    for run in &runs {
        signature.push('\x1f');
        signature.push_str(&run.css);
        signature.push('\x1e');
        signature.push_str(&run.text);
    }
    (signature, runs)
}

fn cell_style(cell: &avt::Cell) -> String {
    let pen = cell.pen();
    let mut foreground = color_css(pen.foreground(), pen.is_bold());
    let mut background = color_css(pen.background(), false);
    if pen.is_inverse() {
        // Swapping needs both sides resolved to concrete colors.
        let fg = foreground.unwrap_or_else(|| "#cfd3dc".to_owned());
        let bg = background.unwrap_or_else(|| "#10121a".to_owned());
        foreground = Some(bg);
        background = Some(fg);
    }

    let mut style = String::new();
    if let Some(color) = foreground {
        style.push_str("color:");
        style.push_str(&color);
        style.push(';');
    }
    if let Some(color) = background {
        style.push_str("background-color:");
        style.push_str(&color);
        style.push(';');
    }
    if pen.is_bold() {
        style.push_str("font-weight:600;");
    }
    if pen.is_faint() {
        style.push_str("opacity:0.65;");
    }
    if pen.is_italic() {
        style.push_str("font-style:italic;");
    }
    if pen.is_underline() {
        style.push_str("text-decoration:underline;");
    }
    if pen.is_strikethrough() {
        style.push_str("text-decoration:line-through;");
    }
    style
}

fn color_css(color: Option<AvtColor>, bold: bool) -> Option<String> {
    match color? {
        AvtColor::Indexed(index) => {
            let index = if bold && index < 8 { index + 8 } else { index };
            Some(match index {
                0..=15 => ANSI[index as usize].to_owned(),
                16..=231 => {
                    let index = index - 16;
                    let r = CUBE[(index / 36) as usize];
                    let g = CUBE[((index % 36) / 6) as usize];
                    let b = CUBE[(index % 6) as usize];
                    format!("#{r:02x}{g:02x}{b:02x}")
                }
                _ => {
                    let level = 8 + 10 * (index - 232);
                    format!("#{level:02x}{level:02x}{level:02x}")
                }
            })
        }
        AvtColor::RGB(rgb) => Some(format!("#{:02x}{:02x}{:02x}", rgb.r, rgb.g, rgb.b)),
    }
}

/// Measures one character cell using the hidden probe in the page.
fn measure_cell() -> (f64, f64) {
    const SAMPLES: f64 = 20.0;
    let probe: HtmlElement = platform::by_id("probe");
    let rect = probe.get_bounding_client_rect();
    let width = if rect.width() > 0.0 {
        rect.width() / SAMPLES
    } else {
        8.4
    };
    let height = if rect.height() > 0.0 {
        rect.height()
    } else {
        18.0
    };
    (width, height)
}

/// The DECSET/DECRST modes whose state the page has to know.
#[derive(Debug, Clone, Copy)]
struct Modes {
    bracketed_paste: bool,
    alternate_screen: bool,
    alternate_scroll: bool,
    mouse_tracking: bool,
    sgr_mouse: bool,
}

impl Modes {
    fn initial() -> Self {
        Self {
            bracketed_paste: false,
            alternate_screen: false,
            // On by default: that is what makes a pager scrollable on a phone,
            // and a program that wants the wheel for itself turns it off.
            alternate_scroll: true,
            mouse_tracking: false,
            sgr_mouse: false,
        }
    }
}

/// Applies one private mode, returning whether the page tracks it.
fn apply_mode(modes: &mut Modes, parameter: &str, enable: bool) -> bool {
    match parameter {
        "47" | "1047" | "1049" => modes.alternate_screen = enable,
        "1000" | "1002" | "1003" => modes.mouse_tracking = enable,
        "1006" => modes.sgr_mouse = enable,
        "1007" => modes.alternate_scroll = enable,
        "2004" => modes.bracketed_paste = enable,
        _ => return false,
    }
    true
}

/// Scans private mode runs (`ESC [ ? <params> h` or `l`) and updates the modes.
///
/// These sequences all have the same shape, so they are parsed once instead of
/// matched per mode: matching per mode is how `?47h` came to never match, and how
/// a combined `?1002;1006h` only half applied. `tail` holds a sequence cut off by
/// a chunk boundary until the next read.
///
/// Returns whether the alternate screen was entered, which drops history.
fn scan_modes(modes: &mut Modes, tail: &mut Vec<u8>, data: &[u8]) -> bool {
    let mut buffer = std::mem::take(tail);
    buffer.extend_from_slice(data);
    let mut entered_alternate = false;
    let mut index = 0;

    while index < buffer.len() {
        let starts_mode = buffer[index] == 0x1b
            && buffer.get(index + 1) == Some(&b'[')
            && buffer.get(index + 2) == Some(&b'?');
        if !starts_mode {
            index += 1;
            continue;
        }
        let mut cursor = index + 3;
        let mut parameters = String::new();
        while cursor < buffer.len() && (buffer[cursor].is_ascii_digit() || buffer[cursor] == b';') {
            parameters.push(buffer[cursor] as char);
            cursor += 1;
        }
        let Some(&final_byte) = buffer.get(cursor) else {
            // Cut off mid-sequence: keep it for the next chunk.
            break;
        };
        if final_byte != b'h' && final_byte != b'l' {
            index = cursor + 1;
            continue;
        }
        let enable = final_byte == b'h';
        for parameter in parameters.split(';').filter(|part| !part.is_empty()) {
            if apply_mode(modes, parameter, enable)
                && enable
                && matches!(parameter, "47" | "1047" | "1049")
            {
                entered_alternate = true;
            }
        }
        index = cursor + 1;
    }

    *tail = buffer[index..].to_vec();
    // A malformed sequence must not make the tail grow without limit.
    if tail.len() > 32 {
        let excess = tail.len() - 32;
        tail.drain(..excess);
    }
    entered_alternate
}

/// How far a pinned view moves back when a chunk of output arrives.
///
/// The buffer grows while history has room, and starts discarding from the front
/// once it is full; either way the content under a scrolled-back view moves back
/// by that many lines.
fn pinned_advance(previous_total: usize, total: usize, discarded: usize) -> usize {
    total
        .saturating_sub(previous_total)
        .saturating_add(discarded)
}

/// Adds a carriage return before every line feed that lacks one.
fn normalise_newlines(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 16);
    let mut previous = 0u8;
    for &byte in bytes {
        if byte == b'\n' && previous != b'\r' {
            out.push(b'\r');
        }
        out.push(byte);
        previous = byte;
    }
    out
}

/// Turns a single typed character into the control code a Ctrl chord would send.
///
/// Used by the on-screen Ctrl key, which cannot hold a modifier down: the next
/// character typed is folded instead.
pub fn control_code(text: &str) -> Option<Vec<u8>> {
    let mut chars = text.chars();
    let (Some(first), None) = (chars.next(), chars.next()) else {
        return None;
    };
    let byte = match first {
        '@' => 0x00,
        'a'..='z' => first as u8 - b'a' + 1,
        'A'..='Z' => first as u8 - b'A' + 1,
        '[' => 0x1b,
        '\\' => 0x1c,
        ']' => 0x1d,
        '^' => 0x1e,
        '_' | '/' | '-' => 0x1f,
        '?' => 0x7f,
        _ => return None,
    };
    Some(vec![byte])
}

/// Translates a key event into the bytes a terminal would send.
///
/// Returns `None` for keys the browser should keep, for copy and paste
/// shortcuts, and for plain text — printable characters arrive through the
/// textarea's input event, which is the only path that also works for soft
/// keyboards and IME composition.
pub fn encode_key(event: &KeyboardEvent, application_cursor: bool) -> Option<Vec<u8>> {
    let key = event.key();
    let ctrl = event.ctrl_key();
    let alt = event.alt_key();
    let meta = event.meta_key();
    let shift = event.shift_key();

    let cursor = |final_byte: &str| {
        if application_cursor {
            format!("\x1bO{final_byte}").into_bytes()
        } else {
            format!("\x1b[{final_byte}").into_bytes()
        }
    };

    let bytes = match key.as_str() {
        "Enter" => b"\r".to_vec(),
        "Tab" if shift => b"\x1b[Z".to_vec(),
        "Tab" => b"\t".to_vec(),
        "Backspace" => {
            if ctrl {
                b"\x08".to_vec()
            } else {
                b"\x7f".to_vec()
            }
        }
        "Escape" => b"\x1b".to_vec(),
        "ArrowUp" => cursor("A"),
        "ArrowDown" => cursor("B"),
        "ArrowRight" => cursor("C"),
        "ArrowLeft" => cursor("D"),
        "Home" => cursor("H"),
        "End" => cursor("F"),
        "Insert" => b"\x1b[2~".to_vec(),
        "Delete" => b"\x1b[3~".to_vec(),
        "PageUp" => b"\x1b[5~".to_vec(),
        "PageDown" => b"\x1b[6~".to_vec(),
        "F1" => b"\x1bOP".to_vec(),
        "F2" => b"\x1bOQ".to_vec(),
        "F3" => b"\x1bOR".to_vec(),
        "F4" => b"\x1bOS".to_vec(),
        "F5" => b"\x1b[15~".to_vec(),
        "F6" => b"\x1b[17~".to_vec(),
        "F7" => b"\x1b[18~".to_vec(),
        "F8" => b"\x1b[19~".to_vec(),
        "F9" => b"\x1b[20~".to_vec(),
        "F10" => b"\x1b[21~".to_vec(),
        "F11" => b"\x1b[23~".to_vec(),
        "F12" => b"\x1b[24~".to_vec(),
        _ => {
            if ctrl {
                match key.as_str() {
                    " " | "@" => vec![0x00],
                    "[" => vec![0x1b],
                    "\\" => vec![0x1c],
                    "]" => vec![0x1d],
                    "^" => vec![0x1e],
                    "_" => vec![0x1f],
                    "/" => vec![0x1f],
                    "-" => vec![0x1f],
                    _ => {
                        let lower = key.to_ascii_lowercase();
                        let mut chars = lower.chars();
                        match (chars.next(), chars.next()) {
                            (Some(c @ 'a'..='z'), None) => vec![(c as u8) - b'a' + 1],
                            _ => return None,
                        }
                    }
                }
            } else if meta {
                // Command on macOS belongs to the browser, not the shell.
                return None;
            } else if alt && key.chars().count() == 1 {
                // Alt+key never arrives as text, so send it as ESC + character.
                let mut bytes = vec![0x1b];
                bytes.extend_from_slice(key.as_bytes());
                bytes
            } else {
                return None;
            }
        }
    };
    Some(bytes)
}

/// Types a string as if pasted, honouring bracketed paste.
pub fn encode_paste(text: &str, bracketed: bool) -> Vec<u8> {
    // Terminals receive CR, not LF, for each line break.
    let normalised = text.replace("\r\n", "\r").replace('\n', "\r");
    if bracketed {
        format!("\x1b[200~{normalised}\x1b[201~").into_bytes()
    } else {
        normalised.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::{Modes, control_code, encode_paste, normalise_newlines, scan_modes};

    fn scan(data: &[u8]) -> (Modes, bool) {
        let mut modes = Modes::initial();
        let mut tail = Vec::new();
        let entered = scan_modes(&mut modes, &mut tail, data);
        (modes, entered)
    }

    #[test]
    fn newline_translation_adds_only_missing_carriage_returns() {
        assert_eq!(normalise_newlines(b"a\nb"), b"a\r\nb");
        assert_eq!(normalise_newlines(b"a\r\nb"), b"a\r\nb");
        assert_eq!(normalise_newlines(b"a\rb"), b"a\rb");
    }

    #[test]
    fn bracketed_paste_follows_the_mode_the_server_set() {
        let (modes, _) = scan(b"\x1b[?2004h");
        assert!(modes.bracketed_paste);
        let (modes, _) = scan(b"output \x1b[?2004l more");
        assert!(!modes.bracketed_paste);
    }

    #[test]
    fn a_sequence_split_across_reads_is_still_seen() {
        let mut modes = Modes::initial();
        let mut tail = Vec::new();
        scan_modes(&mut modes, &mut tail, b"\x1b[?20");
        assert!(!modes.bracketed_paste);
        scan_modes(&mut modes, &mut tail, b"04h");
        assert!(modes.bracketed_paste);
    }

    #[test]
    fn every_alternate_screen_spelling_is_recognised() {
        // Three ways to ask for it, and the short one used to never match.
        for enter in ["\x1b[?47h", "\x1b[?1047h", "\x1b[?1049h"] {
            let (modes, entered) = scan(enter.as_bytes());
            assert!(modes.alternate_screen, "{enter:?}");
            assert!(entered, "{enter:?}");
        }
        let (modes, entered) = scan(b"\x1b[?1049l");
        assert!(!modes.alternate_screen);
        assert!(!entered);
    }

    #[test]
    fn mouse_modes_and_their_encoding_are_tracked() {
        let (modes, _) = scan(b"\x1b[?1000h\x1b[?1006h");
        assert!(modes.mouse_tracking && modes.sgr_mouse);
        let (modes, _) = scan(b"\x1b[?1000l");
        assert!(!modes.mouse_tracking);
    }

    #[test]
    fn combined_parameters_are_each_applied() {
        let (modes, _) = scan(b"\x1b[?1002;1006;1007h");
        assert!(modes.mouse_tracking && modes.sgr_mouse);
        assert!(modes.alternate_scroll);
    }

    #[test]
    fn alternate_scroll_defaults_on_and_can_be_declined() {
        assert!(Modes::initial().alternate_scroll);
        let (modes, _) = scan(b"\x1b[?1007l");
        assert!(!modes.alternate_scroll);
    }

    #[test]
    fn unrelated_private_modes_are_ignored() {
        let (modes, _) = scan(b"\x1b[?25l\x1b[?7h\x1b[?1004h");
        assert!(!modes.mouse_tracking && !modes.sgr_mouse && !modes.bracketed_paste);
        assert!(!modes.alternate_screen);
        assert!(modes.alternate_scroll);
    }

    #[test]
    fn a_paste_is_wrapped_only_when_the_mode_is_on() {
        // Unbracketed: a multi-line paste runs line by line the moment it lands.
        assert_eq!(encode_paste("one\ntwo", false), b"one\rtwo");
        // Bracketed: the editor receives it as one block.
        assert_eq!(
            encode_paste("one\ntwo", true),
            b"\x1b[200~one\rtwo\x1b[201~"
        );
    }

    #[test]
    fn control_codes_follow_the_ctrl_chord() {
        assert_eq!(control_code("c"), Some(vec![0x03]));
        assert_eq!(control_code("C"), Some(vec![0x03]));
        assert_eq!(control_code("@"), Some(vec![0x00]));
        assert_eq!(control_code("?"), Some(vec![0x7f]));
        // Not a single character, so nothing to fold.
        assert_eq!(control_code("ab"), None);
        assert_eq!(control_code("1"), None);
    }
}

#[cfg(test)]
mod pinning_tests {
    use super::pinned_advance;

    #[test]
    fn a_pinned_view_moves_with_the_lines_that_leave_it() {
        // History still has room: the buffer grew by eight lines.
        assert_eq!(pinned_advance(3, 11, 0), 8);
        // History is full: the buffer stayed the same size but discarded 14.
        assert_eq!(pinned_advance(7, 7, 14), 14);
        // Nothing arrived.
        assert_eq!(pinned_advance(11, 11, 0), 0);
    }
}
