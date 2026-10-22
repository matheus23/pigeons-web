//! Terminal emulation and rendering.
//!
//! `vt100` turns the byte stream into a cell grid; this module paints that grid
//! as DOM rows. A row is only rebuilt when its contents or styling change, so
//! typing stays cheap while a screenful of output still repaints in one pass.

use wasm_bindgen::JsCast;
use web_sys::{HtmlElement, KeyboardEvent};

use crate::platform;

/// xterm's first sixteen colors, tuned to the page's palette.
const ANSI: [&str; 16] = [
    "#161821", "#e06c75", "#98c379", "#e5c07b", "#61afef", "#c678dd", "#56b6c2", "#cfd3dc",
    "#5c6370", "#ff8087", "#b3e58f", "#ffd68a", "#82c8ff", "#e2a1ff", "#82dbe6", "#ffffff",
];

const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];

pub struct Terminal {
    parser: vt100::Parser,
    viewport: HtmlElement,
    grid: HtmlElement,
    cursor: HtmlElement,
    rows: Vec<HtmlElement>,
    /// Per-row signature of what is already painted.
    painted: Vec<String>,
    cell_w: f64,
    cell_h: f64,
    title: String,
    cursor_visible: bool,
    /// Tail of what the remote sent, for the byte dump.
    received: std::collections::VecDeque<u8>,
    /// Trailing partial escape sequence, held back for the next chunk so a
    /// sequence split across reads is still recognised as one.
    pending_prefix: Vec<u8>,
    /// Translate bare LF to CRLF. A session without a pseudo-terminal delivers
    /// plain newlines; a real terminal's line discipline would add the CR, and
    /// without it every line starts where the previous one ended.
    crlf: bool,
}

impl Terminal {
    pub fn new(viewport: HtmlElement, grid: HtmlElement, cursor: HtmlElement) -> Self {
        let (cell_w, cell_h) = measure_cell();
        let mut terminal = Self {
            parser: vt100::Parser::new(24, 80, 500),
            viewport,
            grid,
            cursor,
            rows: Vec::new(),
            painted: Vec::new(),
            cell_w,
            cell_h,
            title: String::new(),
            cursor_visible: true,
            received: std::collections::VecDeque::new(),
            pending_prefix: Vec::new(),
            crlf: false,
        };
        terminal.fit();
        terminal
    }

    pub fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    /// Resizes the screen to the viewport. Returns the new size if it changed.
    pub fn fit(&mut self) -> Option<(u16, u16)> {
        let rect = self.viewport.get_bounding_client_rect();
        let columns = ((rect.width() / self.cell_w).floor() as u16).clamp(20, 400);
        let rows = ((rect.height() / self.cell_h).floor() as u16).clamp(6, 200);
        if (columns, rows) == self.parser.screen().size() {
            return None;
        }

        self.parser.set_size(rows, columns);
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
        Some((columns, rows))
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

    pub fn process(&mut self, bytes: &[u8]) {
        self.received.extend(bytes);
        while self.received.len() > 8192 {
            self.received.pop_front();
        }

        // Reassemble the stream, keeping any partial escape prefix for the next
        // chunk so a sequence split across reads is still recognised.
        let mut data = std::mem::take(&mut self.pending_prefix);
        data.extend_from_slice(bytes);
        let tail = escape_prefix_len(&data);
        if tail > 0 {
            self.pending_prefix = data.split_off(data.len() - tail);
        }

        let data = rewrite_save_restore(&data);
        if self.crlf {
            let fixed = normalise_newlines(&data);
            self.parser.process(&fixed);
        } else {
            self.parser.process(&data);
        }
        self.render();
    }

    /// Writes text with newline translation, for locally generated output.
    pub fn write(&mut self, text: &str) {
        let translated = text.replace('\n', "\r\n");
        self.process(translated.as_bytes());
    }

    pub fn clear(&mut self) {
        self.parser = vt100::Parser::new(self.size().0, self.size().1, 500);
        self.painted.clear();
    }

    /// Plain text of the visible screen, used for copying.
    pub fn text(&self) -> String {
        let (rows, columns) = self.size();
        let mut out = String::new();
        for row in 0..rows {
            let mut line = String::new();
            for column in 0..columns {
                if let Some(cell) = self.parser.screen().cell(row, column) {
                    line.push_str(&cell.contents());
                }
            }
            out.push_str(line.trim_end());
            if row + 1 < rows {
                out.push('\n');
            }
        }
        out
    }

    pub fn render(&mut self) {
        let screen = self.parser.screen();
        let (rows, columns) = screen.size();

        for row in 0..rows as usize {
            let (signature, runs) = row_runs(screen, row as u16, columns, self.cell_w);
            if self.painted.get(row) == Some(&signature) {
                continue;
            }
            if let Some(element) = self.rows.get(row) {
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
        }

        // Cursor.
        // vt100 leaves the column at `width` after a line fills the row exactly:
        // its pending-wrap state. A real terminal keeps the cursor block on the
        // last cell until the next character arrives, so clamp rather than draw
        // one cell past the grid (where it is clipped away or lands outside).
        let (rows, columns) = screen.size();
        let (mut row, mut column) = screen.cursor_position();
        if column >= columns {
            column = columns.saturating_sub(1);
        }
        if row >= rows {
            row = rows.saturating_sub(1);
        }

        self.cursor_visible = !screen.hide_cursor();
        let x = column as f64 * self.cell_w;
        let y = row as f64 * self.cell_h;
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

        let title = screen.title().to_owned();
        if title != self.title {
            let label = if title.is_empty() {
                "pigeons-web".to_owned()
            } else {
                format!("{title} — pigeons-web")
            };
            self.title = title;
            platform::document().set_title(&label);
        }
    }

    /// Whether the alternate screen is active, i.e. a full-screen program runs.
    pub fn alternate_screen(&self) -> bool {
        self.parser.screen().alternate_screen()
    }
}

/// Builds one row's style runs plus a signature for change detection.
/// One painted stretch of a row.
struct Run {
    css: String,
    text: String,
}

/// Builds one row's runs plus a signature for change detection.
///
/// Wide glyphs (CJK, emoji) get their own fixed-width box. Left to itself, the
/// text engine lays a fallback CJK glyph out at one em instead of two cells
/// (13px against a 15.6px cell here), so a line containing them drifts left by
/// ~2.6px per glyph and nothing below it lines up. Pinning the advance to two
/// cells keeps the grid intact whatever font the system picks.
fn row_runs(screen: &vt100::Screen, row: u16, columns: u16, cell_width: f64) -> (String, Vec<Run>) {
    let mut signature = String::with_capacity(columns as usize * 4);
    let mut runs: Vec<Run> = Vec::new();

    for column in 0..columns {
        let Some(cell) = screen.cell(row, column) else {
            continue;
        };
        if cell.is_wide_continuation() {
            continue;
        }
        let style = cell_style(cell);
        let text = if cell.has_contents() {
            cell.contents()
        } else {
            " ".to_owned()
        };

        // Any non-ASCII glyph can be laid out at a width that disagrees with the
        // cell model: a CJK ideograph comes out at one em (1.67 cells here) and
        // an emoji that the emulator counts as one column can be drawn two cells
        // wide. Boxing them makes the advance exact, whatever the font does;
        // ASCII runs stay merged so ordinary output is unaffected.
        let exotic = match text.chars().collect::<Vec<_>>().as_slice() {
            [single] => !single.is_ascii(),
            _ => false,
        };
        if exotic {
            let cells = if cell.is_wide() { 2.0 } else { 1.0 };
            let width = cell_width * cells;
            runs.push(Run {
                css: format!("{style}display:inline-block;width:{width}px;text-align:center;"),
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

fn cell_style(cell: &vt100::Cell) -> String {
    let mut foreground = color_css(cell.fgcolor(), cell.bold());
    let mut background = color_css(cell.bgcolor(), false);
    if cell.inverse() {
        // Swapping needs both sides resolved to concrete colors.
        let fg = foreground.unwrap_or_else(|| "#cfd3dc".to_owned());
        let bg = background.unwrap_or_else(|| "#10121a".to_owned());
        foreground = Some(bg.to_owned());
        background = Some(fg.to_owned());
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
    if cell.bold() {
        style.push_str("font-weight:600;");
    }
    if cell.italic() {
        style.push_str("font-style:italic;");
    }
    if cell.underline() {
        style.push_str("text-decoration:underline;");
    }
    style
}

fn color_css(color: vt100::Color, bold: bool) -> Option<String> {
    match color {
        vt100::Color::Default => None,
        vt100::Color::Idx(index) => {
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
        vt100::Color::Rgb(r, g, b) => Some(format!("#{r:02x}{g:02x}{b:02x}")),
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

/// Translates a key event into the bytes a terminal would send.
///
/// Returns `None` for keys the browser should keep, such as copy and paste
/// shortcuts or pure modifier presses.
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
                // Plain text is not sent from here: it goes through the
                // textarea's input event, which is the only path that also
                // works for soft keyboards and IME composition.
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

impl Terminal {
    /// The cursor cell the emulator currently reports, for diagnostics.
    pub fn cursor_cell(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }
}

/// Length of a trailing, incomplete escape prefix (`ESC` or `ESC [`).
fn escape_prefix_len(data: &[u8]) -> usize {
    match data {
        [.., 0x1b] => 1,
        [.., 0x1b, b'['] => 2,
        _ => 0,
    }
}

/// Rewrites `CSI s` / `CSI u` into `DECSC` / `DECRC`.
///
/// Both spellings mean "save cursor" / "restore cursor" in xterm, and prompts
/// that draw a right-hand segment rely on it. The emulator implements only the
/// ESC 7 / ESC 8 form, so the xterm spelling is silently ignored: the cursor is
/// left wherever the segment ended instead of being restored, which then puts
/// the prompt and the cursor on the wrong cells.
fn rewrite_save_restore(data: &[u8]) -> Vec<u8> {
    if !data.windows(3).any(|w| w == b"\x1b[s" || w == b"\x1b[u") {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        if data.len() - index >= 3
            && data[index] == 0x1b
            && data[index + 1] == b'['
            && (data[index + 2] == b's' || data[index + 2] == b'u')
        {
            out.push(0x1b);
            out.push(if data[index + 2] == b's' { b'7' } else { b'8' });
            index += 3;
        } else {
            out.push(data[index]);
            index += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{escape_prefix_len, rewrite_save_restore};

    #[test]
    fn save_restore_is_rewritten_to_decsc_decrc() {
        assert_eq!(rewrite_save_restore(b"a\x1b[sb\x1b[uc"), b"a\x1b7b\x1b8c");
    }

    #[test]
    fn other_sequences_are_left_alone() {
        // CSI with a parameter is not the save/restore spelling.
        assert_eq!(rewrite_save_restore(b"\x1b[1s"), b"\x1b[1s");
        assert_eq!(rewrite_save_restore(b"\x1b[2J"), b"\x1b[2J");
        assert_eq!(rewrite_save_restore(b"plain text"), b"plain text");
    }

    #[test]
    fn a_partial_prefix_is_detected_at_the_end_only() {
        assert_eq!(escape_prefix_len(b"text\x1b"), 1);
        assert_eq!(escape_prefix_len(b"text\x1b["), 2);
        assert_eq!(escape_prefix_len(b"text\x1b[3"), 0);
        assert_eq!(escape_prefix_len(b""), 0);
    }
}
