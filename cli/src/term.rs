/// Terminal UI helpers: ANSI colors, spinner, and formatting.
///
/// Uses true-color ANSI escapes. The brand color is Kerrigan purple (#7C3AED).
/// Falls back gracefully on terminals without color support (NO_COLOR env var).
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Color constants (true-color ANSI)
// ---------------------------------------------------------------------------

/// Brand purple #7C3AED → RGB(124, 58, 237)
pub const PURPLE: &str = "\x1b[38;2;124;58;237m";
/// Bright purple for highlights
pub const PURPLE_BOLD: &str = "\x1b[1;38;2;124;58;237m";
/// Success green
pub const GREEN: &str = "\x1b[38;2;34;197;94m";
/// Bold green
pub const GREEN_BOLD: &str = "\x1b[1;38;2;34;197;94m";
/// Error red
pub const RED: &str = "\x1b[38;2;239;68;68m";
/// Bold red
pub const RED_BOLD: &str = "\x1b[1;38;2;239;68;68m";
/// Warning yellow/amber
pub const YELLOW: &str = "\x1b[38;2;234;179;8m";
/// Dim gray for secondary text
pub const DIM: &str = "\x1b[38;2;128;128;128m";
/// Bold white
pub const BOLD: &str = "\x1b[1m";
/// Reset all formatting
pub const RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Color-aware helpers
// ---------------------------------------------------------------------------

/// Check if color output is enabled (respects NO_COLOR convention).
pub fn colors_enabled() -> bool {
    std::env::var("NO_COLOR").is_err()
}

/// Wrap text in a color code, with reset. Returns plain text if colors disabled.
pub fn color(code: &str, text: &str) -> String {
    if colors_enabled() {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Purple branded text.
pub fn purple(text: &str) -> String { color(PURPLE, text) }
/// Bold purple branded text.
pub fn purple_bold(text: &str) -> String { color(PURPLE_BOLD, text) }
/// Green success text.
pub fn green(text: &str) -> String { color(GREEN, text) }
/// Bold green success text.
pub fn green_bold(text: &str) -> String { color(GREEN_BOLD, text) }
/// Red error text.
pub fn red(text: &str) -> String { color(RED, text) }
/// Bold red error text.
pub fn red_bold(text: &str) -> String { color(RED_BOLD, text) }
/// Yellow warning text.
pub fn yellow(text: &str) -> String { color(YELLOW, text) }
/// Dim secondary text.
pub fn dim(text: &str) -> String { color(DIM, text) }
/// Bold text.
pub fn bold(text: &str) -> String { color(BOLD, text) }

// ---------------------------------------------------------------------------
// Spinner with progress
// ---------------------------------------------------------------------------

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A terminal spinner that shows progress percentage.
///
/// Runs on a background thread, updating the spinner frame and message on stderr.
/// Call [`Spinner::set_progress`] to update the percentage, and [`Spinner::finish`]
/// to clear the line and stop.
pub struct Spinner {
    running: Arc<AtomicBool>,
    progress: Arc<std::sync::Mutex<(f64, String)>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Spinner {
    /// Start a new spinner with the given initial message.
    pub fn start(message: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let progress = Arc::new(std::sync::Mutex::new((0.0, message.to_string())));

        let r = running.clone();
        let p = progress.clone();
        let use_color = colors_enabled();

        let handle = thread::spawn(move || {
            let mut frame_idx = 0;
            while r.load(Ordering::Relaxed) {
                let (pct, msg) = {
                    let guard = p.lock().unwrap();
                    (guard.0, guard.1.clone())
                };

                let spinner_char = SPINNER_FRAMES[frame_idx % SPINNER_FRAMES.len()];
                let pct_display = if pct > 0.0 {
                    let pct_val = f64::min(pct * 100.0, 100.0);
                    format!(" ({pct_val:.0}%)")
                } else {
                    String::new()
                };

                if use_color {
                    eprint!("\r{PURPLE}{spinner_char}{RESET} {msg}{PURPLE_BOLD}{pct_display}{RESET}  ");
                } else {
                    eprint!("\r{spinner_char} {msg}{pct_display}  ");
                }
                let _ = io::stderr().flush();

                frame_idx += 1;
                thread::sleep(Duration::from_millis(80));
            }
        });

        Self {
            running,
            progress,
            handle: Some(handle),
        }
    }

    /// Update the progress (0.0 to 1.0) and optionally the message.
    pub fn set_progress(&self, pct: f64, message: Option<&str>) {
        let mut guard = self.progress.lock().unwrap();
        guard.0 = pct;
        if let Some(msg) = message {
            guard.1 = msg.to_string();
        }
    }

    /// Stop the spinner and clear the line.
    pub fn finish(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        // Clear the spinner line
        eprint!("\r\x1b[2K");
        let _ = io::stderr().flush();
    }

    /// Stop the spinner and print a final success message.
    pub fn finish_with(mut self, message: &str) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        eprint!("\r\x1b[2K");
        let _ = io::stderr().flush();
        if colors_enabled() {
            eprintln!("{GREEN}✓{RESET} {message}");
        } else {
            eprintln!("✓ {message}");
        }
    }

    /// Stop the spinner and print an error message.
    pub fn finish_err(mut self, message: &str) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        eprint!("\r\x1b[2K");
        let _ = io::stderr().flush();
        if colors_enabled() {
            eprintln!("{RED}✗{RESET} {message}");
        } else {
            eprintln!("✗ {message}");
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal width
// ---------------------------------------------------------------------------

/// Get the terminal width in columns. Falls back to 80 if detection fails.
pub fn terminal_width() -> usize {
    #[cfg(unix)]
    {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0
            && ws.ws_col > 0
        {
            return ws.ws_col as usize;
        }
    }

    // Fallback: COLUMNS env var
    if let Ok(cols) = std::env::var("COLUMNS") {
        if let Ok(w) = cols.parse::<usize>() {
            if w > 0 { return w; }
        }
    }

    80
}

// ---------------------------------------------------------------------------
// Box drawing / table helpers
// ---------------------------------------------------------------------------

/// Print a horizontal divider line.
pub fn divider(width: usize) {
    println!("{}", dim(&"─".repeat(width)));
}

/// Print a section header with a purple accent.
pub fn header(text: &str) {
    println!("{} {}", purple_bold("▸"), bold(text));
}
