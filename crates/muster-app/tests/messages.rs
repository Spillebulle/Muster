//! Guards on the sentences Muster shows people.
//!
//! A message is part of the interface, and this one is checked from the source
//! rather than from a call because the defect it catches is invisible at every
//! other stage: it compiles, it passes clippy, it reads perfectly in the editor,
//! and it is only wrong on screen.
//!
//! **It reads the engine as well as the interface.** Written against
//! `muster-app` alone, it watched the crate that draws the messages and not the
//! crate that *writes* most of them: `muster-net` had carried a joined line in
//! a re-check's "could not send ARP requests" caveat from the day it was added,
//! and a guard that cannot see the engine is a guard over the wrong half of the
//! application.

use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The crates whose string literals are *sentences*.
///
/// `muster-desktop` is not one of them and is left out on purpose: the text
/// mode draws tables, so its literals carry runs of spaces that are the column
/// layout rather than a lost continuation, and a guard that cried wolf over
/// every aligned header would be turned off within a week.
const PROSE: [&str; 2] = ["muster-app", "muster-net"];

/// Every `src` directory of [`PROSE`].
///
/// The `tests` directories are deliberately not included: this file is one of
/// them, and the pattern it looks for is written out in it.
fn workspace_sources() -> Vec<PathBuf> {
    let crates = crate_root()
        .parent()
        .expect("the crates directory holds this crate")
        .to_path_buf();
    let mut out = Vec::new();
    for name in PROSE {
        let src = crates.join(name).join("src");
        assert!(src.is_dir(), "{} has no src directory", src.display());
        rust_files(&src, &mut out);
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The body of every double-quoted string literal on one line.
///
/// Deliberately crude: it does not understand raw strings or literals that span
/// lines, and it does not need to. What it is looking for only ever appears on
/// a single line, because it is produced by a line *join*.
fn literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut body = String::new();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    // Skip the escaped character so an escaped quote does not
                    // end the literal early.
                    if let Some(next) = chars.next() {
                        body.push(next);
                    }
                }
                '"' => break,
                _ => body.push(c),
            }
        }
        out.push(body);
    }
    out
}

/// No message carries a run of spaces in the middle of a sentence.
///
/// **This is a real defect that shipped.** Rust's `\` at the end of a line
/// inside a string swallows the newline *and* the indentation of the next line,
/// which is what makes a long message readable in the source. Lose the
/// backslash and the literal keeps the indentation: the compiler is happy, the
/// source still looks right, and the user is shown
///
/// > GitHub is rate limiting this network. It allows 60 checks an
/// >                   hour from one address
///
/// 0.0.5 shipped exactly that in five messages, including the one somebody
/// reads when an update check fails. Nobody types three spaces mid-sentence on
/// purpose, so the run itself is the signal.
#[test]
fn no_message_has_a_run_of_spaces_in_it() {
    let files = workspace_sources();
    assert!(
        files.len() > 1,
        "expected to find the sources of both prose crates"
    );

    let mut bad = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).expect("read a source file");
        for (number, line) in text.lines().enumerate() {
            for body in literals(line) {
                // Three, not two: two spaces after a full stop is a typographic
                // choice somebody might make, and a joined line is always much
                // wider than that.
                if let Some(at) = body.find("   ") {
                    // Leading indentation inside a literal is deliberate in the
                    // few places a layout is being drawn in text.
                    if body[..at].trim().is_empty() {
                        continue;
                    }
                    bad.push(format!(
                        "{}:{}\n    {}",
                        path.display(),
                        number + 1,
                        body.trim()
                    ));
                }
            }
        }
    }

    assert!(
        bad.is_empty(),
        "these strings carry a run of spaces, which is what a lost `\\` \
         line-continuation leaves behind:\n{}",
        bad.join("\n")
    );
}
