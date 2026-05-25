//! `erl-crashdump` — parse an Erlang crash dump into two stores:
//!
//! * **crashdump-db** (`db_dir/`) — address-keyed blobs for heap words,
//!   off-heap binaries, and literals.
//!
//! * **text store** (`text_dir/`) — all other sections stored in zstd-
//!   compressed frames, queryable by `(kind, key)`.
//!
//! Both plain and zstd-compressed crash dump files are accepted.
//!
//! # Example
//!
//! ```no_run
//! use erl_crashdump::{parse, Config};
//! use std::path::Path;
//!
//! let stats = parse(
//!     Path::new("/tmp/erl_crash.dump"),
//!     Path::new("/tmp/out/addr"),
//!     Path::new("/tmp/out/text"),
//!     Config::default(),
//! ).unwrap();
//! println!("{stats}");
//! ```

#![cfg(unix)]

mod scanner;
pub mod extsorter;
pub mod textstore;
pub mod termdecoder;
pub mod model;
pub mod dump_reader;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use extsorter::ExternalSorter;
use textstore::{TextWriter, SectionWriter};
use std::fmt;
use std::io::Read;
use std::path::Path;

pub use extsorter::Config;

// ── Stats ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Stats {
    pub heap_entries: u64,
    pub binary_entries: u64,
    pub literal_entries: u64,
    pub text_sections: u64,
    /// True when the dump had no `=end` marker (file was truncated mid-write).
    pub incomplete: bool,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "heap={} binaries={} literals={} text_sections={}{}",
            self.heap_entries,
            self.binary_entries,
            self.literal_entries,
            self.text_sections,
            if self.incomplete { " [INCOMPLETE — no =end marker]" } else { "" },
        )
    }
}

// ── parse ─────────────────────────────────────────────────────────────────────

pub fn parse(
    dump_path: &Path,
    db_dir: &Path,
    text_dir: &Path,
    config: Config,
    on_progress: Option<&(dyn Fn(&str) + Send)>,
) -> Result<Stats> {
    parse_scanner(
        scanner::Scanner::new(dump_path).context("opening dump")?,
        db_dir,
        text_dir,
        config,
        on_progress,
    )
}

/// Like [`parse`] but reads from any `Read` source instead of a file path.
/// Enables concurrent upload+parse: wrap a channel receiver and start
/// parsing while bytes are still being received.
///
/// `on_progress` is called periodically with human-readable status strings.
/// It is invoked from the calling thread, so use a channel sender to relay
/// messages back to an async context if needed.
pub fn parse_reader<R: Read + 'static>(
    reader: R,
    db_dir: &Path,
    text_dir: &Path,
    config: Config,
    on_progress: Option<Box<dyn Fn(&str) + Send + 'static>>,
) -> Result<Stats> {
    parse_scanner(
        scanner::Scanner::from_reader(reader).context("opening reader")?,
        db_dir,
        text_dir,
        config,
        on_progress.as_deref(),
    )
}

fn parse_scanner(
    scanner: scanner::Scanner,
    db_dir: &Path,
    text_dir: &Path,
    config: Config,
    on_progress: Option<&(dyn Fn(&str) + Send)>,
) -> Result<Stats> {
    let mut text = TextWriter::new(text_dir).context("creating text store")?;
    // Use the dump's own output dir as work space so large sort files don't
    // land in /tmp on a potentially small tmpfs.
    let work_dir = db_dir.parent().unwrap_or(db_dir);
    let mut sorter = ExternalSorter::new(config, work_dir).context("creating external sorter")?;
    let mut stats = Stats::default();
    let mut total_inserted: u64 = 0;
    let mut saw_end = false;

    let mut cur_kind = String::new();
    // Active streaming writer for the current text section (None for heap/binary/literals).
    let mut section_writer: Option<SectionWriter<'_>> = None;
    // Set to Some(addr) after a `=binary:ADDR` header; consumed by the next DataLine.
    let mut pending_binary: Option<u64> = None;

    for event in scanner {
        match event.context("reading dump")? {
            scanner::Event::NewSection { kind, key } => {
                // Finish the previous text section (if any).
                if let Some(sw) = section_writer.take() {
                    sw.finish().context("finishing text section")?;
                    stats.text_sections += 1;
                }
                pending_binary = None;
                if kind == "end" {
                    saw_end = true;
                } else if kind == "binary" {
                    pending_binary =
                        key.as_deref().and_then(|s| u64::from_str_radix(s, 16).ok());
                }
                // Start a new streaming writer for text sections.
                if !is_addr_section(&kind) && kind != "end" && !kind.is_empty() {
                    section_writer = Some(text.begin_section(&kind, key.as_deref()));
                }
                cur_kind = kind;
            }

            scanner::Event::DataLine(line) => {
                if let Some(addr) = pending_binary.take() {
                    match decode_binary_line(&line) {
                        Ok(blob) => {
                            sorter.insert(addr, &blob)?;
                            stats.binary_entries += 1;
                            total_inserted += 1;
                        }
                        Err(e) => eprintln!("warn: binary {addr:#x} decode failed: {e}"),
                    }
                } else if cur_kind == "proc_heap" || cur_kind == "literals" {
                    let trimmed = line.trim_start();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match parse_addr_line(trimmed) {
                        Ok((addr, data)) => {
                            sorter.insert(addr, data.as_bytes())?;
                            if cur_kind == "proc_heap" {
                                stats.heap_entries += 1;
                            } else {
                                stats.literal_entries += 1;
                            }
                            total_inserted += 1;
                        }
                        Err(e) => eprintln!(
                            "warn: skipping {} line '{}': {e}",
                            cur_kind,
                            &trimmed[..trimmed.len().min(60)]
                        ),
                    }
                } else if let Some(sw) = section_writer.as_mut() {
                    // Stream this line directly into the current frame —
                    // no accumulation in RAM.
                    sw.write(&line).context("writing text section line")?;
                    sw.write("\n").context("writing text section newline")?;
                }

                if total_inserted > 0 && total_inserted % 500_000 == 0 {
                    if let Some(f) = on_progress {
                        f(&format!(
                            "Scanning: {} entries ({} heap, {} binary, {} literal)",
                            total_inserted,
                            stats.heap_entries,
                            stats.binary_entries,
                            stats.literal_entries,
                        ));
                    }
                }
            }
        }
    }

    // Finish the last text section (if any).
    if let Some(sw) = section_writer.take() {
        sw.finish().context("finishing last text section")?;
        stats.text_sections += 1;
    }

    stats.incomplete = !saw_end;
    if stats.incomplete {
        text.insert("_meta", Some("incomplete"), "1").context("writing incomplete marker")?;
    }

    text.finish().context("finishing text store")?;

    if let Some(f) = on_progress {
        f(&format!(
            "Scan complete — {} entries total, starting sort…",
            total_inserted
        ));
    }

    let written = sorter.finish(db_dir, on_progress).context("finishing address db")?;
    let expected = stats.heap_entries + stats.binary_entries + stats.literal_entries;
    if written < expected {
        eprintln!("warn: {} duplicate addresses dropped", expected - written);
    }

    Ok(stats)
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn is_addr_section(kind: &str) -> bool {
    matches!(kind, "proc_heap" | "binary" | "literals")
}

fn parse_addr_line(line: &str) -> Result<(u64, &str)> {
    let colon = line.find(':').ok_or_else(|| anyhow::anyhow!("no colon"))?;
    let addr = u64::from_str_radix(&line[..colon], 16)
        .map_err(|e| anyhow::anyhow!("bad hex: {e}"))?;
    Ok((addr, &line[colon + 1..]))
}

fn decode_binary_line(line: &str) -> Result<Vec<u8>> {
    let b64 = line.find(':').map_or(line, |i| &line[i + 1..]);
    Ok(B64.decode(b64.trim())?)
}
