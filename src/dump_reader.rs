//! High-level query API over a parsed Erlang crash dump.
//!
//! Open a previously-parsed dump directory with [`DumpReader::open`], then
//! call query methods to retrieve structured data.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use crashdump_db::Reader;

use crate::model::{EtsTable, MemoryInfo, Page, ProcessDetails, ProcessSummary, StackEntry};
use crate::termdecoder::{ErlTerm, TermDecoder};
use crate::textstore::TextReader;

// ─── DumpReader ──────────────────────────────────────────────────────────────

/// Provides high-level queries over a parsed crash dump store.
///
/// # Example
/// ```no_run
/// use erl_crashdump::dump_reader::DumpReader;
/// let dr = DumpReader::open("/tmp/ecd-out".as_ref()).unwrap();
/// for ps in dr.processes().unwrap() {
///     println!("{} {} {} bytes", ps.pid, ps.state, ps.memory);
/// }
/// ```
pub struct DumpReader {
    decoder: TermDecoder,
    text: TextReader,
}

impl DumpReader {
    /// Open a dump that was previously parsed into `outdir` by [`crate::parse`].
    pub fn open(outdir: &Path) -> Result<Self> {
        let addr = Arc::new(
            Reader::open(outdir.join("addr"))
                .with_context(|| format!("opening addr store in {}", outdir.display()))?,
        );
        let text = TextReader::open(outdir.join("text"))
            .with_context(|| format!("opening text store in {}", outdir.display()))?;
        let decoder = TermDecoder::new(addr);
        Ok(DumpReader { decoder, text })
    }

    /// Returns true if the dump had no `=end` marker, meaning it was
    /// truncated mid-write. In that case some heap/binary addresses may
    /// not be present in the address store.
    pub fn is_incomplete(&self) -> Result<bool> {
        Ok(self.text.get("_meta", Some("incomplete"))?.is_some())
    }

    // ─── Processes ───────────────────────────────────────────────────────────

    /// Return a summary for every process in the dump.
    pub fn processes(&self) -> Result<Vec<ProcessSummary>> {
        let sections = self
            .text
            .list_kind("proc")
            .context("listing proc sections")?;
        let mut out = Vec::with_capacity(sections.len());
        for (key, content) in sections {
            let pid = match key {
                Some(k) => k,
                None => continue,
            };
            if let Ok(ps) = parse_proc_section(&pid, &content) {
                out.push(ps);
            }
        }
        Ok(out)
    }

    /// Return full details for one process, or `None` if not found.
    pub fn process(&self, pid: &str) -> Result<Option<ProcessDetails>> {
        let proc_content = match self.text.get("proc", Some(pid))? {
            None => return Ok(None),
            Some(c) => c,
        };
        let summary = parse_proc_section(pid, &proc_content)?;

        let stack = self
            .text
            .get("proc_stack", Some(pid))?
            .map(|c| self.decode_stack(&c))
            .unwrap_or_default();

        let dictionary = self
            .text
            .get("proc_dictionary", Some(pid))?
            .map(|c| self.decode_term_lines(&c))
            .unwrap_or_default();

        let messages = self
            .text
            .get("proc_messages", Some(pid))?
            .map(|c| self.decode_term_lines(&c))
            .unwrap_or_default();

        Ok(Some(ProcessDetails {
            summary,
            stack,
            dictionary,
            messages,
        }))
    }

    /// Load only the process summary (fast — no stack/dict/messages decoding).
    pub fn process_summary(&self, pid: &str) -> Result<Option<ProcessSummary>> {
        let content = match self.text.get("proc", Some(pid))? {
            None => return Ok(None),
            Some(c) => c,
        };
        Ok(Some(parse_proc_section(pid, &content)?))
    }

    /// Return one page of stack entries for a process.
    pub fn process_stack_page(&self, pid: &str, offset: usize, limit: usize) -> Result<Page<StackEntry>> {
        let page = match self.text.get_lines_range("proc_stack", Some(pid), offset, limit)? {
            None => return Ok(Page::empty(offset, limit)),
            Some(p) => p,
        };
        let items = page.items.iter().map(|raw_line| {
            let (label, term_str) = split_label_term(raw_line);
            let first = term_str.as_bytes().first().copied().unwrap_or(0);
            let is_term_tag = matches!(
                first,
                b'N' | b'I' | b'A' | b'H' | b'P' | b'p' | b'l' | b't'
                    | b'F' | b'B' | b'Y' | b'M' | b'E'
            );
            let term = if is_term_tag {
                self.decoder.parse_term(term_str).ok().map(|(t, _)| t)
            } else {
                None
            };
            StackEntry { label: label.to_string(), term, raw: term_str.to_string() }
        }).collect();
        Ok(Page { items, total: page.total, offset: page.offset, limit: page.limit })
    }

    /// Return one page of process-dictionary terms.
    pub fn process_dict_page(&self, pid: &str, offset: usize, limit: usize) -> Result<Page<ErlTerm>> {
        let page = match self.text.get_lines_range("proc_dictionary", Some(pid), offset, limit)? {
            None => return Ok(Page::empty(offset, limit)),
            Some(p) => p,
        };
        let items = page.items.iter().filter_map(|line| {
            let term_str = if line.starts_with('H') { line.as_str() } else { split_label_term(line).1 };
            self.decoder.parse_term(term_str).ok().map(|(t, _)| t)
        }).collect();
        Ok(Page { items, total: page.total, offset: page.offset, limit: page.limit })
    }

    /// Return one page of message-queue terms.
    pub fn process_messages_page(&self, pid: &str, offset: usize, limit: usize) -> Result<Page<ErlTerm>> {
        let page = match self.text.get_lines_range("proc_messages", Some(pid), offset, limit)? {
            None => return Ok(Page::empty(offset, limit)),
            Some(p) => p,
        };
        let items = page.items.iter().filter_map(|line| {
            let term_str = if line.starts_with('H') { line.as_str() } else { split_label_term(line).1 };
            self.decoder.parse_term(term_str).ok().map(|(t, _)| t)
        }).collect();
        Ok(Page { items, total: page.total, offset: page.offset, limit: page.limit })
    }

    // ─── Memory ──────────────────────────────────────────────────────────────

    /// Return the system memory overview.
    pub fn memory(&self) -> Result<MemoryInfo> {
        let content = match self.text.get("memory", None)? {
            None => return Ok(MemoryInfo::default()),
            Some(c) => c,
        };
        let mut entries = Vec::new();
        for line in content.lines() {
            if let Some((k, v)) = line.split_once(": ") {
                if let Ok(n) = v.trim().parse::<u64>() {
                    entries.push((k.to_string(), n));
                }
            }
        }
        Ok(MemoryInfo { entries })
    }

    // ─── ETS ─────────────────────────────────────────────────────────────────

    /// Return a summary of every ETS table.
    pub fn ets_tables(&self) -> Result<Vec<EtsTable>> {
        let sections = self.text.list_kind("ets").context("listing ets sections")?;
        let mut out = Vec::with_capacity(sections.len());
        for (key, content) in sections {
            let owner = key.unwrap_or_default();
            if let Ok(t) = parse_ets_section(&owner, &content) {
                out.push(t);
            }
        }
        Ok(out)
    }

    // ─── Internal decoders ───────────────────────────────────────────────────

    /// Decode stack lines: `y0:<term>`, `0x<addr>:<term_or_info>`.
    fn decode_stack(&self, content: &str) -> Vec<StackEntry> {
        let mut entries = Vec::new();
        for raw_line in content.lines() {
            if raw_line.is_empty() {
                continue;
            }
            let (label, term_str) = split_label_term(raw_line);
            let first = term_str.as_bytes().first().copied().unwrap_or(0);
            let is_term_tag = matches!(
                first,
                b'N' | b'I' | b'A' | b'H' | b'P' | b'p' | b'l' | b't'
                    | b'F' | b'B' | b'Y' | b'M' | b'E'
            );
            let term = if is_term_tag {
                self.decoder.parse_term(term_str).ok().map(|(t, _)| t)
            } else {
                None
            };
            entries.push(StackEntry {
                label: label.to_string(),
                term,
                raw: term_str.to_string(),
            });
        }
        entries
    }

    /// Decode a section where each line is a heap term (dict, messages).
    /// Each line may be `<term>` or `<heap_addr>:<seq_trace_token>` —
    /// we parse just the leading term and discard the rest.
    fn decode_term_lines(&self, content: &str) -> Vec<ErlTerm> {
        let mut out = Vec::new();
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            // Strip label prefix if present (for message lines: "H<addr>:<token>")
            let term_str = if line.starts_with("H") {
                // Could be a bare H-pointer OR `H<addr>:<token>`.
                // parse_term will consume exactly the H-pointer and ignore the rest.
                line
            } else {
                let (_, ts) = split_label_term(line);
                ts
            };
            if let Ok((term, _)) = self.decoder.parse_term(term_str) {
                out.push(term);
            }
        }
        out
    }
}

// ─── Section parsers ─────────────────────────────────────────────────────────

fn parse_proc_section(pid: &str, content: &str) -> Result<ProcessSummary> {
    let mut state = String::new();
    let mut name: Option<String> = None;
    let mut spawned_as: Option<String> = None;
    let mut spawned_by: Option<String> = None;
    let mut mqueue_len = 0u64;
    let mut stack_heap = 0u64;
    let mut old_heap = 0u64;
    let mut heap_unused = 0u64;
    let mut memory = 0u64;
    let mut reductions = 0u64;
    let mut program_counter: Option<String> = None;
    let mut arity = 0u32;
    let mut links: Vec<String> = Vec::new();
    let mut monitors: Vec<String> = Vec::new();

    for line in content.lines() {
        // Lines are "Key: Value"
        let Some((key, val)) = line.split_once(": ") else {
            continue;
        };
        let val = val.trim();
        match key {
            "State" => state = val.to_string(),
            "Name" => name = Some(val.to_string()),
            "Spawned as" => spawned_as = Some(val.to_string()),
            "Spawned by" => spawned_by = Some(val.to_string()),
            "Message queue length" => mqueue_len = val.parse().unwrap_or(0),
            "Stack+heap" => stack_heap = val.parse().unwrap_or(0),
            "OldHeap" => old_heap = val.parse().unwrap_or(0),
            "Heap unused" => heap_unused = val.parse().unwrap_or(0),
            "Memory" => memory = val.parse().unwrap_or(0),
            "Reductions" => reductions = val.parse().unwrap_or(0),
            "Program counter" => program_counter = Some(val.to_string()),
            "arity" => arity = val.parse().unwrap_or(0),
            "Link list" => links = parse_pid_list(val),
            "Monitor list" => monitors = parse_pid_list(val),
            _ => {}
        }
    }

    Ok(ProcessSummary {
        pid: pid.to_string(),
        name,
        state,
        spawned_as,
        spawned_by,
        mqueue_len,
        stack_heap,
        old_heap,
        heap_unused,
        memory,
        reductions,
        program_counter,
        arity,
        links,
        monitors,
    })
}

fn parse_ets_section(owner_pid: &str, content: &str) -> Result<EtsTable> {
    let mut name = String::new();
    let mut table_type = String::new();
    let mut protection = String::new();
    let mut objects = 0u64;
    let mut words = 0u64;
    let mut buckets: Option<u64> = None;
    let mut write_concurrency = false;
    let mut read_concurrency = false;
    let mut compressed = false;
    let mut fixed = false;

    for line in content.lines() {
        let Some((key, val)) = line.split_once(": ") else {
            continue;
        };
        let val = val.trim();
        match key {
            "Name" => name = val.to_string(),
            "Type" => table_type = val.to_string(),
            "Protection" => protection = val.to_string(),
            "Objects" => objects = val.parse().unwrap_or(0),
            "Words" => words = val.parse().unwrap_or(0),
            "Buckets" => buckets = val.parse().ok(),
            "Write Concurrency" => write_concurrency = val == "true",
            "Read Concurrency" => read_concurrency = val == "true",
            "Compressed" => compressed = val == "true",
            "Fixed" => fixed = val == "true",
            _ => {}
        }
    }

    Ok(EtsTable {
        owner_pid: owner_pid.to_string(),
        name,
        table_type,
        protection,
        objects,
        words,
        buckets,
        write_concurrency,
        read_concurrency,
        compressed,
        fixed,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Split `"y0:A8:infinity"` into `("y0", "A8:infinity")`,
/// or `"0x7f...:Sinfo"` into `("0x7f...", "Sinfo")`.
/// Returns `("", line)` if no label prefix is found.
fn split_label_term(line: &str) -> (&str, &str) {
    if let Some(colon) = line.find(':') {
        let prefix = &line[..colon];
        let is_reg = (prefix.starts_with('y') || prefix.starts_with('x'))
            && prefix[1..].chars().all(|c| c.is_ascii_digit());
        let is_addr = prefix.starts_with("0x")
            || prefix.chars().all(|c| c.is_ascii_hexdigit());
        if is_reg || is_addr {
            return (prefix, &line[colon + 1..]);
        }
    }
    ("", line)
}

/// Parse a list like `[<0.1.0>, <0.2.0>]` into a `Vec<String>` of PID strings.
fn parse_pid_list(s: &str) -> Vec<String> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    if s.is_empty() || s == "[]" {
        return vec![];
    }
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}
