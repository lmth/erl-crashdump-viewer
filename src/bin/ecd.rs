//! `ecd` — debug / inspection CLI for Erlang crash dump stores.
//!
//! Commands:
//!   ecd list                                    — list all cached dumps with IDs
//!   ecd parse    <dump> <outdir>               — parse a crash dump explicitly
//!   ecd <dump|id> procs    [--sort-by size|pid] — list all processes
//!   ecd <dump|id> proc     <pid> [--truncate-terms N] [--raw]
//!   ecd <dump|id> mem      [--raw]              — memory overview
//!   ecd <dump|id> ets      [--raw]              — ETS table list
//!   ecd <dump|id> sections [--sort-by size|kind|key] — all sections with sizes
//!   ecd <dump|id> query    <kind> [key]         — raw text store query
//!   ecd <dump|id> decode   <kind> [key] [--truncate-terms N]
//!   ecd <dump|id> lookup   <hex_addr>           — look up an address
//!
//! <dump|id> may be a path to a crash dump file, or a cache ID (the 16-hex-char
//! fingerprint shown by `ecd list`, or any unambiguous prefix of it).
//!
//! All commands except `list` and `parse` auto-parse into ~/.cache/ecd/ on
//! first use.  Cache is keyed by content fingerprint so it survives copy or
//! move of the dump file.  A meta.json file is written alongside the parsed
//! data so `ecd list` can show the original filename, size and parse date.

#![cfg(unix)]

use anyhow::{Context, Result, bail};
use chrono::Local;
use crashdump_db::Reader;
use erl_crashdump::{
    Config, Stats, parse,
    dump_reader::DumpReader,
    termdecoder::{ErlTerm, TermDecoder, print_term},
    textstore::TextReader,
};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

fn main() {
    if let Err(e) = run() {
        eprintln!("ecd: {e:#}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // ecd list
    if args.get(1).map(String::as_str) == Some("list") {
        return cmd_list();
    }

    // ecd parse <dump> <outdir>  — explicit, subcommand-first
    if args.get(1).map(String::as_str) == Some("parse") {
        return cmd_parse(&args);
    }

    // All other commands: ecd <dump|id> <subcommand> [args...]
    match args.get(2).map(String::as_str) {
        Some("lookup") => cmd_lookup(&args),
        Some("query")  => cmd_query(&args),
        Some("decode") => cmd_decode(&args),
        Some("procs")  => cmd_procs(&args),
        Some("proc")   => cmd_proc(&args),
        Some("mem")    => cmd_mem(&args),
        Some("ets")      => cmd_ets(&args),
        Some("sections") => cmd_sections(&args),
        _ => {
            eprintln!("Usage:");
            eprintln!("  ecd list                                     — list cached dumps");
            eprintln!("  ecd <dump|id> procs    [--sort-by size|pid]  — list all processes");
            eprintln!("  ecd <dump|id> proc     <pid> [--truncate-terms N] [--raw]");
            eprintln!("  ecd <dump|id> mem      [--raw]               — memory overview");
            eprintln!("  ecd <dump|id> ets      [--raw]               — ETS table list");
            eprintln!("  ecd <dump|id> sections [--sort-by size|kind|key]");
            eprintln!("  ecd <dump|id> query    <kind> [key]          — raw text store query");
            eprintln!("  ecd <dump|id> decode   <kind> [key] [--truncate-terms N]");
            eprintln!("  ecd <dump|id> lookup   <hex_addr>            — look up address");
            eprintln!("  ecd parse  <dump>      <outdir>              — explicit parse to directory");
            eprintln!("");
            eprintln!("  <dump|id> may be a file path or a cache ID (from 'ecd list').");
            Ok(())
        }
    }
}

// ─── Cache helpers ────────────────────────────────────────────────────────────

fn xdg_cache_home() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(".cache")
        })
}

/// Cheap content fingerprint: file size + ~8 bytes sampled at five dispersed
/// offsets, combined with FNV-1a. Survives copy/move; ~5 seeks regardless of
/// file size. Collision probability is negligible for real crash dumps.
fn content_fingerprint(dump: &Path) -> Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(dump)
        .with_context(|| format!("opening {}", dump.display()))?;
    let size = f.metadata()?.len();

    let mut h: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    let fnv = |h: &mut u64, bytes: &[u8]| {
        for &b in bytes {
            *h ^= b as u64;
            *h = h.wrapping_mul(0x00000100000001b3);
        }
    };

    // Mix in the file size
    fnv(&mut h, &size.to_le_bytes());

    // Sample 8 bytes at five positions: 0, 1/4, 1/2, 3/4, near-end
    let positions = [0u64, size / 4, size / 2, 3 * size / 4, size.saturating_sub(8)];
    let mut buf = [0u8; 8];
    for pos in positions {
        if pos < size {
            f.seek(SeekFrom::Start(pos))?;
            let n = f.read(&mut buf)?;
            fnv(&mut h, &buf[..n]);
        }
    }
    Ok(h)
}

/// Return the cache directory for a dump, keyed by content fingerprint so the
/// cache survives copy or move of the dump file.
fn cache_dir_for(dump: &Path) -> Result<PathBuf> {
    let fp = content_fingerprint(dump)?;
    Ok(xdg_cache_home().join("ecd").join(format!("{fp:016x}")))
}

/// Ensure the dump is parsed into the cache directory. Because the directory
/// name is derived from the content fingerprint, a hit means the content is
/// already parsed. Prints status to stderr. Returns the outdir.
fn ensure_parsed(dump: &Path) -> Result<PathBuf> {
    let outdir = cache_dir_for(dump)?;
    // A .complete marker is written after a successful parse.
    let complete = outdir.join(".complete");

    if complete.exists() {
        eprintln!("ecd: using cache {}", outdir.display());
    } else {
        if outdir.exists() {
            std::fs::remove_dir_all(&outdir)
                .with_context(|| format!("removing incomplete cache {}", outdir.display()))?;
        }
        std::fs::create_dir_all(&outdir)?;
        eprintln!("ecd: parsing {} -> {}", dump.display(), outdir.display());
        let db_dir = outdir.join("addr");
        let text_dir = outdir.join("text");
        let stats: Stats = parse(dump, &db_dir, &text_dir, Config::default(), Some(&|msg| eprintln!("ecd: {msg}")))?;
        eprintln!("ecd: {stats}");
        if stats.incomplete {
            eprintln!("ecd: warn: dump is incomplete — no =end marker; some data may be missing or truncated");
        }
        write_cache_meta(&outdir, dump)?;
        std::fs::write(&complete, "")?;
    }

    Ok(outdir)
}

// ─── Cache metadata ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct CacheMeta {
    filename: String,
    path: String,
    size_bytes: u64,
    parsed_at: String,
}

fn write_cache_meta(outdir: &Path, dump: &Path) -> Result<()> {
    let dump_abs = dump.canonicalize().unwrap_or_else(|_| dump.to_path_buf());
    let filename = dump_abs
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| dump_abs.to_string_lossy().into_owned());
    let size_bytes = std::fs::metadata(dump).map(|m| m.len()).unwrap_or(0);
    let parsed_at = Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let meta = CacheMeta {
        filename,
        path: dump_abs.to_string_lossy().into_owned(),
        size_bytes,
        parsed_at,
    };
    std::fs::write(outdir.join("meta.json"), serde_json::to_string_pretty(&meta)?)?;
    Ok(())
}

fn read_cache_meta(outdir: &Path) -> Option<CacheMeta> {
    let data = std::fs::read_to_string(outdir.join("meta.json")).ok()?;
    serde_json::from_str(&data).ok()
}

/// Resolve a `<dump|id>` argument to a parsed cache directory.
///
/// Accepts:
/// - a path to an existing file — auto-parsed on first use
/// - a cache ID or unambiguous prefix of one (from `ecd list`)
fn resolve_dump_or_id(arg: &str) -> Result<PathBuf> {
    let p = Path::new(arg);
    // Explicit file path takes priority.
    if p.exists() || arg.contains('/') {
        return ensure_parsed(p);
    }
    // Try as a hex ID prefix (≥4 chars, all hex digits).
    let looks_like_id = arg.len() >= 4 && arg.chars().all(|c| c.is_ascii_hexdigit());
    if looks_like_id {
        let cache = xdg_cache_home().join("ecd");
        if let Ok(rd) = std::fs::read_dir(&cache) {
            let matches: Vec<PathBuf> = rd
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name();
                    let s = name.to_string_lossy();
                    s.starts_with(arg) && e.path().join(".complete").exists()
                })
                .map(|e| e.path())
                .collect();
            match matches.len() {
                0 => bail!(
                    "no cached dump matches ID '{arg}'\n  (use 'ecd list' to see cached dumps)"
                ),
                1 => {
                    let outdir = matches.into_iter().next().unwrap();
                    eprintln!("ecd: using cache {}", outdir.display());
                    return Ok(outdir);
                }
                _ => {
                    let ids: Vec<String> = matches
                        .iter()
                        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                        .collect();
                    bail!("ambiguous ID prefix '{arg}', matches:\n  {}", ids.join("\n  "));
                }
            }
        }
    }
    // Fall through: treat as file path — produces a clear "not found" error.
    ensure_parsed(p)
}

// ─── ecd list ────────────────────────────────────────────────────────────────

fn cmd_list() -> Result<()> {
    let cache = xdg_cache_home().join("ecd");
    if !cache.exists() {
        println!("No cached dumps. (cache dir: {})", cache.display());
        return Ok(());
    }

    let mut entries: Vec<(String, Option<CacheMeta>)> = std::fs::read_dir(&cache)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join(".complete").exists())
        .map(|e| {
            let id = e.file_name().to_string_lossy().into_owned();
            let meta = read_cache_meta(&e.path());
            (id, meta)
        })
        .collect();

    if entries.is_empty() {
        println!("No cached dumps. (cache dir: {})", cache.display());
        return Ok(());
    }

    // Sort newest-first by parsed_at when available.
    entries.sort_by(|a, b| {
        let at_a = a.1.as_ref().map(|m| m.parsed_at.as_str()).unwrap_or("");
        let at_b = b.1.as_ref().map(|m| m.parsed_at.as_str()).unwrap_or("");
        at_b.cmp(at_a)
    });

    println!("{:<16}  {:<28}  {:>8}  {:<22}  {}",
        "ID", "FILENAME", "SIZE", "PARSED", "ORIGINAL PATH");
    println!("{}", "-".repeat(110));
    for (id, meta) in &entries {
        match meta {
            Some(m) => {
                let parsed_display = m.parsed_at.get(..16).unwrap_or(&m.parsed_at).replace('T', " ");
                println!("{:<16}  {:<28}  {:>8}  {:<22}  {}",
                    id,
                    truncate(&m.filename, 28),
                    fmt_bytes(m.size_bytes),
                    parsed_display,
                    truncate(&m.path, 60),
                );
            }
            None => {
                println!("{:<16}  (no metadata)", id);
            }
        }
    }
    println!("\n{} cached dump(s)  —  cache: {}", entries.len(), cache.display());
    Ok(())
}

fn cmd_parse(args: &[String]) -> Result<()> {
    if args.len() < 4 {
        bail!("usage: ecd parse <dump> <outdir>");
    }
    let dump = PathBuf::from(&args[2]);
    let outdir = PathBuf::from(&args[3]);
    let db_dir = outdir.join("addr");
    let text_dir = outdir.join("text");

    let stats: Stats = parse(&dump, &db_dir, &text_dir, Config::default(), Some(&|msg| eprintln!("{msg}")))?;
    println!("{stats}");
    if stats.incomplete {
        eprintln!("warn: dump is incomplete — no =end marker; some data may be missing or truncated");
    }
    Ok(())
}

fn cmd_lookup(args: &[String]) -> Result<()> {
    if args.len() < 4 {
        bail!("usage: ecd <dump> lookup <hex_addr>");
    }
    let outdir = resolve_dump_or_id(&args[1])?;
    let addr = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
    let reader = Reader::open(outdir.join("addr"))?;
    match reader.get(addr)? {
        None => println!("(not found)"),
        Some(data) => match std::str::from_utf8(&data) {
            Ok(s) => println!("{s}"),
            Err(_) => println!("{data:02x?}"),
        },
    }
    Ok(())
}

fn cmd_query(args: &[String]) -> Result<()> {
    if args.len() < 4 {
        bail!("usage: ecd <dump> query <kind> [key]");
    }
    let outdir = resolve_dump_or_id(&args[1])?;
    let kind = &args[3];
    let key = args.get(4).map(String::as_str);
    let reader = TextReader::open(outdir.join("text"))?;

    if let Some(k) = key {
        match reader.get(kind, Some(k))? {
            None => println!("(not found)"),
            Some(content) => print!("{content}"),
        }
    } else {
        let sections = reader.list_kind(kind)?;
        if sections.is_empty() {
            println!("(no sections of kind '{kind}')");
        }
        for (k, content) in sections {
            let k_display = k.as_deref().unwrap_or("(none)");
            println!("=== {kind}:{k_display} ===");
            print!("{content}");
        }
    }
    Ok(())
}

fn cmd_decode(args: &[String]) -> Result<()> {
    if args.len() < 4 {
        bail!("usage: ecd <dump> decode <kind> [key]");
    }
    let outdir = resolve_dump_or_id(&args[1])?;
    let kind = &args[3];
    let key = args.get(4).map(String::as_str);

    let addr_reader = Arc::new(Reader::open(outdir.join("addr"))?);
    let text_reader = TextReader::open(outdir.join("text"))?;
    let decoder = TermDecoder::new(Arc::clone(&addr_reader));

    let decode_and_print = |content: &str| {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for raw_line in content.lines() {
            // Lines may be:  "y0:<term>"  "0x<addr>:<term>"  or just  "<term>"
            let term_str = if let Some(colon) = raw_line.find(':') {
                let prefix = &raw_line[..colon];
                // Looks like a register label (y0, x1) or hex address (0x...)
                if (prefix.starts_with('y') || prefix.starts_with('x'))
                    && prefix[1..].chars().all(|c| c.is_ascii_digit())
                    || prefix.starts_with("0x")
                    || prefix.chars().all(|c| c.is_ascii_hexdigit())
                {
                    &raw_line[colon + 1..]
                } else {
                    raw_line
                }
            } else {
                raw_line
            };

            if term_str.is_empty() {
                writeln!(out).ok();
                continue;
            }

            // Check if first char is a known term tag
            let first = term_str.as_bytes()[0];
            let is_term = matches!(
                first,
                b'N' | b'I' | b'A' | b'H' | b'P' | b'p' | b'S' | b'l' | b't'
                | b'F' | b'B' | b'Y' | b'M' | b'E' | b'D'
            );

            if is_term {
                match decoder.parse_term(term_str) {
                    Ok((term, _rest)) => {
                        print_term(&term, &mut out).ok();
                        writeln!(out).ok();
                    }
                    Err(e) => {
                        writeln!(out, "# parse error: {e}  (raw: {term_str})").ok();
                    }
                }
            } else {
                // Not a term line — print verbatim (e.g. section headers, labels)
                writeln!(out, "{raw_line}").ok();
            }
        }
    };

    if let Some(k) = key {
        match text_reader.get(kind, Some(k))? {
            None => println!("(not found)"),
            Some(content) => decode_and_print(&content),
        }
    } else {
        let sections = text_reader.list_kind(kind)?;
        if sections.is_empty() {
            println!("(no sections of kind '{kind}')");
        }
        for (k, content) in sections {
            let k_display = k.as_deref().unwrap_or("(none)");
            println!("=== {kind}:{k_display} ===");
            decode_and_print(&content);
        }
    }
    Ok(())
}

// ─── ecd procs ───────────────────────────────────────────────────────────────

fn cmd_procs(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        bail!("Usage: ecd <dump> procs [--sort-by size|pid]");
    }
    let outdir = resolve_dump_or_id(&args[1])?;
    let opts = parse_opts(&args[3..]);
    let dr = DumpReader::open(&outdir)?;
    let mut procs = dr.processes()?;
    match opts.sort_by.as_str() {
        "pid" => procs.sort_by(|a, b| a.pid.cmp(&b.pid)),
        _     => procs.sort_by(|a, b| b.memory.cmp(&a.memory)),  // default: size desc
    }

    // MEMORY = total process bytes; STK+HEAP = stack+heap words converted to bytes
    println!("{:<22}  {:>10}  {:>10}  {:>8}  {:>10}  {:^20}  {}",
        "PID", "MEMORY", "REDS", "MQUEUE", "STK+HEAP", "STATE", "NAME/SPAWNED-AS");
    println!("{}", "-".repeat(104));

    for ps in &procs {
        let display_name = ps.name.as_deref()
            .or(ps.spawned_as.as_deref())
            .unwrap_or("-");
        let short_name = display_name.split_whitespace().next().unwrap_or(display_name);
        println!("{:<22}  {:>10}  {:>10}  {:>8}  {:>10}  {:^20}  {}",
            ps.pid,
            fmt_bytes(ps.memory),
            ps.reductions,
            ps.mqueue_len,
            fmt_bytes(ps.stack_heap.saturating_mul(8)),
            truncate(&ps.state, 20),
            truncate(short_name, 60),
        );
    }
    println!("\n{} processes", procs.len());
    Ok(())
}

// ─── ecd proc ────────────────────────────────────────────────────────────────

fn cmd_proc(args: &[String]) -> Result<()> {
    if args.len() < 4 {
        bail!("Usage: ecd <dump> proc <pid> [--truncate-terms N] [--raw]");
    }
    let outdir = resolve_dump_or_id(&args[1])?;
    let pid = &args[3];
    let opts = parse_opts(&args[4..]);

    // --raw: show section text verbatim without decoding
    if opts.raw {
        let text = TextReader::open(outdir.join("text"))?;
        for kind in &["proc", "proc_stack", "proc_dictionary", "proc_messages"] {
            if let Some(content) = text.get(kind, Some(pid))? {
                println!("=== {kind}:{pid} ===");
                print!("{content}");
            }
        }
        return Ok(());
    }

    let dr = DumpReader::open(&outdir)?;
    let details = match dr.process(pid)? {
        None => {
            eprintln!("Process {pid} not found");
            return Ok(());
        }
        Some(d) => d,
    };
    let out = std::io::stdout();
    let mut out = std::io::BufWriter::new(out.lock());

    let ps = &details.summary;
    writeln!(out, "=== Process {} ===", ps.pid)?;
    if let Some(n) = &ps.name          { writeln!(out, "  Name         : {n}")?; }
    if let Some(s) = &ps.spawned_as    { writeln!(out, "  Spawned as   : {s}")?; }
    if let Some(b) = &ps.spawned_by    { writeln!(out, "  Spawned by   : {b}")?; }
    writeln!(out, "  State        : {}", ps.state)?;
    writeln!(out, "  Memory       : {} ({} bytes)", fmt_bytes(ps.memory), ps.memory)?;
    writeln!(out, "  Stack+heap   : {}", fmt_words_kb(ps.stack_heap))?;
    writeln!(out, "  OldHeap      : {}", fmt_words_kb(ps.old_heap))?;
    writeln!(out, "  Heap unused  : {}", fmt_words_kb(ps.heap_unused))?;
    writeln!(out, "  Reductions   : {}", ps.reductions)?;
    writeln!(out, "  Msg queue    : {}", ps.mqueue_len)?;
    if ps.arity > 0 { writeln!(out, "  Arity        : {}", ps.arity)?; }
    if let Some(pc) = &ps.program_counter { writeln!(out, "  PC           : {pc}")?; }
    if !ps.links.is_empty()    { writeln!(out, "  Links        : {}", ps.links.join(", "))?; }
    if !ps.monitors.is_empty() { writeln!(out, "  Monitors     : {}", ps.monitors.join(", "))?; }

    if !details.stack.is_empty() {
        writeln!(out, "\n--- Stack ({} entries) ---", details.stack.len())?;
        for e in &details.stack {
            if let Some(term) = &e.term {
                writeln!(out, "  {:<14}  {}", e.label, render_term(term, opts.truncate_terms))?;
            } else {
                writeln!(out, "  {:<14}  {}", e.label, e.raw)?;
            }
        }
    }

    if !details.dictionary.is_empty() {
        writeln!(out, "\n--- Dictionary ({} entries) ---", details.dictionary.len())?;
        for term in &details.dictionary {
            writeln!(out, "  {}", render_term(term, opts.truncate_terms))?;
        }
    }

    if !details.messages.is_empty() {
        writeln!(out, "\n--- Messages ({} entries) ---", details.messages.len())?;
        for term in &details.messages {
            writeln!(out, "  {}", render_term(term, opts.truncate_terms))?;
        }
    }

    Ok(())
}

// ─── ecd mem ─────────────────────────────────────────────────────────────────

fn cmd_mem(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        bail!("Usage: ecd <dump> mem [--raw]");
    }
    let outdir = resolve_dump_or_id(&args[1])?;
    let opts = parse_opts(&args[3..]);

    if opts.raw {
        let text = TextReader::open(outdir.join("text"))?;
        match text.get("memory", None)? {
            None => println!("(no memory section)"),
            Some(content) => print!("{content}"),
        }
        return Ok(());
    }

    let dr = DumpReader::open(&outdir)?;
    let mem = dr.memory()?;
    if mem.entries.is_empty() {
        println!("(no memory section found)");
        return Ok(());
    }
    // All values in the =memory section are in bytes.
    println!("{:<30}  {:>14}  {:>10}", "KEY", "BYTES", "FORMATTED");
    println!("{}", "-".repeat(58));
    let mut total_bytes = 0u64;
    for (k, v) in &mem.entries {
        println!("{:<30}  {:>14}  {:>10}", k, v, fmt_bytes(*v));
        if k == "total" { total_bytes = *v; }
    }
    if total_bytes > 0 {
        println!("{}", "-".repeat(58));
        println!("{:<30}  {:>14}  {:>10}", "TOTAL", total_bytes, fmt_bytes(total_bytes));
    }
    Ok(())
}

// ─── ecd ets ─────────────────────────────────────────────────────────────────

fn cmd_ets(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        bail!("Usage: ecd <dump> ets [--raw]");
    }
    let outdir = resolve_dump_or_id(&args[1])?;
    let opts = parse_opts(&args[3..]);

    if opts.raw {
        let text = TextReader::open(outdir.join("text"))?;
        let sections = text.list_kind("ets")?;
        for (key, content) in &sections {
            let k = key.as_deref().unwrap_or("(none)");
            println!("=== ets:{k} ===");
            print!("{content}");
        }
        return Ok(());
    }

    let dr = DumpReader::open(&outdir)?;
    let mut tables = dr.ets_tables()?;
    tables.sort_by(|a, b| b.words.cmp(&a.words));

    // WORDS column shows word count + byte equivalent (1 word = 8 bytes on 64-bit)
    println!("{:<24}  {:<20}  {:<10}  {:>8}  {:>18}  {:>6}  {}",
        "OWNER", "NAME", "TYPE", "OBJECTS", "WORDS (MEMORY)", "FLAGS", "PROTECTION");
    println!("{}", "-".repeat(104));
    for t in &tables {
        let mut flags = String::new();
        if t.write_concurrency { flags.push('W'); }
        if t.read_concurrency  { flags.push('R'); }
        if t.compressed        { flags.push('C'); }
        if t.fixed             { flags.push('F'); }
        println!("{:<24}  {:<20}  {:<10}  {:>8}  {:>18}  {:>6}  {}",
            truncate(&t.owner_pid, 24),
            truncate(&t.name, 20),
            truncate(&t.table_type, 10),
            t.objects,
            fmt_words_table(t.words),
            flags,
            t.protection,
        );
    }
    println!("\n{} ETS tables", tables.len());
    Ok(())
}

// ─── ecd sections ────────────────────────────────────────────────────────────

fn cmd_sections(args: &[String]) -> Result<()> {
    if args.len() < 3 {
        bail!("Usage: ecd <dump> sections [--sort-by size|kind|key]");
    }
    let outdir = resolve_dump_or_id(&args[1])?;
    let opts = parse_opts(&args[3..]);
    let reader = TextReader::open(outdir.join("text"))?;
    let mut sections = reader.list_all();

    match opts.sort_by.as_str() {
        "kind" => sections.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1))),
        "key"  => sections.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0))),
        _      => sections.sort_by(|a, b| b.2.cmp(&a.2)),  // default: size desc
    }

    println!("{:<22}  {:<32}  {:>10}", "KIND", "KEY", "SIZE");
    println!("{}", "-".repeat(68));
    for (kind, key, len) in &sections {
        let key_str = key.as_deref().unwrap_or("-");
        println!("{:<22}  {:<32}  {:>10}",
            truncate(&kind, 22), truncate(key_str, 32), fmt_bytes(*len as u64));
    }
    println!("\n{} sections", sections.len());
    Ok(())
}

// ─── Display helpers ─────────────────────────────────────────────────────────

/// Parsed command-line options / flags.
struct Opts {
    truncate_terms: Option<usize>,
    raw: bool,
    sort_by: String,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { truncate_terms: None, raw: false, sort_by: "size".to_string() }
    }
}

/// Parse flags from a slice of argument strings (positional args already removed).
fn parse_opts(args: &[String]) -> Opts {
    let mut opts = Opts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--raw" => opts.raw = true,
            "--truncate-terms" => {
                if let Some(v) = args.get(i + 1) {
                    if let Ok(n) = v.parse::<usize>() {
                        opts.truncate_terms = Some(n);
                        i += 1;
                    }
                }
            }
            "--sort-by" => {
                if let Some(v) = args.get(i + 1) {
                    opts.sort_by = v.clone();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    opts
}

/// Render a term to a string, optionally truncated to `max_chars` characters.
fn render_term(term: &ErlTerm, max_chars: Option<usize>) -> String {
    let mut buf = Vec::new();
    print_term(term, &mut buf).ok();
    let s = String::from_utf8_lossy(&buf).into_owned();
    match max_chars {
        Some(max) if s.len() > max => format!("{}…", &s[..max.saturating_sub(1)]),
        _ => s,
    }
}

fn fmt_bytes(n: u64) -> String {
    if n >= 1_073_741_824 { format!("{:.1}G", n as f64 / 1_073_741_824.0) }
    else if n >= 1_048_576 { format!("{:.1}M", n as f64 / 1_048_576.0) }
    else if n >= 1_024     { format!("{:.1}K", n as f64 / 1_024.0) }
    else                   { format!("{n}B") }
}

/// Format a word count with its byte equivalent (1 word = 8 bytes on 64-bit OTP).
fn fmt_words_kb(n: u64) -> String {
    format!("{n} words ({})", fmt_bytes(n.saturating_mul(8)))
}

/// Compact word + memory format for table cells, e.g. "12345 (96K)".
fn fmt_words_table(n: u64) -> String {
    format!("{n} ({})", fmt_bytes(n.saturating_mul(8)))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max.saturating_sub(1)]) }
}
