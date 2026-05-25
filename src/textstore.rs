//! Zstd-compressed text section store for Erlang crash dump sections.
//!
//! Sections are packed into 64 KiB uncompressed frames, each independently
//! zstd-compressed and written to `sections.zdb`.  A compact binary index
//! (`meta.bin`) is loaded entirely in RAM on open and supports O(log N)
//! lookup by `(kind, key)` via binary search.
//!
//! # On-disk layout
//!
//! ## `meta.bin` (format TDBMETA2)
//! ```text
//! [8]  magic: TDBMETA2
//! [4]  string_table_size: u32 le
//! [4]  section_count:     u32 le
//! [4]  frame_count:       u32 le
//! [N]  string_table       — packed "kind\0key\0" pairs (key="" if absent)
//! [section_count × 28]   section index (sorted by key string, ascending)
//!      str_offset:      u32 le   offset into string_table
//!      start_frame:     u32 le   index of the first frame that holds content
//!      start_pos:       u32 le   byte offset within that first frame
//!      len_lo:          u32 le   low 32 bits of content length in bytes
//!      len_hi:          u32 le   high 32 bits of content length in bytes
//!      line_count_lo:   u32 le   low 32 bits of non-empty line count
//!      line_count_hi:   u32 le   high 32 bits of non-empty line count
//! [frame_count × 12]     frame table
//!      file_offset:   u64 le   byte offset in sections.zdb
//!      compressed_sz: u32 le
//! ```
//!
//! Sections may span multiple frames.  The reader follows frame boundaries
//! automatically using `start_frame`, `start_pos`, and the byte length.
//!
//! ## `sections.zdb`
//! Concatenated independently zstd-compressed frames.
//!
//! ## Upgrade note
//! Files written by the previous format (magic `TDBMETA1`) are not readable
//! by this version.  Re-parse the dump file to regenerate the cache.

use anyhow::{Result, bail};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use crate::model::Page;

const MAGIC: &[u8; 8] = b"TDBMETA2";
const MAGIC_OLD: &[u8; 8] = b"TDBMETA1";

/// Maximum uncompressed bytes per frame before a flush is triggered.
pub const TEXT_FRAME_SIZE: usize = 64 * 1024;

const ZSTD_LEVEL: i32 = 3;

// ── internal structs ──────────────────────────────────────────────────────────

struct SecEntry {
    str_offset: u32,
    start_frame: u32,
    start_pos: u32,
    len_lo: u32,
    len_hi: u32,
    line_count_lo: u32,
    line_count_hi: u32,
}

impl SecEntry {
    fn total_len(&self) -> u64 {
        (self.len_hi as u64) << 32 | self.len_lo as u64
    }
    fn non_empty_lines(&self) -> u64 {
        (self.line_count_hi as u64) << 32 | self.line_count_lo as u64
    }
}

struct FrameEntry {
    file_offset: u64,
    compressed_size: u32,
}

// ── Writer ────────────────────────────────────────────────────────────────────

/// Builds a text store directory from sections inserted in any order.
pub struct TextWriter {
    dir: PathBuf,
    zdb: BufWriter<File>,
    zdb_pos: u64,
    frame_buf: Vec<u8>,
    frame_idx: u32,
    sections: Vec<SecEntry>,
    string_table: Vec<u8>,
    frames: Vec<FrameEntry>,
}

impl TextWriter {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(TextWriter {
            zdb: BufWriter::new(File::create(dir.join("sections.zdb"))?),
            zdb_pos: 0,
            // Pre-allocate slightly more than one frame so extend_from_slice
            // within a single write() never needs to reallocate.
            frame_buf: Vec::with_capacity(TEXT_FRAME_SIZE + 4096),
            frame_idx: 0,
            sections: Vec::new(),
            string_table: Vec::new(),
            frames: Vec::new(),
            dir,
        })
    }

    /// Begin a new streaming section.  Returns a [`SectionWriter`] that must
    /// be finished with [`SectionWriter::finish`]; if nothing is written the
    /// section is silently discarded.
    pub fn begin_section<'a>(&'a mut self, kind: &str, key: Option<&str>) -> SectionWriter<'a> {
        // Invariant: frame_buf.len() < TEXT_FRAME_SIZE outside of write().
        // So start_pos is always a valid offset within the current frame.
        SectionWriter {
            start_frame: self.frame_idx,
            start_pos: self.frame_buf.len() as u32,
            kind: kind.to_string(),
            key: key.map(str::to_string),
            writer: self,
            total_written: 0,
            non_empty_lines: 0,
            current_line_has_content: false,
        }
    }

    /// Insert one text section in a single call (delegates to begin/write/finish).
    pub fn insert(&mut self, kind: &str, key: Option<&str>, content: &str) -> Result<()> {
        if content.is_empty() {
            return Ok(());
        }
        let mut sw = self.begin_section(kind, key);
        sw.write(content)?;
        sw.finish()
    }

    fn flush_frame(&mut self) -> Result<()> {
        if self.frame_buf.is_empty() {
            return Ok(());
        }
        let compressed = zstd::encode_all(self.frame_buf.as_slice(), ZSTD_LEVEL)?;
        let file_offset = self.zdb_pos;
        let compressed_size = compressed.len() as u32;
        self.zdb.write_all(&compressed)?;
        self.zdb_pos += compressed_size as u64;
        self.frames.push(FrameEntry { file_offset, compressed_size });
        self.frame_buf.clear();
        self.frame_idx += 1;
        Ok(())
    }

    /// Flush remaining data, sort the index, and write `meta.bin`.
    pub fn finish(mut self) -> Result<()> {
        self.flush_frame()?;
        self.zdb.flush()?;

        // Sort section index by key string for binary search.
        let st = &self.string_table;
        self.sections
            .sort_unstable_by(|a, b| key_bytes(st, a.str_offset).cmp(key_bytes(st, b.str_offset)));

        let mut meta = BufWriter::new(File::create(self.dir.join("meta.bin"))?);
        meta.write_all(MAGIC)?;
        write_u32(&mut meta, self.string_table.len() as u32)?;
        write_u32(&mut meta, self.sections.len() as u32)?;
        write_u32(&mut meta, self.frames.len() as u32)?;
        meta.write_all(&self.string_table)?;
        for s in &self.sections {
            write_u32(&mut meta, s.str_offset)?;
            write_u32(&mut meta, s.start_frame)?;
            write_u32(&mut meta, s.start_pos)?;
            write_u32(&mut meta, s.len_lo)?;
            write_u32(&mut meta, s.len_hi)?;
            write_u32(&mut meta, s.line_count_lo)?;
            write_u32(&mut meta, s.line_count_hi)?;
        }
        for f in &self.frames {
            write_u64(&mut meta, f.file_offset)?;
            write_u32(&mut meta, f.compressed_size)?;
        }
        meta.flush()?;
        Ok(())
    }
}

// ── SectionWriter ─────────────────────────────────────────────────────────────

/// A streaming writer for a single text section.
///
/// Created by [`TextWriter::begin_section`].  Call [`SectionWriter::write`]
/// one or more times, then [`SectionWriter::finish`].  If `finish` is never
/// called (e.g. the section turned out to be empty) the bytes already written
/// to `frame_buf` will still be there but no index entry is registered —
/// effectively leaking a few bytes into the frame.  Callers should always call
/// `finish` (it is a no-op for zero-byte sections).
pub struct SectionWriter<'a> {
    writer: &'a mut TextWriter,
    kind: String,
    key: Option<String>,
    start_frame: u32,
    start_pos: u32,
    total_written: u64,
    non_empty_lines: u64,
    /// True when the current (unfinished) line contains at least one byte.
    current_line_has_content: bool,
}

impl<'a> SectionWriter<'a> {
    /// Stream `data` into the text store, flushing frames as they fill up.
    ///
    /// Memory footprint: at most one 64 KiB uncompressed frame at a time,
    /// regardless of how large `data` is.
    pub fn write(&mut self, data: &str) -> Result<()> {
        // Track non-empty line count as we scan bytes.
        for &b in data.as_bytes() {
            if b == b'\n' {
                if self.current_line_has_content {
                    self.non_empty_lines += 1;
                }
                self.current_line_has_content = false;
            } else {
                self.current_line_has_content = true;
            }
        }

        // Stream into frames, flushing when each frame is full.
        // Invariant maintained: frame_buf.len() < TEXT_FRAME_SIZE after this returns.
        let mut bytes = data.as_bytes();
        while !bytes.is_empty() {
            let space = TEXT_FRAME_SIZE - self.writer.frame_buf.len();
            let take = bytes.len().min(space);
            self.writer.frame_buf.extend_from_slice(&bytes[..take]);
            self.total_written += take as u64;
            bytes = &bytes[take..];
            if self.writer.frame_buf.len() == TEXT_FRAME_SIZE {
                self.writer.flush_frame()?;
            }
        }
        Ok(())
    }

    /// Register the section in the index and consume this writer.
    ///
    /// If nothing was written, no index entry is created (the section is
    /// silently omitted, matching the behaviour of the old `insert()` for
    /// empty strings).
    pub fn finish(self) -> Result<()> {
        // Count a trailing line that has no terminating newline.
        let total_lines = self.non_empty_lines
            + if self.current_line_has_content { 1 } else { 0 };

        if self.total_written == 0 {
            return Ok(());
        }

        let str_offset = self.writer.string_table.len() as u32;
        self.writer.string_table.extend_from_slice(self.kind.as_bytes());
        self.writer.string_table.push(b'\0');
        self.writer.string_table.extend_from_slice(
            self.key.as_deref().unwrap_or("").as_bytes(),
        );
        self.writer.string_table.push(b'\0');

        self.writer.sections.push(SecEntry {
            str_offset,
            start_frame: self.start_frame,
            start_pos: self.start_pos,
            len_lo: self.total_written as u32,
            len_hi: (self.total_written >> 32) as u32,
            line_count_lo: total_lines as u32,
            line_count_hi: (total_lines >> 32) as u32,
        });
        Ok(())
    }
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// Opens a text store directory for point lookups and kind-scoped iteration.
pub struct TextReader {
    zdb: File,
    sections: Vec<SecEntry>,
    string_table: Vec<u8>,
    frames: Vec<FrameEntry>,
}

impl TextReader {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let mut meta = File::open(dir.join("meta.bin"))?;

        let mut magic = [0u8; 8];
        meta.read_exact(&mut magic)?;
        if &magic == MAGIC_OLD {
            bail!(
                "text store at {} was written by an older version of ecd \
                 (format TDBMETA1).  Delete the cache directory and re-parse \
                 the dump file to regenerate it.",
                dir.display()
            );
        }
        if &magic != MAGIC {
            bail!("invalid text store magic in {}", dir.display());
        }

        let st_size = read_u32(&mut meta)? as usize;
        let sec_count = read_u32(&mut meta)? as usize;
        let frm_count = read_u32(&mut meta)? as usize;

        let mut string_table = vec![0u8; st_size];
        meta.read_exact(&mut string_table)?;

        let mut sections = Vec::with_capacity(sec_count);
        for _ in 0..sec_count {
            sections.push(SecEntry {
                str_offset: read_u32(&mut meta)?,
                start_frame: read_u32(&mut meta)?,
                start_pos: read_u32(&mut meta)?,
                len_lo: read_u32(&mut meta)?,
                len_hi: read_u32(&mut meta)?,
                line_count_lo: read_u32(&mut meta)?,
                line_count_hi: read_u32(&mut meta)?,
            });
        }

        let mut frames = Vec::with_capacity(frm_count);
        for _ in 0..frm_count {
            frames.push(FrameEntry {
                file_offset: read_u64(&mut meta)?,
                compressed_size: read_u32(&mut meta)?,
            });
        }

        Ok(TextReader {
            zdb: File::open(dir.join("sections.zdb"))?,
            sections,
            string_table,
            frames,
        })
    }

    /// Look up a single section by `(kind, key)`.
    ///
    /// **Warning:** loads the entire section content into a `String`.  For
    /// known-large sections such as `proc_stack`, prefer [`get_lines_range`].
    pub fn get(&self, kind: &str, key: Option<&str>) -> Result<Option<String>> {
        let needle = make_key(kind, key);
        match self
            .sections
            .binary_search_by(|s| key_bytes(&self.string_table, s.str_offset).cmp(&needle))
        {
            Err(_) => Ok(None),
            Ok(i) => Ok(Some(self.read_content(&self.sections[i])?)),
        }
    }

    /// Return metadata for every section: `(kind, key, content_bytes)`.
    /// Sections are in the sorted order stored in the index.
    pub fn list_all(&self) -> Vec<(String, Option<String>, u64)> {
        let mut out = Vec::with_capacity(self.sections.len());
        for s in &self.sections {
            let kb = key_bytes(&self.string_table, s.str_offset);
            let null1 = kb.iter().position(|&b| b == 0).unwrap_or(kb.len());
            let kind = String::from_utf8_lossy(&kb[..null1]).into_owned();
            let rest = &kb[null1 + 1..];
            let key_part = &rest[..rest.len().saturating_sub(1)];
            let key = if key_part.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(key_part).into_owned())
            };
            out.push((kind, key, s.total_len()));
        }
        out
    }

    /// Return all sections whose kind matches, ordered by key.
    pub fn list_kind(&self, kind: &str) -> Result<Vec<(Option<String>, String)>> {
        let prefix = {
            let mut v = kind.as_bytes().to_vec();
            v.push(b'\0');
            v
        };
        let start = self
            .sections
            .partition_point(|s| key_bytes(&self.string_table, s.str_offset) < prefix.as_slice());

        let mut out = Vec::new();
        for s in &self.sections[start..] {
            let kb = key_bytes(&self.string_table, s.str_offset);
            if !kb.starts_with(prefix.as_slice()) {
                break;
            }
            let key_bytes = &kb[kind.len() + 1..kb.len() - 1];
            let key = if key_bytes.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(key_bytes).into_owned())
            };
            out.push((key, self.read_content(s)?));
        }
        Ok(out)
    }

    /// Return a paginated slice of non-empty lines from a text section.
    ///
    /// Reads frames one at a time (64 KiB working memory) rather than loading
    /// the whole section.  The total line count is stored in the section index
    /// so it is returned without extra I/O.
    ///
    /// Returns `None` if the section does not exist.
    pub fn get_lines_range(
        &self,
        kind: &str,
        key: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Option<Page<String>>> {
        let needle = make_key(kind, key);
        let idx = match self
            .sections
            .binary_search_by(|s| key_bytes(&self.string_table, s.str_offset).cmp(&needle))
        {
            Err(_) => return Ok(None),
            Ok(i) => i,
        };
        let s = &self.sections[idx];
        let total = s.non_empty_lines() as usize;

        if total == 0 || offset >= total {
            return Ok(Some(Page { items: vec![], total, offset, limit }));
        }

        let mut items: Vec<String> = Vec::with_capacity(limit);
        // Byte buffer for a line being assembled across frame boundaries.
        let mut line_buf: Vec<u8> = Vec::new();
        let mut lines_seen = 0usize;

        let mut remaining = s.total_len();
        let mut frame_idx = s.start_frame as usize;
        let mut pos_in_frame = s.start_pos as usize;

        'frames: while remaining > 0 {
            let frame = self.decompress_frame(frame_idx)?;
            let available = frame.len() - pos_in_frame;
            let take = (remaining as usize).min(available);
            let data = &frame[pos_in_frame..pos_in_frame + take];
            remaining -= take as u64;
            let is_last_chunk = remaining == 0;

            let mut start = 0usize;
            while start <= data.len() {
                // Find next newline or end-of-chunk.
                let nl_pos = data[start..].iter().position(|&b| b == b'\n');

                match nl_pos {
                    Some(rel) => {
                        // Complete line: line_buf + data[start..start+rel]
                        line_buf.extend_from_slice(&data[start..start + rel]);
                        if !line_buf.is_empty() {
                            if lines_seen >= offset && items.len() < limit {
                                items.push(
                                    String::from_utf8_lossy(&line_buf).into_owned(),
                                );
                            }
                            lines_seen += 1;
                            if items.len() >= limit {
                                // We have all items needed; stop scanning.
                                break 'frames;
                            }
                        }
                        line_buf.clear();
                        start += rel + 1;
                    }
                    None => {
                        // No more newlines in this chunk.
                        line_buf.extend_from_slice(&data[start..]);
                        break;
                    }
                }
            }

            // If this is the last chunk and a non-empty partial line remains,
            // emit it (the section has no trailing newline).
            if is_last_chunk && !line_buf.is_empty() {
                if lines_seen >= offset && items.len() < limit {
                    items.push(String::from_utf8_lossy(&line_buf).into_owned());
                }
                line_buf.clear();
            }

            frame_idx += 1;
            pos_in_frame = 0;
        }

        Ok(Some(Page { items, total, offset, limit }))
    }

    // ── private ───────────────────────────────────────────────────────────────

    fn decompress_frame(&self, frame_idx: usize) -> Result<Vec<u8>> {
        let f = self.frames.get(frame_idx).ok_or_else(|| {
            anyhow::anyhow!("text store: frame index {frame_idx} out of range")
        })?;
        let mut compressed = vec![0u8; f.compressed_size as usize];
        self.zdb.read_exact_at(&mut compressed, f.file_offset)?;
        Ok(zstd::decode_all(compressed.as_slice())?)
    }

    /// Read the full content of a section across frame boundaries into a String.
    ///
    /// **Warning:** allocates `total_len` bytes for very large sections.
    /// Use [`get_lines_range`] for sections that may exceed available RAM.
    fn read_content(&self, s: &SecEntry) -> Result<String> {
        let total_len = s.total_len();
        if total_len == 0 {
            return Ok(String::new());
        }
        let cap = total_len.min(8 * 1024 * 1024) as usize;
        let mut result = Vec::with_capacity(cap);
        let mut remaining = total_len;
        let mut frame_idx = s.start_frame as usize;
        let mut pos = s.start_pos as usize;

        while remaining > 0 {
            let frame = self.decompress_frame(frame_idx)?;
            let available = frame.len() - pos;
            let take = (remaining as usize).min(available);
            result.extend_from_slice(&frame[pos..pos + take]);
            remaining -= take as u64;
            frame_idx += 1;
            pos = 0;
        }
        Ok(String::from_utf8_lossy(&result).into_owned())
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Borrow the `"kind\0key\0"` byte string for the entry at `offset`.
fn key_bytes(table: &[u8], offset: u32) -> &[u8] {
    let start = offset as usize;
    let mut nulls = 0usize;
    for (i, &b) in table[start..].iter().enumerate() {
        if b == 0 {
            nulls += 1;
            if nulls == 2 {
                return &table[start..start + i + 1];
            }
        }
    }
    &table[start..]
}

fn make_key(kind: &str, key: Option<&str>) -> Vec<u8> {
    let mut v = kind.as_bytes().to_vec();
    v.push(b'\0');
    v.extend_from_slice(key.unwrap_or("").as_bytes());
    v.push(b'\0');
    v
}

fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_u64(w: &mut impl Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
