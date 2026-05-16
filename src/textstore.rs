//! Zstd-compressed text section store for Erlang crash dump sections.
//!
//! Sections are packed into 64 KiB uncompressed frames, each independently
//! zstd-compressed and written to `sections.zdb`.  A compact binary index
//! (`meta.bin`) is loaded entirely in RAM on open and supports O(log N)
//! lookup by `(kind, key)` via binary search.
//!
//! # On-disk layout
//!
//! ## `meta.bin`
//! ```text
//! [8]  magic: TDBMETA1
//! [4]  string_table_size: u32 le
//! [4]  section_count:     u32 le
//! [4]  frame_count:       u32 le
//! [N]  string_table       — packed "kind\0key\0" pairs (key="" if absent)
//! [section_count × 16]   section index (sorted by key string, ascending)
//!      str_offset:    u32 le   offset into string_table
//!      frame_idx:     u32 le   which compressed frame holds the content
//!      pos_in_frame:  u32 le   byte offset within the decompressed frame
//!      len:           u32 le   content length in bytes
//! [frame_count × 12]     frame table
//!      file_offset:   u64 le   byte offset in sections.zdb
//!      compressed_sz: u32 le
//! ```
//!
//! ## `sections.zdb`
//! Concatenated independently zstd-compressed frames.

use anyhow::{Result, bail};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"TDBMETA1";

/// Maximum uncompressed bytes per frame before a flush is triggered.
pub const TEXT_FRAME_SIZE: usize = 64 * 1024;

const ZSTD_LEVEL: i32 = 3;

// ── internal structs ──────────────────────────────────────────────────────────

struct SecEntry {
    str_offset: u32,
    frame_idx: u32,
    pos_in_frame: u32,
    len: u32,
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
            frame_buf: Vec::with_capacity(TEXT_FRAME_SIZE + 4096),
            frame_idx: 0,
            sections: Vec::new(),
            string_table: Vec::new(),
            frames: Vec::new(),
            dir,
        })
    }

    /// Insert one text section. `kind` and `key` form the lookup key;
    /// `content` is the raw text (may be multi-line).
    pub fn insert(&mut self, kind: &str, key: Option<&str>, content: &str) -> Result<()> {
        // Flush current frame if this section wouldn't fit, so that every
        // section lives entirely within one frame.
        if !self.frame_buf.is_empty()
            && self.frame_buf.len() + content.len() > TEXT_FRAME_SIZE
        {
            self.flush_frame()?;
        }

        let str_offset = self.string_table.len() as u32;
        self.string_table.extend_from_slice(kind.as_bytes());
        self.string_table.push(b'\0');
        self.string_table.extend_from_slice(key.unwrap_or("").as_bytes());
        self.string_table.push(b'\0');

        let pos_in_frame = self.frame_buf.len() as u32;
        self.frame_buf.extend_from_slice(content.as_bytes());

        self.sections.push(SecEntry {
            str_offset,
            frame_idx: self.frame_idx,
            pos_in_frame,
            len: content.len() as u32,
        });
        Ok(())
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
            write_u32(&mut meta, s.frame_idx)?;
            write_u32(&mut meta, s.pos_in_frame)?;
            write_u32(&mut meta, s.len)?;
        }
        for f in &self.frames {
            write_u64(&mut meta, f.file_offset)?;
            write_u32(&mut meta, f.compressed_size)?;
        }
        meta.flush()?;
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
                frame_idx: read_u32(&mut meta)?,
                pos_in_frame: read_u32(&mut meta)?,
                len: read_u32(&mut meta)?,
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

    /// Return metadata for every section: (kind, key, content_bytes).
    /// Sections are in the sorted order stored in the index.
    pub fn list_all(&self) -> Vec<(String, Option<String>, u32)> {
        let mut out = Vec::with_capacity(self.sections.len());
        for s in &self.sections {
            let kb = key_bytes(&self.string_table, s.str_offset);
            // kb is "kind\0key\0"; split on first null
            let null1 = kb.iter().position(|&b| b == 0).unwrap_or(kb.len());
            let kind = String::from_utf8_lossy(&kb[..null1]).into_owned();
            let rest = &kb[null1 + 1..];
            // rest ends with \0; strip it to get the key bytes
            let key_part = &rest[..rest.len().saturating_sub(1)];
            let key = if key_part.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(key_part).into_owned())
            };
            out.push((kind, key, s.len));
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
        // First section with key_bytes >= prefix (= first section of this kind).
        let start = self
            .sections
            .partition_point(|s| key_bytes(&self.string_table, s.str_offset) < prefix.as_slice());

        let mut out = Vec::new();
        for s in &self.sections[start..] {
            let kb = key_bytes(&self.string_table, s.str_offset);
            if !kb.starts_with(prefix.as_slice()) {
                break;
            }
            // Extract key part: bytes between first \0 and second \0.
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

    fn read_content(&self, s: &SecEntry) -> Result<String> {
        let f = &self.frames[s.frame_idx as usize];
        let mut compressed = vec![0u8; f.compressed_size as usize];
        self.zdb.read_exact_at(&mut compressed, f.file_offset)?;
        let frame = zstd::decode_all(compressed.as_slice())?;
        let start = s.pos_in_frame as usize;
        Ok(String::from_utf8_lossy(&frame[start..start + s.len as usize]).into_owned())
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
