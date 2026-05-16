//! crashdump-db: write-once, read-frequently key-value store for memory snapshots.
//!
//! Maps `u64` base addresses to raw byte slices.  Designed for ~800M records /
//! ~20GB of data that must live on disk but be queried with minimal I/O.
//!
//! # On-disk layout (a directory with three files)
//!
//! - `meta.bin`  – sparse index + data-frame index, loaded entirely into RAM on open.
//! - `index.cdb` – sorted index entries divided into fixed-size buckets, each
//!                 independently zstd-compressed.
//! - `data.cdb`  – raw data blobs grouped into fixed-size frames, each
//!                 independently zstd-compressed.
//!
//! # Usage
//!
//! ```no_run
//! use crashdump_db::{Writer, Reader};
//!
//! // Build (records must arrive in ascending address order)
//! let mut w = Writer::new("/tmp/mydb").unwrap();
//! w.insert(0x1000, b"hello").unwrap();
//! w.insert(0x2000, b"world").unwrap();
//! w.finish().unwrap();
//!
//! // Query
//! let r = Reader::open("/tmp/mydb").unwrap();
//! assert_eq!(r.get(0x1000).unwrap().as_deref(), Some(b"hello".as_ref()));
//! assert_eq!(r.get(0xffff).unwrap(), None);
//! ```

#![cfg(unix)]

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ── tunables ─────────────────────────────────────────────────────────────────

/// Number of index entries per compressed index bucket.
pub const BUCKET_SIZE: usize = 10_000;

/// Maximum uncompressed size (bytes) of a data frame before it is flushed.
pub const DATA_FRAME_SIZE: usize = 1024 * 1024; // 1 MiB

/// zstd compression level (1 = fastest, 22 = best; 3 is a good default).
pub const ZSTD_LEVEL: i32 = 3;

// ── file magic ────────────────────────────────────────────────────────────────

const MAGIC: &[u8; 8] = b"CDBMETA1";

// ── internal index structures (20 bytes each on disk) ─────────────────────────

#[derive(Clone, Copy)]
struct SparseEntry {
    first_addr: u64,
    frame_offset: u64,
    frame_compressed_size: u32,
}

#[derive(Clone, Copy)]
struct DataFrameEntry {
    /// Uncompressed byte offset of the first byte of this frame in the logical
    /// data stream.
    uncompressed_start: u64,
    frame_offset: u64,
    frame_compressed_size: u32,
}

// ── Writer ────────────────────────────────────────────────────────────────────

/// Builds a crashdump-db database directory from pre-sorted records.
///
/// Records **must** be inserted in strictly ascending address order.
pub struct Writer {
    index_file: BufWriter<File>,
    data_file: BufWriter<File>,

    // Current index bucket (serialised bytes of index entries).
    index_bucket: Vec<u8>,
    index_bucket_count: usize,
    index_bucket_first_addr: u64,

    // Current data frame (uncompressed data bytes).
    data_buffer: Vec<u8>,

    // Running total of uncompressed bytes committed to the logical data stream.
    data_uncompressed_offset: u64,
    // Uncompressed offset at which the current (not-yet-flushed) data frame begins.
    data_frame_uncompressed_start: u64,

    // Byte position of the next write in each file.
    index_file_pos: u64,
    data_file_pos: u64,

    sparse_index: Vec<SparseEntry>,
    data_frames: Vec<DataFrameEntry>,

    dir: PathBuf,
}

impl Writer {
    /// Create a new database in `dir` (created if absent).
    pub fn new(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        Ok(Writer {
            index_file: BufWriter::new(File::create(dir.join("index.cdb"))?),
            data_file: BufWriter::new(File::create(dir.join("data.cdb"))?),
            index_bucket: Vec::with_capacity(BUCKET_SIZE * 20),
            index_bucket_count: 0,
            index_bucket_first_addr: 0,
            data_buffer: Vec::with_capacity(DATA_FRAME_SIZE + 256 * 1024),
            data_uncompressed_offset: 0,
            data_frame_uncompressed_start: 0,
            index_file_pos: 0,
            data_file_pos: 0,
            sparse_index: Vec::new(),
            data_frames: Vec::new(),
            dir,
        })
    }

    /// Insert one record.  `addr` must be greater than all previously inserted
    /// addresses.  `data` may be empty.
    pub fn insert(&mut self, addr: u64, data: &[u8]) -> io::Result<()> {
        if self.index_bucket_count == 0 {
            self.index_bucket_first_addr = addr;
        }

        // Append 20-byte index entry: addr(8) | data_offset(8) | length(4)
        self.index_bucket
            .extend_from_slice(&addr.to_le_bytes());
        self.index_bucket
            .extend_from_slice(&self.data_uncompressed_offset.to_le_bytes());
        self.index_bucket
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.index_bucket_count += 1;

        self.data_buffer.extend_from_slice(data);
        self.data_uncompressed_offset += data.len() as u64;

        if self.data_buffer.len() >= DATA_FRAME_SIZE {
            self.flush_data_frame()?;
        }
        if self.index_bucket_count >= BUCKET_SIZE {
            self.flush_index_bucket()?;
        }
        Ok(())
    }

    /// Flush remaining data and write `meta.bin`.  Consumes the writer.
    pub fn finish(mut self) -> io::Result<()> {
        self.flush_data_frame()?;
        self.flush_index_bucket()?;
        self.index_file.flush()?;
        self.data_file.flush()?;

        let mut meta = BufWriter::new(File::create(self.dir.join("meta.bin"))?);
        meta.write_all(MAGIC)?;

        write_u64(&mut meta, self.sparse_index.len() as u64)?;
        for e in &self.sparse_index {
            write_u64(&mut meta, e.first_addr)?;
            write_u64(&mut meta, e.frame_offset)?;
            write_u32(&mut meta, e.frame_compressed_size)?;
        }

        write_u64(&mut meta, self.data_frames.len() as u64)?;
        for e in &self.data_frames {
            write_u64(&mut meta, e.uncompressed_start)?;
            write_u64(&mut meta, e.frame_offset)?;
            write_u32(&mut meta, e.frame_compressed_size)?;
        }

        meta.flush()
    }

    fn flush_data_frame(&mut self) -> io::Result<()> {
        if self.data_buffer.is_empty() {
            return Ok(());
        }
        let compressed = zstd_compress(&self.data_buffer)?;
        let frame_offset = self.data_file_pos;
        self.data_frames.push(DataFrameEntry {
            uncompressed_start: self.data_frame_uncompressed_start,
            frame_offset,
            frame_compressed_size: compressed.len() as u32,
        });
        self.data_file.write_all(&compressed)?;
        self.data_file_pos += compressed.len() as u64;
        self.data_frame_uncompressed_start = self.data_uncompressed_offset;
        self.data_buffer.clear();
        Ok(())
    }

    fn flush_index_bucket(&mut self) -> io::Result<()> {
        if self.index_bucket_count == 0 {
            return Ok(());
        }
        let compressed = zstd_compress(&self.index_bucket)?;
        let frame_offset = self.index_file_pos;
        self.sparse_index.push(SparseEntry {
            first_addr: self.index_bucket_first_addr,
            frame_offset,
            frame_compressed_size: compressed.len() as u32,
        });
        self.index_file.write_all(&compressed)?;
        self.index_file_pos += compressed.len() as u64;
        self.index_bucket.clear();
        self.index_bucket_count = 0;
        Ok(())
    }
}

// ── Reader ────────────────────────────────────────────────────────────────────

/// Opens an existing crashdump-db database for point lookups.
///
/// `Reader` is `Send + Sync`: `get` takes `&self` and uses positional reads
/// (`pread(2)`) rather than seeking, so concurrent queries from multiple threads
/// are safe without additional locking.
///
/// Decompressed index buckets and data frames are cached in RAM after first
/// access so that repeated lookups in the same region (e.g. decoding a
/// process's heap) pay the decompression cost only once.
pub struct Reader {
    index_file: File,
    data_file: File,
    sparse_index: Vec<SparseEntry>,
    data_frames: Vec<DataFrameEntry>,
    /// Cache of decompressed index buckets keyed by their file offset.
    index_cache: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
    /// Cache of decompressed data frames keyed by their file offset.
    data_cache: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
}

impl Reader {
    /// Open an existing database directory.
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref();
        let mut meta_bytes = Vec::new();
        File::open(dir.join("meta.bin"))?.read_to_end(&mut meta_bytes)?;

        if meta_bytes.len() < 8 || &meta_bytes[..8] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "crashdump-db: bad magic in meta.bin",
            ));
        }

        let mut pos = 8usize;
        let sparse_index = decode_sparse_index(&meta_bytes, &mut pos)?;
        let data_frames = decode_data_frames(&meta_bytes, &mut pos)?;

        Ok(Reader {
            index_file: File::open(dir.join("index.cdb"))?,
            data_file: File::open(dir.join("data.cdb"))?,
            sparse_index,
            data_frames,
            index_cache: Mutex::new(HashMap::new()),
            data_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Look up `addr`.  Returns `None` if the address is not in the database.
    ///
    /// Decompressed index buckets and data frames are cached after first access,
    /// so repeated lookups within the same region pay the I/O + decompression
    /// cost only once.
    pub fn get(&self, addr: u64) -> io::Result<Option<Vec<u8>>> {
        // 1. Binary search the in-RAM sparse index.
        let bucket_idx = match self.sparse_index.partition_point(|e| e.first_addr <= addr) {
            0 => return Ok(None),
            i => i - 1,
        };
        let sparse = self.sparse_index[bucket_idx];

        // 2. Get the decompressed index bucket, using the cache.
        let bucket: Arc<Vec<u8>> = {
            let mut cache = self.index_cache.lock().unwrap();
            if let Some(cached) = cache.get(&sparse.frame_offset) {
                Arc::clone(cached)
            } else {
                let mut cbuf = vec![0u8; sparse.frame_compressed_size as usize];
                self.index_file.read_at(&mut cbuf, sparse.frame_offset)?;
                let decompressed = Arc::new(zstd_decompress(&cbuf)?);
                cache.insert(sparse.frame_offset, Arc::clone(&decompressed));
                decompressed
            }
        };

        // 3. Binary search within the decompressed bucket.
        let (data_offset, length) = match search_bucket(&bucket, addr) {
            Some(pair) => pair,
            None => return Ok(None),
        };

        // 4. Binary search the in-RAM data-frame index.
        let frame_idx = match self
            .data_frames
            .partition_point(|e| e.uncompressed_start <= data_offset)
        {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "crashdump-db: data_offset maps to no frame",
                ))
            }
            i => i - 1,
        };
        let frame = self.data_frames[frame_idx];

        // 5. Get the decompressed data frame, using the cache.
        let frame_data: Arc<Vec<u8>> = {
            let mut cache = self.data_cache.lock().unwrap();
            if let Some(cached) = cache.get(&frame.frame_offset) {
                Arc::clone(cached)
            } else {
                let mut cbuf = vec![0u8; frame.frame_compressed_size as usize];
                self.data_file.read_at(&mut cbuf, frame.frame_offset)?;
                let decompressed = Arc::new(zstd_decompress(&cbuf)?);
                cache.insert(frame.frame_offset, Arc::clone(&decompressed));
                decompressed
            }
        };

        // 6. Slice out the record.
        let start = (data_offset - frame.uncompressed_start) as usize;
        Ok(Some(frame_data[start..start + length as usize].to_vec()))
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Binary search a flat array of 20-byte index entries for `target`.
/// Returns `(data_offset, length)` on a hit, `None` on a miss.
fn search_bucket(bucket: &[u8], target: u64) -> Option<(u64, u32)> {
    let n = bucket.len() / 20;
    let mut lo = 0usize;
    let mut hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let addr = get_u64(bucket, mid * 20);
        match addr.cmp(&target) {
            Ordering::Equal => {
                return Some((get_u64(bucket, mid * 20 + 8), get_u32(bucket, mid * 20 + 16)))
            }
            Ordering::Less => lo = mid + 1,
            Ordering::Greater => hi = mid,
        }
    }
    None
}

fn decode_sparse_index(buf: &[u8], pos: &mut usize) -> io::Result<Vec<SparseEntry>> {
    let n = get_u64(buf, *pos) as usize;
    *pos += 8;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(SparseEntry {
            first_addr: get_u64(buf, *pos),
            frame_offset: get_u64(buf, *pos + 8),
            frame_compressed_size: get_u32(buf, *pos + 16),
        });
        *pos += 20;
    }
    Ok(v)
}

fn decode_data_frames(buf: &[u8], pos: &mut usize) -> io::Result<Vec<DataFrameEntry>> {
    let n = get_u64(buf, *pos) as usize;
    *pos += 8;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(DataFrameEntry {
            uncompressed_start: get_u64(buf, *pos),
            frame_offset: get_u64(buf, *pos + 8),
            frame_compressed_size: get_u32(buf, *pos + 16),
        });
        *pos += 20;
    }
    Ok(v)
}

#[inline]
fn get_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

#[inline]
fn get_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

#[inline]
fn write_u64(w: &mut impl Write, v: u64) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

#[inline]
fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn zstd_compress(data: &[u8]) -> io::Result<Vec<u8>> {
    zstd::encode_all(data, ZSTD_LEVEL).map_err(io::Error::other)
}

fn zstd_decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    zstd::decode_all(data).map_err(io::Error::other)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("crashdump_db_{name}"));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn roundtrip_small() {
        let dir = tmp_dir("roundtrip_small");
        let records: &[(u64, &[u8])] = &[
            (0x1000, b"hello"),
            (0x2000, b"world"),
            (0x3000, &[0xde, 0xad, 0xbe, 0xef]),
        ];

        let mut w = Writer::new(&dir).unwrap();
        for &(addr, data) in records {
            w.insert(addr, data).unwrap();
        }
        w.finish().unwrap();

        let r = Reader::open(&dir).unwrap();
        for &(addr, expected) in records {
            assert_eq!(r.get(addr).unwrap().as_deref(), Some(expected));
        }
        assert_eq!(r.get(0x0000).unwrap(), None);
        assert_eq!(r.get(0x1001).unwrap(), None);
        assert_eq!(r.get(0xffff_ffff_ffff_ffff).unwrap(), None);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spans_multiple_buckets_and_frames() {
        let dir = tmp_dir("multi_bucket");

        // Insert enough records to cross at least 2 index buckets and 2 data frames.
        let n: u64 = (BUCKET_SIZE * 3) as u64;
        let data_size = DATA_FRAME_SIZE / BUCKET_SIZE + 1; // just over 1 frame worth per bucket

        let mut w = Writer::new(&dir).unwrap();
        for i in 0..n {
            let addr = i * 0x1000;
            let data = vec![(i & 0xff) as u8; data_size];
            w.insert(addr, &data).unwrap();
        }
        w.finish().unwrap();

        let r = Reader::open(&dir).unwrap();

        // Spot-check first, last, and a middle record.
        for &i in &[0u64, n / 2, n - 1] {
            let addr = i * 0x1000;
            let expected = vec![(i & 0xff) as u8; data_size];
            assert_eq!(r.get(addr).unwrap().as_deref(), Some(expected.as_slice()));
        }
        assert_eq!(r.get(n * 0x1000).unwrap(), None);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_database() {
        let dir = tmp_dir("empty");
        Writer::new(&dir).unwrap().finish().unwrap();
        let r = Reader::open(&dir).unwrap();
        assert_eq!(r.get(0).unwrap(), None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_value() {
        let dir = tmp_dir("empty_value");
        let mut w = Writer::new(&dir).unwrap();
        w.insert(0x100, b"").unwrap();
        w.insert(0x200, b"x").unwrap();
        w.finish().unwrap();

        let r = Reader::open(&dir).unwrap();
        assert_eq!(r.get(0x100).unwrap().as_deref(), Some(b"".as_ref()));
        assert_eq!(r.get(0x200).unwrap().as_deref(), Some(b"x".as_ref()));
        fs::remove_dir_all(&dir).unwrap();
    }
}
