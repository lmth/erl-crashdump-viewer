//! External sort + k-way merge feeding into a [`crashdump_db::Writer`].
//!
//! Records arrive in arbitrary order. They are batched into in-memory runs,
//! each sorted and spilled to disk as a zstd-compressed stream of inline
//! `(addr:u64_le)(len:u32_le)(blob_bytes…)` records. When
//! [`ExternalSorter::finish`] is called the runs are k-way merged (min-heap)
//! reading each file **sequentially** — no `raw.bin`, no random I/O.
//!
//! # Parallelism
//!
//! A dedicated background thread handles spills (sort + zstd-encode + write)
//! while the caller thread continues scanning/decompressing the dump. The
//! channel between them has capacity 1 so at most two full runs live in RAM
//! at once (the one being filled + the one being compressed).

use anyhow::Result;
use crashdump_db::Writer;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use tempfile::TempDir;

/// Tuning knobs for the external sort.
pub struct Config {
    /// Maximum number of entries kept in RAM before a spill run is written.
    /// Each entry uses ~20 bytes of index plus the blob bytes (average ~32 B).
    /// The default (10 M entries) uses roughly 500 MB of RAM per run.
    pub run_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config { run_size: 10_000_000 }
    }
}

// In-memory index entry pointing into `current_blobs`.
struct RunEntry {
    addr: u64,
    blob_offset: u64,
    blob_len: u32,
}

struct SpillTask {
    entries: Vec<RunEntry>,
    blobs: Vec<u8>,
    path: PathBuf,
}

pub struct ExternalSorter {
    tmp_dir: TempDir,
    current_run: Vec<RunEntry>,
    current_blobs: Vec<u8>, // flat blob buffer for the current in-memory run
    run_size_limit: usize,
    run_paths: Vec<PathBuf>,
    total_entries: u64, // running count of all inserts across all runs
    // Background spill worker: sort+compress+write in parallel with scanning.
    spill_tx: mpsc::SyncSender<SpillTask>,
    spill_thread: Option<thread::JoinHandle<io::Result<()>>>,
}

impl ExternalSorter {
    /// `work_dir` is the directory under which a temporary subdirectory is
    /// created. Pass the dump's `db_dir` parent so that work files land on
    /// the same filesystem as the output rather than in `/tmp`.
    pub fn new(config: Config, work_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(work_dir)?;
        let tmp_dir = tempfile::Builder::new().prefix("ecd-sort-").tempdir_in(work_dir)?;

        // Channel capacity 1: scan can hand off one spill job and keep going
        // while the worker finishes it; a second spill blocks until the worker
        // is free, capping RAM at two full runs simultaneously.
        let (tx, rx) = mpsc::sync_channel::<SpillTask>(1);
        let handle = thread::spawn(move || -> io::Result<()> {
            for task in rx {
                write_spill_file(task.entries, task.blobs, &task.path)?;
            }
            Ok(())
        });

        Ok(ExternalSorter {
            tmp_dir,
            current_run: Vec::with_capacity(config.run_size),
            current_blobs: Vec::new(),
            run_size_limit: config.run_size,
            run_paths: Vec::new(),
            total_entries: 0,
            spill_tx: tx,
            spill_thread: Some(handle),
        })
    }

    /// Accept one address→blob record (any order). Blobs are accumulated in
    /// RAM; a spill is triggered once `run_size` entries are buffered.
    pub fn insert(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        let blob_offset = self.current_blobs.len() as u64;
        self.current_blobs.extend_from_slice(data);
        self.current_run.push(RunEntry { addr, blob_offset, blob_len: data.len() as u32 });
        self.total_entries += 1;
        if self.current_run.len() >= self.run_size_limit {
            self.spill()?;
        }
        Ok(())
    }

    /// Hand the current run off to the background spill worker and swap in
    /// fresh empty buffers so the caller can continue inserting immediately.
    fn spill(&mut self) -> Result<()> {
        let path = self.tmp_dir.path().join(format!("run_{}.bin.zst", self.run_paths.len()));
        self.run_paths.push(path.clone());

        let entries = std::mem::replace(&mut self.current_run, Vec::with_capacity(self.run_size_limit));
        let blobs   = std::mem::replace(&mut self.current_blobs, Vec::new());

        self.spill_tx
            .send(SpillTask { entries, blobs, path })
            .map_err(|_| anyhow::anyhow!("spill worker thread terminated unexpectedly"))?;
        Ok(())
    }

    /// Sort, merge all runs and stream records into a new crashdump-db at
    /// `db_dir`. Returns the number of unique addresses written.
    pub fn finish(mut self, db_dir: &Path, on_progress: Option<&(dyn Fn(&str) + Send)>) -> Result<u64> {
        if !self.current_run.is_empty() {
            self.spill()?;
        }

        // Signal the spill worker to stop, then wait for it to finish all
        // pending writes before we start reading the run files back.
        let spill_thread = self.spill_thread.take().expect("spill thread always set in new()");
        drop(self.spill_tx); // close channel → worker loop exits after draining
        spill_thread
            .join()
            .map_err(|_| anyhow::anyhow!("spill worker panicked"))?
            .map_err(|e| anyhow::anyhow!("spill worker I/O error: {e}"))?;

        if let Some(f) = on_progress {
            f(&format!(
                "Merging {} run(s), {} M entries…",
                self.run_paths.len(),
                self.total_entries / 1_000_000,
            ));
        }

        // Open all run files through zstd decoders (sequential reads only).
        let mut run_readers: Vec<_> = self
            .run_paths
            .iter()
            .map(|p| -> io::Result<_> { zstd::Decoder::new(BufReader::new(File::open(p)?)) })
            .collect::<io::Result<_>>()?;

        // Min-heap entries: (addr, blob_len, run_idx).
        // After popping, read `blob_len` bytes from run_readers[run_idx] to
        // get the blob (the reader is positioned right after the header).
        let mut heap: BinaryHeap<Reverse<(u64, u32, usize)>> = BinaryHeap::new();
        for (idx, rdr) in run_readers.iter_mut().enumerate() {
            if let Some((addr, len)) = read_header(rdr)? {
                heap.push(Reverse((addr, len, idx)));
            }
        }

        let mut writer = Writer::new(db_dir)?;
        let mut blob_buf: Vec<u8> = Vec::new();
        let mut prev_addr: Option<u64> = None;
        let mut written: u64 = 0;

        while let Some(Reverse((addr, len, run_idx))) = heap.pop() {
            // Read the blob (reader is positioned right after this entry's header).
            blob_buf.resize(len as usize, 0);
            run_readers[run_idx].read_exact(&mut blob_buf)?;

            // Advance this run before any early-continue.
            if let Some((next_addr, next_len)) = read_header(&mut run_readers[run_idx])? {
                heap.push(Reverse((next_addr, next_len, run_idx)));
            }

            // Skip duplicate addresses (keep the first one encountered).
            if prev_addr == Some(addr) {
                continue;
            }
            prev_addr = Some(addr);

            writer.insert(addr, &blob_buf)?;
            written += 1;
            if let Some(f) = on_progress {
                if written % 1_000_000 == 0 {
                    f(&format!(
                        "Merging: {} / {} M entries…",
                        written / 1_000_000,
                        self.total_entries / 1_000_000,
                    ));
                }
            }
        }

        writer.finish()?;
        Ok(written) // tmp_dir dropped here → run files cleaned up
    }
}

/// Sort `entries` in-place by address and write them as a zstd-compressed
/// inline-blob file. Called on the background spill worker thread.
fn write_spill_file(mut entries: Vec<RunEntry>, blobs: Vec<u8>, path: &Path) -> io::Result<()> {
    entries.sort_unstable_by_key(|e| e.addr);
    let f = BufWriter::new(File::create(path)?);
    let mut enc = zstd::Encoder::new(f, 1)?; // level 1: maximise throughput
    for e in &entries {
        enc.write_all(&e.addr.to_le_bytes())?;
        enc.write_all(&e.blob_len.to_le_bytes())?;
        let start = e.blob_offset as usize;
        enc.write_all(&blobs[start..start + e.blob_len as usize])?;
    }
    enc.finish()?;
    // entries and blobs are dropped here, freeing ~500 MB of RAM
    Ok(())
}

/// Read the 12-byte entry header `(addr:u64_le)(len:u32_le)`.
/// Returns `None` at a clean EOF, or an error on a partial read.
fn read_header<R: Read>(rdr: &mut R) -> io::Result<Option<(u64, u32)>> {
    let mut buf = [0u8; 12];
    match rdr.read_exact(&mut buf) {
        Ok(()) => Ok(Some((
            u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        ))),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

