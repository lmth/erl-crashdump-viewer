# crashdump-db Design

## Purpose

A write-once, read-frequently embedded database for crash dump memory snapshots.
Maps 64-bit memory addresses to raw memory content (address regions).

## Data Model

```
Key:   u64 address  (base address of a memory region)
Value: { length: u32, data: [u8] }
```

Scale target: ~800M records, ~20GB of raw data.

## Constraints and Access Pattern

- **Write once**: data is created in a single bulk-load pass from pre-sorted input.
- **Read frequently**: point lookups only — given an exact base address, retrieve its data.
- **No updates, no deletes, no range queries.**
- **Data too large for RAM**: must live on disk with only a small in-RAM index.

## On-Disk Format

Three files:

### 1. Sparse index file (`sparse.idx`) — kept entirely in RAM

A small in-RAM array loaded at open time:

```
[ (first_addr: u64, index_frame_offset: u64, index_frame_compressed_size: u32) ] × num_buckets
```

Serialised to disk so it can be loaded at startup in one read. At ~24 bytes per
bucket and e.g. 80,000 buckets (~10K index entries per bucket), this is ~2MB.

### 2. Index file (`index.cdb`) — sorted, bucket-compressed

The full sorted index, divided into fixed-size buckets of N entries each.
Each bucket is independently zstd-compressed and written contiguously.

Each uncompressed bucket entry:
```
addr:         u64   (8 bytes)
data_offset:  u64   (8 bytes)  — uncompressed byte offset into data file
length:       u32   (4 bytes)
              ----
              20 bytes/entry
```

Sorted u64 addresses + monotonically increasing offsets compress extremely well
(delta-encodable structure); expect 8–12× compression ratio.

Bucket size guideline: 10,000 entries → 200KB uncompressed → ~20KB compressed.

### 3. Data file (`data.cdb`) — frame-compressed

Raw data blobs, grouped into fixed-size uncompressed frames (e.g. 1MB each),
each frame independently zstd-compressed.

A data frame index maps:
```
[ (frame_start_uncompressed_offset: u64, frame_file_offset: u64, frame_compressed_size: u32) ]
```

This is small enough to keep in RAM alongside the sparse index
(e.g. 20,000 frames × 20 bytes = 400KB for 20GB of data at 1MB/frame).

## Lookup Algorithm

Given an address `addr`:

1. Binary search the in-RAM sparse index → find bucket `b` with the largest
   `first_addr ≤ addr`.
2. `pread` compressed index bucket `b` from `index.cdb`, zstd-decompress into
   a local buffer.
3. Binary search the decompressed bucket → find entry with `entry.addr == addr`.
   Return not-found if absent.
4. Binary search the in-RAM data frame index → find the frame containing
   `entry.data_offset`.
5. `pread` compressed data frame from `data.cdb`, zstd-decompress.
6. Slice `[within_frame_offset .. within_frame_offset + entry.length]` from
   the decompressed frame → return data.

**Total disk I/O per lookup: 2 reads** (one index bucket + one data frame).

## Write (Build) Algorithm

Precondition: input records are already sorted by address.

1. Open `index.cdb`, `data.cdb` for sequential writing.
2. Maintain a `data_offset` accumulator (uncompressed byte position in data file).
3. For each bucket of N input records:
   a. Accumulate N index entries `(addr, data_offset, length)`.
   b. For each record's data, accumulate into the current data frame buffer.
      Flush (compress + write) data frame when buffer reaches FRAME_SIZE.
   c. zstd-compress the N index entries → write to `index.cdb`.
   d. Record `(first_addr, index_frame_offset, compressed_size)` in sparse index.
4. Flush any remaining partial data frame and partial index bucket.
5. Write sparse index and data frame index to `sparse.idx`.

**All writes are sequential** — saturates disk write bandwidth.

## Tunables

| Parameter         | Suggested default | Effect                                      |
|-------------------|-------------------|---------------------------------------------|
| `BUCKET_SIZE`     | 10,000 entries    | Index bucket size; trades RAM read vs seeks |
| `DATA_FRAME_SIZE` | 1MB uncompressed  | Data frame size; trades RAM vs read size    |
| `ZSTD_LEVEL`      | 3 (default)       | Compression speed vs ratio                  |

## Dependencies (Rust)

- `zstd` — compression (wraps libzstd)

No database dependencies. No sorted structure overhead. No compaction.

## Estimated Footprint

| Component             | Uncompressed | Compressed (est.) |
|-----------------------|-------------|-------------------|
| Index file            | 16 GB       | 1.5–2 GB          |
| Data file             | 20 GB       | varies by content |
| Sparse index (RAM)    | ~2 MB       | —                 |
| Data frame idx (RAM)  | ~400 KB     | —                 |
