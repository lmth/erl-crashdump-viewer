# erl-crashdump

A fast Erlang crash dump analyser with both a command-line interface and a
browser-based web UI.

Erlang crash dumps can be very large (gigabytes) and are text-format files that
are hard to navigate with ordinary tools.  `erl-crashdump` parses and indexes
the dump into a compact on-disk store the first time you open it, then answers
queries in milliseconds — even for the largest dumps.

---

## Features

### Parsing & storage

- **Streaming parse** — the dump is never fully loaded into RAM; it is scanned
  and indexed in a single forward pass.
- **Compressed input** — plain `.txt`, zstd (`.zst`), gzip (`.gz`) and XZ (`.xz`) dumps are
  accepted directly; compression is detected by magic bytes, not file extension, so any
  of these can also be piped in without a named file.
- **Content-fingerprint cache** — a 5-point file sample produces a stable
  fingerprint; a previously-indexed dump is reused without re-parsing even if
  the file is renamed or moved.
- **Incomplete dump detection** — if the dump was truncated before Erlang
  finished writing it (no `=end` marker), the tool flags it clearly in both the
  CLI and the web UI, and renders truncated heap references as `(dump_truncated)`
  rather than silently omitting them.
- **Parallel sort** — the external sort pipeline runs scan and
  sort+compress+write on separate threads for better CPU utilisation.

### Process inspection

- Browse all processes with their registered name, current function, message
  queue length, and heap/stack sizes.
- Sort process list by heap size or PID.
- Drill into an individual process to see its full stack trace, heap variables,
  and binary references, with paginated lazy loading so even a process with a
  30 GB heap is browsable.

### Term rendering

- ETF blobs stored in the dump are decoded and rendered as readable Erlang terms.
- Supports atoms, integers, floats, binaries, lists, tuples, maps, pids, ports,
  references, fun/lambda terms (`#Fun<Mod.Index.Uniq>`), and more.
- Client-side `~p`-style pretty-printing with collapsible fold for long terms.

### Memory overview

- System-wide memory breakdown (total, processes, ETS, binary heap, etc.)
  matching the output of `erlang:memory/0`.

### ETS tables

- List all ETS tables with name, owner PID, type, size, and memory usage.

### Sections explorer

- Browse every raw section in the dump (sorted by kind, key, or size).
- Useful for inspecting uncommon section types not yet given their own UI.

---

## Installation

### Prerequisites

- **Rust toolchain** (stable, 2024 edition).  The recommended way to install it
  is via [rustup](https://rustup.rs/):

  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source "$HOME/.cargo/env"    # or open a new terminal
  ```

  Verify:

  ```sh
  rustc --version   # e.g. rustc 1.78.0
  cargo --version   # e.g. cargo 1.78.0
  ```

### Clone and build

```sh
git clone https://github.com/yourname/erl-crashdump.git
cd erl-crashdump
cargo build --release
```

The two binaries are written to `target/release/`:

| Binary | Purpose |
|---|---|
| `ecd` | Command-line analyser |
| `ecd-server` | Web UI server |

You can copy them to any directory on your `$PATH`, e.g.:

```sh
cp target/release/ecd target/release/ecd-server ~/.local/bin/
```

---

## CLI usage — `ecd`

All subcommands take the dump file as their first argument.  The dump is
parsed and cached automatically on first use; subsequent commands against the
same file are instant.

```
ecd list
ecd <dump|id> procs    [--sort-by size|pid]
ecd <dump|id> proc     <pid> [--truncate-terms N] [--raw]
ecd <dump|id> mem      [--raw]
ecd <dump|id> ets      [--raw]
ecd <dump|id> sections [--sort-by size|kind|key]
ecd <dump|id> query    <kind> [key]
ecd <dump|id> decode   <kind> [key] [--truncate-terms N]
ecd <dump|id> lookup   <hex_addr>
ecd parse  <dump>   <outdir>
```

`<dump|id>` may be a path to a crash dump file, or the cache ID (or any
unambiguous prefix of it) shown by `ecd list`.  Dumps are parsed and indexed
the first time they are accessed; a `meta.json` is written alongside the index
so the listing is always informative.

### Examples

**List all cached dumps:**
```sh
ecd list
# ID                FILENAME                 SIZE      PARSED               ORIGINAL PATH
# a1b2c3d4e5f60708  erl_crash.dump           1.2G      2026-05-16 10:35     /path/to/...
```

**List all processes, largest heap first** (using file path or cache ID):
```sh
ecd /path/to/erl_crash.dump procs --sort-by size
ecd a1b2c3d4 procs --sort-by size   # cache ID prefix works too
```

**Inspect a specific process:**
```sh
ecd a1b2c3d4 proc '<0.214.0>'
```

**Memory overview:**
```sh
ecd a1b2c3d4 mem
```

**ETS table list:**
```sh
ecd a1b2c3d4 ets
```

**Browse all dump sections, sorted by size:**
```sh
ecd a1b2c3d4 sections --sort-by size
```

**Decode a raw heap term at a known address:**
```sh
ecd a1b2c3d4 decode proc '<0.214.0>'
```

**Explicitly parse a dump into a named directory** (useful for scripting or
pre-building the index ahead of time):
```sh
ecd parse /path/to/erl_crash.dump /var/cache/my-dump-index
```

**Compressed input** works transparently (detected by magic bytes, not extension):
```sh
ecd /path/to/erl_crash.dump.zst procs
ecd /path/to/erl_crash.dump.gz procs
ecd /path/to/erl_crash.dump.xz mem
```

---

## Web UI — `ecd-server`

Start the server:

```sh
ecd-server
# Listening on http://127.0.0.1:4000
```

By default it binds to `127.0.0.1:4000`.  Override with `--bind` and `--port`:

```sh
ecd-server --bind 0.0.0.0 --port 8080
```

Open `http://localhost:4000` in your browser.

### What you can do in the UI

1. **Upload a dump** — drag-and-drop or use the file picker.  Plain, zstd, gzip, and
   XZ dumps are accepted.  Compression is detected by magic bytes so the file extension
   does not matter.  A progress bar tracks the upload; parsing begins
   immediately while the file is still uploading.

2. **Manage dumps** — each parsed dump appears in the overview table.  You can
   give it a human-readable label and delete it when no longer needed.
   Incomplete dumps (truncated before writing finished) are highlighted with a
   yellow warning banner.

3. **Browse processes** — sortable table with registered name, current function,
   message queue depth, and heap/stack sizes.  Click a row to open the process
   detail page.

4. **Process detail** — stack frames, heap bindings, and message queue rendered
   as pretty-printed Erlang terms.  Long terms are folded to one line and expand
   on click.  Large processes load their sections lazily with paging so the
   browser stays responsive.

5. **Memory overview** — system-wide memory breakdown.

6. **ETS tables** — complete table list with sizes.

7. **Sections explorer** — every raw section in the dump, grouped and sortable.

---

## REST API

Every endpoint in `ecd-server` supports content-negotiation.  Add
`Accept: application/json` to any request and you get structured JSON back
instead of the HTMX HTML fragment.  This makes the server usable as a
headless analysis back-end from scripts, CI pipelines, or other tooling.

Typical workflow:

```sh
# 1. Upload and start parsing
JOB=$(curl -sF dump=@erl_crash.dump http://localhost:4000/dumps | jq -r .job_id)

# 2. Poll until done
until [ "$(curl -s http://localhost:4000/jobs/$JOB | jq -r .status)" = "done" ]; do
  sleep 2
done
FP=$(curl -s http://localhost:4000/jobs/$JOB | jq -r .fingerprint)

# 3. Query the data
curl -sH 'Accept: application/json' http://localhost:4000/dumps/$FP | jq .process_count
curl -sH 'Accept: application/json' "http://localhost:4000/dumps/$FP/procs" | jq '.processes[0]'
```

See **[docs/REST.md](docs/REST.md)** for the full endpoint reference.

---

## Development

```sh
cargo test          # run the test suite
cargo build         # debug build
cargo build --release  # optimised build
```

Set `RUST_LOG=debug` for verbose server logging:

```sh
RUST_LOG=debug ecd-server
```
