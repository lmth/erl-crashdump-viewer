# ecd-server REST API

`ecd-server` exposes a REST API that is used by the HTMX web UI and can be
consumed directly by scripts or other tooling. All endpoints perform HTTP
content-negotiation: send `Accept: application/json` to get structured JSON
back; omit it (or send `Accept: text/html`) to get an HTMX-friendly HTML
fragment instead.

Error responses follow the same rule — with `Accept: application/json` you get:

```json
{ "error": "message", "status": 404 }
```

Base URL defaults to `http://127.0.0.1:8080`. Override with `--bind` / `--port`.

---

## Typical machine-to-machine workflow

```
1.  POST   /dumps                       upload & start parsing
2.  GET    /jobs/{job_id}               poll until status == "done"
3.  GET    /dumps/{fp}                  read crash overview
4.  GET    /dumps/{fp}/procs            list processes
5.  GET    /dumps/{fp}/procs/{pid}      full process details
6.  GET    /dumps/{fp}/procs/{pid}/stack   paginated stack (large procs)
7.  DELETE /dumps/{fp}                  clean up when done
```

`{fp}` is the fingerprint returned in the `done` job response; it is the same
value as `job_id` from the upload response.

---

## Endpoints

### `GET /dumps`

List all parsed dumps cached on the server.

**Response** `200 OK`

```json
[
  {
    "fingerprint": "a1b2c3d4...",
    "filename":    "erl_crash.dump",
    "size_bytes":  1234567890,
    "uploaded_at": "2026-05-16T10:35:00+02:00",
    "label":       "my-node prod 2026-05-16"
  }
]
```

`label` is absent when no label has been set.

---

### `POST /dumps`

Upload a crash dump file and start parsing it. The body must be
`multipart/form-data` with a field named `dump` containing the file.
Supported formats: plain text, gzip (`.gz`), xz (`.xz`), zstd (`.zst`).

```sh
curl -F dump=@erl_crash.dump http://127.0.0.1:8080/dumps
```

**Response** `200 OK`

```json
{ "job_id": "550e8400-e29b-41d4-a716-446655440000" }
```

Parsing happens asynchronously. Poll `GET /jobs/{job_id}` or subscribe to
`GET /jobs/{job_id}/stream` (SSE) to track progress.

---

### `GET /jobs/{job_id}`

Poll the status of an upload/parse job.

**Response** `200 OK` — always JSON regardless of `Accept` header.

```json
{
  "job_id":      "550e8400-e29b-41d4-a716-446655440000",
  "status":      "running",
  "progress":    "Merging: 12 / 38 M entries…"
}
```

Once finished:

```json
{
  "job_id":      "550e8400-e29b-41d4-a716-446655440000",
  "status":      "done",
  "fingerprint": "550e8400-e29b-41d4-a716-446655440000",
  "progress":    "Merging: 38 / 38 M entries…"
}
```

On failure:

```json
{
  "job_id": "550e8400-...",
  "status":  "failed",
  "error":   "not a valid Erlang crash dump"
}
```

Fields `fingerprint`, `error`, and `progress` are omitted when not applicable.
`404` is returned if the job ID is unknown (server restarted, or never existed).

---

### `GET /jobs/{job_id}/stream`

SSE stream of parse progress events. Each event has an `event:` type and a
`data:` payload.

| Event      | Data (JSON)                                      |
|------------|--------------------------------------------------|
| `started`  | `{"filename":"erl_crash.dump","size_bytes":...}` |
| `progress` | `"Merging: 12 / 38 M entries…"`                  |
| `done`     | `{"fingerprint":"...","redirect":"/dumps/..."}`  |
| `error`    | `"error message string"`                         |

The stream closes after `done` or `error`.

---

### `GET /dumps/{fp}`

Crash dump overview: node identity, process count, memory summary.

**Response** `200 OK`

```json
{
  "fingerprint":    "550e8400-...",
  "filename":       "erl_crash.dump",
  "size_bytes":     1234567890,
  "uploaded_at":    "2026-05-16T10:35:00+02:00",
  "parsed":         true,
  "process_count":  4821,
  "memory": {
    "total":        34359738368,
    "processes":    8589934592,
    "atom":         2097152
  }
}
```

`404` if the fingerprint is unknown or the dump has not finished parsing.

---

### `DELETE /dumps/{fp}`

Remove a parsed dump and its cached data from the server.

**Response** `200 OK` (empty body)

---

### `GET /dumps/{fp}/label`

Read the human-readable label for a dump.

**Response** `200 OK` — plain text label string, or empty body if unset.

### `PUT /dumps/{fp}/label`

Set the label. Body: `application/x-www-form-urlencoded` with field `label`.

```sh
curl -X PUT -d 'label=prod node 2026-05-16' http://127.0.0.1:8080/dumps/{fp}/label
```

**Response** `200 OK`

---

### `GET /dumps/{fp}/procs`

List all processes. Supports filtering and sorting via query parameters.

| Parameter | Description                                    | Default         |
|-----------|------------------------------------------------|-----------------|
| `q`       | Filter substring (pid, name, spawned_as, state)| —               |
| `sort_by` | `memory` (default) or `pid`                    | `memory`        |

**Response** `200 OK`

```json
{
  "fingerprint": "550e8400-...",
  "sorted_by":   "memory_bytes_desc",
  "total":       4821,
  "processes": [
    {
      "pid":                  "<0.42.0>",
      "name":                 "my_gen_server",
      "state":                "Waiting",
      "memory_bytes":         2097152,
      "stack_heap_words":     512,
      "stack_heap_bytes":     4096,
      "reductions":           1234567,
      "message_queue_length": 0
    }
  ]
}
```

---

### `GET /dumps/{fp}/procs/{pid}`

Full process details. For large processes with many stack frames or dictionary
entries, use the paginated sub-section endpoints below instead.

`{pid}` is URL-encoded, e.g. `%3C0.42.0%3E` for `<0.42.0>`.

| Parameter  | Description                                  | Default    |
|------------|----------------------------------------------|------------|
| `truncate` | Max characters per rendered term             | unlimited  |

**Response** `200 OK`

```json
{
  "pid":                  "<0.42.0>",
  "name":                 "my_gen_server",
  "state":                "Waiting",
  "spawned_as":           "my_gen_server:init/1",
  "spawned_by":           "<0.1.0>",
  "memory_bytes":         2097152,
  "stack_heap_words":     512,
  "stack_heap_bytes":     4096,
  "old_heap_words":       256,
  "heap_unused_words":    128,
  "reductions":           1234567,
  "message_queue_length": 0,
  "links":                ["<0.1.0>", "<0.99.0>"],
  "monitors":             [],
  "stack": [
    { "label": "y0", "term": "{ok, #Port<0.3>}" }
  ],
  "dictionary": ["{my_key, my_value}"],
  "messages":   []
}
```

---

### `GET /dumps/{fp}/procs/{pid}/stack`

Paginated stack frames for a process. Use this instead of the full process
endpoint when the stack is very large.

| Parameter  | Description              | Default |
|------------|--------------------------|---------|
| `page`     | 0-based page number      | 0       |
| `per_page` | Items per page           | 200     |
| `truncate` | Max chars per term       | unlimited |

**Response** `200 OK`

```json
{
  "pid":      "<0.42.0>",
  "page":     0,
  "per_page": 200,
  "total":    843,
  "items": [
    { "label": "y0", "term": "{ok, #Port<0.3>}" },
    { "label": "CP",  "term": "0x00007f..." }
  ]
}
```

---

### `GET /dumps/{fp}/procs/{pid}/dict`

Paginated process dictionary entries. Same query parameters as `/stack`.

**Response** `200 OK`

```json
{
  "pid":      "<0.42.0>",
  "section":  "dict",
  "page":     0,
  "per_page": 200,
  "total":    12,
  "items":    ["{my_key, my_value}", "{counter, 42}"]
}
```

---

### `GET /dumps/{fp}/procs/{pid}/messages`

Paginated message queue. Same query parameters as `/stack`.

**Response** `200 OK` — same envelope as `/dict` with `"section": "messages"`.

---

### `GET /dumps/{fp}/mem`

Memory allocator breakdown.

**Response** `200 OK`

```json
{
  "fingerprint": "550e8400-...",
  "entries": [
    { "key": "total",     "bytes": 34359738368 },
    { "key": "processes", "bytes":  8589934592 }
  ],
  "total_bytes": 34359738368
}
```

---

### `GET /dumps/{fp}/ets`

ETS table list.

**Response** `200 OK`

```json
{
  "fingerprint": "550e8400-...",
  "tables": [
    {
      "id":       "ac_tab",
      "name":     "ac_tab",
      "owner":    "<0.11.0>",
      "type":     "set",
      "size":     42,
      "memory_words": 1024
    }
  ]
}
```

---

### `GET /dumps/{fp}/sections`

Raw named sections from the crash dump (anything between `^=tag:key` lines).

| Parameter | Description                     | Default  |
|-----------|---------------------------------|----------|
| `sort_by` | `name` or omit for natural order| —        |

**Response** `200 OK`

```json
{
  "fingerprint": "550e8400-...",
  "sections": [
    { "kind": "memory",  "key": null,       "size_bytes": 128 },
    { "kind": "proc",    "key": "<0.42.0>", "size_bytes": 4096 }
  ]
}
```

---

### `GET /dumps/{fp}/query/{kind}`

Fetch the raw text of a specific named section.

| Parameter | Description                           |
|-----------|---------------------------------------|
| `key`     | Section key (pid, table id, etc.)     |

**Response** `200 OK` — `Content-Type: text/plain; charset=utf-8` with the raw
section text as stored in the dump. Useful for sections not otherwise parsed
(e.g. `loaded_modules`, `hash_table`).

```sh
curl "http://127.0.0.1:8080/dumps/{fp}/query/memory"
curl "http://127.0.0.1:8080/dumps/{fp}/query/proc?key=%3C0.42.0%3E"
```
