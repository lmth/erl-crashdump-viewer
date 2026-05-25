#![cfg(unix)]

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Multipart, Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response, Sse, sse::{Event, KeepAlive}},
    routing::get,
};
use chrono::{SecondsFormat, Utc};
use erl_crashdump::{
    Config, dump_reader::DumpReader, parse_reader,
    termdecoder::{ErlTerm, print_term, term_to_json},
    textstore::TextReader,
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    path::{Path, PathBuf},
    process,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc},
    time::sleep,
};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use uuid::Uuid;

// ── Channel-based reader for streaming parse ───────────────────────────────────

/// Wraps a `tokio::mpsc` receiver as a `std::io::Read`, allowing the blocking
/// parse task to consume bytes produced by the async upload handler
/// concurrently.  `blocking_recv` is safe to call from a `spawn_blocking` thread.
struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<axum::body::Bytes>,
    current: Option<axum::body::Bytes>,
    pos: usize,
}

impl ChannelReader {
    fn new(rx: tokio::sync::mpsc::Receiver<axum::body::Bytes>) -> Self {
        Self { rx, current: None, pos: 0 }
    }
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some(data) = &self.current {
                let rem = &data[self.pos..];
                if !rem.is_empty() {
                    let n = rem.len().min(buf.len());
                    buf[..n].copy_from_slice(&rem[..n]);
                    self.pos += n;
                    if self.pos >= data.len() {
                        self.current = None;
                        self.pos = 0;
                    }
                    return Ok(n);
                }
                self.current = None;
                self.pos = 0;
            }
            match self.rx.blocking_recv() {
                Some(b) if !b.is_empty() => self.current = Some(b),
                Some(_) => {}         // skip empty chunks
                None => return Ok(0), // sender dropped → EOF
            }
        }
    }
}

#[derive(Clone)]
struct AppState {
    cache_root: PathBuf,
    jobs: Arc<Mutex<HashMap<String, ParseJob>>>,
}

#[derive(Clone)]
struct ParseJob {
    status: JobStatus,
    events: Arc<Mutex<Vec<SseEvent>>>,
}

#[derive(Clone)]
enum JobStatus {
    Running,
    Done { fingerprint: String },
    Failed(String),
}

#[derive(Clone)]
struct SseEvent {
    event: String,
    data: String,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    wants_json: bool,
    htmx: bool,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, headers: &HeaderMap, message: impl Into<String>) -> Self {
        Self {
            status,
            wants_json: wants_json(headers),
            htmx: is_htmx(headers),
            message: message.into(),
        }
    }

    fn bad_request(headers: &HeaderMap, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, headers, message)
    }

    fn not_found(headers: &HeaderMap, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, headers, message)
    }

    fn internal(headers: &HeaderMap, err: impl std::fmt::Display) -> Self {
        let message = err.to_string();
        eprintln!("ecd-server: {message}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, headers, message)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if self.wants_json {
            return (
                self.status,
                Json(json!({
                    "error": self.message,
                    "status": self.status.as_u16(),
                })),
            )
                .into_response();
        }

        let body = html! {
            section class="panel" {
                h1 { (self.status.as_u16()) " " (self.status.canonical_reason().unwrap_or("Error")) }
                p { (self.message) }
                p { a href="/" { "Back to dumps" } }
            }
        };
        if self.htmx {
            (self.status, body).into_response()
        } else {
            (self.status, layout("ecd — Error", body)).into_response()
        }
    }
}

type AppResult<T = Response> = std::result::Result<T, AppError>;

#[derive(Clone, Serialize)]
struct DumpMeta {
    fingerprint: String,
    label: String,
    filename: String,
    size_bytes: u64,
    uploaded_at: Option<String>,
    parsed: bool,
}

#[derive(Serialize, Deserialize)]
struct MetaFile {
    filename: String,
    size_bytes: u64,
    uploaded_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Deserialize, Default)]
struct ProcsParams {
    sort_by: Option<String>,
    q: Option<String>,
}

#[derive(Deserialize, Default)]
struct ProcParams {
    truncate: Option<usize>,
}

#[derive(Deserialize, Default)]
struct ProcSectionParams {
    /// 0-based page number.
    #[serde(default)]
    page: usize,
    per_page: Option<usize>,
    truncate: Option<usize>,
}

#[derive(Deserialize, Default)]
struct SectionsParams {
    sort_by: Option<String>,
}

#[derive(Deserialize, Default)]
struct SectionQueryParams {
    key: Option<String>,
}

#[derive(Serialize)]
struct ProcessListResponse {
    fingerprint: String,
    sorted_by: String,
    total: usize,
    processes: Vec<ProcessListItem>,
}

#[derive(Serialize)]
struct ProcessListItem {
    pid: String,
    name: Option<String>,
    state: String,
    memory_bytes: u64,
    stack_heap_words: u64,
    stack_heap_bytes: u64,
    reductions: u64,
    message_queue_length: u64,
}

#[derive(Serialize)]
struct ProcessDetailsResponse {
    pid: String,
    name: Option<String>,
    state: String,
    spawned_as: Option<String>,
    spawned_by: Option<String>,
    memory_bytes: u64,
    stack_heap_words: u64,
    stack_heap_bytes: u64,
    old_heap_words: u64,
    heap_unused_words: u64,
    reductions: u64,
    message_queue_length: u64,
    links: Vec<String>,
    monitors: Vec<String>,
    stack: Vec<StackEntryJson>,
    dictionary: Vec<String>,
    messages: Vec<String>,
}

#[derive(Serialize)]
struct StackEntryJson {
    label: String,
    term: String,
}

#[derive(Serialize)]
struct JobStatusResponse {
    job_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Latest human-readable progress message, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    progress: Option<String>,
}

#[derive(Serialize)]
struct ProcStackResponse {
    pid: String,
    page: usize,
    per_page: usize,
    total: usize,
    items: Vec<StackEntryJson>,
}

#[derive(Serialize)]
struct ProcTermsResponse {
    pid: String,
    section: String,
    page: usize,
    per_page: usize,
    total: usize,
    items: Vec<String>,
}

#[derive(Serialize)]
struct MemoryResponse {
    fingerprint: String,
    entries: Vec<MemoryEntryJson>,
    total_bytes: u64,
}

#[derive(Serialize)]
struct MemoryEntryJson {
    key: String,
    bytes: u64,
}

#[derive(Serialize)]
struct EtsResponse {
    fingerprint: String,
    tables: Vec<EtsTableJson>,
}

#[derive(Serialize)]
struct EtsTableJson {
    owner_pid: String,
    name: String,
    #[serde(rename = "type")]
    type_name: String,
    protection: String,
    objects: u64,
    words: u64,
    memory_bytes: u64,
    flags: EtsFlagsJson,
}

#[derive(Serialize)]
struct EtsFlagsJson {
    write_concurrency: bool,
    read_concurrency: bool,
    compressed: bool,
    fixed: bool,
}

#[derive(Serialize)]
struct SectionsResponse {
    fingerprint: String,
    sorted_by: String,
    total: usize,
    sections: Vec<SectionItemJson>,
}

#[derive(Serialize)]
struct SectionItemJson {
    kind: String,
    key: Option<String>,
    size_bytes: u64,
}

#[derive(Serialize)]
struct UploadResponse {
    job_id: String,
}

#[derive(Serialize)]
struct OverviewJson {
    fingerprint: String,
    filename: String,
    size_bytes: u64,
    uploaded_at: Option<String>,
    parsed: bool,
    process_count: usize,
    memory: HashMap<String, u64>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ecd_server=debug,tower_http=info".parse().unwrap()),
        )
        .init();
    if let Err(err) = run().await {
        eprintln!("ecd-server: {err:#}");
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    let (bind, port) = parse_args()?;
    let cache_root = cache_root();
    std::fs::create_dir_all(&cache_root)
        .with_context(|| format!("creating cache root {}", cache_root.display()))?;

    let state = AppState {
        cache_root,
        jobs: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/dumps", get(list_dumps).post(upload_dump))
        .route("/jobs/{id}", get(job_status))
        .route("/jobs/{id}/stream", get(job_stream))
        .route("/dumps/{fp}", get(dump_overview).delete(delete_dump))
        .route("/dumps/{fp}/label", get(label_view).put(label_update))
        .route("/dumps/{fp}/label/edit", get(label_edit))
        .route("/dumps/{fp}/procs", get(processes))
        .route("/dumps/{fp}/procs/{pid}", get(process_detail))
        .route("/dumps/{fp}/procs/{pid}/stack", get(proc_stack_section))
        .route("/dumps/{fp}/procs/{pid}/dict", get(proc_dict_section))
        .route("/dumps/{fp}/procs/{pid}/messages", get(proc_messages_section))
        .route("/dumps/{fp}/mem", get(memory_view))
        .route("/dumps/{fp}/ets", get(ets_view))
        .route("/dumps/{fp}/sections", get(sections_view))
        .route("/dumps/{fp}/query/{kind}", get(query_section))
        .layer(DefaultBodyLimit::disable())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr: SocketAddr = format!("{bind}:{port}").parse()?;
    let url = format!("http://{addr}");
    let listener = TcpListener::bind(addr).await?;
    eprintln!("ecd-server listening on {url}");

    axum::serve(listener, app).await?;
    Ok(())
}

fn parse_args() -> Result<(String, u16)> {
    let mut bind = "127.0.0.1".to_string();
    let mut port = 8080u16;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                let value = args.get(i + 1).context("missing value for --bind")?;
                bind = value.clone();
                i += 1;
            }
            "--port" => {
                let value = args.get(i + 1).context("missing value for --port")?;
                port = value.parse().context("invalid --port value")?;
                i += 1;
            }
            "-h" | "--help" => {
                println!("ecd-server [--bind <addr>] [--port <port>]");
                process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
        i += 1;
    }
    Ok((bind, port))
}

async fn index(headers: HeaderMap, State(state): State<AppState>) -> AppResult<Response> {
    let dumps = list_parsed_dumps(&state.cache_root);
    let body = index_markup(&dumps);
    Ok(page_response(&headers, "ecd — Erlang Crash Dump Viewer", body))
}

async fn list_dumps(State(state): State<AppState>) -> Response {
    Json(list_parsed_dumps(&state.cache_root)).into_response()
}

async fn upload_dump(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> AppResult<Response> {
    // The job UUID doubles as the dump ID — no fingerprinting needed.
    let job_id = Uuid::new_v4().to_string();
    let outdir = state.cache_root.join(&job_id);
    tracing::info!(job_id, "upload started");

    // Register SSE job before spawning so clients can connect immediately.
    {
        let mut jobs = state.jobs.lock().await;
        jobs.insert(
            job_id.clone(),
            ParseJob {
                status: JobStatus::Running,
                events: Arc::new(Mutex::new(Vec::new())),
            },
        );
    }

    // Channel: async upload writer → blocking parse reader.
    let (tx, rx) = tokio::sync::mpsc::channel::<axum::body::Bytes>(64);

    // Progress relay: parse thread sends strings; this task forwards them as SSE events.
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let jobs_for_progress = state.jobs.clone();
    let job_id_for_progress = job_id.clone();
    tokio::spawn(async move {
        while let Some(msg) = progress_rx.recv().await {
            push_job_event(
                &job_id_for_progress,
                &jobs_for_progress,
                "progress",
                json!({ "message": msg }).to_string(),
            )
            .await;
        }
    });

    let outdir_for_parse = outdir.clone();
    let parse_handle = tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&outdir_for_parse)
            .with_context(|| format!("creating {}", outdir_for_parse.display()))?;
        parse_reader(
            ChannelReader::new(rx),
            &outdir_for_parse.join("addr"),
            &outdir_for_parse.join("text"),
            Config::default(),
            Some(Box::new(move |msg: &str| {
                let _ = progress_tx.send(msg.to_string());
            })),
        )
    });

    let mut found = false;
    let mut filename = "upload.dump".to_string();
    let mut size_bytes = 0u64;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(&headers, e.to_string()))?
    {
        tracing::debug!(name = field.name(), "multipart field");
        if field.name() != Some("dump") {
            continue;
        }
        found = true;
        filename = field
            .file_name()
            .map(ToString::to_string)
            .unwrap_or_else(|| "upload.dump".to_string());
        tracing::info!(job_id, filename, "receiving file");
        let mut field = field;
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| AppError::bad_request(&headers, e.to_string()))?
        {
            size_bytes += chunk.len() as u64;
            if tx.send(chunk).await.is_err() {
                tracing::warn!(job_id, "parse task died before upload finished");
                break; // parse task died; error surfaces below
            }
        }
        break;
    }
    drop(tx); // signal EOF to the parse task
    tracing::info!(job_id, size_bytes, "upload transfer done");

    if !found {
        let _ = tokio::fs::remove_dir_all(&outdir).await;
        return Err(AppError::bad_request(&headers, "multipart field 'dump' is required"));
    }

    // Return the job_id immediately so the browser can open the SSE stream and
    // see live progress while the sort/merge phase completes in the background.
    let jobs_bg = state.jobs.clone();
    let job_id_bg = job_id.clone();
    let filename_bg = filename.clone();
    tokio::spawn(async move {
        let uploaded_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        // "started" goes out now so the client immediately sees the filename.
        push_job_event(
            &job_id_bg,
            &jobs_bg,
            "started",
            json!({ "filename": filename_bg, "size_bytes": size_bytes }).to_string(),
        )
        .await;

        let parse_result = parse_handle
            .await
            .map_err(|e| anyhow::anyhow!("parse task join: {e}"))
            .and_then(|r| r);

        match parse_result {
            Ok(stats) => {
                tracing::info!(job_id = job_id_bg, %stats, "parse succeeded");
                let meta = MetaFile {
                    filename: filename_bg.clone(),
                    size_bytes,
                    uploaded_at,
                    label: None,
                };
                if let Err(e) = write_meta_file(outdir.clone(), meta).await {
                    tracing::error!(job_id = job_id_bg, error = %e, "write meta failed");
                }
                if let Err(e) = tokio::fs::write(outdir.join(".complete"), b"").await {
                    tracing::error!(job_id = job_id_bg, error = %e, "write .complete failed");
                }
                push_job_event(
                    &job_id_bg,
                    &jobs_bg,
                    "done",
                    json!({
                        "fingerprint": job_id_bg,
                        "redirect": format!("/dumps/{job_id_bg}"),
                        "stats": stats.to_string(),
                    })
                    .to_string(),
                )
                .await;
                set_job_status(&job_id_bg, &jobs_bg, JobStatus::Done { fingerprint: job_id_bg.clone() })
                    .await;
            }
            Err(err) => {
                tracing::error!(job_id = job_id_bg, error = %err, "parse failed");
                let _ = tokio::fs::remove_dir_all(&outdir).await;
                let msg = err.to_string();
                push_job_event(
                    &job_id_bg,
                    &jobs_bg,
                    "error",
                    json!({ "message": msg.clone() }).to_string(),
                )
                .await;
                set_job_status(&job_id_bg, &jobs_bg, JobStatus::Failed(msg)).await;
            }
        }
    });

    Ok(Json(UploadResponse { job_id }).into_response())
}

async fn job_status(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let guard = state.jobs.lock().await;
    let Some(job) = guard.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "job not found", "status": 404 })),
        )
            .into_response();
    };
    let progress = {
        let events = job.events.lock().await;
        events
            .iter()
            .rev()
            .find(|e| e.event == "progress" || e.event == "started")
            .map(|e| e.data.clone())
    };
    let resp = match &job.status {
        JobStatus::Running => JobStatusResponse {
            job_id: id,
            status: "running".into(),
            fingerprint: None,
            error: None,
            progress,
        },
        JobStatus::Done { fingerprint } => JobStatusResponse {
            job_id: id,
            status: "done".into(),
            fingerprint: Some(fingerprint.clone()),
            error: None,
            progress,
        },
        JobStatus::Failed(msg) => JobStatusResponse {
            job_id: id,
            status: "failed".into(),
            fingerprint: None,
            error: Some(msg.clone()),
            progress,
        },
    };
    Json(resp).into_response()
}

async fn job_stream(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> AppResult<Response> {
    if state.jobs.lock().await.get(&id).is_none() {
        return Err(AppError::not_found(&headers, "job not found"));
    }

    let jobs = state.jobs.clone();
    let id_clone = id.clone();
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut index = 0usize;
        loop {
            let snapshot = {
                let jobs_guard = jobs.lock().await;
                jobs_guard.get(&id_clone).cloned()
            };
            let Some(job) = snapshot else {
                break;
            };

            let pending = {
                let events = job.events.lock().await;
                let slice = events.get(index..).unwrap_or(&[]);
                let out = slice.to_vec();
                index = events.len();
                out
            };

            for ev in pending {
                if tx
                    .send(Event::default().event(ev.event).data(ev.data))
                    .await
                    .is_err()
                {
                    return;
                }
            }

            let finished = match &job.status {
                JobStatus::Running => false,
                JobStatus::Done { fingerprint } => {
                    let _ = fingerprint;
                    true
                }
                JobStatus::Failed(message) => {
                    let _ = message;
                    true
                }
            };
            if finished {
                break;
            }
            sleep(Duration::from_millis(250)).await;
        }
    });

    let stream = ReceiverStream::new(rx).map(Ok::<Event, Infallible>);
    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response())
}

async fn delete_dump(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
) -> AppResult<Response> {
    let dir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    if dir.exists() {
        let dir_for_delete = dir.clone();
        blocking(move || {
            std::fs::remove_dir_all(&dir_for_delete)
                .with_context(|| format!("deleting {}", dir_for_delete.display()))?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::internal(&headers, e))?;
    }
    Ok(StatusCode::OK.into_response())
}

fn label_display_markup(fp: &str, label: &str) -> Markup {
    html! {
        span id=(format!("label-{fp}")) style="display:flex;align-items:center;gap:0.4rem" {
            span { (label) }
            button
                style="background:none;border:none;cursor:pointer;color:var(--muted);padding:0 0.2rem;font-size:0.9rem"
                hx-get=(format!("/dumps/{fp}/label/edit"))
                hx-target=(format!("#label-{fp}"))
                hx-swap="outerHTML" { "✎" }
        }
    }
}

async fn label_view(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
) -> AppResult<Response> {
    let meta = read_dump_meta(&state.cache_root, &fp)
        .ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    Ok(label_display_markup(&fp, &meta.label).into_response())
}

async fn label_edit(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
) -> AppResult<Response> {
    let meta = read_dump_meta(&state.cache_root, &fp)
        .ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    let body = html! {
        span id=(format!("label-{fp}")) style="display:flex;align-items:center;gap:0.4rem" {
            form style="display:contents"
                hx-put=(format!("/dumps/{fp}/label"))
                hx-target=(format!("#label-{fp}"))
                hx-swap="outerHTML" {
                input type="text" name="label" value=(meta.label)
                    style="width:180px"
                    autofocus;
                button type="submit" { "Save" }
                button type="button"
                    hx-get=(format!("/dumps/{fp}/label"))
                    hx-target=(format!("#label-{fp}"))
                    hx-swap="outerHTML" { "Cancel" }
            }
        }
    };
    Ok(body.into_response())
}

#[derive(Deserialize)]
struct LabelForm {
    label: String,
}

async fn label_update(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
    axum::Form(form): axum::Form<LabelForm>,
) -> AppResult<Response> {
    let dir = dump_dir(&state.cache_root, &fp)
        .ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    if !dir.join(".complete").exists() {
        return Err(AppError::not_found(&headers, "dump not found"));
    }

    let label = form.label.trim().to_string();
    let label_for_write = label.clone();
    let fp_for_closure = fp.clone();

    // Read existing meta, update label, write back
    blocking(move || {
        let meta_path = dir.join("meta.json");
        let mut meta: serde_json::Value = if meta_path.exists() {
            let bytes = std::fs::read(&meta_path)?;
            serde_json::from_slice(&bytes)?
        } else {
            serde_json::json!({ "filename": fp_for_closure, "size_bytes": 0, "uploaded_at": "" })
        };
        meta["label"] = serde_json::Value::String(label_for_write);
        std::fs::write(&meta_path, serde_json::to_vec_pretty(&meta)?)?;
        Ok(())
    })
    .await
    .map_err(|e: anyhow::Error| AppError::internal(&headers, e))?;

    Ok(label_display_markup(&fp, &label).into_response())
}


async fn dump_overview(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
) -> AppResult<Response> {
    let meta = read_dump_meta(&state.cache_root, &fp)
        .ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;

    let (memory, mut procs, incomplete) = blocking(move || {
        let dr = DumpReader::open(&outdir)?;
        Ok((dr.memory()?, dr.processes()?, dr.is_incomplete()?))
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?;
    procs.sort_by(|a, b| b.memory.cmp(&a.memory).then_with(|| a.pid.cmp(&b.pid)));

    if wants_json(&headers) {
        let memory_map = memory.entries.iter().cloned().collect::<HashMap<_, _>>();
        return Ok(Json(OverviewJson {
            fingerprint: meta.fingerprint,
            filename: meta.filename,
            size_bytes: meta.size_bytes,
            uploaded_at: meta.uploaded_at,
            parsed: meta.parsed,
            process_count: procs.len(),
            memory: memory_map,
        })
        .into_response());
    }

    let total = memory.entries.iter().find(|(k, _)| k == "total").map(|(_, v)| *v).unwrap_or(0);
    let processes_bytes = memory.entries.iter().find(|(k, _)| k == "processes").map(|(_, v)| *v).unwrap_or(0);
    let code_bytes = memory.entries.iter().find(|(k, _)| k == "code").map(|(_, v)| *v).unwrap_or(0);
    let ets_bytes = memory.entries.iter().find(|(k, _)| k == "ets").map(|(_, v)| *v).unwrap_or(0);
    let body = overview_markup(&meta, &fp, total, processes_bytes, code_bytes, ets_bytes, &procs, incomplete);
    Ok(page_response(&headers, &format!("Dump {fp}"), body))
}

async fn processes(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
    Query(params): Query<ProcsParams>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;

    let mut procs = blocking(move || {
        let dr = DumpReader::open(&outdir)?;
        dr.processes()
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?;

    let filter = params.q.clone().unwrap_or_default();
    if !filter.is_empty() {
        let needle = filter.to_lowercase();
        procs.retain(|ps| {
            ps.pid.to_lowercase().contains(&needle)
                || ps.name.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                || ps.spawned_as.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                || ps.state.to_lowercase().contains(&needle)
        });
    }

    let sorted_by = match params.sort_by.as_deref() {
        Some("pid") => {
            procs.sort_by(|a, b| a.pid.cmp(&b.pid));
            "pid_asc"
        }
        _ => {
            procs.sort_by(|a, b| b.memory.cmp(&a.memory).then_with(|| a.pid.cmp(&b.pid)));
            "memory_bytes_desc"
        }
    }
    .to_string();

    if wants_json(&headers) {
        let items = procs
            .iter()
            .map(|ps| ProcessListItem {
                pid: ps.pid.clone(),
                name: ps.name.clone().or_else(|| ps.spawned_as.clone()),
                state: ps.state.clone(),
                memory_bytes: ps.memory,
                stack_heap_words: ps.stack_heap,
                stack_heap_bytes: ps.stack_heap.saturating_mul(8),
                reductions: ps.reductions,
                message_queue_length: ps.mqueue_len,
            })
            .collect();
        return Ok(Json(ProcessListResponse {
            fingerprint: fp,
            sorted_by,
            total: procs.len(),
            processes: items,
        })
        .into_response());
    }

    let body = processes_markup(&fp, &filter, &sorted_by, &procs, !is_htmx(&headers));
    Ok(page_response(&headers, &format!("Processes {fp}"), body))
}

async fn process_detail(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath((fp, pid)): AxumPath<(String, String)>,
    Query(params): Query<ProcParams>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;
    let truncate = params.truncate;
    let pid_for_query = pid.clone();

    if wants_json(&headers) {
        // JSON consumers get all sections at once (no pagination).
        let details = blocking(move || {
            let dr = DumpReader::open(&outdir)?;
            dr.process(&pid_for_query)
        })
        .await
        .map_err(|e| AppError::internal(&headers, e))?
        .ok_or_else(|| AppError::not_found(&headers, format!("process {pid} not found")))?;
        return Ok(Json(ProcessDetailsResponse {
            pid: details.summary.pid.clone(),
            name: details.summary.name.clone(),
            state: details.summary.state.clone(),
            spawned_as: details.summary.spawned_as.clone(),
            spawned_by: details.summary.spawned_by.clone(),
            memory_bytes: details.summary.memory,
            stack_heap_words: details.summary.stack_heap,
            stack_heap_bytes: details.summary.stack_heap.saturating_mul(8),
            old_heap_words: details.summary.old_heap,
            heap_unused_words: details.summary.heap_unused,
            reductions: details.summary.reductions,
            message_queue_length: details.summary.mqueue_len,
            links: details.summary.links.clone(),
            monitors: details.summary.monitors.clone(),
            stack: details
                .stack
                .iter()
                .map(|entry| StackEntryJson {
                    label: entry.label.clone(),
                    term: entry
                        .term
                        .as_ref()
                        .map(|term| render_term_str(term, truncate))
                        .unwrap_or_else(|| truncate_str(&entry.raw, truncate.unwrap_or(usize::MAX))),
                })
                .collect(),
            dictionary: details
                .dictionary
                .iter()
                .map(|term| render_term_str(term, truncate))
                .collect(),
            messages: details
                .messages
                .iter()
                .map(|term| render_term_str(term, truncate))
                .collect(),
        })
        .into_response());
    }

    // HTML path: load only the summary; sections are lazily fetched by the browser.
    let summary = blocking(move || {
        let dr = DumpReader::open(&outdir)?;
        dr.process_summary(&pid_for_query)
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?
    .ok_or_else(|| AppError::not_found(&headers, format!("process {pid} not found")))?;

    let htmx = is_htmx(&headers);
    let body = process_summary_markup(&fp, &summary, truncate, !htmx);
    if htmx {
        Ok(body.into_response())
    } else {
        Ok(page_response(&headers, &format!("Process {}", summary.pid), body))
    }
}

const PROC_SECTION_DEFAULT_PER_PAGE: usize = 200;

async fn proc_stack_section(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath((fp, pid)): AxumPath<(String, String)>,
    Query(params): Query<ProcSectionParams>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;
    let per_page = params.per_page.unwrap_or(PROC_SECTION_DEFAULT_PER_PAGE);
    let offset = params.page * per_page;
    let truncate = params.truncate;
    let pid2 = pid.clone();
    let page = blocking(move || {
        let dr = DumpReader::open(&outdir)?;
        dr.process_stack_page(&pid2, offset, per_page)
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?;
    if wants_json(&headers) {
        return Ok(Json(ProcStackResponse {
            pid,
            page: params.page,
            per_page,
            total: page.total,
            items: page
                .items
                .iter()
                .map(|entry| StackEntryJson {
                    label: entry.label.clone(),
                    term: entry
                        .term
                        .as_ref()
                        .map(|t| render_term_str(t, truncate))
                        .unwrap_or_else(|| truncate_str(&entry.raw, truncate.unwrap_or(usize::MAX))),
                })
                .collect(),
        })
        .into_response());
    }
    Ok(proc_stack_markup(&fp, &pid, &page, truncate, params.page, per_page).into_response())
}

async fn proc_dict_section(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath((fp, pid)): AxumPath<(String, String)>,
    Query(params): Query<ProcSectionParams>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;
    let per_page = params.per_page.unwrap_or(PROC_SECTION_DEFAULT_PER_PAGE);
    let offset = params.page * per_page;
    let truncate = params.truncate;
    let pid2 = pid.clone();
    let page = blocking(move || {
        let dr = DumpReader::open(&outdir)?;
        dr.process_dict_page(&pid2, offset, per_page)
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?;
    if wants_json(&headers) {
        return Ok(Json(ProcTermsResponse {
            pid,
            section: "dict".into(),
            page: params.page,
            per_page,
            total: page.total,
            items: page.items.iter().map(|t| render_term_str(t, truncate)).collect(),
        })
        .into_response());
    }
    Ok(proc_term_section_markup(&fp, &pid, "dict", "Dictionary", &page, truncate, params.page, per_page).into_response())
}

async fn proc_messages_section(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath((fp, pid)): AxumPath<(String, String)>,
    Query(params): Query<ProcSectionParams>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;
    let per_page = params.per_page.unwrap_or(PROC_SECTION_DEFAULT_PER_PAGE);
    let offset = params.page * per_page;
    let truncate = params.truncate;
    let pid2 = pid.clone();
    let page = blocking(move || {
        let dr = DumpReader::open(&outdir)?;
        dr.process_messages_page(&pid2, offset, per_page)
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?;
    if wants_json(&headers) {
        return Ok(Json(ProcTermsResponse {
            pid,
            section: "messages".into(),
            page: params.page,
            per_page,
            total: page.total,
            items: page.items.iter().map(|t| render_term_str(t, truncate)).collect(),
        })
        .into_response());
    }
    Ok(proc_term_section_markup(&fp, &pid, "messages", "Messages", &page, truncate, params.page, per_page).into_response())
}

async fn memory_view(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;
    let memory = blocking(move || {
        let dr = DumpReader::open(&outdir)?;
        dr.memory()
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?;

    let total_bytes = memory.entries.iter().find(|(k, _)| k == "total").map(|(_, v)| *v).unwrap_or(0);
    if wants_json(&headers) {
        return Ok(Json(MemoryResponse {
            fingerprint: fp,
            entries: memory
                .entries
                .into_iter()
                .map(|(key, bytes)| MemoryEntryJson { key, bytes })
                .collect(),
            total_bytes,
        })
        .into_response());
    }

    let body = memory_markup(&fp, &memory.entries, total_bytes);
    Ok(page_response(&headers, &format!("Memory {fp}"), body))
}

async fn ets_view(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;
    let mut tables = blocking(move || {
        let dr = DumpReader::open(&outdir)?;
        dr.ets_tables()
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?;
    tables.sort_by(|a, b| b.words.cmp(&a.words).then_with(|| a.name.cmp(&b.name)));

    if wants_json(&headers) {
        return Ok(Json(EtsResponse {
            fingerprint: fp,
            tables: tables
                .iter()
                .map(|table| EtsTableJson {
                    owner_pid: table.owner_pid.clone(),
                    name: table.name.clone(),
                    type_name: table.table_type.clone(),
                    protection: table.protection.clone(),
                    objects: table.objects,
                    words: table.words,
                    memory_bytes: table.words.saturating_mul(8),
                    flags: EtsFlagsJson {
                        write_concurrency: table.write_concurrency,
                        read_concurrency: table.read_concurrency,
                        compressed: table.compressed,
                        fixed: table.fixed,
                    },
                })
                .collect(),
        })
        .into_response());
    }

    let body = ets_markup(&fp, &tables);
    Ok(page_response(&headers, &format!("ETS {fp}"), body))
}

async fn sections_view(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(fp): AxumPath<String>,
    Query(params): Query<SectionsParams>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;
    let mut sections = blocking(move || {
        let tr = TextReader::open(outdir.join("text"))?;
        Ok::<_, anyhow::Error>(tr.list_all())
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?;

    let sorted_by = match params.sort_by.as_deref() {
        Some("kind") => {
            sections.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
            "kind_asc"
        }
        Some("key") => {
            sections.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            "key_asc"
        }
        _ => {
            sections.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
            "size_bytes_desc"
        }
    }
    .to_string();

    if wants_json(&headers) {
        return Ok(Json(SectionsResponse {
            fingerprint: fp,
            sorted_by,
            total: sections.len(),
            sections: sections
                .iter()
                .map(|(kind, key, size_bytes)| SectionItemJson {
                    kind: kind.clone(),
                    key: key.clone(),
                    size_bytes: *size_bytes,
                })
                .collect(),
        })
        .into_response());
    }

    let body = sections_markup(&fp, &sorted_by, &sections);
    Ok(page_response(&headers, &format!("Sections {fp}"), body))
}

async fn query_section(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath((fp, kind)): AxumPath<(String, String)>,
    Query(params): Query<SectionQueryParams>,
) -> AppResult<Response> {
    let outdir = dump_dir(&state.cache_root, &fp).ok_or_else(|| AppError::not_found(&headers, "dump not found"))?;
    ensure_complete(&headers, &outdir)?;
    let key = params.key.clone();
    let text = blocking(move || {
        let tr = TextReader::open(outdir.join("text"))?;
        tr.get(&kind, key.as_deref())
    })
    .await
    .map_err(|e| AppError::internal(&headers, e))?
    .ok_or_else(|| AppError::not_found(&headers, "section not found"))?;

    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response())
}

async fn push_job_event(job_id: &str, jobs: &Arc<Mutex<HashMap<String, ParseJob>>>, event: &str, data: String) {
    let job = {
        let guard = jobs.lock().await;
        guard.get(job_id).cloned()
    };
    if let Some(job) = job {
        let mut events = job.events.lock().await;
        events.push(SseEvent {
            event: event.to_string(),
            data,
        });
    }
}

async fn set_job_status(job_id: &str, jobs: &Arc<Mutex<HashMap<String, ParseJob>>>, status: JobStatus) {
    let mut guard = jobs.lock().await;
    if let Some(job) = guard.get_mut(job_id) {
        job.status = status;
    }
}

fn page_response(headers: &HeaderMap, title: &str, body: Markup) -> Response {
    if is_htmx(headers) {
        body.into_response()
    } else {
        layout(title, body).into_response()
    }
}

fn layout(title: &str, content: Markup) -> Markup {
    let css = r#"
:root {
  color-scheme: dark light;
  --bg: #111315;
  --panel: #171a1d;
  --panel-2: #1e2328;
  --text: #e7eaee;
  --muted: #a5adb8;
  --line: #30363d;
  --accent: #7cc4ff;
  --danger: #ff7b72;
  --good: #3fb950;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  background: var(--bg);
  color: var(--text);
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
main { max-width: 1400px; margin: 0 auto; padding: 1.5rem; }
nav {
  border-bottom: 1px solid var(--line);
  background: rgba(17,19,21,0.95);
  position: sticky;
  top: 0;
  backdrop-filter: blur(6px);
}
nav .inner { max-width: 1400px; margin: 0 auto; padding: 1rem 1.5rem; }
h1, h2, h3 { margin: 0 0 0.8rem; }
p { color: var(--muted); }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 0.65rem 0.75rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { text-align: left; color: var(--muted); font-weight: 600; }
tr.clickable { cursor: pointer; }
tr.clickable:hover td { background: rgba(124,196,255,0.08); }
.panel, .card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 1rem;
}
.grid { display: grid; gap: 1rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.75rem; }
.card .label { color: var(--muted); font-size: 0.85rem; margin-bottom: 0.4rem; }
.card .value { font-size: 1.3rem; font-weight: 700; }
.controls { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: center; margin-bottom: 1rem; }
.controls a, .button, button {
  display: inline-block;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 0.45rem 0.7rem;
  background: var(--panel-2);
  color: var(--text);
}
.controls a.active { border-color: var(--accent); color: var(--accent); }
input[type="search"], input[type="file"] {
  width: 100%;
  max-width: 420px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #0f1113;
  color: var(--text);
  padding: 0.55rem 0.7rem;
}
button, .button { cursor: pointer; }
button.danger { border-color: rgba(255,123,114,0.35); color: var(--danger); }
dialog.confirm-modal { background: var(--panel); color: var(--text); border: 1px solid var(--line); border-radius: 10px; padding: 1.5rem; min-width: 320px; max-width: 420px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); }
dialog.confirm-modal::backdrop { background: rgba(0,0,0,0.55); backdrop-filter: blur(2px); }
dialog.confirm-modal h3 { margin: 0 0 0.6rem; font-size: 1rem; }
dialog.confirm-modal p { color: var(--muted); margin: 0 0 1.2rem; font-size: 0.9rem; }
dialog.confirm-modal .modal-actions { display: flex; gap: 0.6rem; justify-content: flex-end; }
small, .muted { color: var(--muted); }
.kv { display: grid; grid-template-columns: 180px 1fr; gap: 0.45rem 0.8rem; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; }
.sidebar-layout { display: grid; grid-template-columns: minmax(0, 2.2fr) minmax(320px, 1fr); gap: 1rem; align-items: start; }
.badge { display: inline-block; padding: 0.1rem 0.45rem; border-radius: 999px; border: 1px solid var(--line); color: var(--muted); }
.banner { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; border-left: 4px solid; }
.banner-warn { background: rgba(210,153,34,0.12); border-color: #d29922; color: #e3b341; }
.highlight td { background: rgba(63,185,80,0.08); }
pre.raw { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; }
.details-list { margin: 0; padding-left: 1.25rem; }
.pager { display: flex; align-items: center; gap: 0.75rem; margin: 0.5rem 0; font-size: 0.9rem; }
.pager button { padding: 0.2rem 0.6rem; cursor: pointer; }
pre.erl-term { white-space: pre; margin: 0; padding: 0; line-height: 1.4; font-family: inherit; font-size: inherit; overflow-x: auto; }
pre.erl-term.folded { height: 1.4em; overflow: hidden; }
.fold-btn { display: inline; border: none; background: none; color: var(--accent); cursor: pointer; padding: 0 0.3rem 0 0; font-family: inherit; font-size: 0.85em; }
.fold-controls { display: flex; gap: 0.5rem; margin: 0.4rem 0 0.8rem; }
.sec-group { margin-bottom: 0.5rem; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
.sec-group summary { display: flex; gap: 0.75rem; align-items: baseline; padding: 0.55rem 0.75rem; cursor: pointer; background: var(--panel-2); user-select: none; list-style: none; }
.sec-group summary::-webkit-details-marker { display: none; }
.sec-group summary::before { content: '▶'; font-size: 0.7em; color: var(--muted); transition: transform 0.15s; flex-shrink: 0; }
.sec-group[open] summary::before { transform: rotate(90deg); }
.sec-group summary .sec-kind { font-weight: 600; }
.sec-group summary .sec-meta { color: var(--muted); font-size: 0.85em; }
.sec-group .table-wrap { padding: 0; }
.sec-group table th, .sec-group table td { padding: 0.5rem 0.75rem; }
@media (max-width: 980px) {
  .sidebar-layout { grid-template-columns: 1fr; }
}
"#;

    let term_js = r#"
(function() {
'use strict';

// ─── Erlang keywords ─────────────────────────────────────────────────────────
const KW = new Set(['after','and','andalso','band','begin','bnot','bor','bsl',
  'bsr','bxor','case','catch','cond','div','else','end','fun','if','let',
  'maybe','not','of','or','orelse','query','receive','rem','try','when','xor']);

const FOLD_THRESHOLD = 3;

// ─── String helpers ───────────────────────────────────────────────────────────
function escStr(s) {
  return s.replace(/\\/g,'\\\\').replace(/"/g,'\\"')
    .replace(/\x08/g,'\\b').replace(/\t/g,'\\t').replace(/\n/g,'\\n')
    .replace(/\x0b/g,'\\v').replace(/\x0c/g,'\\f').replace(/\r/g,'\\r')
    .replace(/\x1b/g,'\\e');
}

function fmtFloat(f) {
  if (!isFinite(f)) return isNaN(f) ? 'nan' : (f > 0 ? 'inf' : '-inf');
  const s = String(f);
  return (s.includes('.') || s.includes('e')) ? s : s + '.0';
}

function writeAtom(name) {
  if (name.length > 0 && /^[a-z][a-zA-Z0-9_@]*$/.test(name) && !KW.has(name)) return name;
  return "'" + name.replace(/\\/g,'\\\\').replace(/'/g,"\\'")
    .replace(/\n/g,'\\n').replace(/\t/g,'\\t').replace(/\r/g,'\\r') + "'";
}

function hexBytes(hex) {
  const a = [];
  for (let i = 0; i < hex.length; i += 2) a.push(parseInt(hex.slice(i,i+2), 16));
  return a.join(',');
}

// ─── Flat printer ─────────────────────────────────────────────────────────────
function flatTerm(n) {
  switch (n.t) {
    case 'nil':     return '[]';
    case 'int':     return String(n.v);
    case 'bigint':  return String(n.v);
    case 'float':   return typeof n.v === 'number' ? fmtFloat(n.v) : String(n.v);
    case 'atom':    return writeAtom(n.v);
    case 'pid':     return '<' + n.v + '>';
    case 'port':    return '#Port<' + n.v + '>';
    case 'str':     return '"' + escStr(n.v) + '"';
    case 'bin':     return n.str != null ? '<<"' + escStr(n.str) + '">>' : '<<' + hexBytes(n.hex) + '>>';
    case 'info':    return n.v;
    case 'etf':     return '#ETF<<' + hexBytes(n.hex) + '>>';
    case 'missing': return '#NotInDump<' + n.v + '>';
    case 'list': {
      const parts = n.elems.map(flatTerm);
      return '[' + parts.join(',') + (n.tail ? '|' + flatTerm(n.tail) : '') + ']';
    }
    case 'tuple':   return '{' + n.elems.map(flatTerm).join(',') + '}';
    case 'map':     return '#{' + n.pairs.map(p => flatTerm(p.k) + ' => ' + flatTerm(p.v)).join(',') + '}';
    default:        return '?';
  }
}

// ─── Pretty printer (~p style) ────────────────────────────────────────────────
// Elements are aligned to the column immediately after the opening bracket,
// matching Erlang's io_lib_pretty behaviour.
function prettyTerm(n, col, width) {
  const flat = flatTerm(n);
  if (col + flat.length <= width) return flat;
  switch (n.t) {
    case 'tuple': return n.elems.length ? prettySeq(n.elems, col, width, '{', '}', null) : '{}';
    case 'list':  return n.elems.length ? prettySeq(n.elems, col, width, '[', ']', n.tail) : flat;
    case 'map':   return n.pairs.length ? prettyMap(n.pairs, col, width) : '#{}';
    default:      return flat;
  }
}

function prettySeq(elems, col, width, open, close, tail) {
  const ic = col + open.length;
  const pad = '\n' + ' '.repeat(ic);
  const parts = elems.map((e, i) => (i ? pad : '') + prettyTerm(e, ic, width));
  const tailStr = (tail && tail.t !== 'nil') ? '|' + flatTerm(tail) : '';
  return open + parts.join(',') + tailStr + close;
}

function prettyMap(pairs, col, width) {
  const ic = col + 2;
  const pad = '\n' + ' '.repeat(ic);
  const parts = pairs.map((p, i) => {
    const k = flatTerm(p.k);
    const v = prettyTerm(p.v, ic + k.length + 4, width); // ' => ' = 4
    return (i ? pad : '') + k + ' => ' + v;
  });
  return '#{' + parts.join(',') + '}';
}

// ─── Width measurement ────────────────────────────────────────────────────────
let _charW = 0;
function charWidth() {
  if (_charW > 0) return _charW;
  const s = document.createElement('span');
  s.style.cssText = 'position:fixed;top:-9999px;left:0;white-space:pre;font-family:inherit;font-size:inherit;';
  s.textContent = 'x'.repeat(80);
  document.body.appendChild(s);
  _charW = s.offsetWidth / 80;
  document.body.removeChild(s);
  return _charW > 0 ? _charW : 8;
}

function termCols(panel) {
  const cs = window.getComputedStyle(panel);
  const avail = panel.clientWidth
    - (parseFloat(cs.paddingLeft) || 0)
    - (parseFloat(cs.paddingRight) || 0);
  return Math.max(40, Math.floor(avail / charWidth()));
}

// ─── Render & fold ────────────────────────────────────────────────────────────
function renderAllTerms(root) {
  const pres = root.querySelectorAll('pre.erl-term[data-term]');
  if (!pres.length) return;
  pres.forEach(pre => {
    try {
      const node = JSON.parse(pre.getAttribute('data-term'));
      const panel = pre.closest('.panel') || root;
      const rendered = prettyTerm(node, 0, termCols(panel));
      pre.textContent = rendered;
      pre.dataset.lines = rendered.split('\n').length;
    } catch(_) {}
  });
  setupFolds(root);
}

function setupFolds(root) {
  root.querySelectorAll('pre.erl-term').forEach(pre => {
    if (parseInt(pre.dataset.lines || '1', 10) <= FOLD_THRESHOLD) return;
    if (pre.previousElementSibling && pre.previousElementSibling.classList.contains('fold-btn')) return;
    const btn = document.createElement('button');
    btn.className = 'fold-btn';
    btn.textContent = '[-]';
    btn.addEventListener('click', () => {
      const folded = pre.classList.toggle('folded');
      btn.textContent = folded ? '[+]' : '[-]';
    });
    pre.parentElement.insertBefore(btn, pre);
  });
}

// ─── Global controls ──────────────────────────────────────────────────────────
document.addEventListener('click', ev => {
  if (ev.target.id === 'collapse-all') {
    document.querySelectorAll('pre.erl-term').forEach(p => p.classList.add('folded'));
    document.querySelectorAll('.fold-btn').forEach(b => b.textContent = '[+]');
  } else if (ev.target.id === 'expand-all') {
    document.querySelectorAll('pre.erl-term').forEach(p => p.classList.remove('folded'));
    document.querySelectorAll('.fold-btn').forEach(b => b.textContent = '[-]');
  }
});

// ─── HTMX hook ────────────────────────────────────────────────────────────────
// For outerHTML swaps the target is detached after the swap, so
// ev.detail.target is no longer in the DOM. Fall back to document.body so
// we search the newly-inserted replacement element instead.
document.addEventListener('htmx:afterSwap', ev => {
  const t = ev.detail && ev.detail.target;
  renderAllTerms((t && document.contains(t)) ? t : document.body);
});

// ─── Resize ───────────────────────────────────────────────────────────────────
let _resizeTimer;
window.addEventListener('resize', () => {
  _charW = 0;
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(() => renderAllTerms(document.body), 150);
});

// ─── Delete confirmation modal ────────────────────────────────────────────────
(function() {
  const modal  = document.getElementById('confirm-modal');
  const msgEl  = document.getElementById('confirm-modal-msg');
  const yesBtn = document.getElementById('confirm-modal-yes');
  const noBtn  = document.getElementById('confirm-modal-cancel');
  let _url = null, _row = null;

  document.addEventListener('click', ev => {
    const btn = ev.target.closest('[data-confirm-delete]');
    if (!btn) return;
    ev.preventDefault();
    _url = btn.dataset.confirmDelete;
    _row = btn.closest('tr');
    msgEl.textContent = 'Delete "' + (btn.dataset.confirmLabel || _url) + '"? This cannot be undone.';
    modal.showModal();
  });

  yesBtn.addEventListener('click', () => {
    modal.close();
    if (_url && _row) htmx.ajax('DELETE', _url, { target: _row, swap: 'outerHTML' });
    _url = null; _row = null;
  });

  noBtn.addEventListener('click', () => { modal.close(); _url = null; _row = null; });

  // Close on backdrop click
  modal.addEventListener('click', ev => { if (ev.target === modal) modal.close(); });
})();

// ─── Initial render ───────────────────────────────────────────────────────────
renderAllTerms(document.body);
})();
"#;

    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                script src="https://unpkg.com/htmx.org@2.0.4" {}
                style { (PreEscaped(css)) }
            }
            body {
                nav {
                    div class="inner" {
                        a href="/" { strong { "ecd" } " — Erlang Crash Dump Viewer" }
                    }
                }
                main { (content) }
                dialog class="confirm-modal" id="confirm-modal" {
                    h3 { "Confirm deletion" }
                    p id="confirm-modal-msg" {}
                    div class="modal-actions" {
                        button id="confirm-modal-cancel" { "Cancel" }
                        button class="danger" id="confirm-modal-yes" { "Delete" }
                    }
                }
                script { (PreEscaped(term_js)) }
            }
        }
    }
}

fn index_markup(dumps: &[DumpMeta]) -> Markup {
    let script = r#"
const form = document.getElementById('upload-form');
const progress = document.getElementById('progress');

function fmtBytesJs(n) {
  if (n >= 1073741824) return (n/1073741824).toFixed(1) + ' GB';
  if (n >= 1048576)    return (n/1048576).toFixed(1) + ' MB';
  if (n >= 1024)       return (n/1024).toFixed(1) + ' KB';
  return n + ' B';
}

if (form && !form.dataset.uploadBound) {
  form.dataset.uploadBound = '1';
  let uploading = false;
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    event.stopPropagation(); // stop HTMX ancestors from also processing this
    if (uploading) return;
    uploading = true;
    const submitBtn = form.querySelector('[type=submit]');
    if (submitBtn) submitBtn.disabled = true;
    const done = () => {
      uploading = false;
      if (submitBtn) submitBtn.disabled = false;
    };

    progress.hidden = false;
    progress.innerHTML = '';

    const label = document.createElement('div');
    label.textContent = 'Uploading…';
    progress.appendChild(label);

    const bar = document.createElement('progress');
    bar.max = 100; bar.value = 0;
    bar.style.cssText = 'width:100%;margin:.5rem 0;';
    progress.appendChild(bar);

    const append = (cls, text) => {
      const row = document.createElement('div');
      row.className = cls;
      row.innerHTML = `<strong>${cls}</strong> ${text}`;
      progress.appendChild(row);
    };

    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/dumps');

    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) {
        const pct = Math.round(e.loaded / e.total * 100);
        bar.value = pct;
        label.textContent = `Uploading… ${pct}% (${fmtBytesJs(e.loaded)} / ${fmtBytesJs(e.total)})`;
      }
    });

    xhr.upload.addEventListener('load', () => {
      bar.value = 100;
      label.textContent = 'Transfer complete — parsing…';
    });

    xhr.addEventListener('load', () => {
      let data;
      try { data = JSON.parse(xhr.responseText); }
      catch { done(); append('error', 'invalid server response'); return; }
      if (xhr.status >= 400) {
        done(); append('error', data.error || 'upload failed');
        return;
      }
      bar.style.display = 'none';
      const es = new EventSource(`/jobs/${data.job_id}/stream`);
      es.addEventListener('started', (ev) => {
        const msg = JSON.parse(ev.data);
        label.textContent = `Parsing ${msg.filename} (${fmtBytesJs(msg.size_bytes)})…`;
      });
      es.addEventListener('progress', (ev) => {
        const msg = JSON.parse(ev.data);
        label.textContent = msg.message;
      });
      es.addEventListener('done', (ev) => {
        const msg = JSON.parse(ev.data);
        label.textContent = msg.stats || 'Done.';
        es.close();
        window.location = msg.redirect;
      });
      es.addEventListener('error', (ev) => {
        if (ev.data) {
          const msg = JSON.parse(ev.data);
          append('error', msg.message || 'error');
          es.close();
          done();
        }
      });
      es.onerror = () => { append('error', 'connection lost'); done(); };
    });

    xhr.addEventListener('error', () => {
      done();
      append('error', 'network error');
    });

    xhr.send(new FormData(form));
  });
}
"#;

    html! {
        div class="grid" {
            section class="panel" {
                h1 { "Parsed Dumps" }
                div class="table-wrap" {
                    table {
                        thead {
                            tr {
                                th { "Fingerprint" }
                                th { "Label" }
                                th { "Filename" }
                                th { "Size" }
                                th { "Uploaded" }
                                th { "Actions" }
                            }
                        }
                        tbody {
                            @if dumps.is_empty() {
                                tr {
                                    td colspan="6" class="muted" { "No parsed dumps yet." }
                                }
                            } @else {
                                @for dump in dumps {
                                    tr {
                                        td {
                                            a href=(format!("/dumps/{}", dump.fingerprint)) { (dump.fingerprint) }
                                        }
                                        td { (label_display_markup(&dump.fingerprint, &dump.label)) }
                                        td { (dump.filename) }
                                        td { (fmt_bytes(dump.size_bytes)) " " span class="muted" { "(" (dump.size_bytes) " bytes)" } }
                                        td { (dump.uploaded_at.as_deref().unwrap_or("-")) }
                                        td {
                                            button class="danger"
                                                data-confirm-delete=(format!("/dumps/{}", dump.fingerprint))
                                                data-confirm-label=(dump.label) {
                                                "Delete"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            section class="panel" {
                h2 { "Upload Dump" }
                form id="upload-form" enctype="multipart/form-data" {
                    p { "Choose an Erlang crash dump. The server fingerprints the content, stores metadata, and parses it in the background." }
                    input type="file" name="dump" required;
                    p { button type="submit" { "Upload + Parse" } }
                }
                div id="progress" class="panel" hidden style="margin-top:1rem;" {}
            }
        }
        script { (PreEscaped(script)) }
    }
}

fn overview_markup(
    meta: &DumpMeta,
    fp: &str,
    total: u64,
    processes_bytes: u64,
    code_bytes: u64,
    ets_bytes: u64,
    procs: &[erl_crashdump::model::ProcessSummary],
    incomplete: bool,
) -> Markup {
    html! {
        @if incomplete {
            div class="banner banner-warn" {
                "⚠ This dump is incomplete (no " code { "=end" } " marker). "
                "The file was likely truncated mid-write. "
                "Some heap/binary data may be missing — references to absent addresses are shown as "
                code { "(dump_truncated)" } "."
            }
        }
        div class="grid" {
            section class="panel" {
                h1 { "Dump: " (meta.label) " (" (fmt_bytes(meta.size_bytes)) ")" }
                p class="muted" {
                    "Fingerprint: " code { (fp) } " · Filename: " (meta.filename) " · Uploaded: " (meta.uploaded_at.as_deref().unwrap_or("unknown"))
                }
                div class="cards" {
                    (summary_card("Total", total))
                    (summary_card("Processes", processes_bytes))
                    (summary_card("Code", code_bytes))
                    (summary_card("ETS", ets_bytes))
                }
            }
            section class="panel" {
                div class="controls" {
                    a href=(format!("/dumps/{fp}/procs")) { "Processes" }
                    a href=(format!("/dumps/{fp}/mem")) { "Memory" }
                    a href=(format!("/dumps/{fp}/ets")) { "ETS" }
                    a href=(format!("/dumps/{fp}/sections")) { "Sections" }
                }
            }
            section class="panel" {
                h2 { "Top processes by memory" }
                div class="table-wrap" {
                    table {
                        thead {
                            tr {
                                th { "PID" }
                                th { "Name" }
                                th { "Memory" }
                                th { "STK+HEAP" }
                                th { "Reductions" }
                                th { "MQueue" }
                                th { "State" }
                            }
                        }
                        tbody {
                            @for ps in procs.iter().take(10) {
                                tr {
                                    td {
                                        a href=(format!("/dumps/{fp}/procs/{}", url_encode_component(&ps.pid))) { (&ps.pid) }
                                    }
                                    td { (ps.name.as_deref().or(ps.spawned_as.as_deref()).unwrap_or("-")) }
                                    td { (fmt_bytes(ps.memory)) }
                                    td { (fmt_bytes(ps.stack_heap.saturating_mul(8))) }
                                    td { (ps.reductions) }
                                    td { (ps.mqueue_len) }
                                    td { (&ps.state) }
                                }
                            }
                        }
                    }
                }
                p { a href=(format!("/dumps/{fp}/procs")) { "View all processes →" } }
            }
        }
    }
}

fn summary_card(label: &str, bytes: u64) -> Markup {
    html! {
        div class="card" {
            div class="label" { (label) }
            div class="value" { (fmt_bytes(bytes)) }
            div class="muted" { (bytes) " bytes" }
        }
    }
}

fn processes_markup(
    fp: &str,
    filter: &str,
    sorted_by: &str,
    procs: &[erl_crashdump::model::ProcessSummary],
    full_page: bool,
) -> Markup {
    let content = html! {
        div id="procs-main" class="panel" {
            div class="controls" {
                span class="muted" { "Sort by:" }
                a class=(if sorted_by == "memory_bytes_desc" { "active" } else { "" })
                    href=(build_procs_url(fp, "memory", filter))
                    hx-get=(build_procs_url(fp, "memory", filter))
                    hx-target="#procs-main"
                    hx-swap="outerHTML"
                    hx-push-url="true" {
                    "Memory ▾"
                }
                a class=(if sorted_by == "pid_asc" { "active" } else { "" })
                    href=(build_procs_url(fp, "pid", filter))
                    hx-get=(build_procs_url(fp, "pid", filter))
                    hx-target="#procs-main"
                    hx-swap="outerHTML"
                    hx-push-url="true" {
                    "PID"
                }
                input id="proc-filter"
                    type="search"
                    name="q"
                    value=(filter)
                    placeholder="Filter by PID, name, spawned_as, state"
                    hx-get=(format!("/dumps/{fp}/procs"))
                    hx-include="#proc-sort"
                    hx-target="#procs-main"
                    hx-swap="outerHTML"
                    hx-trigger="keyup changed delay:300ms, search";
                input id="proc-sort" type="hidden" name="sort_by" value=(if sorted_by == "pid_asc" { "pid" } else { "memory" });
            }
            div class="table-wrap" {
                table {
                    thead {
                        tr {
                            th { "PID" }
                            th { "Name" }
                            th { "Memory" }
                            th { "STK+HEAP" }
                            th { "Reductions" }
                            th { "MQueue" }
                            th { "State" }
                        }
                    }
                    tbody {
                        @if procs.is_empty() {
                            tr { td colspan="7" class="muted" { "No matching processes." } }
                        } @else {
                            @for ps in procs {
                                tr class="clickable"
                                    hx-get=(format!("/dumps/{fp}/procs/{}?truncate=240", url_encode_component(&ps.pid)))
                                    hx-target="#proc-detail"
                                    hx-swap="innerHTML" {
                                    td {
                                        a href=(format!("/dumps/{fp}/procs/{}", url_encode_component(&ps.pid))) { (&ps.pid) }
                                    }
                                    td { (truncate_str(ps.name.as_deref().or(ps.spawned_as.as_deref()).unwrap_or("-"), 64)) }
                                    td { (fmt_bytes(ps.memory)) }
                                    td { (fmt_bytes(ps.stack_heap.saturating_mul(8))) }
                                    td { (ps.reductions) }
                                    td { (ps.mqueue_len) }
                                    td { (truncate_str(&ps.state, 22)) }
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    if full_page {
        html! {
            div class="sidebar-layout" {
                div class="grid" {
                    div class="controls" {
                        a href=(format!("/dumps/{fp}")) { "← Overview" }
                        span class="badge" { (procs.len()) " processes" }
                    }
                    (content)
                }
                aside id="proc-detail" class="panel" {
                    h2 { "Process detail" }
                    p { "Click a process row to inspect stack, dictionary, and messages." }
                }
            }
        }
    } else {
        content
    }
}

fn process_summary_markup(
    fp: &str,
    ps: &erl_crashdump::model::ProcessSummary,
    truncate: Option<usize>,
    embed_back_link: bool,
) -> Markup {
    let pid_enc = url_encode_component(&ps.pid);
    let trunc_qs = truncate.map(|t| format!("&truncate={t}")).unwrap_or_default();
    html! {
        div class="panel" {
            @if embed_back_link {
                p { a href=(format!("/dumps/{fp}/procs")) { "← Back to processes" } }
            }
            h2 { "Process " (&ps.pid) }
            dl class="kv" {
                dt { "Name" } dd { (ps.name.as_deref().unwrap_or("-")) }
                dt { "State" } dd { (&ps.state) }
                dt { "Spawned as" } dd { (ps.spawned_as.as_deref().unwrap_or("-")) }
                dt { "Spawned by" } dd { (ps.spawned_by.as_deref().unwrap_or("-")) }
                dt { "Memory" } dd { (fmt_bytes(ps.memory)) " (" (ps.memory) " bytes)" }
                dt { "Stack+heap" } dd { (ps.stack_heap) " words (" (fmt_bytes(ps.stack_heap.saturating_mul(8))) ")" }
                dt { "Old heap" } dd { (ps.old_heap) " words" }
                dt { "Heap unused" } dd { (ps.heap_unused) " words" }
                dt { "Reductions" } dd { (ps.reductions) }
                dt { "Message queue" } dd { (ps.mqueue_len) }
                dt { "Program counter" } dd { (ps.program_counter.as_deref().unwrap_or("-")) }
                dt { "Arity" } dd { (ps.arity) }
                dt { "Links" } dd { (if ps.links.is_empty() { "-".to_string() } else { ps.links.join(", ") }) }
                dt { "Monitors" } dd { (if ps.monitors.is_empty() { "-".to_string() } else { ps.monitors.join(", ") }) }
            }

            // Each section is an independently paginated lazy-loaded HTMX fragment.
            div id="proc-stack"
                hx-get=(format!("/dumps/{fp}/procs/{pid_enc}/stack?page=0{trunc_qs}"))
                hx-trigger="load"
                hx-target="#proc-stack"
                hx-swap="outerHTML" {
                p class="muted" { "Loading stack…" }
            }
            div id="proc-dict"
                hx-get=(format!("/dumps/{fp}/procs/{pid_enc}/dict?page=0{trunc_qs}"))
                hx-trigger="load"
                hx-target="#proc-dict"
                hx-swap="outerHTML" {
                p class="muted" { "Loading dictionary…" }
            }
            div id="proc-messages"
                hx-get=(format!("/dumps/{fp}/procs/{pid_enc}/messages?page=0{trunc_qs}"))
                hx-trigger="load"
                hx-target="#proc-messages"
                hx-swap="outerHTML" {
                p class="muted" { "Loading messages…" }
            }
        }
    }
}

fn build_extra_qs(truncate: Option<usize>, per_page: usize) -> String {
    let mut qs = String::new();
    if let Some(t) = truncate {
        qs.push_str(&format!("&truncate={t}"));
    }
    if per_page != PROC_SECTION_DEFAULT_PER_PAGE {
        qs.push_str(&format!("&per_page={per_page}"));
    }
    qs
}

fn proc_pager(base_url: &str, extra_qs: &str, page: usize, total: usize, per_page: usize, target: &str) -> Markup {
    if total <= per_page {
        return html! {};
    }
    let total_pages = total.div_ceil(per_page);
    let start = page * per_page + 1;
    let end = ((page + 1) * per_page).min(total);
    let last_page = total_pages - 1;
    let go_js = format!(
        "htmx.ajax('GET','{}?page='+(this.value-1)+'{}',{{target:'#{}',swap:'outerHTML'}})",
        base_url, extra_qs, target
    );
    html! {
        div class="pager" {
            span class="muted" { (start) "–" (end) " of " (total) }
            @if page > 0 {
                button
                    hx-get=(format!("{base_url}?page=0{extra_qs}"))
                    hx-target=(format!("#{target}"))
                    hx-swap="outerHTML" { "⇤" }
                button
                    hx-get=(format!("{base_url}?page={}{extra_qs}", page - 1))
                    hx-target=(format!("#{target}"))
                    hx-swap="outerHTML" { "← Prev" }
            }
            span {
                "Page "
                input
                    type="number"
                    value=(page + 1)
                    min="1"
                    max=(total_pages)
                    style="width:3.5em; text-align:center;"
                    onchange=(go_js) {}
                " / " (total_pages)
            }
            @if page < last_page {
                button
                    hx-get=(format!("{base_url}?page={}{extra_qs}", page + 1))
                    hx-target=(format!("#{target}"))
                    hx-swap="outerHTML" { "Next →" }
                button
                    hx-get=(format!("{base_url}?page={last_page}{extra_qs}"))
                    hx-target=(format!("#{target}"))
                    hx-swap="outerHTML" { "⇥" }
            }
        }
    }
}

fn proc_stack_markup(
    fp: &str,
    pid: &str,
    page: &erl_crashdump::model::Page<erl_crashdump::model::StackEntry>,
    truncate: Option<usize>,
    page_num: usize,
    per_page: usize,
) -> Markup {
    let pid_enc = url_encode_component(pid);
    let base = format!("/dumps/{fp}/procs/{pid_enc}/stack");
    let extra_qs = build_extra_qs(truncate, per_page);
    html! {
        div id="proc-stack" {
            h3 style="margin-top:1.2rem;" { "Stack (" (page.total) " entries)" }
            (proc_pager(&base, &extra_qs, page_num, page.total, per_page, "proc-stack"))
            div class="table-wrap" {
                table {
                    thead { tr { th { "Label" } th { "Term" } } }
                    tbody {
                        @if page.items.is_empty() {
                            tr { td colspan="2" class="muted" { "No stack entries." } }
                        } @else {
                            @for entry in &page.items {
                                tr {
                                    td { (&entry.label) }
                                    td {
                                        @if let Some(term) = &entry.term {
                                            @if let Some(json_str) = term_json_attr(term) {
                                                pre class="erl-term" data-term=(json_str) {
                                                    (render_term_str(term, truncate))
                                                }
                                            } @else {
                                                pre class="erl-term" {
                                                    (render_term_str(term, truncate))
                                                }
                                            }
                                        } @else {
                                            code { (truncate_str(&entry.raw, truncate.unwrap_or(usize::MAX))) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (proc_pager(&base, &extra_qs, page_num, page.total, per_page, "proc-stack"))
        }
    }
}

fn proc_term_section_markup(
    fp: &str,
    pid: &str,
    section: &str,
    title: &str,
    page: &erl_crashdump::model::Page<ErlTerm>,
    truncate: Option<usize>,
    page_num: usize,
    per_page: usize,
) -> Markup {
    let pid_enc = url_encode_component(pid);
    let id = format!("proc-{section}");
    let base = format!("/dumps/{fp}/procs/{pid_enc}/{section}");
    let extra_qs = build_extra_qs(truncate, per_page);
    let render_item = |term: &ErlTerm| -> Markup {
        let flat = render_term_str(term, truncate);
        if let Some(json_str) = term_json_attr(term) {
            html! { li { pre class="erl-term" data-term=(json_str) { (flat) } } }
        } else {
            html! { li { pre class="erl-term" { (flat) } } }
        }
    };
    html! {
        div id=(id) {
            h3 style="margin-top:1.2rem;" { (title) " (" (page.total) ")" }
            @if page.total == 0 {
                p class="muted" { "None." }
            } @else {
                (proc_pager(&base, &extra_qs, page_num, page.total, per_page, &id))
                ol class="details-list" {
                    @for term in &page.items { (render_item(term)) }
                }
                (proc_pager(&base, &extra_qs, page_num, page.total, per_page, &id))
            }
        }
    }
}

fn memory_markup(fp: &str, entries: &[(String, u64)], total_bytes: u64) -> Markup {
    html! {
        div class="grid" {
            div class="controls" { a href=(format!("/dumps/{fp}")) { "← Overview" } }
            section class="panel" {
                h1 { "Memory" }
                div class="table-wrap" {
                    table {
                        thead { tr { th { "Key" } th { "Bytes" } th { "Formatted" } } }
                        tbody {
                            @for (key, bytes) in entries {
                                tr class=(if key == "total" { "highlight" } else { "" }) {
                                    td { (key) }
                                    td { (bytes) }
                                    td { (fmt_bytes(*bytes)) }
                                }
                            }
                            @if total_bytes == 0 && entries.is_empty() {
                                tr { td colspan="3" class="muted" { "No memory section found." } }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn ets_markup(fp: &str, tables: &[erl_crashdump::model::EtsTable]) -> Markup {
    html! {
        div class="grid" {
            div class="controls" { a href=(format!("/dumps/{fp}")) { "← Overview" } }
            section class="panel" {
                h1 { "ETS" }
                div class="table-wrap" {
                    table {
                        thead {
                            tr {
                                th { "Owner" }
                                th { "Name" }
                                th { "Type" }
                                th { "Objects" }
                                th { "Words" }
                                th { "Memory" }
                                th { "Flags" }
                                th { "Protection" }
                            }
                        }
                        tbody {
                            @if tables.is_empty() {
                                tr { td colspan="8" class="muted" { "No ETS tables found." } }
                            } @else {
                                @for table in tables {
                                    tr {
                                        td { (&table.owner_pid) }
                                        td { (&table.name) }
                                        td { (&table.table_type) }
                                        td { (table.objects) }
                                        td { (table.words) }
                                        td { (fmt_bytes(table.words.saturating_mul(8))) }
                                        td { (ets_flags(table)) }
                                        td { (&table.protection) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn ets_flags(table: &erl_crashdump::model::EtsTable) -> String {
    let mut flags = Vec::new();
    if table.write_concurrency {
        flags.push("write_concurrency");
    }
    if table.read_concurrency {
        flags.push("read_concurrency");
    }
    if table.compressed {
        flags.push("compressed");
    }
    if table.fixed {
        flags.push("fixed");
    }
    if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join(", ")
    }
}

fn sections_markup(fp: &str, _sorted_by: &str, sections: &[(String, Option<String>, u64)]) -> Markup {
    // Group entries by kind; preserve insertion order then sort groups by total size.
    let mut group_order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<(Option<String>, u64)>> =
        std::collections::HashMap::new();

    for (kind, key, size) in sections {
        let e = groups.entry(kind.clone()).or_insert_with(|| {
            group_order.push(kind.clone());
            Vec::new()
        });
        e.push((key.clone(), *size));
    }

    // Sort groups by total byte size descending, then alphabetically.
    group_order.sort_by(|a, b| {
        let ta: u64 = groups[a].iter().map(|(_, s)| *s).sum();
        let tb: u64 = groups[b].iter().map(|(_, s)| *s).sum();
        tb.cmp(&ta).then_with(|| a.cmp(b))
    });

    // Sort entries within each group by key.
    for entries in groups.values_mut() {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
    }

    html! {
        div class="grid" {
            div class="controls" {
                a href=(format!("/dumps/{fp}")) { "← Overview" }
                span class="muted" { (sections.len()) " sections in " (group_order.len()) " groups" }
                button onclick="document.querySelectorAll('.sec-group').forEach(d=>d.open=true)" { "Expand all" }
                button onclick="document.querySelectorAll('.sec-group').forEach(d=>d.open=false)" { "Collapse all" }
            }
            section class="panel" {
                h1 { "Sections" }
                @for kind in &group_order {
                    @let entries = &groups[kind];
                    @let total: u64 = entries.iter().map(|(_, s)| *s).sum();
                    details class="sec-group" {
                        summary {
                            span class="sec-kind" { (kind) }
                            span class="sec-meta" {
                                (entries.len())
                                @if entries.len() == 1 { " entry" } @else { " entries" }
                                " · " (fmt_bytes(total))
                            }
                        }
                        @let has_keys = entries.iter().any(|(k, _)| k.is_some());
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        @if has_keys { th { "Key" } }
                                        th { "Size" }
                                    }
                                }
                                tbody {
                                    @for (key, size) in entries {
                                        tr {
                                            @if has_keys {
                                                td {
                                                    @if let Some(k) = key {
                                                        a href=(format!("/dumps/{fp}/query/{}?key={}",
                                                            url_encode_component(kind),
                                                            url_encode_component(k))) {
                                                            (k)
                                                        }
                                                    } @else {
                                                        span class="muted" { "—" }
                                                    }
                                                }
                                            }
                                            td {
                                                @if !has_keys {
                                                    a href=(format!("/dumps/{fp}/query/{}",
                                                        url_encode_component(kind))) {
                                                        (fmt_bytes(*size))
                                                    }
                                                } @else {
                                                    (fmt_bytes(*size))
                                                }
                                                " "
                                                span class="muted" { "(" (*size) " B)" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                @if sections.is_empty() {
                    p class="muted" { "No sections found." }
                }
            }
        }
    }
}

fn cache_root() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(".cache")
        })
        .join("ecd")
}

fn list_parsed_dumps(cache_root: &Path) -> Vec<DumpMeta> {
    let mut dumps = Vec::new();
    let Ok(entries) = std::fs::read_dir(cache_root) else {
        return dumps;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() || !path.join(".complete").exists() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        dumps.push(read_meta_from_dir(&path, name));
    }

    dumps.sort_by(|a, b| b.uploaded_at.cmp(&a.uploaded_at).then_with(|| a.fingerprint.cmp(&b.fingerprint)));
    dumps
}

fn read_dump_meta(cache_root: &Path, fp: &str) -> Option<DumpMeta> {
    let dir = dump_dir(cache_root, fp)?;
    if !dir.join(".complete").exists() {
        return None;
    }
    Some(read_meta_from_dir(&dir, fp))
}

fn read_meta_from_dir(dir: &Path, fingerprint: &str) -> DumpMeta {
    let meta = std::fs::read(dir.join("meta.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<MetaFile>(&bytes).ok());

    let filename = meta
        .as_ref()
        .map(|m| m.filename.clone())
        .unwrap_or_else(|| fingerprint.to_string());

    // Label: explicit override > basename of filename > fingerprint
    let label = meta
        .as_ref()
        .and_then(|m| m.label.clone())
        .unwrap_or_else(|| {
            Path::new(&filename)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(&filename)
                .to_string()
        });

    DumpMeta {
        fingerprint: fingerprint.to_string(),
        label,
        filename,
        size_bytes: meta.as_ref().map(|m| m.size_bytes).unwrap_or(0),
        uploaded_at: meta.map(|m| Some(m.uploaded_at)).unwrap_or(None),
        parsed: true,
    }
}

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.contains("application/json"))
        .unwrap_or(false)
}

fn is_htmx(headers: &HeaderMap) -> bool {
    headers
        .get("HX-Request")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn fmt_bytes(n: u64) -> String {
    if n >= 1_073_741_824 {
        format!("{:.1}G", n as f64 / 1_073_741_824.0)
    } else if n >= 1_048_576 {
        format!("{:.1}M", n as f64 / 1_048_576.0)
    } else if n >= 1_024 {
        format!("{:.1}K", n as f64 / 1_024.0)
    } else {
        format!("{n}B")
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out = String::new();
    for ch in s.chars().take(keep) {
        out.push(ch);
    }
    out.push('…');
    out
}

fn render_term_str(term: &ErlTerm, max_chars: Option<usize>) -> String {
    let mut buf = Vec::new();
    print_term(term, &mut buf).ok();
    let rendered = String::from_utf8_lossy(&buf).into_owned();
    match max_chars {
        Some(max) => truncate_str(&rendered, max),
        None => rendered,
    }
}

/// Serialise `term` to a JSON string for the `data-term` HTML attribute.
/// Returns `None` when the serialised JSON exceeds the size limit, in which
/// case the caller should fall back to the flat text representation.
const MAX_TERM_JSON_BYTES: usize = 200 * 1024;

fn term_json_attr(term: &ErlTerm) -> Option<String> {
    let val = term_to_json(term);
    let s = serde_json::to_string(&val).ok()?;
    if s.len() <= MAX_TERM_JSON_BYTES { Some(s) } else { None }
}

fn build_procs_url(fp: &str, sort_by: &str, filter: &str) -> String {
    let q = if filter.is_empty() {
        String::new()
    } else {
        format!("&q={}", url_encode_component(filter))
    };
    format!("/dumps/{fp}/procs?sort_by={sort_by}{q}")
}

fn url_encode_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn dump_dir(cache_root: &Path, fp: &str) -> Option<PathBuf> {
    let valid = !fp.is_empty() && fp.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if !valid {
        return None;
    }
    let dir = cache_root.join(fp);
    if dir.join(".complete").exists() { Some(dir) } else { None }
}

fn ensure_complete(headers: &HeaderMap, outdir: &Path) -> AppResult<()> {
    if outdir.join(".complete").exists() {
        Ok(())
    } else {
        Err(AppError::not_found(headers, "dump not found"))
    }
}

async fn blocking<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .context("join error")?
}

async fn write_meta_file(outdir: PathBuf, meta: MetaFile) -> Result<()> {
    blocking(move || {
        std::fs::create_dir_all(&outdir)
            .with_context(|| format!("creating {}", outdir.display()))?;
        std::fs::write(outdir.join("meta.json"), serde_json::to_vec_pretty(&meta)?)
            .with_context(|| format!("writing meta.json in {}", outdir.display()))?;
        Ok(())
    })
    .await
}
