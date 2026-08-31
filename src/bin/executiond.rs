//! executiond — hosted executor service (Phase 2)
//!
//! ```sh
//! cargo run --bin executiond -- --port 3000 --workspace /tmp/work
//! curl http://localhost:3000/health
//! curl http://localhost:3000/v1/tools
//! curl -X POST http://localhost:3000/v1/execute \
//!   -H 'content-type: application/json' \
//!   -d '{"tool":"filesystem","args":{"operation":"list","path":"/tmp/work"}}'
//! ```
//!
//! Design mirrors `executor.sh`: session = isolated `Sandbox` on `tmpfs` (here
//! `std::env::temp_dir()/executiond/<uuid>`), pooled via `concurrency_limit`
//! + token bucket quotas.
//!
//! Phase 2 uses `LocalProcessBackend`; Phase 3 swaps to `WasmBackend`/`ContainerBackend`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{sse::Event, IntoResponse, Response, Sse},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

use execution_tool::{
    destination as dest, shell::AllowedCommand, ArgumentPolicy, EgressPolicy, ExecutionPolicy,
    FileSystemTool, HttpTool, Limits, Sandbox, ShellTool, ToolOutcome, ToolRegistry,
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    registry: Arc<tokio::sync::RwLock<Arc<ToolRegistry>>>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    /// Concurrency cap (pool). `executor.sh` default ~32 per node.
    semaphore: Arc<Semaphore>,
    /// Audit log path (JSONL). If None, logs to tracing only.
    audit_path: Option<PathBuf>,
    /// workspace root for new sessions (tmpfs on Linux).
    workspace_root: PathBuf,
    metrics: Arc<Metrics>,
    audit_lock: Arc<Mutex<()>>,
    /// Egress allowlist from ExecutionPolicy (host file) — server-side enforcement.
    egress_hosts: Arc<Mutex<Vec<String>>>,
}

#[derive(Debug)]
struct Metrics {
    requests_total: std::sync::atomic::AtomicU64,
    success_total: std::sync::atomic::AtomicU64,
    failure_total: std::sync::atomic::AtomicU64,
    duration_ms_sum: std::sync::atomic::AtomicU64,
    // Histogram buckets: 10, 50, 100, 500, 1000, 5000, +Inf ms
    buckets: [std::sync::atomic::AtomicU64; 7],
    per_tool: std::sync::Mutex<std::collections::HashMap<String, (u64, u64)>>, // tool -> (success, failure)
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            requests_total: std::sync::atomic::AtomicU64::new(0),
            success_total: std::sync::atomic::AtomicU64::new(0),
            failure_total: std::sync::atomic::AtomicU64::new(0),
            duration_ms_sum: std::sync::atomic::AtomicU64::new(0),
            buckets: [0, 0, 0, 0, 0, 0, 0].map(|_| std::sync::atomic::AtomicU64::new(0)),
            per_tool: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl Metrics {
    fn inc_request(&self) {
        self.requests_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    #[allow(dead_code)]
    fn observe(&self, success: bool, duration_ms: u64) {
        self.observe_with_tool("", success, duration_ms);
    }
    fn observe_with_tool(&self, tool: &str, success: bool, duration_ms: u64) {
        if success {
            self.success_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.failure_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.duration_ms_sum
            .fetch_add(duration_ms, std::sync::atomic::Ordering::Relaxed);
        let idx = match duration_ms {
            0..=10 => 0,
            11..=50 => 1,
            51..=100 => 2,
            101..=500 => 3,
            501..=1000 => 4,
            1001..=5000 => 5,
            _ => 6,
        };
        self.buckets[idx].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !tool.is_empty() {
            if let Ok(mut map) = self.per_tool.lock() {
                let entry = map.entry(tool.to_string()).or_insert((0, 0));
                if success {
                    entry.0 += 1;
                } else {
                    entry.1 += 1;
                }
            }
        }
    }
    fn exposition(&self) -> String {
        let r = self
            .requests_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let s = self
            .success_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let f = self
            .failure_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let d = self
            .duration_ms_sum
            .load(std::sync::atomic::Ordering::Relaxed);
        let b: Vec<u64> = self
            .buckets
            .iter()
            .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
            .collect();
        // Prometheus histogram buckets must be cumulative.
        let mut cum = 0u64;
        let mut cb = Vec::with_capacity(7);
        for &v in &b {
            cum += v;
            cb.push(cum);
        }
        let mut out = format!(
            "# HELP executiond_requests_total Total execute requests\n# TYPE executiond_requests_total counter\nexecutiond_requests_total {r}\n# HELP executiond_success_total Successful tool outcomes\n# TYPE executiond_success_total counter\nexecutiond_success_total {s}\n# HELP executiond_failure_total Failed tool outcomes\n# TYPE executiond_failure_total counter\nexecutiond_failure_total {f}\n# HELP executiond_duration_ms_sum Sum of durations ms\n# TYPE executiond_duration_ms_sum counter\nexecutiond_duration_ms_sum {d}\n# HELP executiond_duration_ms_bucket Histogram\n# TYPE executiond_duration_ms_bucket histogram\nexecutiond_duration_ms_bucket{{le=\"10\"}} {}\nexecutiond_duration_ms_bucket{{le=\"50\"}} {}\nexecutiond_duration_ms_bucket{{le=\"100\"}} {}\nexecutiond_duration_ms_bucket{{le=\"500\"}} {}\nexecutiond_duration_ms_bucket{{le=\"1000\"}} {}\nexecutiond_duration_ms_bucket{{le=\"5000\"}} {}\nexecutiond_duration_ms_bucket{{le=\"+Inf\"}} {}\nexecutiond_duration_ms_count {r}\nexecutiond_duration_ms_sum {d}\n",
            cb[0], cb[1], cb[2], cb[3], cb[4], cb[5], cb[6]
        );
        if let Ok(map) = self.per_tool.lock() {
            if !map.is_empty() {
                out.push_str("# HELP executiond_tool_requests_total Per-tool requests\n# TYPE executiond_tool_requests_total counter\n");
                for (tool, (succ, fail)) in map.iter() {
                    out.push_str(&format!("executiond_tool_requests_total{{tool=\"{tool}\",status=\"success\"}} {succ}\n"));
                    out.push_str(&format!("executiond_tool_requests_total{{tool=\"{tool}\",status=\"failure\"}} {fail}\n"));
                }
            }
        }
        out
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct Session {
    id: String,
    sandbox: Sandbox,
    root: PathBuf,
    created: Instant,
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ExecuteRequest {
    tool: String,
    args: serde_json::Value,
    /// Optional session id — if omitted, uses default workspace sandbox.
    session_id: Option<String>,
    /// Idempotency key for `execute_once`.
    idempotency_key: Option<String>,
}

#[derive(Serialize)]
struct ExecuteResponse {
    outcome: ToolOutcome,
}

#[derive(Deserialize)]
struct BatchRequest {
    requests: Vec<ExecuteRequest>,
    max_concurrency: Option<usize>,
    /// Optional session to scope all steps (validates paths inside session root)
    session_id: Option<String>,
}

#[derive(Serialize)]
struct BatchResponse {
    outcomes: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct SequenceRequest {
    steps: Vec<ExecuteRequest>,
    continue_on_error: Option<bool>,
    /// Optional session to scope all steps
    session_id: Option<String>,
}

#[derive(Serialize)]
struct SequenceResponse {
    outcomes: Vec<serde_json::Value>,
    executed: usize,
    total: usize,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct CreateSessionRequest {
    /// Optional label for audit.
    label: Option<String>,
}

#[derive(Serialize)]
struct CreateSessionResponse {
    session_id: String,
    root: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    tools: Vec<String>,
    sessions: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    code: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let sessions = state.sessions.lock().await.len();
    let registry = state.registry.read().await.clone();
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        tools: registry.tool_names(),
        sessions,
    })
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.exposition(),
    )
}

#[tracing::instrument(skip(state))]
async fn list_tools(State(state): State<AppState>) -> impl IntoResponse {
    let registry = state.registry.read().await.clone();
    Json(registry.definitions())
}

async fn create_session(
    State(state): State<AppState>,
    Json(_req): Json<CreateSessionRequest>,
) -> impl IntoResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let root = state.workspace_root.join(&id);
    if let Err(e) = std::fs::create_dir_all(&root) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    let sandbox = match Sandbox::new([&root]) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let session = Session {
        id: id.clone(),
        sandbox: sandbox.clone(),
        root: root.clone(),
        created: Instant::now(),
    };

    // Register per-session filesystem tool dynamically? For P2 we keep global
    // registry + validate session root manually. Full per-session registry is
    // Phase 3 (requires registry interior mutability). For now we just track
    // session and let callers pass absolute path inside session root.

    state.sessions.lock().await.insert(id.clone(), session);

    info!(session_id = %id, root = %root.display(), "session created");

    (
        StatusCode::CREATED,
        Json(CreateSessionResponse {
            session_id: id,
            root: root.display().to_string(),
        }),
    )
        .into_response()
}

fn redacted_url(url: &str) -> String {
    dest::host_of(url).unwrap_or_else(|_| "invalid".into())
}

async fn egress_allowed_hosts(state: &AppState) -> Vec<String> {
    let policy_hosts = state.egress_hosts.lock().await.clone();
    if !policy_hosts.is_empty() {
        return policy_hosts;
    }
    std::env::var("EXECUTIOND_ALLOWED_HOSTS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect()
}

fn check_session_path(sess: &Session, args: &serde_json::Value) -> Option<Response> {
    for key in ["path", "destination"] {
        if let Some(p) = args.get(key).and_then(|v| v.as_str()) {
            let path = Path::new(p);
            // Must be inside session root (absolute check). Relative paths are also denied to enforce session isolation.
            if !path.starts_with(&sess.root) {
                // Allow also normalized path that equals root
                if path != sess.root.as_path() {
                    return Some(
                        (
                            StatusCode::FORBIDDEN,
                            Json(ErrorResponse {
                                error: "path_not_allowed: outside session".into(),
                                code: "path_not_allowed".into(),
                            }),
                        )
                            .into_response(),
                    );
                }
            }
        }
    }
    None
}

fn inject_session_id(requests: &mut [ExecuteRequest], top_sid: &Option<String>) {
    if let Some(sid) = top_sid {
        for r in requests.iter_mut() {
            if matches!(r.tool.as_str(), "memory" | "todo" | "plan")
                && r.args.get("session_id").is_none()
            {
                if let Some(obj) = r.args.as_object_mut() {
                    obj.insert(
                        "session_id".to_string(),
                        serde_json::Value::String(sid.clone()),
                    );
                }
            }
        }
    }
}

#[tracing::instrument(skip(state, req), fields(tool = %req.tool))]
async fn execute(State(state): State<AppState>, Json(req): Json<ExecuteRequest>) -> Response {
    state.metrics.inc_request();
    // Concurrency guard — 503 if at cap (pool).
    let _permit = match state.semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            state.metrics.observe_with_tool("", false, 0);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "too many concurrent executions".into(),
                    code: "concurrency_limited".into(),
                }),
            )
                .into_response();
        }
    };

    // Session validation: if session_id given, ensure it exists and paths are inside it.
    if let Some(sid) = &req.session_id {
        let sessions = state.sessions.lock().await;
        if let Some(sess) = sessions.get(sid) {
            if let Some(resp) = check_session_path(sess, &req.args) {
                return resp;
            }
        } else {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("session not found: {sid}"),
                    code: "session_not_found".into(),
                }),
            )
                .into_response();
        }
    }

    // Egress proxy — server-side SSRF enforcement (Phase 3 defense-in-depth).
    if req.tool == "http" {
        if let Some(url) = req.args.get("url").and_then(|v| v.as_str()) {
            // Always validate destination (blocks 169.254.169.254, private ranges etc.)
            if let Err(e) = dest::validate_destination(url) {
                warn!(error = %e, url = %redacted_url(url), "egress blocked (destination)");
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: e.to_string(),
                    }),
                )
                    .into_response();
            }
            // If allowlist configured via policy file or env, enforce it server-side (not just HttpTool).
            let allowed = egress_allowed_hosts(&state).await;
            if !allowed.is_empty() {
                let egress = EgressPolicy::new(allowed);
                if let Err(err) = egress.check(url) {
                    warn!(error = %err.code, url = %err.url_redacted, "egress blocked (allowlist)");
                    return (
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: err.code.clone(),
                            code: err.code,
                        }),
                    )
                        .into_response();
                }
            }
        }
    }

    let started = Instant::now();
    let registry = state.registry.read().await.clone();
    let outcome = if let Some(key) = req.idempotency_key {
        match registry.execute_once(&key, &req.tool, req.args).await {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, tool = %req.tool, "execute_once rejected");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: extract_code(&e.to_string()),
                    }),
                )
                    .into_response();
            }
        }
    } else {
        match registry.execute(&req.tool, req.args).await {
            Ok(o) => o,
            Err(e) => {
                warn!(error = %e, tool = %req.tool, "execute rejected");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: extract_code(&e.to_string()),
                    }),
                )
                    .into_response();
            }
        }
    };

    // Audit: JSONL with sha256 (P0 redaction intact).
    audit_log(&state, &outcome, started.elapsed().as_millis() as u64).await;

    // Metrics + OTel
    state
        .metrics
        .observe_with_tool(&outcome.tool, outcome.success, outcome.duration_ms);
    info!(
        tool = %outcome.tool,
        success = outcome.success,
        duration_ms = outcome.duration_ms,
        error_code = ?outcome.error_code,
        "tool executed via http"
    );

    (StatusCode::OK, Json(ExecuteResponse { outcome })).into_response()
}

async fn execute_batch(
    State(state): State<AppState>,
    Json(mut req): Json<BatchRequest>,
) -> Response {
    // Auto-scope agentic state to top-level session
    inject_session_id(&mut req.requests, &req.session_id);
    // Admission control: limit batch size and concurrency to avoid OOM / fan-out.
    const MAX_BATCH: usize = 64;
    if req.requests.len() > MAX_BATCH {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("batch too large: {} > {MAX_BATCH}", req.requests.len()),
                code: "batch_too_large".into(),
            }),
        )
            .into_response();
    }
    // Acquire permits proportional to concurrency to avoid fan-out bypassing global limit.
    let max = req.max_concurrency.unwrap_or(8).clamp(1, 32);
    // Try to acquire `max` permits or fail fast; simpler to acquire 1 global permit and rely on inner sem.
    // To avoid 32x blow-up, we acquire 1 but bound max to 32 and batch size to 64.
    let _permit = match state.semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            state.metrics.observe_with_tool("", false, 0);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "too many concurrent executions".into(),
                    code: "concurrency_limited".into(),
                }),
            )
                .into_response();
        }
    };
    // Session validation (top-level + per-step)
    let top_sid = req.session_id.clone();
    {
        let sessions = state.sessions.lock().await;
        if let Some(sid) = &top_sid {
            if !sessions.contains_key(sid) {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: format!("session not found: {sid}"),
                        code: "session_not_found".into(),
                    }),
                )
                    .into_response();
            }
            if let Some(sess) = sessions.get(sid) {
                for r in &req.requests {
                    if let Some(resp) = check_session_path(sess, &r.args) {
                        return resp;
                    }
                    if let Some(url) = r.args.get("url").and_then(|v| v.as_str()) {
                        if r.tool == "http" {
                            if let Err(e) = dest::validate_destination(url) {
                                return (
                                    StatusCode::FORBIDDEN,
                                    Json(ErrorResponse {
                                        error: e.to_string(),
                                        code: e.to_string(),
                                    }),
                                )
                                    .into_response();
                            }
                            let allowed = egress_allowed_hosts(&state).await;
                            if !allowed.is_empty() {
                                let egress = EgressPolicy::new(allowed);
                                if let Err(err) = egress.check(url) {
                                    return (
                                        StatusCode::FORBIDDEN,
                                        Json(ErrorResponse {
                                            error: err.code.clone(),
                                            code: err.code,
                                        }),
                                    )
                                        .into_response();
                                }
                            }
                        }
                    }
                    // Per-step session override validation
                    if let Some(psid) = &r.session_id {
                        if !sessions.contains_key(psid) {
                            return (
                                StatusCode::NOT_FOUND,
                                Json(ErrorResponse {
                                    error: format!("session not found: {psid}"),
                                    code: "session_not_found".into(),
                                }),
                            )
                                .into_response();
                        }
                        if let Some(psess) = sessions.get(psid) {
                            if let Some(resp) = check_session_path(psess, &r.args) {
                                return resp;
                            }
                        }
                    }
                }
            }
        } else {
            // No top-level session, still validate per-step sessions
            for r in &req.requests {
                if let Some(psid) = &r.session_id {
                    if !sessions.contains_key(psid) {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(ErrorResponse {
                                error: format!("session not found: {psid}"),
                                code: "session_not_found".into(),
                            }),
                        )
                            .into_response();
                    }
                }
                if r.tool == "http" {
                    if let Some(url) = r.args.get("url").and_then(|v| v.as_str()) {
                        if let Err(e) = dest::validate_destination(url) {
                            return (
                                StatusCode::FORBIDDEN,
                                Json(ErrorResponse {
                                    error: e.to_string(),
                                    code: e.to_string(),
                                }),
                            )
                                .into_response();
                        }
                        let allowed = egress_allowed_hosts(&state).await;
                        if !allowed.is_empty() {
                            let egress = EgressPolicy::new(allowed);
                            if let Err(err) = egress.check(url) {
                                return (
                                    StatusCode::FORBIDDEN,
                                    Json(ErrorResponse {
                                        error: err.code.clone(),
                                        code: err.code,
                                    }),
                                )
                                    .into_response();
                            }
                        }
                    }
                }
            }
        }
    }
    let inner: Vec<(String, serde_json::Value)> =
        req.requests.into_iter().map(|r| (r.tool, r.args)).collect();
    state.metrics.inc_request();
    let registry = state.registry.read().await.clone();
    let results = registry.execute_batch(inner, max).await;
    let mut outcomes: Vec<serde_json::Value> = Vec::with_capacity(results.len());
    for r in results {
        match r {
            Ok(o) => {
                let tool = o.tool.clone();
                state
                    .metrics
                    .observe_with_tool(&tool, o.success, o.duration_ms);
                outcomes.push(
                    serde_json::to_value(o).unwrap_or(serde_json::json!({"error":"serialize"})),
                );
            }
            Err(e) => {
                state.metrics.observe_with_tool("", false, 0);
                outcomes.push(serde_json::json!({"error": e.to_string(), "code": extract_code(&e.to_string())}));
            }
        }
    }
    (StatusCode::OK, Json(BatchResponse { outcomes })).into_response()
}

async fn execute_sequence(
    State(state): State<AppState>,
    Json(mut req): Json<SequenceRequest>,
) -> Response {
    // Auto-scope agentic state to top-level session
    inject_session_id(&mut req.steps, &req.session_id);
    const MAX_STEPS: usize = 32;
    if req.steps.len() > MAX_STEPS {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("sequence too large: {} > {MAX_STEPS}", req.steps.len()),
                code: "sequence_too_large".into(),
            }),
        )
            .into_response();
    }
    let _permit = match state.semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            state.metrics.observe_with_tool("", false, 0);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "too many concurrent executions".into(),
                    code: "concurrency_limited".into(),
                }),
            )
                .into_response();
        }
    };
    if let Some(sid) = &req.session_id {
        let sessions = state.sessions.lock().await;
        if let Some(sess) = sessions.get(sid) {
            for r in &req.steps {
                if let Some(resp) = check_session_path(sess, &r.args) {
                    return resp;
                }
                if let Some(psid) = &r.session_id {
                    if !sessions.contains_key(psid) {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(ErrorResponse {
                                error: format!("session not found: {psid}"),
                                code: "session_not_found".into(),
                            }),
                        )
                            .into_response();
                    }
                }
            }
        } else {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("session not found: {sid}"),
                    code: "session_not_found".into(),
                }),
            )
                .into_response();
        }
    } else {
        let sessions = state.sessions.lock().await;
        for r in &req.steps {
            if let Some(psid) = &r.session_id {
                if !sessions.contains_key(psid) {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: format!("session not found: {psid}"),
                            code: "session_not_found".into(),
                        }),
                    )
                        .into_response();
                }
            }
        }
    }
    // Egress check for each step if http
    for r in &req.steps {
        if r.tool == "http" {
            if let Some(url) = r.args.get("url").and_then(|v| v.as_str()) {
                if let Err(e) = dest::validate_destination(url) {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: e.to_string(),
                            code: e.to_string(),
                        }),
                    )
                        .into_response();
                }
                let allowed = egress_allowed_hosts(&state).await;
                if !allowed.is_empty() {
                    let egress = EgressPolicy::new(allowed);
                    if let Err(err) = egress.check(url) {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(ErrorResponse {
                                error: err.code.clone(),
                                code: err.code,
                            }),
                        )
                            .into_response();
                    }
                }
            }
        }
    }
    let continue_on_error = req.continue_on_error.unwrap_or(false);
    let total = req.steps.len();
    let inner: Vec<(String, serde_json::Value)> =
        req.steps.into_iter().map(|r| (r.tool, r.args)).collect();
    state.metrics.inc_request();
    let registry = state.registry.read().await.clone();
    let results = registry.execute_sequence(inner, continue_on_error).await;
    let executed = results.len();
    let mut outcomes: Vec<serde_json::Value> = Vec::with_capacity(results.len());
    for r in results {
        match r {
            Ok(o) => {
                let tool = o.tool.clone();
                state
                    .metrics
                    .observe_with_tool(&tool, o.success, o.duration_ms);
                outcomes.push(
                    serde_json::to_value(o).unwrap_or(serde_json::json!({"error":"serialize"})),
                );
            }
            Err(e) => {
                state.metrics.observe_with_tool("", false, 0);
                outcomes.push(serde_json::json!({"error": e.to_string(), "code": extract_code(&e.to_string()), "success": false}));
            }
        }
    }
    (
        StatusCode::OK,
        Json(SequenceResponse {
            outcomes,
            executed,
            total,
        }),
    )
        .into_response()
}

/// SSE streaming — for `shell` long output. Currently buffers then streams chunks
/// (Phase 2); Phase 3 will stream truly via `backend::execute_streaming`.
async fn execute_stream(
    State(state): State<AppState>,
    Json(req): Json<ExecuteRequest>,
) -> Response {
    // Only shell streaming is meaningful; others fallback to single event.

    if req.tool != "shell" {
        return execute(State(state), Json(req)).await.into_response();
    }

    let _permit = match state.semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "too many concurrent executions".into(),
                    code: "concurrency_limited".into(),
                }),
            )
                .into_response();
        }
    };

    // For P2 we execute then stream buffered chunks as SSE.
    // Real streaming will call `ShellTool::execute_streaming` directly.
    let registry = state.registry.read().await.clone();
    let outcome = match registry.execute(&req.tool, req.args).await {
        Ok(o) => o,
        Err(e) => {
            let err_event = Event::default()
                .event("error")
                .data(serde_json::json!({"error": e.to_string()}).to_string());
            let stream = tokio_stream::once(Ok::<_, std::convert::Infallible>(err_event));
            return Sse::new(stream).into_response();
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel(16);

    // Spawn chunk emission.
    tokio::spawn(async move {
        // Summary event.
        let summary = Event::default()
            .event("summary")
            .data(serde_json::to_string(&outcome.summary).unwrap_or_default());
        let _ = tx.send(Ok::<_, std::convert::Infallible>(summary)).await;

        // Content chunks (cap 64k per SSE event to avoid large frames).
        if let Some(content) = outcome.content {
            for chunk in content.chunks(64 * 1024) {
                let data = serde_json::json!({
                    "bytes": chunk.len(),
                    "sha256": execution_tool::sha256_hex(chunk),
                    "chunk_b64": base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD, chunk
                    ),
                });
                let ev = Event::default().event("chunk").data(data.to_string());
                if tx.send(Ok(ev)).await.is_err() {
                    break;
                }
            }
        }

        let done = Event::default().event("done").data(
            serde_json::json!({
                "success": outcome.success,
                "error_code": outcome.error_code,
                "duration_ms": outcome.duration_ms
            })
            .to_string(),
        );
        let _ = tx.send(Ok(done)).await;
    });

    Sse::new(ReceiverStream::new(rx)).into_response()
}

async fn delete_session(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let mut sessions = state.sessions.lock().await;
    if let Some(sess) = sessions.remove(&id) {
        let _ = std::fs::remove_dir_all(&sess.root);
        info!(session_id = %id, "session deleted");
        (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("session not found: {id}"),
                code: "session_not_found".into(),
            }),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_code(msg: &str) -> String {
    // Policy errors are `code` strings like `path_not_allowed` — first token.
    msg.split(':').next().unwrap_or(msg).trim().to_string()
}

async fn audit_log(state: &AppState, outcome: &ToolOutcome, _elapsed: u64) {
    let entry = serde_json::json!({
        "ts": chrono_like_now(),
        "tool": outcome.tool,
        "success": outcome.success,
        "error_code": outcome.error_code,
        "duration_ms": outcome.duration_ms,
        "summary": outcome.summary,
        "content_sha256": outcome.content.as_ref().map(|b| execution_tool::sha256_hex(b)),
        "redaction_policy_version": execution_tool::REDACTION_POLICY_VERSION,
    });
    let line = serde_json::to_string(&entry).unwrap_or_default();
    tracing::info!(audit = %line, "audit");

    if let Some(path) = &state.audit_path {
        let path = path.clone();
        let lock = state.audit_lock.clone();
        let _guard = lock.lock().await;
        let line_clone = line.clone();
        let _ = tokio::task::spawn_blocking(move || {
            use std::io::Write;
            // Rotate if >10MiB: audit.jsonl -> audit.jsonl.1, serialized via audit_lock.
            if let Ok(meta) = std::fs::metadata(&path) {
                if meta.len() > 10 * 1024 * 1024 {
                    let rotated = path.with_extension("jsonl.1");
                    let _ = std::fs::rename(&path, &rotated);
                }
            }
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = writeln!(f, "{line_clone}");
            }
        })
        .await;
    }
}

fn chrono_like_now() -> String {
    // No `chrono` dep — use `std::time`.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs.to_string()
}

fn build_registry(workspace: &Path) -> anyhow::Result<ToolRegistry> {
    build_registry_from_policy(&ExecutionPolicy {
        workspace: workspace.to_path_buf(),
        ..Default::default()
    })
}

fn build_registry_from_policy(policy: &ExecutionPolicy) -> anyhow::Result<ToolRegistry> {
    let sandbox = policy.sandbox()?;
    let mut registry = ToolRegistry::new();

    // Filesystem
    let mut fs = FileSystemTool::new(sandbox.clone());
    if policy.filesystem.writable {
        fs = fs.writable();
    }
    fs = fs.with_read_limit(policy.filesystem.read_limit);
    registry.register(std::sync::Arc::new(fs));

    // Shell — from policy or fallback to echo/cat demo
    let mut commands = policy.allowed_commands();
    if commands.is_empty() {
        let echo = if Path::new("/bin/echo").exists() {
            "/bin/echo"
        } else {
            "/usr/bin/echo"
        };
        let cat = if Path::new("/bin/cat").exists() {
            "/bin/cat"
        } else {
            "/usr/bin/cat"
        };
        commands = vec![
            AllowedCommand::new(echo).with_arguments(ArgumentPolicy::NoFlags),
            AllowedCommand::new(cat).with_arguments(ArgumentPolicy::NoFlags),
        ];
    }
    let mut shell = ShellTool::new(commands)
        .with_working_dirs(sandbox.clone())
        .with_timeout(policy.shell_timeout())
        .with_output_limit(policy.shell.output_limit);
    if let Some(env) = &policy.shell.allowed_env {
        shell = shell.with_allowed_env(env.clone());
    }
    registry.register(std::sync::Arc::new(shell));

    // HTTP + egress proxy (server-side allowlist)
    let egress = EgressPolicy::new(policy.http.allowed_hosts.clone());
    // egress is checked again in `execute` handler for defense-in-depth
    let http = HttpTool::new(policy.http.allowed_hosts.clone())
        .with_timeout(policy.http_timeout())
        .with_body_limit(policy.http.response_body_limit)
        .with_request_body_limit(policy.http.request_body_limit);
    let _ = egress; // kept for middleware use; HttpTool already validates
    registry.register(std::sync::Arc::new(http));

    // Agentic meta-tools — think/memory/todo/plan/reflect (no sandbox, pure planning)
    {
        use execution_tool::{MemoryTool, PlanTool, ReflectTool, ThinkTool, TodoTool};
        registry.register(std::sync::Arc::new(ThinkTool));
        registry.register(std::sync::Arc::new(MemoryTool::new()));
        registry.register(std::sync::Arc::new(TodoTool::new()));
        registry.register(std::sync::Arc::new(PlanTool::new()));
        registry.register(std::sync::Arc::new(ReflectTool));
    }

    // Code execution (python/javascript/bash) — like executor.sh code cells
    {
        use execution_tool::CodeTool;
        let langs = policy.code_languages();
        let mut code_tool = CodeTool::new()
            .with_sandbox(sandbox.clone())
            .with_timeout(policy.code_timeout())
            .with_output_limit(policy.code.output_limit);
        if langs.is_empty() {
            code_tool = code_tool.allow_all();
        } else {
            for lang in langs {
                code_tool = code_tool.allow_language(lang);
            }
        }
        // Inherit env allowlist if specified for shell
        if let Some(env) = &policy.shell.allowed_env {
            code_tool = code_tool.with_allowed_env(env.clone());
        }
        registry.register(std::sync::Arc::new(code_tool));
    }

    Ok(registry)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing (json if `EXECUTIOND_JSON_LOGS=1`).
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if std::env::var("EXECUTIOND_JSON_LOGS").is_ok() {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    let port: u16 = std::env::var("PORT")
        .or_else(|_| std::env::var("EXECUTIOND_PORT"))
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    // CLI: `--port`, `--workspace`, `--audit-log`, `--config`
    let mut args = std::env::args().skip(1);
    let mut workspace = std::env::temp_dir().join("executiond");
    let mut audit_path: Option<PathBuf> = None;
    let mut concurrency: usize = 32;
    let mut config_path: Option<PathBuf> = None;
    let mut policy = ExecutionPolicy::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                if let Some(p) = args.next() {
                    if let Ok(v) = p.parse::<u16>() {
                        std::env::set_var("PORT", v.to_string());
                    }
                }
            }
            "--workspace" => {
                if let Some(p) = args.next() {
                    workspace = PathBuf::from(p);
                }
            }
            "--audit-log" => {
                if let Some(p) = args.next() {
                    audit_path = Some(PathBuf::from(p));
                }
            }
            "--concurrency" => {
                if let Some(c) = args.next() {
                    if let Ok(v) = c.parse() {
                        concurrency = v;
                    }
                }
            }
            "--config" | "-c" => {
                if let Some(p) = args.next() {
                    config_path = Some(PathBuf::from(p));
                }
            }
            "--validate-config" => {
                if let Some(p) = args.next() {
                    let pol = ExecutionPolicy::from_file(Path::new(&p))?;
                    println!("config valid: {}", p);
                    println!("{:#?}", pol);
                    return Ok(());
                }
            }
            "--help" | "-h" => {
                println!(
                    "executiond -- hosted executor\n\nUsage: executiond [--port 3000] [--workspace /tmp/work] [--audit-log audit.jsonl] [--concurrency 32] [--config execution.yaml]\n\nEnv: PORT, EXECUTIOND_ALLOWED_HOSTS (comma list), RUST_LOG, EXECUTIOND_JSON_LOGS\n\nPolicy: --config execution.yaml (hot-reloaded via notify), or --validate-config <path>"
                );
                return Ok(());
            }
            _ => {}
        }
    }

    // Load policy from --config or ./execution.yaml if present
    if let Some(p) = config_path.clone().or_else(|| {
        let cand = PathBuf::from("execution.yaml");
        if cand.exists() {
            Some(cand)
        } else {
            None
        }
    }) {
        match ExecutionPolicy::from_file(&p) {
            Ok(pol) => {
                info!(config = %p.display(), "loaded execution.yaml");
                workspace = pol.workspace.clone();
                audit_path = pol.audit_log.clone().or(audit_path);
                concurrency = pol.concurrency;
                policy = pol;
            }
            Err(e) => {
                warn!(config = %p.display(), error = %e, "failed to load execution.yaml, using defaults");
            }
        }
    }

    // Re-read port after CLI override.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(port);

    // If policy already loaded, workspace etc come from it; ensure consistent
    if config_path.is_some() || Path::new("execution.yaml").exists() {
        // policy already holds workspace/audit/concurrency; rebuild registry from it
        std::fs::create_dir_all(&policy.workspace)?;
        Limits::default().apply_rlimits();
        let registry = Arc::new(build_registry_from_policy(&policy)?);
        info!(
            workspace = %policy.workspace.display(),
            tools = ?registry.tool_names(),
            concurrency,
            "starting executiond (policy)"
        );
        return serve(
            registry,
            policy.workspace,
            policy.audit_log.or(audit_path),
            concurrency,
            port,
            config_path,
        )
        .await;
    }

    std::fs::create_dir_all(&workspace)?;
    Limits::default().apply_rlimits();

    let registry = Arc::new(build_registry(&workspace)?);
    info!(
        workspace = %workspace.display(),
        tools = ?registry.tool_names(),
        concurrency,
        "starting executiond"
    );

    let state = AppState {
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        semaphore: Arc::new(Semaphore::new(concurrency)),
        audit_path,
        workspace_root: workspace,
        metrics: Arc::new(Metrics::default()),
        audit_lock: Arc::new(Mutex::new(())),
        egress_hosts: Arc::new(Mutex::new(Vec::new())),
    };

    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn serve(
    registry: Arc<ToolRegistry>,
    workspace_root: PathBuf,
    audit_path: Option<PathBuf>,
    concurrency: usize,
    port: u16,
    config_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Derive egress hosts from initial registry's policy was already via ExecutionPolicy; keep in sync
    let initial_hosts = {
        // Try to read from execution.yaml if exists, else empty
        if let Some(cfg) = config_path.clone() {
            ExecutionPolicy::from_file(&cfg)
                .map(|p| p.http.allowed_hosts)
                .unwrap_or_default()
        } else if Path::new("execution.yaml").exists() {
            ExecutionPolicy::from_file(Path::new("execution.yaml"))
                .map(|p| p.http.allowed_hosts)
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };
    let state = AppState {
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        semaphore: Arc::new(Semaphore::new(concurrency)),
        audit_path: audit_path.clone(),
        workspace_root: workspace_root.clone(),
        metrics: Arc::new(Metrics::default()),
        audit_lock: Arc::new(Mutex::new(())),
        egress_hosts: Arc::new(Mutex::new(initial_hosts)),
    };

    // Hot reload: watch config file and swap registry atomically, including egress hosts.
    if let Some(cfg) = config_path.clone() {
        let registry_ref = state.registry.clone();
        let hosts_ref = state.egress_hosts.clone();
        tokio::spawn(async move {
            use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
            let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
            let tx_clone = tx.clone();
            let cfg_clone = cfg.clone();
            let mut watcher: RecommendedWatcher = match RecommendedWatcher::new(
                move |res: notify::Result<notify::Event>| {
                    if let Ok(ev) = res {
                        if ev.kind.is_modify() {
                            let _ = tx_clone.blocking_send(());
                        }
                    }
                },
                NotifyConfig::default(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    warn!(error = %e, "notify watcher failed");
                    return;
                }
            };
            let _ = watcher.watch(&cfg_clone, RecursiveMode::NonRecursive);
            // Keep watcher alive
            let _watcher = watcher;
            while rx.recv().await.is_some() {
                // Debounce
                tokio::time::sleep(Duration::from_millis(300)).await;
                while rx.try_recv().is_ok() {}
                match ExecutionPolicy::from_file(&cfg) {
                    Ok(pol) => match build_registry_from_policy(&pol) {
                        Ok(new_reg) => {
                            *registry_ref.write().await = Arc::new(new_reg);
                            *hosts_ref.lock().await = pol.http.allowed_hosts.clone();
                            info!(config = %cfg.display(), "hot-reloaded execution.yaml");
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to rebuild registry from reloaded policy")
                        }
                    },
                    Err(e) => warn!(error = %e, config = %cfg.display(), "failed to reload policy"),
                }
            }
        });
    }

    let app = build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, "listening (policy mode)");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/tools", get(list_tools))
        .route("/v1/sessions", post(create_session))
        .route("/v1/sessions/:id", axum::routing::delete(delete_session))
        .route("/v1/execute", post(execute))
        .route("/v1/execute/batch", post(execute_batch))
        .route("/v1/execute/sequence", post(execute_sequence))
        .route("/v1/execute/stream", post(execute_stream))
        .route("/v1/policy", get(get_policy))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::any())
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                ])
                .allow_headers([axum::http::header::CONTENT_TYPE]),
        )
}

async fn get_policy(State(_state): State<AppState>) -> impl IntoResponse {
    // Return current execution.yaml if present, else defaults.
    let path = PathBuf::from("execution.yaml");
    if path.exists() {
        if let Ok(s) = std::fs::read_to_string(&path) {
            return (StatusCode::OK, s).into_response();
        }
    }
    (
        StatusCode::OK,
        serde_yaml::to_string(&ExecutionPolicy::default()).unwrap_or_default(),
    )
        .into_response()
}
