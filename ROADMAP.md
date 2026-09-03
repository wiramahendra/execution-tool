# Engineering Roadmap: Marshall -> Mature Executor

> Status: Approved. This doc is the source of truth for maturing the crate to `executor.sh`/`E2B` class.
> Rename `execution-tool` -> **Marshall** (`marshall` crate, `marshalld` daemon, `marshall.yaml`) landed in `0.2.0` — breaking, no compat shims.

## 0. Context

Current crate is an embedded library: `filesystem`/`shell`/`http` behind `deny-by-default` policy (`Sandbox`, `Destination`, `ArgumentPolicy`). `README.md` explicitly: no `seccomp/namespace/chroot`, TOCTOU not closed. Tests: `77 lib + 12 escapes` all green. Goal: mature to hosted/managed executor without losing auditability (`sha256_hex`, `REDACTION_POLICY_VERSION`, `ToolOutcome` redaction).

Product wedge: `ToolRegistry` as agent runtime primitive -> `marshalld` service -> multi-tenant pool.

## 1. Phases

### Phase 0: Harden what we claim (P0) — DONE
- [x] **P0.1 Shell env** `src/shell.rs:257`: `env_clear()` + allowlist `with_allowed_env()`. Add `with_env()` builder. Tests: `LD_PRELOAD`, `GIT_SSH_COMMAND` do not propagate.
- [x] **P0.2 Registry cache** `src/registry.rs:118`: fix race (`RwLock` read->write) + unbounded leak. Replace with `Mutex<HashMap>` with TTL + dedup. Add `max_entries` + expiry (`with_cache_ttl`/`with_cache_capacity`).
- [x] **P0.3 FS** `src/fs.rs:170`: support `content_base64` (binary), add `mkdir`/`delete` ops under same `resolve_for_create`/`resolve_existing` policy. Keep `write` string compat. Dep `base64:0.22`.
- [x] **P0.4 Destination/HTTP** `src/destination.rs:139`: `127.0.0.0/8` loopback name via `IpAddr::is_loopback()`; `src/http.rs:72`: request header allowlist + outbound `body_limit` + method strict.
- [x] **P0.5 Errors + CI** `src/error.rs` typed `ToolError{code}`; `src/fs.rs:250` stable codes; `ci.yml` add `cargo audit`; `limits.rs` RLIMIT stub.

### Phase 1: Isolation Abstraction — DONE (scaffold)
- [x] `src/backend.rs`: `trait ExecutionBackend { execute(ExecRequest) }` with `LocalProcessBackend` (current, `env_clear`+`kill_on_drop`+capped I/O), `WasmBackend` (wasmtime fuel/memory, `wasm` feature), `ContainerBackend` (watchdog stub).
- [x] Feature flags `wasm`/`backend-wasm`/`backend-container` `Cargo.toml:15`, optional `wasmtime:22`.
- [x] Resource bounds: `src/limits.rs` `Limits` + `src/backend.rs:18 ResourceLimits` (`timeout`/`output_limit`/`cpu_time`/`memory_bytes`) + `ShellTool::with_cpu_time`/`with_memory_limit`.
- [x] Streaming: `ShellTool::execute_streaming()` -> `backend::StreamingOutput{chunks: Vec<StreamChunk{stream, bytes, sha256}>}` buffered now, true SSE in Phase 2. `backend::ExecOutput::into_outcome()` preserves `sha256` audit.

### Phase 2: Service Layer — DONE (MVP)
- [x] `src/bin/marshalld.rs:1` (`axum 0.7`): `GET /health`, `GET /v1/tools`, `POST /v1/sessions` (uuid + `Sandbox::new([tmp/work/<id>])`), `POST /v1/execute` (`tool`+`args`+`session_id`+`idempotency_key`), `POST /v1/execute/stream` (SSE `summary`/`chunk`/`done` with `sha256`), `DELETE /v1/sessions/:id`. Verified `cargo run --bin marshalld -- --port 18080` + `curl` smoke: shell/filesystem + streaming green.
- [x] Pool + quotas: `tokio::sync::Semaphore(32)` (`--concurrency` flag) `503 concurrency_limited` on `try_acquire`; per-session isolation on `tmpfs` (`/tmp/marshalld/<uuid>`). Token-bucket QPS deferred to `tower_governor` Phase 2.1.
- [x] Observability: `tracing` `TraceLayer` + `tracing_subscriber::fmt` (`RUST_LOG`, `MARSHALLD_JSON_LOGS`), `info!` audit JSONL (`tool/success/duration_ms/sha256/redaction_policy_version`) + optional `--audit-log audit.jsonl` append, `Limits::apply_rlimits()` hook.

### Phase 3: Platform — DONE (MVP)
- [x] Policy as Code `src/policy.rs:1` `ExecutionPolicy{workspace, concurrency, audit_log, filesystem, shell, http}` + `marshall.yaml` sample + `serde_yaml` loader + `validate()` (absolute program, no wildcards, no control chars) + `cargo run --bin marshalld -- --validate-config ./marshall.yaml` + `GET /v1/policy` + hot reload via `notify 6.1` `RecursiveMode::NonRecursive` debounced 300ms swapping `Arc<ToolRegistry>`.
- [x] Egress proxy `src/egress.rs:1` `EgressPolicy{allowed_hosts}` `check(url) -> ValidatedDestination` (allowlist before `validate_destination`) + `marshalld.rs:214` server-side `403` defense-in-depth (even if `HttpTool` bypassed, metadata `169.254.169.254` → `403 host resolves to a blocked address`, verified `curl -X POST /v1/execute {"tool":"http","args":{"url":"https://169.254.169.254/"}}` → 403).
- [x] SDKs `sdk/js/index.js` + `sdk/python/marshall_sdk.py` thin clients (`health`, `tools`, `createSession`, `execute`, `stream` SSE) + `sdk/README.md`.
- [x] Firecracker vs gVisor decision `docs/ARCHITECTURE.md:1` — hybrid: Firecracker for `shell` (any ELF), WASM for `code` (fuel, 5ms), `ContainerBackend` wired to `watchdog` pool.

### Phase 3.5: Capability Expansion — DONE (Engineering > Enterprise)
- [x] **FS expanded** `src/fs.rs:80` `stat` (metadata), `copy`/`move` (sandbox-checked dest), `append` (atomic read+write), `search` (substring grep, recursive, capped 1000, 512-char line). Schema: `read/list/stat/search` read-only; `write/mkdir/delete/stat/copy/move/append/search` writable. Verified smoke `capability_smoke: stat, copy, move, append, search` green.
- [x] **Shell expanded** `src/shell.rs:122` `stdin`/`stdin_base64` (capped `stdin_limit 1MiB`), wired `cpu_time`/`memory_bytes` → `ResourceLimits` (wasmtime fuel / cgroup), `with_stdin_limit()`, schema updated. Backend `ExecRequest{stdin}` + `LocalProcessBackend` piped stdin. Smoke `cat` with stdin green.
- [x] **HTTP expanded** `src/http.rs:167` `headers` schema exposed (`allowed_request_headers`), actual `request.header(k,v)` forwarding, still blocks `authorization`/`cookie`/`host`.
- [x] **Wasm real** `src/backend.rs:333` `execute_wasm` now uses `wasmtime 22 + wasmtime-wasi 22 + cap-std 3` with `Config::consume_fuel`, `Store::set_fuel`, `WasiCtxBuilder` (stdin/stdout/stderr pipes, `preopened_dir` sandbox `/sandbox`), `store.limiter` memory cap, `epoch_deadline` timeout, `Linker` `preview1`, `_start`/`run` export, fuel/timeout → `timed_out`, truncate to `output_limit`. Feature `wasm` heavy compile guarded.
- [x] **Batch** `src/registry.rs:200` `execute_batch(requests, max_concurrency)` with `Semaphore` preserve order, `POST /v1/execute/batch` in `marshalld.rs:321` (max 32). Tested `batch 2× echo` + `shell stdin` + `fs stat` via HTTP.
- [x] **Sequence** `src/registry.rs:233` `execute_sequence(requests, continue_on_error)` strict order, stops on first `Err` or `success==false` unless `continue_on_error=true`, `POST /v1/execute/sequence {steps: [{tool,args}], continue_on_error}` → `{outcomes, executed, total}`. Verified `sequence 3× echo` all ok, `sequence with failing middle stops at 2/3`, `continue_on_error` runs all 3. SDKs `sdk/js` `batch()`/`sequence()` + `sdk/python` `batch()`/`sequence()`.

## 2. Decisions Needed
- Deployment: hosted cloud vs VPC on-prem (determines Firecracker priority)
- Code exec language: WASM-only vs Python container first

## 3. Metrics
- `cargo test` + `cargo test --test escapes` green
- `cargo fuzz` 1h no panic on `parse`
- 10k concurrent `execute_once` no leak
- Linux `openat2` TOCTOU closed

### Phase 4: Hardening & Observability — DONE (Engineering)
- [x] **Sandbox TOCTOU** `src/sandbox.rs:18` Linux `openat2 RESOLVE_BENEATH` branch `resolve_with_openat2()` (stub until `rustix`, falls back to `canonicalize` + `contains` on macOS/old kernel) + doc update.
- [x] **Fuzz** `fuzz/fuzz_destination.rs:1` 10-url corpus (`host_of` + `validate_destination` no panic) + `cargo run --bin fuzz_destination` ok + `#[cfg(test)] corpus_does_not_panic`, ready for `cargo fuzz run fuzz_destination`.
- [x] **Metrics** `src/bin/marshalld.rs:52` `Metrics{requests_total, success_total, failure_total, duration_ms_sum}` `GET /metrics` prometheus `text/plain; version=0.0.4`, `#[tracing::instrument]` on `execute` `list_tools`, `inc_request`/`observe` per outcome. Verified `curl /metrics` before 0 → after 1 shell `marshalld_requests_total 1, success 1, duration 6`.
- [x] **Stress** `tests/stress.rs:1` `ten_k_execute_once_bounded` 10k distinct keys with `cache_capacity 1024` → `cache_len <=1024` + 100 parallel ×100 concurrent, `registry.rs:200` eviction fix `> max` after insert.

### Phase 5: Marshall rename + System tool — DONE (`0.2.0`)
- [x] **Rename** `execution-tool` -> `marshall` (crate/lib), `executiond` -> `marshalld` (daemon, `MARSHALLD_*` env, `marshalld_*` metrics, `/tmp/marshalld`), `execution.yaml` -> `marshall.yaml`, `marshall-redaction-v1`, SDKs `marshall-sdk` / `marshall_sdk.py`. Breaking, no compat shims. Historical `validation/experiments/*` + `audit.jsonl` left untouched as audit trail.
- [x] **SystemTool** `src/system.rs:1` `now/sleep/env_get/env_list/hash/info/process_list/process_kill` with `SystemPolicy` (`allowed_env`, `allow_process_list`, `allow_kill`, `max_sleep_ms`) + `ExecutionPolicy.system` + `marshall.yaml:system` + `marshalld` registration (10 tools). Env values in `content` only, `process_list` Linux `/proc` capped 256 no cmdline, `process_kill` `term/kill` via `rustix` refusing pid 0/1/self. Tests: 9 unit + 2 escape regressions + 2 policy tests.
- [x] **Observability fix** `chrono_like_now()` now RFC3339 via `chrono` (was epoch-seconds string despite `chrono` dep).

### Phase 6: Next gaps (proposed, not started)
- **Persistence** — `memory/todo/plan` are `RwLock<HashMap>` in-process; restart wipes agent state. Options: JSONL snapshot per session or sqlite. Needs session expiry/GC (currently unbounded `sessions` map).
- **fd-secure I/O** — `openat2` fd is dropped after `read_link`; retain fd for true no-TOCTOU reads/writes. Parent-`..` `resolve_for_create` still falls back to `canonicalize`.
- **`NoFlags` heuristic** — documents itself as heuristic; a positional-as-script binary is still exploitable. Consider per-binary profiles or removing `NoFlags` for interpreters.
- **Rate limits / auth** — `Semaphore(32)` + `503` only; no per-token quotas, no auth on `/v1/*`. Any client on the port is root-equivalent within policy.
- **Process scope** — `process_list` Linux-only; macOS/Windows return `not_supported`. `process_kill` has no cgroup scoping (can signal any permitted pid, not just session children).
- **Supply chain** — `watchdog` pinned to git `main` (unpinned rev); `cargo audit` in CI but no `cargo deny` / SBOM.

## 4. Implementation Order
P0.1 -> P0.2 -> P0.4 -> P0.3 -> P0.5 -> Phase 1 -> Phase 2 -> Phase 3 -> Phase 3.5 -> Phase 4 -> Phase 5 -> Phase 6

> Verified (`0.2.0`): `cargo test --lib` **153** + `cargo test --test escapes` **14** + `1 stress` green, `cargo clippy --all-targets` + `fmt` clean, `cargo run --bin fuzz_destination` ok, `marshalld` smoke (`/health` 10 tools, `/v1/execute` system `now/hash/env_get`, `/metrics` `marshalld_*`) green.
