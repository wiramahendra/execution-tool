# Marshall

Marshall is sandboxed tool execution for agents — filesystem, shell, HTTP, code, system, and agentic planning, each behind a policy that denies by default.

```rust
use std::sync::Arc;
use marshall::{CodeTool, FileSystemTool, HttpTool, MemoryTool, ThinkTool, TodoTool, Sandbox, ToolRegistry};

let sandbox = Sandbox::new(["/srv/agent/workspace"])?;

let mut tools = ToolRegistry::new();
tools.register(Arc::new(FileSystemTool::new(sandbox.clone())));   // read-only, 12 ops
tools.register(Arc::new(HttpTool::new(["api.github.com"])));      // SSRF-protected
tools.register(Arc::new(CodeTool::new().with_sandbox(sandbox.clone()).allow_all())); // python/bash/js via temp file
tools.register(Arc::new(ThinkTool));                              // scratchpad
tools.register(Arc::new(MemoryTool::new()));                      // session-aware KV
tools.register(Arc::new(TodoTool::new()));                        // session-aware todo
```

Every allowlist starts empty, so an unconfigured tool does nothing at all. `marshalld` exposes 10 tools via `GET /v1/tools`.

## What "sandboxed" means here

Each tool checks its target against an allowlist before acting: paths must resolve inside a configured root, hosts must resolve to public addresses, commands must be on a list, languages must be allowlisted.

It does **not** mean OS-level isolation. There is no seccomp filter, no namespace, no chroot, no separate process. A tool that gets past its policy has the parent's full privileges. If you need real isolation, run this inside something that provides it — the sibling [`watchdog`] crate does resource bounds and process containment, and composes with this. `WasmBackend`/`ContainerBackend` are scaffolded (`src/backend.rs:338` stub) and `LocalProcessBackend` is the default (`env_clear`, `kill_on_drop`, capped I/O).

[`watchdog`]: https://github.com/wiramahendra/watchdog

## SSRF protection

This is the part that took the most care. When an agent chooses its own URLs, the target that matters is the cloud metadata endpoint at `169.254.169.254`, which hands out instance credentials to anything inside the instance that asks.

Naive URL validation does not stop it. Each of these defeats a check that looks reasonable, and `tests/escapes.rs` asserts each one is refused:

| attempt | why a simple check misses it |
|---|---|
| `https://169.254.169.254/` | a literal blocklist catches this one address and nothing else |
| `https://[::ffff:169.254.169.254]/` | IPv4-mapped IPv6 is the same address, spelled differently |
| `https://[2002:a9fe:a9fe::1]/` | 6to4 embeds an arbitrary IPv4 address in an IPv6 one |
| `https://example.com@169.254.169.254/` | the host is the metadata endpoint; parsers that split on `@` read `example.com` |
| `https://metadata.evil.com/` | a public-looking name with a private A record |
| `https://ok.com/` → 302 → metadata | the redirect is a request nobody validated |
| DNS answers public to the checker, private to the client | validation and connection resolve separately |

The last two cannot be handled by URL inspection at all, so `HttpTool` refuses redirects outright and pins the connection to the addresses that were actually validated (`resolve_to_addrs`) rather than re-resolving the name. `EgressPolicy` enforces the same server-side in `marshalld` (`403` even if client bypasses).

Ports are an allowlist (`443`, `8443` for public `https`; `80,3000,8000,8080,5000` etc for loopback `http`), not a blocklist, because an agent that can pick arbitrary ports can map its own network through timing differences even when every address check holds. `is_blocked_v6` also covers `NAT64 64:ff9b::/96`, `ORCHID`, `fec0::/10`, `100::/64`, `192.0.0.170/32`, etc (`src/destination.rs:322`).

The host allowlist is also checked **before** any DNS lookup. Resolving first turns every rejected request into a lookup for whatever hostname the agent supplied, and a hostname is an excellent channel for getting data out of a network that blocks everything else. Percent-encoded hosts (`%65`) and numeric IP bypasses (`0xC0.0xA8...`, `0300...`, `3232235777`) are rejected as `malformed`.

## The shell tool is not a sandbox

Read this before enabling it.

An allowlist decides *which binary* runs. It does not decide what that binary does, and for most real binaries the arguments decide that entirely:

```text
allow /usr/bin/find  →  find / -exec sh -c '…' \;
allow /usr/bin/git   →  git --exec-path=/tmp/evil status
allow /usr/bin/tar   →  tar --to-command=/tmp/evil -xf …
```

Each is an allowlisted binary reaching arbitrary execution through its own documented options. `ArgumentPolicy` is the control that matters:

```rust
use marshall::{ArgumentPolicy, ShellTool, shell::AllowedCommand};

ShellTool::new(vec![
    // Safe by construction.
    AllowedCommand::new("/usr/bin/uptime"),

    // Only these exact invocations.
    AllowedCommand::new("/usr/bin/git")
        .with_arguments(ArgumentPolicy::Exact(vec![vec!["status".into()]])),

    // Positionals but no options — blocks the shapes above.
    AllowedCommand::new("/usr/bin/wc")
        .with_arguments(ArgumentPolicy::NoFlags),
]);
```

It defaults to `ArgumentPolicy::None`. Programs must be absolute paths, so whoever controls `PATH` does not get to choose the binary. No shell is invoked, so `;`, `|`, and `$(…)` in arguments are inert. `stdin`/`stdin_base64` are piped (capped 1MiB, base64 raw length pre-checked `src/shell.rs:314`).

## Output is redacted by default

A tool result travels further than the call that produced it — into a transcript, a log line, a trace span, sometimes an evidence record. If the result carries file contents, every one of those becomes a copy.

So `ToolOutcome` splits them. `summary` is structured, bounded, and safe to log:

```json
{"operation":"read","bytes":20,"sha256":"6e459f…","truncated":false,
 "content_redacted":true,"redaction_policy_version":"marshall-redaction-v1"}
```

The bytes live in `content`, which is `None` unless the tool produced a payload and is omitted entirely from the serialized form. Logging an outcome is therefore the safe thing as well as the easy thing. HTTP response headers pass through an allowlist, so `set-cookie` and `authorization` never reach a log. `think`/`reflect` content is also hashed.

## What this fixes

The code this was extracted from had a well-built destination policy and a badly-built sandbox. Both filesystem escapes below were confirmed by running them before the rewrite:

- **String prefixes were treated as path prefixes.** A root of `/tmp/safe` admitted `/tmp/safe_evil/…` — a sibling directory sharing a textual prefix. `Path::starts_with` compares whole components; `str::starts_with` does not.
- **`..` was rejected textually and paths were otherwise trusted.** A symlink at `/tmp/safe/link -> /etc` made `/tmp/safe/link/passwd` legal by inspection and an arbitrary read in practice. Everything canonicalizes now, with `openat2 RESOLVE_BENEATH` on Linux (`src/sandbox.rs:191`, `rustix 0.38`) closing the TOCTOU race; fallback to `canonicalize` on macOS.
- **The shell allowlist covered the binary and not its arguments**, which for most binaries is no restriction at all. Hence `ArgumentPolicy`.
- **Programs resolved through `PATH`.** Absolute paths only now.
- **A timed-out child was never killed** — `tokio::time::timeout` dropped the future and left the process running. `kill_on_drop` now.
- **stdout, stderr, response bodies, and file reads were unbounded.** All capped via streaming (`read_file_capped` 64MiB clamp, `http` bytes_stream 1MiB, shell 1MiB), truncation reported.
- **A hand-rolled DNS fallback** queried `1.1.1.1` over UDP without verifying the response transaction ID — spoofable off-path, in the middle of the check it was part of. Removed; resolution failure now fails closed.
- **Missing address ranges**: 6to4 relay, IETF protocol assignments, reserved `240/4`, Teredo, IPv4-compatible IPv6, NAT64 `64:ff9b::/96`, ORCHID `2001:10::/28`, `fec0::/10`, `100::/64`, numeric IP bypass.

Dropped from the extraction: a database tool that forwarded inserts to a specific internal HTTP gateway. It was a client for one service rather than a general capability.

## Honest limits

- **TOCTOU.** On Linux the check is now via `openat2` `RESOLVE_BENEATH` (`src/sandbox.rs:191`, `rustix 0.38`), closing the symlink-swap race for `resolve_existing` and `resolve_for_create` (parent `..` case still falls back to `canonicalize` for `parent == "."`). On other platforms the classic check-then-use race remains. `openat2` fd is dropped after `read_link /proc/self/fd` — true fd-secure I/O not yet retained.
- **`ArgumentPolicy::NoFlags` is a heuristic**, not a guarantee. A binary that treats a bare positional as a script name is still fully exploitable.
- **No isolation by default.** Repeating it because it matters: this is policy, not a sandbox in the kernel sense. Use `backend::WasmBackend` (wasmtime fuel/memory, WASI preopen `/sandbox`, epoch timeout — currently stubbed to fake `hello wasm` for compilation, `cargo test --features wasm` uses heuristic) or `backend::ContainerBackend` (watchdog/Firecracker per-child `Limits{128MiB,pids 64,cpu_time}` + `seccomp` — `cargo check --features container` fetches `watchdog` git, `is_kvm_available()` checks `/dev/kvm` on Linux else fallback `LocalProcessBackend` with `tracing::warn` on `darwin` `src/backend.rs:412`, `cargo test --lib backend::tests::container_backend_falls_back_on_macos` verifies) for real isolation, or run `marshalld` behind them. `Limits::apply_rlimits` is server-wide, not per-child — per-child only via `watchdog`.
- **The HTTP tool trusts your allowlist.** If you allowlist a host that redirects or proxies, you have allowlisted wherever it points. Server-side `EgressPolicy` (`src/egress.rs:1`) now enforces `403` in `marshalld` even if client bypasses, and `batch`/`sequence` also enforce `dest::validate_destination` + `EgressPolicy::check` before fan-out.
- **Agentic state is in-memory.** `MemoryTool`/`TodoTool`/`PlanTool` are `RwLock<HashMap<scope, ...>>` with `scope = session_id|global` auto-injected from top-level `session_id` in `batch`/`sequence` (`src/bin/marshalld.rs:370` `inject_session_id`). No persistence across restarts, LRU eviction on cap.

## Current product state — 10 tools, 3 layers

**Execution (5):**
*   **Filesystem** `src/fs.rs:73` `read/write/list/mkdir/delete/stat/copy/move/append/search/glob/patch` (12 ops, `search` substring `recursive` capped 1000 + 512-char line, `glob` `**/*.py` canonical-inside `starts_with`, `patch` single `replacen` non-empty `search`, `read` streaming `read_file_capped` `read_limit` clamp `1..64MiB`, `with_read_limit`).
*   **Shell** `src/shell.rs:115` `stdin`/`stdin_base64` piped (capped 1MiB, raw base64 pre-checked `len > 4/3*limit+1024`), `cpu_time`/`memory_bytes` → `ResourceLimits` (wasmtime fuel `cpu_time*10k` / cgroup), `execute_streaming` SSE, `ArgumentPolicy` `None`/`Exact`/`NoFlags`/`Unrestricted`.
*   **HTTP** `src/http.rs:34` `allowlist before DNS` + `validate_destination` + `redirect none` + `resolve_to_addrs pin` + `https_only` + `streaming body cap` (`bytes_stream` + `Content-Length` pre-check `body_limit`/`request_body_limit` 4MiB) + `Header CRLF` check + `allowlisted_headers` + `body_sha256`.
*   **Code** `src/code.rs:51` `python`/`javascript`/`bash` via `ExecutionBackend` (deny-by-default `allowed_languages` `src/policy.rs:129` `code: {allowed_languages: [python,bash,javascript], timeout_ms, output_limit}`), `code 1..64KiB`, `stdin 1MiB`, `timeout 1..30000ms` (policy `code_timeout`), sandboxed `working_dir` from `Sandbox`, temp-file execution `write_code_to_file` `code_<uuid>_<lang>.<ext>` in `sandbox.roots[0]` or `temp_dir` then `python3 file`/`node file`/`bash file` with cleanup, `stderr` in summary.
*   **System** `src/system.rs:1` `now/sleep/env_get/env_list/hash/info/process_list/process_kill` (deny-by-default `SystemPolicy` `system: {allowed_env, allow_process_list, allow_kill, max_sleep_ms}`), `env` values in `content` only (`sha256` in summary), `hash` pure `sha256`, `sleep` bounded `1..max_sleep_ms`, `process_list` Linux `/proc` capped 256 no cmdline, `process_kill` `term/kill` via `rustix` refusing pid 0/1/self.

**Agentic planning (5) — no sandbox, session-aware:**
*   **Think** `src/agent.rs:26` `thought 1..4096` + `next_action? 1..512` + `confidence 0.0..1.0` + `alternatives[] max3` — private reasoning, `sha256` audit, always `success`.
*   **Memory** `src/agent.rs:98` `operation: store/recall/list/search/forget` `key 1..128` `value any JSON 16KiB` `ttl_ms 1s..1h` `session_id?` `query?` — `scope = session_id|global` auto-injected in `batch`/`sequence`, `RwLock<HashMap<scope, HashMap>>` LRU `max_keys 256`, `search` substring over keys+values cap 50.
*   **Todo** `src/agent.rs:312` `operation: add/list/get/update/done/clear` `task 1..512` `priority high|medium|low` `id/status pending|in_progress|done` `session_id?` — `HashMap<scope, Vec<TodoItem>>` `max 64`, `add` generates `tN`, `clear` removes `done`.
*   **Plan** `src/agent.rs:651` `operation: create/list/get/add_step/update_step/clear` `goal 1..512` `steps[] 1..16` `depends_on[]` `status pending|in_progress|done|blocked` `session_id?` — `scope -> plan_id -> Plan` `max_plans 32`, links `think` → `todo`.
*   **Reflect** `src/agent.rs:820` `outcome:object` `thought? 1..1024` `next_action?` — `critique` success vs `Failed — diagnose error_code`, `outcome_type` from `tool`.

**Registry `src/registry.rs:46`** `ToolRegistry` `execute` `execute_once` dedup `Mutex` TTL 300s cap 1024 + `execute_batch` concurrent `Semaphore 1..32` cap `64` preserve order + `execute_sequence` ordered `32` `continue_on_error` + templating `{{steps[0].stdout}}` single-pass 32 placeholders, safe `replace_range` not re-expanding, `cache_len` for metrics. Container tests gated `#[cfg(all(target_os="linux", feature="container"))]` for CI `ubuntu-latest` vs `darwin` fallback.

**Service `marshalld` `src/bin/marshalld.rs:1` (`axum 0.7` `tokio`):** `GET /health /metrics /v1/tools /v1/policy` `POST /v1/sessions` `DELETE /v1/sessions/:id` `POST /v1/execute /v1/execute/batch /v1/execute/sequence /v1/execute/stream` `session_id` top-level `Option<String>` validated `sessions.contains_key → 404 session_not_found`, `check_session_path` 403 outside `sess.root`, `EgressPolicy` + `dest::validate_destination` per-request and per-batch/step, `inject_session_id` auto-scopes `memory/todo/plan` to top-level `session_id`, `Semaphore 32` `503 concurrency_limited`, `MAX_BATCH 64` `MAX_STEPS 32`, `Prometheus` histogram `marshalld_requests_total` + `per-tool counters` + `marshalld_duration_ms_bucket`, `audit JSONL sha256 rotation 10MiB`, `tracing` `TraceLayer`, `Cors` restricted `GET/POST/DELETE` `AllowOrigin::any()`, `marshall.yaml` hot-reload `notify` `RwLock<ToolRegistry>` + `egress_hosts` swap debounced 300ms, `--validate-config`.

## Testing

```sh
cargo test                  # 108 lib (incl. code 6 + agent 3 + container 2) + 12 escapes + 1 stress
cargo test --test escapes   # attack regressions (sibling-prefix, symlink, traversal, option-injection, SSRF)
cargo test --test stress    # 10k execute_once bounded (cache 1024) ~8s
cargo run --bin fuzz_destination -- 10  # destination parse corpus (control/percent/numeric bypass)
cargo run --example agent_tools         # think→todo→memory→filesystem→code loop
cargo run --bin marshalld -- --config marshall.yaml --port 3000
curl http://localhost:3000/health
curl http://localhost:3000/v1/tools | jq '.[].name' # 10: code filesystem http memory plan reflect shell system think todo
curl http://localhost:3000/metrics | grep marshalld_tool
curl -X POST http://localhost:3000/v1/execute -d '{"tool":"code","args":{"language":"python","code":"print(42)"}}'
curl -X POST http://localhost:3000/v1/execute -d '{"tool":"think","args":{"thought":"plan","confidence":0.9}}'
# session-aware batch
curl -X POST http://localhost:3000/v1/sessions | jq .session_id # SID
curl -X POST http://localhost:3000/v1/execute/batch -d "{\"session_id\":\"$SID\",\"requests\":[{\"tool\":\"memory\",\"args\":{\"operation\":\"store\",\"key\":\"k\",\"value\":1}}]}"
```

`tests/escapes.rs` is written as attacks rather than assertions, because that is how they were found and the shape is the part worth keeping.

## Status

`0.2.0`. The API will move before `1.0`. 10 tools (5 execution + 5 agentic). `CodePolicy` default now `[python,bash,javascript]` `src/policy.rs:206` (was `[python,bash]`) to match `marshall.yaml:31`. Wasm stubbed (fake `hello wasm` unless `--features wasm` with real `wasmtime` 22), `ContainerBackend` wired with `watchdog` optional `container` feature + KVM check + fallback `LocalProcessBackend` `src/backend.rs:412` (`cargo test --lib backend::tests::container_backend_falls_back_on_macos` on `darwin`), `LocalProcessBackend` default. Agentic state in-memory per `marshalld` instance `scope=session_id|global` (not persisted, LRU). MIT.
