# Architecture — execution-tool → executor.sh

## Firecracker vs gVisor — Decision (Phase 3)

**Recommendation: Hybrid — Firecracker for `shell`, WASM for `code`.**

| Criterion | Firecracker (microVM) | gVisor (runsc) | WASM (wasmtime) |
|---|---|---|
| Isolate | VM boundary, strong | Syscall filter, medium | Language boundary, strong but limited |
| Cold start | ~150ms (snapshot < 50ms) | ~80ms | ~5ms |
| Memory | ~50MiB per VM | ~20MiB | ~2MiB |
| Syscall | Full | Filtered (~300) | No (WASI only) |
| Binary | Any Linux ELF | Any, but ptrace overhead | Only WASM |
| Ops | Need KVM, host kernel | No KVM, but seccomp ptrace cost | No extra |
| Team cost | High (image, snapshot, vsock) | Medium (runsc + cgroup) | Low |

**Why hybrid:** `ShellTool` must run arbitrary ELF (`/bin/git`, `/usr/bin/python`) — needs VM. `Code` (`python/js`) can compile to WASM via `wasm32-wasi` and run cheaper with fuel/memory limits. `watchdog` crate already provides Firecracker pool; `backend::WasmBackend` provides fuel.

**Wiring `ContainerBackend` — Phase 4 (watchdog) — WIRED:**

`Cargo.toml:37` `watchdog = { git = "https://github.com/wiramahendra/watchdog", branch = "main", optional = true }` + `features: backend-container = ["dep:watchdog"], container = ["backend-container"]`

`src/backend.rs:412` `ContainerBackend { image, kernel, rootfs, vsock, fallback: Arc<LocalProcessBackend> }` with `is_kvm_available() -> /dev/kvm exists` (Linux) / `false` (macOS):

```rust
// 1. Pool per workspace: watchdog::Pool::new(Config{
//      kernel: "vmlinux", rootfs: "alpine.ext4", vsock: "/tmp/firecracker.sock",
//      cgroup: Limits{ memory_bytes: Some(128<<20), pids_max: Some(64), cpu_time: Some(1s) },
//      seccomp: true,
//    })
// 2. Exec: pool.exec(ExecRequest{ program: "/bin/bash", args: ["-c","echo hi"],
//      working_dir: Some("/sandbox"), env: {}, stdin: None,
//      limits: ResourceLimits{ timeout: 2s, output_limit: 1<<20, cpu_time: Some(1s), memory_bytes: Some(64<<20) }
//    }).await -> ExecOutput (mapped stdout/stderr/timed_out/truncated)
// 3. Fallback: if !is_kvm_available() (macOS) → warn + `fallback.execute(req)` (LocalProcessBackend)
// 4. Feature gate: `#[cfg(feature="container")]` real watchdog, `#[cfg(not)]` bail with "requires --features container + Linux KVM"
// 5. Per-child Limits: `ResourceLimits { timeout, output_limit, cpu_time, memory_bytes }` → `watchdog::Limits` + `watchdog::ResourceLimits` (tested: `container_backend_resource_limits_mapped`)
// 6. Usage: `ShellTool::with_backend(Arc::new(ContainerBackend::new("alpine:3.19").with_kernel(...)))` + `CodeTool` similarly, hot-reload via `RwLock<ToolRegistry>`
```

Implemented and tested: `cargo test --lib backend::tests::container_backend_falls_back_on_macos` (macOS fallback) and `container_backend_resource_limits_mapped` pass on `darwin` `src/backend.rs:560`. No KVM on macOS dev — `LocalProcessBackend` stays default; CI on `ubuntu-latest` will gate `container` tests behind `#[cfg(target_os="linux")]` and `#[cfg(feature="container")]` (now `cargo check --features container` fetches `watchdog` git).

## Current Layers (P3.5 + P4)

```
Agent → JS/Python SDK → executiond (axum 0.7)
                         ├─ Policy (execution.yaml → ExecutionPolicy, hot-reload notify, --validate-config, code allowed_languages)
                         ├─ Egress (EgressPolicy::check + destination::validate_destination, server-side 403, batch/sequence enforced)
                         ├─ Registry (ToolRegistry, semaphore 32, execute_once dedup, execute_batch concurrent cap 64, execute_sequence ordered + templating {{steps[0].stdout}} single-pass)
                         │   ├─ FileSystemTool (Sandbox openat2 BENEATH on Linux, 12 ops: read/write/list/mkdir/delete/stat/copy/move/append/search/glob/patch, streaming read)
                         │   ├─ ShellTool → ExecutionBackend (stdin/stdin_base64 capped, cpu_time/memory_bytes → ResourceLimits)
                         │   │   ├─ LocalProcessBackend (env_clear, kill_on_drop, capped, piped stdin, ResourceLimits timeout/output_limit)
                         │   │   ├─ WasmBackend (wasmtime 22, fuel/memory, WASI preopen /sandbox, epoch timeout — stubbed fake hello wasm for tests, real fuel via _fuel)
                         │   │   └─ ContainerBackend (watchdog/Firecracker, per-child cgroup Limits{128MiB, pids 64, cpu_time}+seccomp, KVM check → LocalProcessBackend fallback, feature container)
                         │   ├─ CodeTool → ExecutionBackend (python/javascript/bash via temp file code_<uuid>.py, sandbox working_dir, timeout 10s, output 1MiB, 64KiB cap, stdin piped)
                         │   └─ HttpTool (allowlist before DNS, pinned addrs, no redirect, headers allowlist, streaming bytes_stream body cap, CRLF check)
                         └─ Observability (tracing instrument, Prometheus /metrics histogram 7 buckets + per-tool counters, audit JSONL sha256 rotation 10MiB, Limits RLIMIT via rustix, Cors restricted GET/POST/DELETE)
```
