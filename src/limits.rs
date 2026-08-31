#![allow(missing_docs)]
//! Resource limits — cgroup/RLIMIT/seccomp hook for `watchdog` integration.
//!
//! Phase 1 exposes the knobs; Phase 2 wires them to the OS.
//! On macOS/Linux without `watchdog` these are advisory (timeout + output_limit
//! already enforced by `LocalProcessBackend`). On Linux with `watchdog` they
//! become `cgroup v2` `cpu.max`/`memory.max` + `RLIMIT_NPROC/NOFILE` + seccomp
//! `deny mount, ptrace, kexec`.

use std::time::Duration;

/// Limits for a single tool invocation.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Wall time.
    pub timeout: Duration,
    /// Per-stream byte cap.
    pub output_limit: usize,
    /// CPU time (wasmtime fuel or cgroup `cpu.max`).
    pub cpu_time: Option<Duration>,
    /// Memory bytes (`memory.max` or wasmtime limiter).
    pub memory_bytes: Option<u64>,
    /// Max pids (`pids.max` / `RLIMIT_NPROC`).
    pub pids_max: Option<u64>,
    /// Max open files (`RLIMIT_NOFILE`).
    pub nofile: Option<u64>,
    /// Whether to apply seccomp `deny mount/ptrace/kexec` (Linux + watchdog).
    pub seccomp: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            output_limit: 1024 * 1024,
            cpu_time: None,
            memory_bytes: None,
            // pids_max/nofile are None by default — setting them globally via
            // `setrlimit` in the server process would cap the entire server
            // (e.g. 64 pids → EAGAIN fork). Per-child limits should be set
            // via `pre_exec` or cgroup, not via the server's own rlimit.
            pids_max: None,
            nofile: None,
            seccomp: false,
        }
    }
}

impl Limits {
    /// Apply RLIMITs to the current process (best-effort, Unix only).
    /// Real cgroup/seccomp wiring lives in `watchdog`; this now actually
    /// calls `setrlimit` via `rustix` for `NOFILE`, `NPROC`, `AS`, `CPU`.
    pub fn apply_rlimits(&self) {
        #[cfg(unix)]
        {
            if let Some(n) = self.nofile {
                set_rlimit(rustix::process::Resource::Nofile, n);
            }
            if let Some(n) = self.pids_max {
                set_rlimit(rustix::process::Resource::Nproc, n);
            }
            if let Some(b) = self.memory_bytes {
                set_rlimit(rustix::process::Resource::As, b);
            }
            if let Some(d) = self.cpu_time {
                set_rlimit(rustix::process::Resource::Cpu, d.as_secs());
            }
        }
    }
}

#[cfg(unix)]
fn set_rlimit(resource: rustix::process::Resource, limit: u64) {
    use rustix::process::{setrlimit, Rlimit};
    let lim = Rlimit {
        current: Some(limit),
        maximum: Some(limit),
    };
    let _ = setrlimit(resource, lim);
}
