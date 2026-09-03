//! System tool — time, environment, hashing, and process inspection.
//!
//! A deny-by-default companion to `shell` for the read-only questions agents
//! ask constantly ("what time is it?", "is this env var set?", "what is
//! running?") without handing them a shell to answer with.
//!
//! Operations (`operation`):
//! - `now` — current UTC time (`unix_ms`, RFC3339). Always allowed.
//! - `sleep` — sleep `duration_ms` (`1..=max_sleep_ms`). Bounded so an agent
//!   cannot stall a sequence.
//! - `env_get` — value of one allowlisted env key. The value travels in
//!   `content` only; `summary` carries key, byte count, and sha256.
//! - `env_list` — which allowlisted keys are currently set. Keys only, never
//!   values.
//! - `hash` — SHA-256 of `input` (`1..64KiB`). Pure computation, always
//!   allowed. Useful for evidence without storing payloads.
//! - `info` — static host facts: `os`, `arch`, `pid`, time. Always allowed.
//! - `process_list` — Linux `/proc` scan, capped at 256 entries, no cmdline
//!   arguments (those leak secrets). Gated by `allow_process_list`
//!   (default deny). Elsewhere returns `not_supported`.
//! - `process_kill` — `SIGTERM`/`SIGKILL` to one pid via `rustix`. Gated by
//!   `allow_kill` (default deny). Refuses pid 0/1 and our own pid.
//!
//! Every allowlist starts empty, so `env_get`/`env_list` do nothing until
//! configured, and process operations are refused unless explicitly enabled.

use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::{sha256_hex, Tool, ToolOutcome};

/// Longest `hash` input accepted (64 KiB).
pub const MAX_HASH_INPUT_BYTES: usize = 64 * 1024;
/// Longest env key accepted.
pub const MAX_ENV_KEY_LEN: usize = 256;
/// Cap on `process_list` entries.
pub const MAX_PROCESS_ENTRIES: usize = 256;
/// Default ceiling for a single `sleep`.
pub const DEFAULT_MAX_SLEEP_MS: u64 = 5_000;
/// Hard ceiling for `max_sleep_ms` configuration.
pub const MAX_SLEEP_MS_HARD_CAP: u64 = 30_000;

/// Policy for [`SystemTool`]. Deny-by-default: no env keys, no process
/// access, 5s max sleep.
#[derive(Debug, Clone)]
pub struct SystemPolicy {
    /// Env keys readable via `env_get` / visible via `env_list`.
    pub allowed_env: HashSet<String>,
    /// Whether `process_list` is permitted (Linux `/proc` only).
    pub allow_process_list: bool,
    /// Whether `process_kill` is permitted (`term`/`kill` only).
    pub allow_kill: bool,
    /// Upper bound for one `sleep` call.
    pub max_sleep_ms: u64,
}

impl Default for SystemPolicy {
    fn default() -> Self {
        Self {
            allowed_env: HashSet::new(),
            allow_process_list: false,
            allow_kill: false,
            max_sleep_ms: DEFAULT_MAX_SLEEP_MS,
        }
    }
}

/// Read-only system facts and bounded process control for agents.
#[derive(Debug, Clone, Default)]
pub struct SystemTool {
    policy: SystemPolicy,
}

impl SystemTool {
    /// A tool with everything denied (except `now`/`hash`/`info`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow reading these env keys (exact match, case-sensitive).
    pub fn with_allowed_env(mut self, keys: Vec<String>) -> Self {
        self.policy.allowed_env = keys.into_iter().collect();
        self
    }

    /// Permit `process_list` (Linux `/proc` scan, no cmdline).
    pub fn with_process_list(mut self, allow: bool) -> Self {
        self.policy.allow_process_list = allow;
        self
    }

    /// Permit `process_kill` (`term`/`kill` only, never pid 0/1/self).
    pub fn with_kill(mut self, allow: bool) -> Self {
        self.policy.allow_kill = allow;
        self
    }

    /// Cap a single `sleep` (`1..=30_000ms`).
    pub fn with_max_sleep_ms(mut self, ms: u64) -> Self {
        self.policy.max_sleep_ms = ms.clamp(1, MAX_SLEEP_MS_HARD_CAP);
        self
    }

    fn op_of(args: &Value) -> Result<&str> {
        args.get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing_operation"))
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn valid_env_key(key: &str) -> bool {
    if key.is_empty() || key.len() > MAX_ENV_KEY_LEN {
        return false;
    }
    key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !key.bytes().next().is_some_and(|b| b.is_ascii_digit())
}

#[async_trait::async_trait]
impl Tool for SystemTool {
    fn name(&self) -> &str {
        "system"
    }

    fn description(&self) -> &str {
        "System facts and bounded control: UTC time, allowlisted env vars, SHA-256 hashing, host info, Linux process listing, and opt-in SIGTERM/SIGKILL to one pid. Deny-by-default; env keys and process access must be enabled."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["now", "sleep", "env_get", "env_list", "hash", "info", "process_list", "process_kill"],
                    "description": "Which query to run."
                },
                "duration_ms": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_SLEEP_MS_HARD_CAP,
                    "description": "Sleep duration for `sleep` (bounded by policy max_sleep_ms)."
                },
                "key": {
                    "type": "string",
                    "maxLength": MAX_ENV_KEY_LEN,
                    "description": "Env key for `env_get` (must be allowlisted, e.g. PATH, TZ)."
                },
                "input": {
                    "type": "string",
                    "maxLength": MAX_HASH_INPUT_BYTES,
                    "description": "Input string for `hash` (1..64KiB)."
                },
                "pid": {
                    "type": "integer",
                    "minimum": 2,
                    "description": "Target pid for `process_kill` (never 0/1/self)."
                },
                "signal": {
                    "type": "string",
                    "enum": ["term", "kill"],
                    "description": "Signal for `process_kill`. `term` (SIGTERM) lets the process clean up; `kill` (SIGKILL) does not."
                }
            },
            "required": ["operation"]
        })
    }

    async fn validate(&self, args: &Value) -> Result<()> {
        let op = Self::op_of(args)?;
        match op {
            "now" | "env_list" | "info" | "hash" if op == "hash" => {
                if op == "hash" {
                    let input = args
                        .get("input")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("missing_input"))?;
                    if input.is_empty() {
                        bail!("input_empty");
                    }
                    if input.len() > MAX_HASH_INPUT_BYTES {
                        bail!("input_too_long");
                    }
                }
                Ok(())
            }
            "now" | "env_list" | "info" => Ok(()),
            "sleep" => {
                let ms = args
                    .get("duration_ms")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("missing_duration_ms"))?;
                if ms == 0 || ms > self.policy.max_sleep_ms {
                    bail!("sleep_out_of_bounds");
                }
                Ok(())
            }
            "env_get" => {
                let key = args
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing_key"))?;
                if !valid_env_key(key) {
                    bail!("invalid_env_key");
                }
                if !self.policy.allowed_env.contains(key) {
                    bail!("env_not_allowed");
                }
                Ok(())
            }
            "process_list" => {
                if !self.policy.allow_process_list {
                    bail!("process_list_not_allowed");
                }
                Ok(())
            }
            "process_kill" => {
                if !self.policy.allow_kill {
                    bail!("process_kill_not_allowed");
                }
                let pid = args
                    .get("pid")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("missing_pid"))?;
                if pid <= 1 {
                    bail!("invalid_pid");
                }
                if pid == std::process::id() as u64 {
                    bail!("cannot_kill_self");
                }
                let sig = args.get("signal").and_then(Value::as_str).unwrap_or("term");
                if !matches!(sig, "term" | "kill") {
                    bail!("invalid_signal");
                }
                Ok(())
            }
            _ => anyhow::bail!("unknown_operation"),
        }
    }

    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;
        let op = Self::op_of(&args)?;
        match op {
            "now" => {
                let ms = now_ms();
                let summary = json!({
                    "operation": "now",
                    "unix_ms": ms,
                    "rfc3339": now_rfc3339(),
                    "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                });
                Ok(ToolOutcome::success("system", summary, elapsed(started)))
            }
            "sleep" => {
                let ms = args.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                let summary = json!({
                    "operation": "sleep",
                    "slept_ms": ms,
                    "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                });
                Ok(ToolOutcome::success("system", summary, elapsed(started)))
            }
            "env_get" => {
                let key = args.get("key").and_then(Value::as_str).unwrap_or("");
                match std::env::var(key) {
                    Ok(value) => {
                        let digest = sha256_hex(value.as_bytes());
                        let summary = json!({
                            "operation": "env_get",
                            "key": key,
                            "bytes": value.len(),
                            "sha256": digest,
                            "content_redacted": true,
                            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                        });
                        Ok(ToolOutcome::success("system", summary, elapsed(started))
                            .with_content(value.into_bytes())
                            .with_metadata("sha256", digest))
                    }
                    Err(_) => Ok(ToolOutcome::failure(
                        "system",
                        "env_not_found",
                        elapsed(started),
                    )),
                }
            }
            "env_list" => {
                let mut keys: Vec<String> = self
                    .policy
                    .allowed_env
                    .iter()
                    .filter(|k| std::env::var_os(k).is_some())
                    .cloned()
                    .collect();
                keys.sort();
                let summary = json!({
                    "operation": "env_list",
                    "keys": keys,
                    "count": keys.len(),
                    "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                });
                Ok(ToolOutcome::success("system", summary, elapsed(started)))
            }
            "hash" => {
                let input = args.get("input").and_then(Value::as_str).unwrap_or("");
                let digest = sha256_hex(input.as_bytes());
                let summary = json!({
                    "operation": "hash",
                    "bytes": input.len(),
                    "sha256": digest,
                    "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                });
                Ok(ToolOutcome::success("system", summary, elapsed(started))
                    .with_metadata("sha256", digest))
            }
            "info" => {
                let summary = json!({
                    "operation": "info",
                    "os": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                    "pid": std::process::id(),
                    "unix_ms": now_ms(),
                    "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                });
                Ok(ToolOutcome::success("system", summary, elapsed(started)))
            }
            "process_list" => execute_process_list(started).await,
            "process_kill" => {
                let pid = args.get("pid").and_then(Value::as_u64).unwrap_or(0);
                let sig = args.get("signal").and_then(Value::as_str).unwrap_or("term");
                execute_process_kill(started, pid as i32, sig)
            }
            _ => anyhow::bail!("unknown_operation"),
        }
    }
}

async fn execute_process_list(started: Instant) -> Result<ToolOutcome> {
    if !cfg!(target_os = "linux") {
        return Ok(ToolOutcome::failure(
            "system",
            "not_supported",
            elapsed(started),
        ));
    }
    let entries = tokio::task::spawn_blocking(read_proc_table)
        .await
        .unwrap_or_default();
    let truncated = entries.len() >= MAX_PROCESS_ENTRIES;
    let digest = sha256_hex(
        serde_json::to_string(&entries)
            .unwrap_or_default()
            .as_bytes(),
    );
    let summary = json!({
        "operation": "process_list",
        "count": entries.len(),
        "truncated": truncated,
        "processes_sha256": digest,
        "processes": entries,
        "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
    });
    Ok(ToolOutcome::success("system", summary, elapsed(started)))
}

/// Blocking `/proc` scan. No cmdline: process arguments routinely contain
/// tokens, paths, and flags an agent must not see by default.
fn read_proc_table() -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in dir.flatten() {
        if out.len() >= MAX_PROCESS_ENTRIES {
            break;
        }
        let name = entry.file_name();
        let Some(pid_str) = name.to_str() else {
            continue;
        };
        if !pid_str.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid_str}/comm"))
            .map(|s| {
                let t = s.trim().to_string();
                if t.len() > 128 {
                    t[..128].to_string()
                } else {
                    t
                }
            })
            .unwrap_or_else(|_| "?".into());
        let state = std::fs::read_to_string(format!("/proc/{pid_str}/stat"))
            .ok()
            .and_then(|s| {
                s.rfind(')').and_then(|i| {
                    s[i + 2..]
                        .split_whitespace()
                        .next()
                        .map(|st| st.to_string())
                })
            })
            .unwrap_or_else(|| "?".into());
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        out.push(json!({"pid": pid, "name": comm, "state": state}));
    }
    out.sort_by_key(|v| v.get("pid").and_then(Value::as_u64).unwrap_or(0));
    out
}

fn execute_process_kill(started: Instant, pid: i32, sig: &str) -> Result<ToolOutcome> {
    let signal = match sig {
        "term" => rustix::process::Signal::Term,
        "kill" => rustix::process::Signal::Kill,
        _ => bail!("invalid_signal"),
    };
    let Some(target) = rustix::process::Pid::from_raw(pid) else {
        bail!("invalid_pid");
    };
    match rustix::process::kill_process(target, signal) {
        Ok(()) => {
            let summary = json!({
                "operation": "process_kill",
                "pid": pid,
                "signal": sig,
                "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
            });
            Ok(ToolOutcome::success("system", summary, elapsed(started)))
        }
        Err(e) => {
            let code = match e {
                rustix::io::Errno::PERM => "kill_permission_denied",
                rustix::io::Errno::SRCH => "process_not_found",
                _ => "kill_failed",
            };
            Ok(ToolOutcome::failure("system", code, elapsed(started)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn now_and_info_need_no_policy() {
        let tool = SystemTool::new();
        let now = tool.execute(json!({"operation": "now"})).await.unwrap();
        assert!(now.success);
        assert!(now.summary.get("unix_ms").is_some());

        let info = tool.execute(json!({"operation": "info"})).await.unwrap();
        assert!(info.success);
        assert_eq!(
            info.summary.get("os").and_then(Value::as_str),
            Some(std::env::consts::OS)
        );
    }

    #[tokio::test]
    async fn hash_matches_sha256_hex() {
        let tool = SystemTool::new();
        let out = tool
            .execute(json!({"operation": "hash", "input": "abc"}))
            .await
            .unwrap();
        assert!(out.success);
        assert_eq!(
            out.summary.get("sha256").and_then(Value::as_str),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[tokio::test]
    async fn env_is_deny_by_default_and_allowlisted_when_configured() {
        let denied = SystemTool::new();
        assert!(denied
            .validate(&json!({"operation": "env_get", "key": "PATH"}))
            .await
            .is_err());

        std::env::set_var("MARSHALL_TEST_VAR", "s3cret");
        let tool = SystemTool::new().with_allowed_env(vec!["MARSHALL_TEST_VAR".into()]);
        let out = tool
            .execute(json!({"operation": "env_get", "key": "MARSHALL_TEST_VAR"}))
            .await
            .unwrap();
        assert!(out.success);
        // Value in content only, never in the log-safe summary.
        assert_eq!(out.content, Some(b"s3cret".to_vec()));
        assert!(!serde_json::to_string(&out.summary)
            .unwrap()
            .contains("s3cret"));

        let list = tool
            .execute(json!({"operation": "env_list"}))
            .await
            .unwrap();
        assert!(list.success);
        let keys = list
            .summary
            .get("keys")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(keys.contains(&json!("MARSHALL_TEST_VAR")));
        std::env::remove_var("MARSHALL_TEST_VAR");
    }

    #[tokio::test]
    async fn env_key_shape_is_validated() {
        let tool = SystemTool::new().with_allowed_env(vec!["123BAD".into(), "HAS SPACE".into()]);
        assert!(tool
            .validate(&json!({"operation": "env_get", "key": "123BAD"}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"operation": "env_get", "key": "HAS SPACE"}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn sleep_is_bounded_by_policy() {
        let tool = SystemTool::new().with_max_sleep_ms(50);
        assert!(tool
            .validate(&json!({"operation": "sleep", "duration_ms": 51}))
            .await
            .is_err());
        let out = tool
            .execute(json!({"operation": "sleep", "duration_ms": 5}))
            .await
            .unwrap();
        assert!(out.success);
        assert_eq!(out.summary.get("slept_ms").and_then(Value::as_u64), Some(5));
    }

    #[tokio::test]
    async fn process_operations_deny_by_default() {
        let tool = SystemTool::new();
        assert!(tool
            .validate(&json!({"operation": "process_list"}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"operation": "process_kill", "pid": 1234}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_kill_refuses_dangerous_targets() {
        let tool = SystemTool::new().with_kill(true);
        assert!(tool
            .validate(&json!({"operation": "process_kill", "pid": 1}))
            .await
            .is_err());
        let self_pid = std::process::id() as u64;
        assert!(tool
            .validate(&json!({"operation": "process_kill", "pid": self_pid}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"operation": "process_kill", "pid": 999999, "signal": "hup"}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn process_list_returns_table_or_not_supported() {
        let tool = SystemTool::new().with_process_list(true);
        let out = tool
            .execute(json!({"operation": "process_list"}))
            .await
            .unwrap();
        if cfg!(target_os = "linux") {
            assert!(out.success);
            assert!(out.summary.get("count").is_some());
            // No cmdline arguments leak into the table.
            let text = serde_json::to_string(&out.summary).unwrap();
            assert!(!text.contains("cmdline"));
        } else {
            assert!(!out.success);
            assert_eq!(out.error_code.as_deref(), Some("not_supported"));
        }
    }

    #[tokio::test]
    async fn unknown_operations_are_rejected() {
        let tool = SystemTool::new();
        assert!(tool
            .validate(&json!({"operation": "reboot"}))
            .await
            .is_err());
        assert!(tool.validate(&json!({})).await.is_err());
    }
}
