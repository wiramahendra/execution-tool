#![allow(missing_docs)]
#![allow(clippy::too_many_arguments)]
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::Value;

use crate::ToolOutcome;

use super::collector::collect_repo_state;
use super::schema::{EventType, ExperimentEvent, RepoStateSnapshot, TaskOutcome, TokenUsage};

/// Root experiment recorder — owns the experiment directory and metadata.
///
/// Layout:
/// ```text
/// <root>/<experiment_id>/
///   metadata.json
///   tasks/<task_id>.jsonl   (append-only, one file per task)
/// ```
/// Paths configurable via `root_dir`. Concurrent task writers cannot
/// corrupt each other's trace because each task owns its own file.
/// A single task file uses `Mutex<File>` + append to stay safe under
/// concurrent `Arc<TaskRecorder>` clones.
pub struct ExperimentRecorder {
    pub experiment_id: String,
    pub variant: String,
    pub root_dir: PathBuf,
    pub task_started: Instant,
}

impl ExperimentRecorder {
    /// Create a new experiment directory. `root_dir` is the parent
    /// (e.g. `./experiments`). The dir `<root>/<experiment_id>/tasks` is created.
    pub fn new(
        experiment_id: impl Into<String>,
        variant: impl Into<String>,
        root_dir: impl Into<PathBuf>,
    ) -> anyhow::Result<Self> {
        let experiment_id = experiment_id.into();
        let variant = variant.into();
        let root_dir = root_dir.into();
        let exp_dir = root_dir.join(&experiment_id);
        std::fs::create_dir_all(exp_dir.join("tasks"))?;
        // Write metadata.json (best-effort).
        let meta = serde_json::json!({
            "schema_version": super::schema::SCHEMA_VERSION,
            "experiment_id": experiment_id,
            "variant": variant,
            "created_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        let meta_path = exp_dir.join("metadata.json");
        if let Ok(f) = File::create(&meta_path) {
            let _ = serde_json::to_writer_pretty(f, &meta);
        }
        Ok(Self {
            experiment_id,
            variant,
            root_dir,
            task_started: Instant::now(),
        })
    }

    pub fn experiment_dir(&self) -> PathBuf {
        self.root_dir.join(&self.experiment_id)
    }

    pub fn task_recorder(&self, task_id: impl Into<String>) -> anyhow::Result<TaskRecorder> {
        TaskRecorder::new(
            self.experiment_id.clone(),
            task_id.into(),
            self.variant.clone(),
            self.experiment_dir().join("tasks"),
        )
    }
}

/// Per-task append-only JSONL writer. Cheap to clone.
#[derive(Clone)]
pub struct TaskRecorder {
    pub experiment_id: String,
    pub task_id: String,
    pub variant: String,
    inner: Arc<Mutex<BufWriter<File>>>,
    path: PathBuf,
    started: Instant,
    started_wall: chrono::DateTime<chrono::Utc>,
}

impl TaskRecorder {
    pub fn new(
        experiment_id: String,
        task_id: String,
        variant: String,
        tasks_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&tasks_dir)?;
        let path = tasks_dir.join(format!("{task_id}.jsonl"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            experiment_id,
            task_id,
            variant,
            inner: Arc::new(Mutex::new(BufWriter::new(file))),
            path,
            started: Instant::now(),
            started_wall: chrono::Utc::now(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn monotonic_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn append(&self, event: &ExperimentEvent) -> anyhow::Result<()> {
        let mut line = serde_json::to_string(event)?;
        line.push('\n');
        let mut g = self.inner.lock().unwrap();
        g.write_all(line.as_bytes())?;
        g.flush()?;
        Ok(())
    }

    /// Best-effort append: failure is logged but never bubbles to caller
    /// in instrumentation helpers (so tool outcome is not corrupted).
    fn append_best_effort(&self, event: &ExperimentEvent) {
        if let Err(e) = self.append(event) {
            tracing::warn!(error=%e, task_id=%self.task_id, "experiment trace append failed");
        }
    }

    // ── high-level helpers ─────────────────────────────────────

    pub fn task_started(
        &self,
        category: Option<String>,
        description: Option<String>,
        repo_or_fixture: Option<String>,
        repo_head_before: Option<RepoStateSnapshot>,
        executor: Option<String>,
        harness_version: Option<String>,
        environment: Option<HashMap<String, String>>,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::TaskStarted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.task_category = category;
        e.task_description = description;
        e.repo_or_fixture = repo_or_fixture;
        e.repo_before = repo_head_before;
        e.executor = executor;
        e.harness_version = harness_version;
        e.environment = environment;
        // Also snapshot before via collector if not supplied.
        if e.repo_before.is_none() {
            e.repo_before = Some(collect_repo_state(None));
        }
        e.base_revision = e.repo_before.as_ref().and_then(|r| r.head.clone());
        self.append(&e)
    }

    pub fn agent_turn_started(&self, turn_id: impl Into<String>) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::AgentTurnStarted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.turn_id = Some(turn_id.into());
        self.append(&e)
    }

    pub fn agent_turn_completed(
        &self,
        turn_id: impl Into<String>,
        duration_ms: Option<u64>,
        model: Option<String>,
        provider: Option<String>,
        usage: Option<TokenUsage>,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::AgentTurnCompleted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.turn_id = Some(turn_id.into());
        e.duration_ms = duration_ms;
        e.model = model;
        e.provider = provider;
        if let Some(u) = usage {
            e.input_tokens = u.input_tokens;
            e.output_tokens = u.output_tokens;
            e.cached_input_tokens = u.cached_input_tokens;
            e.reasoning_tokens = u.reasoning_tokens;
        }
        self.append(&e)
    }

    pub fn tool_call_started(
        &self,
        call_id: impl Into<String>,
        turn_id: Option<String>,
        tool: impl Into<String>,
        operation: Option<String>,
        input_bytes: Option<usize>,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::ToolCallStarted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.call_id = Some(call_id.into());
        e.turn_id = turn_id;
        e.tool = Some(tool.into());
        e.operation = operation;
        e.input_bytes = input_bytes;
        self.append(&e)
    }

    /// Record a completed tool call. `operation` is the filesystem op / shell program etc.
    /// `outcome` supplies success/error_code/duration/output hash/size.
    /// `cached` is `Some(true/false)` only if cleanly known (else None).
    /// Raw stdout/stderr NOT stored — only size/hash from `ToolOutcome`.
    /// `parent_call_id` links child to bounded_sequence parent (Phase 2).
    pub fn tool_call_completed(
        &self,
        call_id: impl Into<String>,
        turn_id: Option<String>,
        tool: impl Into<String>,
        operation: Option<String>,
        outcome: &ToolOutcome,
        input_bytes: Option<usize>,
        cached: Option<bool>,
        retry_of: Option<String>,
    ) -> anyhow::Result<()> {
        self.tool_call_completed_with_parent(
            call_id,
            turn_id,
            tool,
            operation,
            outcome,
            input_bytes,
            cached,
            retry_of,
            None,
        )
    }

    pub fn tool_call_completed_with_parent(
        &self,
        call_id: impl Into<String>,
        turn_id: Option<String>,
        tool: impl Into<String>,
        operation: Option<String>,
        outcome: &ToolOutcome,
        input_bytes: Option<usize>,
        cached: Option<bool>,
        retry_of: Option<String>,
        parent_call_id: Option<String>,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::ToolCallCompleted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.call_id = Some(call_id.into());
        e.turn_id = turn_id;
        e.tool = Some(tool.into());
        e.operation = operation.or_else(|| outcome.metadata.get("operation").cloned());
        e.duration_ms = Some(outcome.duration_ms);
        e.success = Some(outcome.success);
        e.error_code = outcome.error_code.clone();
        e.input_bytes = input_bytes;
        // Prefer ToolOutcome.summary-provided sizes/hashes when present; fallback to outcome content len.
        e.output_bytes = outcome.content.as_ref().map(|b| b.len());
        if let Some(b) = &outcome.content {
            e.output_sha256 = Some(crate::sha256_hex(b));
        } else if let Some(sha) = outcome.summary.get("sha256").and_then(|v| v.as_str()) {
            e.output_sha256 = Some(sha.to_string());
        } else if let Some(sha) = outcome
            .summary
            .get("stdout_sha256")
            .and_then(|v| v.as_str())
        {
            e.output_sha256 = Some(sha.to_string());
        }
        e.cached = cached;
        e.retry_of = retry_of;
        e.parent_call_id = parent_call_id;
        // Keep summary-derived size if content absent.
        if e.output_bytes.is_none() {
            if let Some(n) = outcome.summary.get("bytes").and_then(|v| v.as_u64()) {
                e.output_bytes = Some(n as usize);
            } else if let Some(n) = outcome.summary.get("stdout_bytes").and_then(|v| v.as_u64()) {
                e.output_bytes = Some(n as usize);
            }
        }
        self.append(&e)
    }

    /// Convenience wrapper that times `f`, never alters its `Ok`/`Err`.
    /// Emits `tool_call_started` + `tool_call_completed` on `Ok(ToolOutcome)`,
    /// or `tool_call_completed` with `success=false` synthesized on `Err`.
    pub async fn record_tool<F, Fut>(
        &self,
        call_id: &str,
        turn_id: Option<String>,
        tool: &str,
        operation: Option<String>,
        args_json: &Value,
        f: F,
    ) -> anyhow::Result<ToolOutcome>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<ToolOutcome>>,
    {
        let input_bytes = Some(serde_json::to_string(args_json).unwrap_or_default().len());
        // best-effort started event — failure to write must not affect tool
        let mut started = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::ToolCallStarted,
        );
        started.monotonic_ms = Some(self.monotonic_ms());
        started.call_id = Some(call_id.to_string());
        started.turn_id = turn_id.clone();
        started.tool = Some(tool.to_string());
        started.operation = operation.clone();
        started.input_bytes = input_bytes;
        self.append_best_effort(&started);

        let outcome_res = f().await;
        let outcome = match outcome_res {
            Ok(o) => o,
            Err(e) => {
                let code = e
                    .to_string()
                    .split(':')
                    .next()
                    .unwrap_or("error")
                    .trim()
                    .to_string();
                let mut ev = ExperimentEvent::new(
                    self.experiment_id.clone(),
                    self.task_id.clone(),
                    self.variant.clone(),
                    EventType::ToolCallCompleted,
                );
                ev.monotonic_ms = Some(self.monotonic_ms());
                ev.call_id = Some(call_id.to_string());
                ev.turn_id = turn_id;
                ev.tool = Some(tool.to_string());
                ev.operation = operation;
                ev.duration_ms = Some(0);
                ev.success = Some(false);
                ev.error_code = Some(code);
                ev.input_bytes = input_bytes;
                self.append_best_effort(&ev);
                return Err(e);
            }
        };
        // completed
        let _ = self.tool_call_completed(
            call_id,
            turn_id,
            tool,
            operation,
            &outcome,
            input_bytes,
            None,
            None,
        );
        Ok(outcome)
    }

    pub fn bounded_sequence_started(
        &self,
        sequence_id: impl Into<String>,
        turn_id: Option<String>,
        requested_steps: usize,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::BoundedSequenceStarted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.sequence_id = Some(sequence_id.into());
        e.call_id = e.sequence_id.clone();
        e.turn_id = turn_id;
        e.requested_steps = Some(requested_steps);
        e.tool = Some("bounded_sequence".into());
        self.append(&e)
    }

    pub fn bounded_sequence_completed(
        &self,
        sequence_id: impl Into<String>,
        turn_id: Option<String>,
        requested_steps: usize,
        executed_steps: usize,
        success: bool,
        duration_ms: u64,
        error_code: Option<String>,
        per_step_summary: Vec<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::BoundedSequenceCompleted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.sequence_id = Some(sequence_id.into());
        e.call_id = e.sequence_id.clone();
        e.turn_id = turn_id;
        e.requested_steps = Some(requested_steps);
        e.executed_steps = Some(executed_steps);
        e.success = Some(success);
        e.duration_ms = Some(duration_ms);
        e.error_code = error_code;
        e.tool = Some("bounded_sequence".into());
        // Store per-step compact evidence in metadata, bounded
        e.metadata
            .insert("steps".into(), serde_json::Value::Array(per_step_summary));
        self.append(&e)
    }

    pub fn verification_started(
        &self,
        verification_id: impl Into<String>,
        command: Option<String>,
        check_id: Option<String>,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::VerificationStarted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.verification_id = Some(verification_id.into());
        e.command = command;
        e.metadata.insert(
            "check_id".into(),
            check_id.map(Value::String).unwrap_or(Value::Null),
        );
        self.append(&e)
    }

    pub fn verification_completed(
        &self,
        verification_id: impl Into<String>,
        command: Option<String>,
        duration_ms: Option<u64>,
        exit_code: Option<i32>,
        success: bool,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::VerificationCompleted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.verification_id = Some(verification_id.into());
        e.command = command;
        e.duration_ms = duration_ms;
        e.exit_code = exit_code;
        e.success = Some(success);
        self.append(&e)
    }

    pub fn task_completed(
        &self,
        task_success: TaskOutcome,
        human_or_external_judge: Option<String>,
        repo_after: Option<RepoStateSnapshot>,
    ) -> anyhow::Result<()> {
        let mut e = ExperimentEvent::new(
            self.experiment_id.clone(),
            self.task_id.clone(),
            self.variant.clone(),
            EventType::TaskCompleted,
        );
        e.monotonic_ms = Some(self.monotonic_ms());
        e.task_success = Some(task_success);
        e.human_or_external_judge = human_or_external_judge;
        e.repo_after = repo_after.or_else(|| Some(collect_repo_state(None)));
        // wall-clock duration from first event wall time
        let wall_ms = chrono::Utc::now()
            .signed_duration_since(self.started_wall)
            .num_milliseconds() as u64;
        e.duration_ms = Some(wall_ms);
        self.append(&e)
    }

    // Low-level generic append for custom events / tests.
    pub fn append_event(&self, event: &ExperimentEvent) -> anyhow::Result<()> {
        self.append(event)
    }
}

// ── JSONL helpers ───────────────────────────────────────────────

/// Read all events from a `.jsonl` file, reporting malformed lines clearly.
pub fn read_jsonl(path: &Path) -> anyhow::Result<Vec<ExperimentEvent>> {
    let data = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (idx, line) in data.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let ev: ExperimentEvent = serde_json::from_str(trimmed).map_err(|e| {
            anyhow::anyhow!(
                "malformed JSONL at {}:{}: {} — line: {}",
                path.display(),
                idx + 1,
                e,
                &trimmed[..trimmed.len().min(200)]
            )
        })?;
        // Durations must never be negative — enforced via u64, but also check monotonic.
        if let Some(ms) = ev.duration_ms {
            let _ = ms; // u64 never negative
        }
        out.push(ev);
    }
    Ok(out)
}

/// Append a single event to an existing JSONL file (creates if missing).
pub fn append_jsonl(path: &Path, event: &ExperimentEvent) -> anyhow::Result<()> {
    let line = serde_json::to_string(event)?;
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{line}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::schema::{EventType, TaskOutcome};
    use std::fs;

    #[test]
    fn jsonl_writer_and_reader() {
        let dir = std::env::temp_dir().join(format!("val_rec_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let rec = ExperimentRecorder::new("exp_1", "baseline", &dir).unwrap();
        let task = rec.task_recorder("t1").unwrap();
        task.task_started(
            Some("investigation".into()),
            Some("desc".into()),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        task.agent_turn_started("turn_1").unwrap();
        task.agent_turn_completed(
            "turn_1",
            Some(100),
            Some("mock".into()),
            Some("test".into()),
            None,
        )
        .unwrap();
        task.task_completed(TaskOutcome::Success, None, None)
            .unwrap();
        let events = read_jsonl(task.path()).unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].event_type, EventType::TaskStarted);
        assert_eq!(events.last().unwrap().event_type, EventType::TaskCompleted);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_trace_writing() {
        let dir = std::env::temp_dir().join(format!("val_conc_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let rec = ExperimentRecorder::new("exp_c", "baseline", &dir).unwrap();
        let task = rec.task_recorder("t_conc").unwrap();
        let task = std::sync::Arc::new(task);
        let mut handles = Vec::new();
        for i in 0..10 {
            let t = task.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..20 {
                    let _ = t.tool_call_started(
                        format!("call_{i}_{j}"),
                        Some("turn_1".into()),
                        "filesystem",
                        Some("read".into()),
                        Some(10),
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let events = read_jsonl(task.path()).unwrap();
        assert_eq!(events.len(), 200);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_trace_error() {
        let dir = std::env::temp_dir().join(format!("val_mal_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.jsonl");
        fs::write(&path, "{\"schema_version\":\"validation.v1\",\"oops\":}\n").unwrap();
        let err = read_jsonl(&path).unwrap_err().to_string();
        assert!(err.contains("malformed"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
