#![allow(missing_docs)]
#![allow(clippy::needless_range_loop)]
use std::collections::BTreeMap;
use std::path::Path;

use chrono::DateTime;

use super::recorder::read_jsonl;
use super::schema::{EventType, ExperimentEvent};

/// Per-task normalized metrics — see `validation/README.md` for definitions.
///
/// Token totals include only known values; unknown remains `None`.
/// `model_round_trip_count` == `agent_turn_count` (one turn == one round-trip).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct PerTaskMetrics {
    pub task_id: String,
    pub experiment_id: String,
    pub variant: String,

    pub agent_turn_count: usize,
    pub model_round_trip_count: usize,
    pub model_visible_tool_call_count: usize,
    /// Phase 2: distinct handoff vs underlying
    #[serde(default)]
    pub model_visible_handoff_count: usize,
    #[serde(default)]
    pub underlying_tool_operation_count: usize,
    pub unique_tool_count: usize,
    pub tool_calls_by_tool: BTreeMap<String, usize>,
    pub tool_execution_duration_ms_total: u64,
    pub task_wall_clock_duration_ms: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_known_tokens: Option<u64>,

    pub retry_count: usize,
    pub verification_count: usize,
    pub verification_pass_count: usize,
    pub verification_fail_count: usize,

    pub files_changed_count: Option<usize>,
    pub lines_added: Option<u64>,
    pub lines_deleted: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_success: Option<String>,
}

impl PerTaskMetrics {
    /// `files_read` not directly tracked; use `tool_calls_by_tool["filesystem"]` as proxy if needed.
    pub fn files_read_proxy(&self) -> usize {
        *self.tool_calls_by_tool.get("filesystem").unwrap_or(&0)
    }
}

pub fn analyze_events(events: &[ExperimentEvent]) -> anyhow::Result<PerTaskMetrics> {
    if events.is_empty() {
        anyhow::bail!("no events");
    }
    let first = &events[0];
    let task_id = first.task_id.clone();
    let experiment_id = first.experiment_id.clone();
    let variant = first.variant.clone();

    // Ensure uniform task_id
    for e in events {
        if e.task_id != task_id {
            anyhow::bail!("mixed task_id in single-task analysis");
        }
    }

    // Must have explicit task_started and task_completed
    let has_started = events
        .iter()
        .any(|e| e.event_type == EventType::TaskStarted);
    let has_completed = events
        .iter()
        .any(|e| e.event_type == EventType::TaskCompleted);
    if !has_started {
        anyhow::bail!("missing task_started");
    }
    if !has_completed {
        anyhow::bail!("missing task_completed — task completion must be explicit");
    }

    let agent_turn_count = events
        .iter()
        .filter(|e| e.event_type == EventType::AgentTurnCompleted)
        .count();
    let model_round_trip_count = agent_turn_count;

    let tool_completed: Vec<&ExperimentEvent> = events
        .iter()
        .filter(|e| e.event_type == EventType::ToolCallCompleted)
        .collect();
    let model_visible_tool_call_count = tool_completed.len();
    // Phase 2: handoff vs underlying
    let bounded_handoffs = events
        .iter()
        .filter(|e| e.event_type == EventType::BoundedSequenceCompleted)
        .count();
    let standalone_handoffs = tool_completed
        .iter()
        .filter(|e| e.parent_call_id.is_none())
        .count();
    let model_visible_handoff_count = bounded_handoffs + standalone_handoffs;
    let underlying_tool_operation_count = tool_completed.len();
    let mut tool_calls_by_tool: BTreeMap<String, usize> = BTreeMap::new();
    let mut tool_duration_total: u64 = 0;
    let mut retry_count = 0;
    let mut unique = std::collections::HashSet::new();
    for e in &tool_completed {
        if let Some(t) = &e.tool {
            *tool_calls_by_tool.entry(t.clone()).or_default() += 1;
            unique.insert(t.clone());
        }
        if let Some(d) = e.duration_ms {
            tool_duration_total = tool_duration_total.saturating_add(d);
        }
        if e.retry_of.is_some() {
            retry_count += 1;
        }
        // Durations must never be negative — u64 prevents, but check monotonic sanity.
        // No-op: u64 already.
    }
    let unique_tool_count = unique.len();

    // Tokens — sum only known values; if no known values, stay None.
    let mut input_sum: Option<u64> = None;
    let mut output_sum: Option<u64> = None;
    let mut cached_sum: Option<u64> = None;
    let mut reasoning_sum: Option<u64> = None;
    for e in events
        .iter()
        .filter(|e| e.event_type == EventType::AgentTurnCompleted)
    {
        if let Some(v) = e.input_tokens {
            input_sum = Some(input_sum.unwrap_or(0) + v);
        }
        if let Some(v) = e.output_tokens {
            output_sum = Some(output_sum.unwrap_or(0) + v);
        }
        if let Some(v) = e.cached_input_tokens {
            cached_sum = Some(cached_sum.unwrap_or(0) + v);
        }
        if let Some(v) = e.reasoning_tokens {
            reasoning_sum = Some(reasoning_sum.unwrap_or(0) + v);
        }
    }
    let total_known_tokens: Option<u64> = {
        let mut t = 0u64;
        let mut any = false;
        for v in [input_sum, output_sum, cached_sum, reasoning_sum]
            .into_iter()
            .flatten()
        {
            t += v;
            any = true;
        }
        if any {
            Some(t)
        } else {
            None
        }
    };

    let verification_count = events
        .iter()
        .filter(|e| e.event_type == EventType::VerificationCompleted)
        .count();
    let verification_pass_count = events
        .iter()
        .filter(|e| e.event_type == EventType::VerificationCompleted && e.success == Some(true))
        .count();
    let verification_fail_count = events
        .iter()
        .filter(|e| e.event_type == EventType::VerificationCompleted && e.success == Some(false))
        .count();

    // Repo mutation — prefer repo_after from task_completed, else last repo_after.
    let repo_after = events.iter().rev().find_map(|e| e.repo_after.as_ref());
    let repo_before = events.iter().find_map(|e| e.repo_before.as_ref());
    let files_changed_count = repo_after
        .map(|r| r.changed_count)
        .or_else(|| repo_before.map(|r| r.changed_count));
    let lines_added = repo_after.and_then(|r| r.lines_added);
    let lines_deleted = repo_after.and_then(|r| r.lines_deleted);

    // Wall-clock from timestamps of task_started -> task_completed
    let started_ts = events
        .iter()
        .find(|e| e.event_type == EventType::TaskStarted)
        .map(|e| &e.timestamp);
    let completed_ts = events
        .iter()
        .rev()
        .find(|e| e.event_type == EventType::TaskCompleted)
        .map(|e| &e.timestamp);
    let task_wall_clock_duration_ms = match (started_ts, completed_ts) {
        (Some(s), Some(c)) => {
            let sp: Result<DateTime<chrono::Utc>, _> = s.parse();
            let cp: Result<DateTime<chrono::Utc>, _> = c.parse();
            match (sp, cp) {
                (Ok(sdt), Ok(cdt)) => {
                    let d = cdt.signed_duration_since(sdt).num_milliseconds();
                    Some(if d < 0 { 0 } else { d as u64 })
                }
                _ => {
                    // Fallback monotonic_ms diff
                    let sm = events
                        .iter()
                        .find(|e| e.event_type == EventType::TaskStarted)
                        .and_then(|e| e.monotonic_ms);
                    let cm = events
                        .iter()
                        .rev()
                        .find(|e| e.event_type == EventType::TaskCompleted)
                        .and_then(|e| e.monotonic_ms);
                    match (sm, cm) {
                        (Some(a), Some(b)) => Some(b.saturating_sub(a)),
                        _ => None,
                    }
                }
            }
        }
        _ => None,
    };

    let task_success = events
        .iter()
        .rev()
        .find_map(|e| e.task_success.clone())
        .map(|o| match o {
            super::schema::TaskOutcome::Success => "success".to_string(),
            super::schema::TaskOutcome::Failure => "failure".to_string(),
            super::schema::TaskOutcome::Partial => "partial".to_string(),
            super::schema::TaskOutcome::InvalidRun => "invalid_run".to_string(),
            super::schema::TaskOutcome::Unknown => "unknown".to_string(),
        });

    Ok(PerTaskMetrics {
        task_id,
        experiment_id,
        variant,
        agent_turn_count,
        model_round_trip_count,
        model_visible_tool_call_count,
        model_visible_handoff_count,
        underlying_tool_operation_count,
        unique_tool_count,
        tool_calls_by_tool,
        tool_execution_duration_ms_total: tool_duration_total,
        task_wall_clock_duration_ms,
        input_tokens: input_sum,
        output_tokens: output_sum,
        cached_input_tokens: cached_sum,
        reasoning_tokens: reasoning_sum,
        total_known_tokens,
        retry_count,
        verification_count,
        verification_pass_count,
        verification_fail_count,
        files_changed_count,
        lines_added,
        lines_deleted,
        task_success,
    })
}

pub fn analyze_file(path: &Path) -> anyhow::Result<PerTaskMetrics> {
    let events = read_jsonl(path)?;
    analyze_events(&events)
}

pub fn analyze_files(paths: &[std::path::PathBuf]) -> anyhow::Result<Vec<PerTaskMetrics>> {
    let mut out = Vec::new();
    for p in paths {
        out.push(analyze_file(p)?);
    }
    Ok(out)
}

/// Discover `.jsonl` files under `experiment_dir` (recursively or tasks/).
pub fn discover_traces(experiment_dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let candidates = [experiment_dir.join("tasks"), experiment_dir.to_path_buf()];
    for base in candidates {
        if let Ok(rd) = std::fs::read_dir(&base) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p.extension().map(|e| e == "jsonl").unwrap_or(false) {
                    out.push(p);
                }
            }
            if !out.is_empty() {
                break;
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::recorder::ExperimentRecorder;
    use crate::experiment::schema::{TaskOutcome, TokenUsage};

    fn make_task_with_tokens(
        include_tokens: bool,
    ) -> Vec<crate::experiment::schema::ExperimentEvent> {
        let dir = std::env::temp_dir().join(format!("ana_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let rec = ExperimentRecorder::new("exp_a", "baseline", &dir).unwrap();
        let task = rec.task_recorder("t_ana").unwrap();
        task.task_started(
            Some("feature".into()),
            Some("desc".into()),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        task.agent_turn_started("turn_1").unwrap();
        let usage = if include_tokens {
            Some(TokenUsage {
                input_tokens: Some(100),
                output_tokens: Some(50),
                cached_input_tokens: Some(10),
                reasoning_tokens: Some(5),
            })
        } else {
            None
        };
        task.agent_turn_completed(
            "turn_1",
            Some(200),
            Some("mock".into()),
            Some("test".into()),
            usage,
        )
        .unwrap();
        task.agent_turn_started("turn_2").unwrap();
        let usage2 = if include_tokens {
            Some(TokenUsage {
                input_tokens: Some(20),
                output_tokens: Some(30),
                ..Default::default()
            })
        } else {
            None
        };
        task.agent_turn_completed(
            "turn_2",
            Some(100),
            Some("mock".into()),
            Some("test".into()),
            usage2,
        )
        .unwrap();
        // tool calls
        let outcome =
            crate::ToolOutcome::success("filesystem", serde_json::json!({"operation":"read"}), 15)
                .with_content(b"hello".to_vec());
        task.tool_call_completed(
            "call_1",
            Some("turn_1".into()),
            "filesystem",
            Some("read".into()),
            &outcome,
            Some(20),
            None,
            None,
        )
        .unwrap();
        let outcome2 = crate::ToolOutcome::success("shell", serde_json::json!({"exit_code":0}), 30);
        task.tool_call_completed(
            "call_2",
            Some("turn_2".into()),
            "shell",
            Some("/bin/echo".into()),
            &outcome2,
            Some(10),
            None,
            None,
        )
        .unwrap();
        task.verification_started("v1", Some("cargo test".into()), None)
            .unwrap();
        task.verification_completed("v1", Some("cargo test".into()), Some(50), Some(0), true)
            .unwrap();
        task.verification_started("v2", Some("cargo lint".into()), None)
            .unwrap();
        task.verification_completed("v2", Some("cargo lint".into()), Some(10), Some(1), false)
            .unwrap();
        task.task_completed(TaskOutcome::Failure, None, None)
            .unwrap();
        let events = crate::experiment::recorder::read_jsonl(task.path()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        events
    }

    #[test]
    fn single_tool_call_accounting() {
        let ev = make_task_with_tokens(false);
        let m = analyze_events(&ev).unwrap();
        assert_eq!(m.model_visible_tool_call_count, 2);
        assert_eq!(m.unique_tool_count, 2);
        assert_eq!(m.tool_calls_by_tool["filesystem"], 1);
        assert_eq!(m.tool_calls_by_tool["shell"], 1);
    }

    #[test]
    fn unknown_tokens_remain_null() {
        let ev = make_task_with_tokens(false);
        let m = analyze_events(&ev).unwrap();
        assert_eq!(m.input_tokens, None);
        assert_eq!(m.total_known_tokens, None);
    }

    #[test]
    fn known_tokens_aggregate() {
        let ev = make_task_with_tokens(true);
        let m = analyze_events(&ev).unwrap();
        assert_eq!(m.input_tokens, Some(120));
        assert_eq!(m.output_tokens, Some(80));
        assert_eq!(m.cached_input_tokens, Some(10));
        assert_eq!(m.reasoning_tokens, Some(5));
        assert_eq!(m.total_known_tokens, Some(215));
    }

    #[test]
    fn verification_counts() {
        let ev = make_task_with_tokens(false);
        let m = analyze_events(&ev).unwrap();
        assert_eq!(m.verification_count, 2);
        assert_eq!(m.verification_pass_count, 1);
        assert_eq!(m.verification_fail_count, 1);
    }

    #[test]
    fn failed_task_with_successful_tools_remains_failure() {
        let ev = make_task_with_tokens(false);
        let m = analyze_events(&ev).unwrap();
        // tools succeeded but task outcome is Failure
        assert_eq!(m.task_success.as_deref(), Some("failure"));
    }

    #[test]
    fn batch_not_double_counted() {
        // Batch of 3 child calls should be 3, not 4.
        let dir = std::env::temp_dir().join(format!("ana_batch_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let rec = ExperimentRecorder::new("exp_b", "baseline", &dir).unwrap();
        let task = rec.task_recorder("t_b").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        for i in 0..3 {
            let o = crate::ToolOutcome::success("filesystem", serde_json::json!({}), 5);
            task.tool_call_completed(
                format!("call_{i}"),
                None,
                "filesystem",
                Some("read".into()),
                &o,
                None,
                None,
                None,
            )
            .unwrap();
        }
        task.task_completed(TaskOutcome::Success, None, None)
            .unwrap();
        let ev = crate::experiment::recorder::read_jsonl(task.path()).unwrap();
        let m = analyze_events(&ev).unwrap();
        assert_eq!(m.model_visible_tool_call_count, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sequence_not_double_counted() {
        // Same as batch
        let dir = std::env::temp_dir().join(format!("ana_seq_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let rec = ExperimentRecorder::new("exp_s", "baseline", &dir).unwrap();
        let task = rec.task_recorder("t_s").unwrap();
        task.task_started(None, None, None, None, None, None, None)
            .unwrap();
        for i in 0..2 {
            let o = crate::ToolOutcome::success("shell", serde_json::json!({}), 10);
            task.tool_call_completed(
                format!("s_{i}"),
                None,
                "shell",
                Some("/bin/echo".into()),
                &o,
                None,
                None,
                None,
            )
            .unwrap();
        }
        task.task_completed(TaskOutcome::Success, None, None)
            .unwrap();
        let ev = crate::experiment::recorder::read_jsonl(task.path()).unwrap();
        let m = analyze_events(&ev).unwrap();
        assert_eq!(m.model_visible_tool_call_count, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn model_round_trip_equals_agent_turns() {
        let ev = make_task_with_tokens(false);
        let m = analyze_events(&ev).unwrap();
        assert_eq!(m.model_round_trip_count, m.agent_turn_count);
        assert_eq!(m.agent_turn_count, 2);
    }
}
