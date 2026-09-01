//! Validation harness required tests (spec §tests).

use std::sync::Arc;

use execution_tool::experiment::analyzer::analyze_events;
use execution_tool::experiment::collector::collect_repo_state;
use execution_tool::experiment::instrumentation::{
    instrument_batch, instrument_execute, instrument_execute_once, instrument_sequence,
};
use execution_tool::experiment::recorder::{read_jsonl, ExperimentRecorder};
use execution_tool::experiment::schema::{EventType, ExperimentEvent, TaskOutcome, TokenUsage};
use execution_tool::{Tool, ToolOutcome, ToolRegistry};
use serde_json::{json, Value};
// ── helpers ─────────────────────────────────────────────────

struct Counter {
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Tool for Counter {
    fn name(&self) -> &str {
        "counter"
    }
    fn description(&self) -> &str {
        "counter"
    }
    fn parameters_schema(&self) -> Value {
        json!({})
    }
    async fn execute(&self, _args: Value) -> anyhow::Result<ToolOutcome> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ToolOutcome::success("counter", json!({"n": n}), 2))
    }
}

fn tmp_dir() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("val_test_{}", uuid::Uuid::new_v4()))
}

// ── spec tests ─────────────────────────────────────────────

#[test]
fn schema_round_trip_via_file() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_schema", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_schema").unwrap();
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
    task.task_completed(TaskOutcome::Success, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    // round-trip via serde_json per event
    for e in &evs {
        let s = serde_json::to_string(e).unwrap();
        let d: ExperimentEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(e.event_id, d.event_id);
        assert_eq!(e.schema_version, "validation.v1");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn jsonl_writer_reader_roundtrip() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_j", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_j").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    task.agent_turn_started("turn_1").unwrap();
    task.agent_turn_completed("turn_1", Some(10), None, None, None)
        .unwrap();
    task.task_completed(TaskOutcome::Unknown, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    assert_eq!(evs.len(), 4);
    assert_eq!(evs[0].event_type, EventType::TaskStarted);
    assert_eq!(evs[3].event_type, EventType::TaskCompleted);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_trace_writing_no_corruption() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_conc2", "baseline", &dir).unwrap();
    let task = Arc::new(rec.task_recorder("t_conc2").unwrap());
    let mut handles = Vec::new();
    for i in 0..8 {
        let t = task.clone();
        handles.push(std::thread::spawn(move || {
            for j in 0..25 {
                let _ = t.tool_call_started(
                    format!("c_{i}_{j}"),
                    None,
                    "filesystem",
                    Some("read".into()),
                    Some(5),
                );
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let evs = read_jsonl(task.path()).unwrap();
    assert_eq!(evs.len(), 200);
    // all lines valid JSON
    for e in &evs {
        assert_eq!(e.schema_version, "validation.v1");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn single_tool_call_accounting() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_single", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_single").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    let counter = Arc::new(Counter {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut reg = ToolRegistry::new();
    reg.register(counter.clone());
    let outcome = instrument_execute(
        &reg,
        &task,
        Some("turn_1".into()),
        "call_1",
        "counter",
        json!({}),
    )
    .await
    .unwrap();
    assert!(outcome.success);
    task.task_completed(TaskOutcome::Success, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    let m = analyze_events(&evs).unwrap();
    assert_eq!(m.model_visible_tool_call_count, 1);
    assert_eq!(m.tool_calls_by_tool["counter"], 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn execute_once_cache_accounting_not_double() {
    // Even with execute_once caching, trace should have exactly one completed event per logical call
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_once", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_once").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    let counter = Arc::new(Counter {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut reg = ToolRegistry::new();
    reg.register(counter.clone());
    // two instrumented once calls with same key — underlying registry dedupes
    instrument_execute_once(&reg, &task, None, "k1", "counter", json!({}))
        .await
        .unwrap();
    instrument_execute_once(&reg, &task, None, "k1", "counter", json!({}))
        .await
        .unwrap();
    task.task_completed(TaskOutcome::Success, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    let m = analyze_events(&evs).unwrap();
    assert_eq!(
        m.model_visible_tool_call_count, 2,
        "each logical once call counts"
    );
    // Underlying tool should have run once due to dedup
    assert_eq!(counter.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn batch_accounting_n_not_n_plus_one() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_batch", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_batch").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    let counter = Arc::new(Counter {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut reg = ToolRegistry::new();
    reg.register(counter.clone());
    let reqs = vec![
        ("counter".to_string(), json!({})),
        ("counter".to_string(), json!({})),
        ("counter".to_string(), json!({})),
    ];
    let res = instrument_batch(&reg, &task, None, reqs, 2).await;
    assert_eq!(res.len(), 3);
    task.task_completed(TaskOutcome::Success, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    // Started + 3 completed = but analyzer counts only completed
    let m = analyze_events(&evs).unwrap();
    assert_eq!(
        m.model_visible_tool_call_count, 3,
        "batch wrapper not counted"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn sequence_accounting_n_not_n_plus_one() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_seq", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_seq").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    let counter = Arc::new(Counter {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut reg = ToolRegistry::new();
    reg.register(counter.clone());
    let reqs = vec![
        ("counter".to_string(), json!({})),
        ("counter".to_string(), json!({})),
    ];
    let res = instrument_sequence(&reg, &task, None, reqs, false).await;
    assert_eq!(res.len(), 2);
    task.task_completed(TaskOutcome::Success, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    let m = analyze_events(&evs).unwrap();
    assert_eq!(m.model_visible_tool_call_count, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_tokens_remain_null_analysis() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_tok_null", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_tok_null").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    task.agent_turn_completed("turn_1", Some(10), Some("m".into()), Some("p".into()), None)
        .unwrap();
    task.task_completed(TaskOutcome::Success, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    let m = analyze_events(&evs).unwrap();
    assert_eq!(m.input_tokens, None);
    assert_eq!(m.total_known_tokens, None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn known_tokens_aggregate_correctly() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_tok_known", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_tok_known").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    task.agent_turn_completed(
        "turn_1",
        Some(10),
        Some("m".into()),
        Some("p".into()),
        Some(TokenUsage {
            input_tokens: Some(100),
            output_tokens: Some(50),
            ..Default::default()
        }),
    )
    .unwrap();
    task.agent_turn_completed(
        "turn_2",
        Some(10),
        Some("m".into()),
        Some("p".into()),
        Some(TokenUsage {
            input_tokens: Some(20),
            cached_input_tokens: Some(5),
            ..Default::default()
        }),
    )
    .unwrap();
    task.task_completed(TaskOutcome::Success, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    let m = analyze_events(&evs).unwrap();
    assert_eq!(m.input_tokens, Some(120));
    assert_eq!(m.output_tokens, Some(50));
    assert_eq!(m.cached_input_tokens, Some(5));
    assert_eq!(m.total_known_tokens, Some(175));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repo_collector_inside_temp_git() {
    let dir = std::env::temp_dir().join(format!("val_git_int_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    // init git
    let run = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["init"]);
    run(&["config", "user.email", "a@b.com"]);
    run(&["config", "user.name", "a"]);
    std::fs::write(dir.join("f.txt"), "hi").unwrap();
    run(&["add", "f.txt"]);
    run(&["commit", "-m", "init"]);
    let s = collect_repo_state(Some(&dir));
    assert!(s.head.is_some());
    assert!(!s.dirty);
    // modify
    std::fs::write(dir.join("f.txt"), "hi2").unwrap();
    let s2 = collect_repo_state(Some(&dir));
    assert!(s2.dirty);
    assert!(s2.changed_count > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repo_collector_non_git_graceful() {
    let dir = std::env::temp_dir().join(format!("val_nogit_int_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let s = collect_repo_state(Some(&dir));
    assert_eq!(s.head, None);
    assert!(!s.dirty);
    assert_eq!(s.changed_count, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verification_metrics() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_ver", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_ver").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    task.verification_completed("v1", Some("cargo test".into()), Some(100), Some(0), true)
        .unwrap();
    task.verification_completed("v2", Some("cargo lint".into()), Some(50), Some(1), false)
        .unwrap();
    task.task_completed(TaskOutcome::Success, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    let m = analyze_events(&evs).unwrap();
    assert_eq!(m.verification_count, 2);
    assert_eq!(m.verification_pass_count, 1);
    assert_eq!(m.verification_fail_count, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn failed_task_with_successful_tools_is_failure() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_fail_task", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_fail_task").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    let ok = ToolOutcome::success("filesystem", json!({}), 5);
    task.tool_call_completed(
        "c1",
        None,
        "filesystem",
        Some("read".into()),
        &ok,
        None,
        None,
        None,
    )
    .unwrap();
    task.task_completed(TaskOutcome::Failure, None, None)
        .unwrap();
    let evs = read_jsonl(task.path()).unwrap();
    let m = analyze_events(&evs).unwrap();
    assert_eq!(m.task_success.as_deref(), Some("failure"));
    assert_eq!(m.model_visible_tool_call_count, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_trace_useful_error() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.jsonl");
    std::fs::write(&path, "{\"schema_version\":\"validation.v1\",\"oops\":}\n").unwrap();
    let err = read_jsonl(&path).unwrap_err().to_string();
    assert!(err.contains("malformed"), "{err}");
    assert!(err.contains("bad.jsonl"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn analyzer_requires_task_completed_explicit() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_no_complete", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_no_complete").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    // no task_completed
    let evs = read_jsonl(task.path()).unwrap();
    let err = analyze_events(&evs).unwrap_err().to_string();
    assert!(err.contains("task_completed"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn instrumentation_does_not_alter_outcome() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_alter", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_alter").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    let counter = Arc::new(Counter {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut reg = ToolRegistry::new();
    reg.register(counter.clone());
    let direct = reg.execute("counter", json!({})).await.unwrap();
    let via = instrument_execute(&reg, &task, None, "call_via", "counter", json!({}))
        .await
        .unwrap();
    // instrumentation must not double-execute: total calls == 2 (direct + via)
    assert_eq!(counter.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(direct.success, via.success);
    // n differs by 1 due to sequential calls, but both should be success with same shape
    assert!(direct.summary.get("n").is_some());
    assert!(via.summary.get("n").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn instrumentation_failure_not_silent_success() {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let rec = ExperimentRecorder::new("exp_fail_instr", "baseline", &dir).unwrap();
    let task = rec.task_recorder("t_fail_instr").unwrap();
    task.task_started(None, None, None, None, None, None, None)
        .unwrap();
    let reg = ToolRegistry::new(); // no tools
    let res = instrument_execute(&reg, &task, None, "call_fail", "counter", json!({})).await;
    assert!(res.is_err(), "should be tool_not_found");
    // trace should have a failed tool_call_completed, not silent success
    let evs = read_jsonl(task.path()).unwrap();
    let completed = evs
        .iter()
        .find(|e| e.event_type == EventType::ToolCallCompleted)
        .unwrap();
    assert_eq!(completed.success, Some(false));
    let _ = std::fs::remove_dir_all(&dir);
}
