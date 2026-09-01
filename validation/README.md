# Validation Harness — Baseline Measurement (Phase 0)

This directory holds the **measurement harness** for the hypothesis:

> Bundling deterministic execution steps into bounded sequences can later reduce
> model-visible tool calls and round trips without reducing correctness.

**This harness measures behavior; it does not prove the product hypothesis by itself.**
No compressed execution, no automatic plan generation, no DB/queue/cloud is included.

## What this measures

One *task* is one coding-agent job (investigation, bug_fix, feature, refactor, test_failure, unknown).
Each task trace is an **append-only JSONL** of versioned `ExperimentEvent`s with `schema_version: validation.v1`.

### Required per-task metrics (analyzer output)

| Metric | Definition | Source |
|---|---|---|
| `agent_turn_count` | Count of `agent_turn_completed` | external harness must emit |
| `model_round_trip_count` | **== `agent_turn_count`** (one turn == one model round-trip) | same |
| `model_visible_tool_call_count` | Count of `tool_call_completed` (child calls only; batch/sequence wrapper not counted) | instrumentation |
| `unique_tool_count` | Distinct `tool` in `tool_call_completed` | same |
| `tool_calls_by_tool` | Map tool → count | same |
| `tool_execution_duration_ms_total` | Sum `duration_ms` of `tool_call_completed` | same (monotonic) |
| `task_wall_clock_duration_ms` | `task_completed.timestamp - task_started.timestamp` (or `monotonic_ms` fallback) | timestamps |
| `input_tokens` / `output_tokens` / `cached_input_tokens` / `reasoning_tokens` | Sum of known values from `agent_turn_completed`; **unknown stays `null` never zero** | harness if provider supplies |
| `total_known_tokens` | Sum of all known token categories | same |
| `retry_count` | Count of `tool_call_completed` where `retry_of` set (explicit parent relationship). No heuristic inference. | harness |
| `verification_count` / `pass` / `fail` | Count of `verification_completed` total / success true / false | harness |
| `files_changed_count`, `lines_added`, `lines_deleted` | From `repo_after` snapshot (`git status --porcelain` + `git diff --numstat`) | collector |
| `task_success` | Explicit `TaskOutcome` in `task_completed` (`success`/`failure`/`partial`/`invalid_run`/`unknown`) — **never inferred from tool success** | harness/verifier |

### What is automatic vs. harness-supplied

**Automatic (by `TaskRecorder` / instrumentation):**
- `tool_call_*` duration (monotonic), success/error_code, output_bytes/sha256 (via `ToolOutcome`), input_bytes, `repo_before`/`repo_after` snapshots (git collector), `task_wall_clock_duration_ms`.

**Must be supplied by external harness** (Codex, Claude Code, custom):
- `agent_turn_started` / `agent_turn_completed` with `turn_id`, optional `model`/`provider`/`input_tokens` etc. The repo cannot observe model turns directly without harness integration.
- `task_started` task metadata (category, description, repo_or_fixture, base_revision …) + `task_completed` with `task_success` + optional `human_or_external_judge`.
- `verification_started` / `verification_completed` — caller specifies which commands are verification; nothing is auto-invented.
- `retry_of` if a tool call is an explicit retry.

If token usage is unavailable for a provider, leave it absent → analyzer keeps `null`. Do not fabricate zeros.

## Experiment layout

```
<experiment_root>/<experiment_id>/
  metadata.json
  tasks/<task_id>.jsonl   # append-only, one file per task
```

- `root` configurable in `ExperimentRecorder::new(experiment_id, variant, root_dir)`.
- Each `TaskRecorder` owns one file with `Mutex<BufWriter<File>>` + `append` → concurrent tasks never collide; concurrent clones of same task share `Arc<Mutex<_>>`.
- No daemon or DB; inspect with `cat`, `jq`, or analyzer.

`variant` is `baseline` for now; future `execution_tool` variant reuses same schema shape.

### Baseline rule

Baseline runs **must not use compressed execution sequences** (no automatic bundling). They record normal agent behavior first.

## How to record a baseline task

### Rust API (library)

```rust
use execution_tool::experiment::{ExperimentRecorder, TaskOutcome, TokenUsage};
use execution_tool::experiment::collector::collect_repo_state;

let exp = ExperimentRecorder::new("exp_2025_09_01", "baseline", "./experiments")?;
let task = exp.task_recorder("bug_fix_001")?;

// 1. task_started — snapshot before
task.task_started(
    Some("bug_fix".into()),
    Some("fix pagination off-by-one".into()),
    Some("execution-tool@HEAD".into()),
    Some(collect_repo_state(None)),
    Some("my-harness".into()),
    Some("0.1.0".into()),
    None,
)?;

// 2. agent turns — harness must emit
task.agent_turn_started("turn_1")?;
// ... model call, optionally with usage
task.agent_turn_completed("turn_1", Some(1200), Some("mock-model".into()), Some("test-provider".into()),
    Some(TokenUsage{ input_tokens: Some(800), output_tokens: Some(200), ..Default::default() }))?;

// 3. tool calls — via instrumentation wrappers (measurement separate from semantics)
use execution_tool::experiment::instrumentation::instrument_execute;
use serde_json::json;
// underlying outcome unchanged; trace emitted best-effort
let outcome = instrument_execute(&registry, &task, Some("turn_1".into()), "call_1", "filesystem",
    json!({"operation":"read","path":"/tmp/..."} )).await?;
// For batch/sequence use instrument_batch / instrument_sequence (N child events, not N+1)

// 4. verification — explicit
task.verification_started("v1", Some("cargo test --lib".into()), Some("cargo-test".into()))?;
// ... run cargo test, capture exit code
task.verification_completed("v1", Some("cargo test --lib".into()), Some(1234), Some(0), true)?;

// 5. task_completed — explicit task_success + after snapshot
task.task_completed(TaskOutcome::Success, None, Some(collect_repo_state(None)))?;
```

Raw FS: `cat experiments/exp_2025_09_01/tasks/bug_fix_001.jsonl | jq .`

Notes on `TaskRecorder` helpers:
- `tool_call_started` / `tool_call_completed` can be called directly if not using instrumentation wrappers.
- `instrument_execute*` helpers never alter `ToolOutcome` or convert `Err` to `Ok`; trace write failure is logged (`tracing::warn`) but does not corrupt execution.
- `ToolOutcome.content` raw bytes are **never** persisted — only `output_bytes` + `output_sha256` via `sha256_hex`.

### What is recorded and what is NOT

**Recorded per tool call:** `tool`, `operation` (e.g. fs op / shell program), `duration_ms`, `success`, `error_code`, `input_bytes`, `output_bytes`, `output_sha256`, `cached` (if known), `turn_id`/`call_id`.

**NOT persisted:** env vars, secrets, auth headers, bearer tokens, raw file content, full stdout/stderr, unredacted request headers. Reuses existing `sha256_hex` / redaction utilities.

**Repo snapshot:** `head`, `branch`, `dirty`, `changed_files`, `changed_count`, `status_porcelain` (8 KiB truncated), `lines_added`/`lines_deleted` from `git diff --numstat`. Gracefully returns `head: None` outside git.

## How to analyze a trace

```sh
# One experiment dir → per-task metrics human-readable
cargo run --bin validation-analyzer -- ./experiments/exp_2025_09_01

# One task file
cargo run --bin validation-analyzer -- ./experiments/exp_2025_09_01/tasks/bug_fix_001.jsonl --json --out metrics.json

# Multiple
cargo run --bin validation-analyzer -- ./experiments/exp_A ./experiments/exp_B --json
```

Output (human):
```
task bug_fix_001 variant baseline — turns 3 rt 3 calls 7 tools 3 duration_ms_total 420 wall_ms Some(1234) success Some("success") ver 2/2 files 3 +42 -10
  tokens in:Some(1600) out:Some(400) cached:None reasoning:None total_known:Some(2000)
  by_tool: filesystem:3 shell:2 http:2

--- aggregate (1 tasks) ---
total_turns 3 total_calls 7 avg_calls_per_task 7.00
```

Machine JSON is array of `PerTaskMetrics`.

Analyzer rules:
- Unknown token categories stay `null` (not zero) — sums include only known.
- `model_round_trip_count` == `agent_turn_count`.
- Batch/sequence wrapper calls are **not** double-counted: only child `tool_call_completed` events count.
- Durations never negative (u64, validated).
- Missing `task_started` or `task_completed` → analyzer error (completion must be explicit, not EOF).
- Retry counted only if `retry_of` set explicitly; no command-equality heuristic.
- Failed tools with `TaskOutcome::Failure` → task remains `failure` (tools may succeed while task fails).

## Task manifest

`validation/tasks.sample.json` shows the machine-readable format:

```json
{ "schema_version":"validation.v1", "tasks": [ { "task_id","title","category","description","repo_or_fixture","base_revision","verification_commands_or_checks":[],"success_criteria","notes" } ] }
```

- 3 sample entries (bug_fix, feature, investigation) marked `SAMPLE` for parser validation only — no synthetic results.
- Real baseline corpus should be 15-25 tasks per spec, each run as both `baseline` and future `execution_tool` variant by `task_id` for A/B.

## After this harness

Do **not** begin compressed execution. Record ~15-25 real baseline tasks, review traces, then design the variant.

## Confirmation

This harness does **not** implement compressed execution, automatic execution-plan/DAG generation, model planner, semantic caching, context compilation, conditional retry engine, Postgres/SQLite/Redis/queue/Kafka/object storage/K8s/Docker/distributed workers/cloud services, or LLM provider integration beyond optional usage passthrough. Measurement is separate from execution semantics.
