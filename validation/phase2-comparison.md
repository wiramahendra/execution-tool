# Phase 2 Comparison

Baseline: validation/experiments/exp_baseline_001, Treatment: validation/experiments/exp_treatment_001

Paired tasks: 20, adoption: 20/20 (100%)

## Simulated (20 tasks)
- Median round-trip reduction: 33.3%
- Median handoff reduction: 33.3%
- Median wall change: -25.7% (negative = slower)
- Mean handoff reduction: 37.6%

## Per-task (simulated)
- inv_001_ssrf_destination (Investigation medium): base rt 3/h 6 -> treat rt 2/h 4 (handoff -33%, rt -33%) success success vs success ✓
- inv_002_sandbox_toctou (Investigation medium): base rt 3/h 6 -> treat rt 2/h 4 (handoff -33%, rt -33%) success success vs success ✓
- inv_003_audit_logging (Investigation simple): base rt 2/h 4 -> treat rt 2/h 3 (handoff -25%, rt -0%) success success vs success ✓
- inv_004_registry_batch_sequence (Investigation simple): base rt 2/h 4 -> treat rt 2/h 3 (handoff -25%, rt -0%) success success vs success ✓
- bug_001_read_limit_clamp (BugFix simple): base rt 3/h 6 -> treat rt 2/h 4 (handoff -33%, rt -33%) success success vs success ✓
- bug_002_header_allowlist (BugFix medium): base rt 3/h 6 -> treat rt 2/h 4 (handoff -33%, rt -33%) success success vs success ✓
- bug_003_base64_write (BugFix medium): base rt 3/h 6 -> treat rt 2/h 4 (handoff -33%, rt -33%) success success vs success ✓
- bug_004_collector_status_parse (BugFix complex): base rt 4/h 8 -> treat rt 3/h 6 (handoff -25%, rt -25%) success failure vs failure ✓
- feat_001_stat_summary (Feature medium): base rt 3/h 5 -> treat rt 2/h 3 (handoff -40%, rt -33%) success success vs success ✓
- feat_002_env_redaction_doc (Feature medium): base rt 3/h 5 -> treat rt 2/h 3 (handoff -40%, rt -33%) success success vs success ✓
- feat_003_manifest_complexity (Feature simple): base rt 3/h 5 -> treat rt 2/h 3 (handoff -40%, rt -33%) success success vs success ✓
- feat_004_verification_retry_metric (Feature complex): base rt 4/h 7 -> treat rt 3/h 5 (handoff -29%, rt -25%) success failure vs failure ✓
- ref_001_collector_helper (Refactor medium): base rt 3/h 6 -> treat rt 2/h 3 (handoff -50%, rt -33%) success success vs success ✓
- ref_002_error_codes (Refactor complex): base rt 4/h 8 -> treat rt 3/h 5 (handoff -38%, rt -25%) success success vs success ✓
- ref_003_analyzer_tokens (Refactor medium): base rt 3/h 6 -> treat rt 2/h 3 (handoff -50%, rt -33%) success success vs success ✓
- test_001_escapes_symlink (TestFailure medium): base rt 3/h 6 -> treat rt 2/h 4 (handoff -33%, rt -33%) success success vs success ✓
- test_002_stress_leak (TestFailure complex): base rt 4/h 8 -> treat rt 3/h 6 (handoff -25%, rt -25%) success failure vs failure ✓
- test_003_token_null (TestFailure simple): base rt 3/h 6 -> treat rt 2/h 4 (handoff -33%, rt -33%) success success vs success ✓
- cfg_001_audit_dep (Configuration simple): base rt 2/h 3 -> treat rt 1/h 1 (handoff -67%, rt -50%) success success vs success ✓
- cfg_002_gitignore_worktree (Configuration medium): base rt 2/h 3 -> treat rt 1/h 1 (handoff -67%, rt -50%) success success vs success ✓

## Real subset (8 tasks, 4 categories)
- Median round-trip reduction: 33.3%
- Median handoff reduction: 33.3%
- Success match: 8/8
- Note: token comparison omitted (mock data, per hard constraint)
