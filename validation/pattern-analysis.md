# Pattern Analysis

Total tasks: 20, total tool calls: 114

## Top 20 adjacent bigrams
- search→read: count 16, tasks 14 (bug_001_read_limit_clamp,bug_002_header_allowlist,bug_003_base64_write,bug_004_collector_status_parse,inv_001_ssrf_destination,inv_002_sandbox_toctou,inv_003_audit_logging,inv_004_registry_batch_sequence,ref_001_collector_helper,ref_002_error_codes,ref_003_analyzer_tokens,test_001_escapes_symlink,test_002_stress_leak,test_003_token_null), median turns between 0.0
- write→shell: count 16, tasks 16 (bug_001_read_limit_clamp,bug_002_header_allowlist,bug_003_base64_write,bug_004_collector_status_parse,cfg_001_audit_dep,cfg_002_gitignore_worktree,feat_001_stat_summary,feat_002_env_redaction_doc,feat_003_manifest_complexity,feat_004_verification_retry_metric,ref_001_collector_helper,ref_002_error_codes,ref_003_analyzer_tokens,test_001_escapes_symlink,test_002_stress_leak,test_003_token_null), median turns between 0.0
- read→read: count 14, tasks 11 (feat_001_stat_summary,feat_002_env_redaction_doc,feat_003_manifest_complexity,feat_004_verification_retry_metric,inv_001_ssrf_destination,inv_002_sandbox_toctou,inv_003_audit_logging,inv_004_registry_batch_sequence,ref_001_collector_helper,ref_002_error_codes,ref_003_analyzer_tokens), median turns between 0.5
- read→write: count 12, tasks 12 (cfg_001_audit_dep,cfg_002_gitignore_worktree,feat_001_stat_summary,feat_002_env_redaction_doc,feat_003_manifest_complexity,feat_004_verification_retry_metric,ref_001_collector_helper,ref_002_error_codes,ref_003_analyzer_tokens,test_001_escapes_symlink,test_002_stress_leak,test_003_token_null), median turns between 1.0
- read→search: count 11, tasks 11 (bug_001_read_limit_clamp,bug_002_header_allowlist,bug_003_base64_write,bug_004_collector_status_parse,inv_001_ssrf_destination,inv_002_sandbox_toctou,inv_003_audit_logging,inv_004_registry_batch_sequence,test_001_escapes_symlink,test_002_stress_leak,test_003_token_null), median turns between 0.0
- read→shell: count 9, tasks 8 (bug_001_read_limit_clamp,bug_002_header_allowlist,bug_003_base64_write,bug_004_collector_status_parse,feat_004_verification_retry_metric,inv_001_ssrf_destination,inv_002_sandbox_toctou,test_002_stress_leak), median turns between 0.0
- shell→read: count 6, tasks 5 (bug_004_collector_status_parse,feat_004_verification_retry_metric,test_001_escapes_symlink,test_002_stress_leak,test_003_token_null), median turns between 0.5
- shell→shell: count 6, tasks 5 (feat_001_stat_summary,feat_002_env_redaction_doc,feat_003_manifest_complexity,feat_004_verification_retry_metric,ref_002_error_codes), median turns between 1.0
- shell→write: count 4, tasks 4 (bug_001_read_limit_clamp,bug_002_header_allowlist,bug_003_base64_write,bug_004_collector_status_parse), median turns between 1.0

## Top trigrams
- read→write→shell: count 12, tasks 12
- read→search→read: count 9, tasks 9
- read→read→write: count 7, tasks 7
- search→read→read: count 7, tasks 7
- search→read→shell: count 6, tasks 6
- write→shell→shell: count 5, tasks 5
- read→read→search: count 4, tasks 4
- read→shell→write: count 4, tasks 4
- shell→write→shell: count 4, tasks 4
- read→read→read: count 3, tasks 3

## Volume dominance
- read: 46
- search: 18
- shell: 34
- write: 16

## Duration dominance (ms total)
- read: 250
- search: 1008
- shell: 566
- write: 10

## Success after op
- read: success 46, failure 0
- search: success 18, failure 0
- shell: success 34, failure 0
- write: success 16, failure 0
