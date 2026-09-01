//! Purpose-specific, post-edit verification for an already changed repository.
#![allow(missing_docs)]

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::sandbox::Sandbox;
use crate::shell::{AllowedCommand, ArgumentPolicy, ShellTool};
use crate::{sha256_hex, Tool, ToolOutcome, ToolRegistry};

const MAX_CHECKS: usize = 4;
const MAX_DIAGNOSTIC_BYTES: usize = 2_048;
const MAX_DIFF_STAT_BYTES: usize = 8_192;
const ORDER: [&str; 5] = [
    "targeted_test",
    "typecheck",
    "lint",
    "build_check",
    "git_diff",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyConfig {
    pub version: u32,
    pub checks: HashMap<String, CheckDef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CheckDef {
    /// Repository-owner configured executable; callers may select only its id.
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_stop_on_failure")]
    pub stop_on_failure: bool,
}
fn default_stop_on_failure() -> bool {
    true
}

impl VerifyConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(match path.extension().and_then(|e| e.to_str()) {
            Some("yaml" | "yml") => serde_yaml::from_str(&data)?,
            _ => serde_json::from_str(&data)?,
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct VerifyChangeRequest {
    pub scope: Option<Vec<String>>,
    pub checks: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerCheckResult {
    pub check: String,
    pub status: String,
    pub duration_ms: u64,
    pub exit_code: Option<i32>,
    pub diagnostic: String,
    pub output_sha256: Option<String>,
    pub output_bytes: usize,
    pub truncated: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyChangeResponse {
    pub overall_success: bool,
    pub changed_files: Vec<String>,
    pub diff_stat: String,
    pub checks_requested: Vec<String>,
    pub checks_executed: Vec<String>,
    pub per_check: Vec<PerCheckResult>,
    pub failed_check: Option<String>,
}

/// Executes exact configured commands through `ShellTool`, preserving its
/// absolute-program, sandbox-working-directory, and `ArgumentPolicy::Exact`
/// enforcement. It has no write or repair code path.
pub struct VerifyChangeTool {
    workdir: PathBuf,
    config: VerifyConfig,
}

impl VerifyChangeTool {
    pub fn from_config_path(
        workdir: impl AsRef<Path>,
        config_path: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            workdir: workdir.as_ref().canonicalize()?,
            config: VerifyConfig::load(config_path.as_ref())?,
        })
    }
    fn resolve_checks(&self, requested: Option<Vec<String>>) -> anyhow::Result<Vec<String>> {
        let checks = requested.unwrap_or_else(|| {
            ORDER
                .iter()
                .filter(|id| self.config.checks.contains_key(**id))
                .take(MAX_CHECKS)
                .map(|id| (*id).to_owned())
                .collect()
        });
        if checks.len() > MAX_CHECKS {
            anyhow::bail!("too_many_checks");
        }
        let mut seen = BTreeSet::new();
        for id in &checks {
            if !self.config.checks.contains_key(id) {
                anyhow::bail!("unknown_check");
            }
            if !seen.insert(id) {
                anyhow::bail!("duplicate_check");
            }
        }
        Ok(checks)
    }
    fn validate_scope(&self, scope: Option<&Vec<String>>) -> anyhow::Result<Vec<String>> {
        let Some(scope) = scope else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for item in scope {
            let path = Path::new(item);
            if item.is_empty()
                || path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                anyhow::bail!("invalid_scope");
            }
            out.push(item.clone());
        }
        Ok(out)
    }
    fn git_output(&self, args: &[&str], scope: &[String]) -> anyhow::Result<Vec<u8>> {
        let mut command = std::process::Command::new("git");
        command.args(args).current_dir(&self.workdir);
        if !scope.is_empty() {
            command.arg("--").args(scope);
        }
        let output = command.output()?;
        if !output.status.success() {
            anyhow::bail!("git_inspection_failed");
        }
        Ok(output.stdout)
    }
    fn configured_registry(&self, requested: &[String]) -> anyhow::Result<ToolRegistry> {
        let sandbox = Sandbox::new([&self.workdir])?;
        let mut policies: HashMap<String, Vec<Vec<String>>> = HashMap::new();
        for id in requested {
            let check = &self.config.checks[id];
            policies
                .entry(resolve_program(&check.program)?)
                .or_default()
                .push(check.args.clone());
        }
        let allowed = policies
            .into_iter()
            .map(|(program, args)| {
                AllowedCommand::new(program).with_arguments(ArgumentPolicy::Exact(args))
            })
            .collect();
        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(ShellTool::new(allowed).with_working_dirs(sandbox)));
        Ok(registry)
    }
}

fn resolve_program(program: &str) -> anyhow::Result<String> {
    let candidate = Path::new(program);
    if candidate.is_absolute() {
        if candidate.is_file() {
            return Ok(program.to_owned());
        }
        anyhow::bail!("configured_program_not_found");
    }
    let path = std::env::var_os("PATH").ok_or_else(|| anyhow::anyhow!("path_unavailable"))?;
    for dir in std::env::split_paths(&path) {
        let found = dir.join(program);
        if found.is_file() {
            return Ok(found.to_string_lossy().into_owned());
        }
    }
    anyhow::bail!("configured_program_not_found")
}
fn bounded_text(bytes: &[u8], limit: usize) -> (String, bool) {
    (
        String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]).into_owned(),
        bytes.len() > limit,
    )
}

#[async_trait::async_trait]
impl Tool for VerifyChangeTool {
    fn name(&self) -> &str {
        "verify_change"
    }
    fn description(&self) -> &str {
        "Verify the current code change using repository-defined checks and return structured results. Use when you have finished making a change and do not need additional reasoning between verification checks."
    }
    fn parameters_schema(&self) -> Value {
        json!({"type":"object","properties":{"scope":{"type":"array","items":{"type":"string"}},"checks":{"type":"array","maxItems":4,"items":{"type":"string","enum":ORDER}}}})
    }
    async fn validate(&self, args: &Value) -> anyhow::Result<()> {
        let request: VerifyChangeRequest = serde_json::from_value(args.clone())?;
        self.validate_scope(request.scope.as_ref())?;
        self.resolve_checks(request.checks)?;
        Ok(())
    }
    async fn execute(&self, args: Value) -> anyhow::Result<ToolOutcome> {
        self.validate(&args).await?;
        let start = Instant::now();
        let request: VerifyChangeRequest = serde_json::from_value(args)?;
        let scope = self.validate_scope(request.scope.as_ref())?;
        let requested = self.resolve_checks(request.checks)?;
        let changed_files =
            String::from_utf8_lossy(&self.git_output(&["diff", "--name-only"], &scope)?)
                .lines()
                .map(str::to_owned)
                .filter(|p| !p.is_empty())
                .collect();
        let (diff_stat, _) = bounded_text(
            &self.git_output(&["diff", "--stat"], &scope)?,
            MAX_DIFF_STAT_BYTES,
        );
        let registry = self.configured_registry(&requested)?;
        let mut executed = Vec::new();
        let mut per_check = Vec::new();
        let mut failed_check = None;
        for id in &requested {
            let check = &self.config.checks[id];
            let program = resolve_program(&check.program)?;
            let args = check.args.clone();
            let workdir = self.workdir.to_string_lossy().into_owned();
            let outcome = registry
                .execute(
                    "shell",
                    json!({"program": program, "args": args, "working_dir": workdir}),
                )
                .await?;
            let bytes = outcome.content.as_deref().unwrap_or_default();
            let (diagnostic, truncated) = bounded_text(bytes, MAX_DIAGNOSTIC_BYTES);
            let success = outcome.success;
            per_check.push(PerCheckResult {
                check: id.clone(),
                status: if success {
                    "passed".into()
                } else {
                    "failed".into()
                },
                duration_ms: outcome.duration_ms,
                exit_code: outcome
                    .summary
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .map(|v| v as i32),
                diagnostic,
                output_sha256: (!bytes.is_empty()).then(|| sha256_hex(bytes)),
                output_bytes: bytes.len(),
                truncated,
            });
            executed.push(id.clone());
            if !success {
                failed_check = Some(id.clone());
                if check.stop_on_failure {
                    break;
                }
            }
        }
        let response = VerifyChangeResponse {
            overall_success: failed_check.is_none(),
            changed_files,
            diff_stat,
            checks_requested: requested,
            checks_executed: executed,
            per_check,
            failed_check,
        };
        let duration_ms = start.elapsed().as_millis() as u64;
        let summary = serde_json::to_value(&response)?;
        Ok(if response.overall_success {
            ToolOutcome::success("verify_change", summary, duration_ms)
        } else {
            let mut out = ToolOutcome::failure(
                "verify_change",
                response
                    .failed_check
                    .clone()
                    .unwrap_or_else(|| "verification_failed".into()),
                duration_ms,
            );
            out.summary = summary;
            out
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        fs::write(dir.path().join("a.txt"), "before\n").unwrap();
        std::process::Command::new("git")
            .args(["add", "a.txt"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        std::process::Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "initial",
            ])
            .current_dir(dir.path())
            .status()
            .unwrap();
        fs::write(dir.path().join("a.txt"), "after\n").unwrap();
        let config = dir.path().join("verify.yaml");
        fs::write(&config, "version: 1\nchecks:\n  targeted_test:\n    program: echo\n    args: [targeted]\n  typecheck:\n    program: echo\n    args: [typecheck]\n").unwrap();
        (dir, config)
    }
    #[tokio::test]
    async fn unknown_check_is_rejected() {
        let (dir, config) = fixture();
        let tool = VerifyChangeTool::from_config_path(dir.path(), config).unwrap();
        assert!(tool.execute(json!({"checks":["unknown"]})).await.is_err());
    }
    #[tokio::test]
    async fn configured_checks_are_ordered_and_source_is_unchanged() {
        let (dir, config) = fixture();
        let before = fs::read(dir.path().join("a.txt")).unwrap();
        let tool = VerifyChangeTool::from_config_path(dir.path(), config).unwrap();
        let outcome = tool
            .execute(json!({"checks":["typecheck", "targeted_test"]}))
            .await
            .unwrap();
        assert!(outcome.success);
        assert_eq!(
            outcome.summary["checks_executed"],
            json!(["typecheck", "targeted_test"])
        );
        assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), before);
    }
    #[tokio::test]
    async fn failure_is_preserved_without_retry() {
        let (dir, config) = fixture();
        fs::write(&config, "version: 1\nchecks:\n  targeted_test:\n    program: false\n    args: []\n  typecheck:\n    program: echo\n    args: [not-run]\n").unwrap();
        let tool = VerifyChangeTool::from_config_path(dir.path(), config).unwrap();
        let outcome = tool
            .execute(json!({"checks":["targeted_test", "typecheck"]}))
            .await
            .unwrap();
        assert!(!outcome.success);
        assert_eq!(outcome.summary["failed_check"], "targeted_test");
        assert_eq!(outcome.summary["checks_executed"], json!(["targeted_test"]));
    }
}
