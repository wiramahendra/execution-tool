//! Running an allowlisted binary.
//!
//! Read this before enabling it.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::debug;

use crate::sandbox::Sandbox;
use crate::{sha256_hex, Tool, ToolOutcome};

/// Default cap on captured stdout/stderr, per stream.
pub const DEFAULT_OUTPUT_LIMIT: usize = 1024 * 1024;

/// Default wall-clock budget for one command.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// What arguments a command may receive.
///
/// This exists because a binary allowlist alone is not a security boundary,
/// and the crate this was extracted from had only a binary allowlist.
#[derive(Debug, Clone)]
pub enum ArgumentPolicy {
    /// No arguments at all. The only policy that is safe by construction.
    None,

    /// Only these exact argument vectors, matched in full.
    ///
    /// The safe way to allow a small number of known invocations.
    Exact(Vec<Vec<String>>),

    /// Any argument, as long as none begins with `-`.
    ///
    /// Blocks the common option-injection shapes — `--exec`, `-o ProxyCommand`,
    /// `--upload-file` — while still permitting positional arguments like a
    /// filename. Not a guarantee: a binary that treats a bare positional as a
    /// script name is still fully exploitable.
    NoFlags,

    /// Anything at all.
    ///
    /// Equivalent to granting whatever the binary can do. `git` reaches
    /// arbitrary execution through `--exec-path`; `find` through `-exec`;
    /// `tar` through `--to-command`. Choose this only when the binary is
    /// trusted with everything the parent process can do.
    Unrestricted,
}

impl ArgumentPolicy {
    fn permits(&self, args: &[String]) -> bool {
        match self {
            ArgumentPolicy::None => args.is_empty(),
            ArgumentPolicy::Exact(allowed) => allowed.iter().any(|candidate| candidate == args),
            ArgumentPolicy::NoFlags => !args.iter().any(|a| a.starts_with('-')),
            ArgumentPolicy::Unrestricted => true,
        }
    }
}

/// One permitted command.
#[derive(Debug, Clone)]
pub struct AllowedCommand {
    /// Absolute path to the executable.
    ///
    /// Absolute on purpose: resolving through `PATH` means whoever controls
    /// the environment chooses which binary runs.
    pub program: PathBuf,
    /// What arguments it may be given.
    pub arguments: ArgumentPolicy,
}

impl AllowedCommand {
    /// Permit `program` with no arguments.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        AllowedCommand {
            program: program.into(),
            arguments: ArgumentPolicy::None,
        }
    }

    /// Set the argument policy.
    pub fn with_arguments(mut self, policy: ArgumentPolicy) -> Self {
        self.arguments = policy;
        self
    }
}

/// Runs allowlisted binaries with a bounded runtime and bounded output.
///
/// # This is not a sandbox
///
/// The allowlist decides *which binary* runs. It does not decide what that
/// binary does, and for most binaries the arguments decide that entirely:
///
/// ```text
/// allow: /usr/bin/find      →  find / -exec sh -c '…' \;
/// allow: /usr/bin/git       →  git --exec-path=/tmp/evil status
/// allow: /usr/bin/tar       →  tar --to-command=/tmp/evil -xf …
/// ```
///
/// Every one of those is a whitelisted binary reaching arbitrary execution
/// through its own documented options. [`ArgumentPolicy`] is the control that
/// matters, and it defaults to [`ArgumentPolicy::None`].
///
/// There is no shell. Commands are executed directly, so shell metacharacters
/// in an argument are inert — `;`, `|`, `$(…)` are passed through as literal
/// text.
pub struct ShellTool {
    commands: Vec<AllowedCommand>,
    working_dirs: Option<Sandbox>,
    timeout: Duration,
    output_limit: usize,
}

impl ShellTool {
    /// A shell tool permitting exactly these commands.
    ///
    /// An empty list denies everything, which is the correct behaviour for an
    /// unconfigured tool.
    pub fn new(commands: Vec<AllowedCommand>) -> Self {
        ShellTool {
            commands,
            working_dirs: None,
            timeout: DEFAULT_TIMEOUT,
            output_limit: DEFAULT_OUTPUT_LIMIT,
        }
    }

    /// Permit `working_dir` arguments inside this sandbox.
    ///
    /// Without it, `working_dir` is rejected and commands inherit the parent's
    /// directory.
    pub fn with_working_dirs(mut self, sandbox: Sandbox) -> Self {
        self.working_dirs = Some(sandbox);
        self
    }

    /// Set the wall-clock budget. The process is killed when it elapses.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the per-stream capture limit.
    pub fn with_output_limit(mut self, bytes: usize) -> Self {
        self.output_limit = bytes;
        self
    }

    fn lookup(&self, program: &str) -> Option<&AllowedCommand> {
        self.commands
            .iter()
            .find(|candidate| candidate.program.as_os_str() == program)
    }

    fn parse(&self, args: &Value) -> Result<(PathBuf, Vec<String>, Option<PathBuf>)> {
        let program = args
            .get("program")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'program'"))?;

        let arguments: Vec<String> = match args.get("args") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow::anyhow!("'args' must be an array of strings"))
                })
                .collect::<Result<_>>()?,
            Some(_) => bail!("'args' must be an array of strings"),
        };

        let allowed = self
            .lookup(program)
            .ok_or_else(|| anyhow::anyhow!("command_not_allowed"))?;

        if !allowed.arguments.permits(&arguments) {
            bail!("arguments_not_allowed");
        }

        let working_dir = match args.get("working_dir").and_then(Value::as_str) {
            None => None,
            Some(dir) => {
                let sandbox = self
                    .working_dirs
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("working_dir_not_allowed"))?;
                Some(
                    sandbox
                        .resolve_existing(dir)
                        .map_err(|_| anyhow::anyhow!("working_dir_not_allowed"))?,
                )
            }
        };

        Ok((allowed.program.clone(), arguments, working_dir))
    }
}

#[async_trait::async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn description(&self) -> &str {
        "Run an allowlisted executable with bounded runtime and output"
    }

    fn parameters_schema(&self) -> Value {
        let names: Vec<String> = self
            .commands
            .iter()
            .map(|c| c.program.display().to_string())
            .collect();
        json!({
            "type": "object",
            "properties": {
                "program": {
                    "type": "string",
                    "description": "Absolute path to an allowlisted executable",
                    "enum": names
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Arguments, subject to this command's argument policy"
                },
                "working_dir": {
                    "type": "string",
                    "description": "Directory to run in; must be inside the configured sandbox"
                }
            },
            "required": ["program"]
        })
    }

    async fn validate(&self, args: &Value) -> Result<()> {
        self.parse(args).map(|_| ())
    }

    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        let (program, arguments, working_dir) = self.parse(&args)?;

        debug!(program = %program.display(), argc = arguments.len(), "shell exec");

        let mut command = Command::new(&program);
        command
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Without this the child survives a timeout and keeps running
            // unsupervised, which the original did.
            .kill_on_drop(true);

        if let Some(dir) = &working_dir {
            command.current_dir(dir);
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                return Ok(ToolOutcome::failure(
                    "shell",
                    "spawn_failed",
                    elapsed(started),
                ))
            }
        };

        let mut stdout = child.stdout.take().expect("stdout is piped");
        let mut stderr = child.stderr.take().expect("stderr is piped");
        let limit = self.output_limit;

        let collect = async {
            // Capped reads: an unbounded capture lets a chatty command exhaust
            // memory in the supervising process.
            let (out, err) = tokio::join!(
                read_capped(&mut stdout, limit),
                read_capped(&mut stderr, limit)
            );
            let status = child.wait().await?;
            std::io::Result::Ok((status, out?, err?))
        };

        match tokio::time::timeout(self.timeout, collect).await {
            Err(_) => Ok(ToolOutcome::failure("shell", "timed_out", elapsed(started))
                .with_metadata("timeout_ms", self.timeout.as_millis().to_string())),

            Ok(Err(_)) => Ok(ToolOutcome::failure("shell", "io_error", elapsed(started))),

            Ok(Ok((status, (out, out_truncated), (err, err_truncated)))) => {
                let code = status.code();
                let summary = json!({
                    "exit_code": code,
                    "stdout_bytes": out.len(),
                    "stdout_sha256": sha256_hex(&out),
                    "stdout_truncated": out_truncated,
                    "stderr_bytes": err.len(),
                    "stderr_sha256": sha256_hex(&err),
                    "stderr_truncated": err_truncated,
                    "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                });

                let outcome = if status.success() {
                    ToolOutcome::success("shell", summary, elapsed(started))
                } else {
                    let mut failed =
                        ToolOutcome::failure("shell", "nonzero_exit", elapsed(started));
                    failed.summary = summary;
                    failed
                };

                // Command output is not redacted the way file contents are:
                // an exit code alone is rarely actionable. It is returned as
                // `content` rather than in the summary, so it is not logged by
                // default.
                Ok(outcome
                    .with_content(out)
                    .with_metadata(
                        "exit_code",
                        code.map(|c| c.to_string())
                            .unwrap_or_else(|| "signal".into()),
                    )
                    .with_metadata("program", program.display().to_string()))
            }
        }
    }
}

/// Read at most `limit` bytes, reporting whether more were available.
async fn read_capped<R>(reader: &mut R, limit: usize) -> std::io::Result<(Vec<u8>, bool)>
where
    R: AsyncReadExt + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;

    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        if buffer.len() < limit {
            let room = limit - buffer.len();
            buffer.extend_from_slice(&chunk[..read.min(room)]);
            if read > room {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((buffer, truncated))
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

/// Names of the commands an allowlist permits, for diagnostics.
pub fn allowed_names(commands: &[AllowedCommand]) -> HashSet<String> {
    commands
        .iter()
        .map(|c| c.program.display().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_path() -> &'static str {
        if std::path::Path::new("/bin/echo").exists() {
            "/bin/echo"
        } else {
            "/usr/bin/echo"
        }
    }

    fn tool_allowing(policy: ArgumentPolicy) -> ShellTool {
        ShellTool::new(vec![AllowedCommand::new(echo_path()).with_arguments(policy)])
    }

    #[tokio::test]
    async fn an_empty_allowlist_denies_everything() {
        let tool = ShellTool::new(vec![]);
        let err = tool
            .validate(&json!({"program": echo_path()}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("command_not_allowed"));
    }

    #[tokio::test]
    async fn a_non_allowlisted_program_is_denied() {
        let tool = tool_allowing(ArgumentPolicy::None);
        let err = tool
            .validate(&json!({"program": "/bin/rm"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("command_not_allowed"));
    }

    #[tokio::test]
    async fn a_relative_program_name_does_not_match_an_absolute_allowlist() {
        // PATH resolution is the point: `echo` must not satisfy `/bin/echo`,
        // or whoever controls PATH chooses the binary.
        let tool = tool_allowing(ArgumentPolicy::None);
        assert!(tool.validate(&json!({"program": "echo"})).await.is_err());
    }

    #[tokio::test]
    async fn the_default_argument_policy_rejects_arguments() {
        let tool = tool_allowing(ArgumentPolicy::None);
        let err = tool
            .validate(&json!({"program": echo_path(), "args": ["hello"]}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("arguments_not_allowed"));
    }

    #[tokio::test]
    async fn no_flags_blocks_option_injection_but_allows_positionals() {
        let tool = tool_allowing(ArgumentPolicy::NoFlags);
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["hello"]}))
            .await
            .is_ok());
        // The shape that turns a whitelisted binary into arbitrary execution.
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["--exec-path=/tmp/evil"]}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["-exec"]}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn exact_matches_the_whole_vector() {
        let tool = tool_allowing(ArgumentPolicy::Exact(vec![vec!["status".into()]]));
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["status"]}))
            .await
            .is_ok());
        // A permitted prefix must not admit extra arguments.
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": ["status", "--porcelain"]}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": []}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_command_runs_and_reports_its_output() {
        let tool = tool_allowing(ArgumentPolicy::NoFlags);
        let outcome = tool
            .execute(json!({"program": echo_path(), "args": ["hello"]}))
            .await
            .unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.summary["exit_code"], json!(0));
        assert_eq!(
            String::from_utf8_lossy(outcome.content.as_ref().unwrap()).trim(),
            "hello"
        );
    }

    #[tokio::test]
    async fn shell_metacharacters_are_inert() {
        // No shell is involved, so this must be echoed literally rather than
        // interpreted as a command separator.
        let tool = tool_allowing(ArgumentPolicy::NoFlags);
        let outcome = tool
            .execute(json!({"program": echo_path(), "args": ["a; touch /tmp/exectool_pwned"]}))
            .await
            .unwrap();

        let out = String::from_utf8_lossy(outcome.content.as_ref().unwrap()).to_string();
        assert!(
            out.contains("touch"),
            "argument was not passed literally: {out}"
        );
        assert!(!std::path::Path::new("/tmp/exectool_pwned").exists());
    }

    #[tokio::test]
    async fn output_is_capped_and_truncation_is_reported() {
        let yes = ["/bin/cat", "/usr/bin/cat"]
            .iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(cat) = yes else { return };

        let big = std::env::temp_dir().join(format!("exectool_big_{}.txt", std::process::id()));
        std::fs::write(&big, vec![b'x'; 100_000]).unwrap();

        let tool = ShellTool::new(vec![
            AllowedCommand::new(*cat).with_arguments(ArgumentPolicy::NoFlags)
        ])
        .with_output_limit(1024);

        let outcome = tool
            .execute(json!({"program": cat, "args": [big.to_string_lossy()]}))
            .await
            .unwrap();

        assert_eq!(outcome.content.as_ref().unwrap().len(), 1024);
        assert_eq!(outcome.summary["stdout_truncated"], json!(true));
        let _ = std::fs::remove_file(&big);
    }

    #[tokio::test]
    async fn a_working_dir_is_rejected_without_a_sandbox() {
        let tool = tool_allowing(ArgumentPolicy::None);
        let err = tool
            .validate(&json!({"program": echo_path(), "working_dir": "/tmp"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("working_dir_not_allowed"));
    }

    #[tokio::test]
    async fn a_working_dir_outside_the_sandbox_is_rejected() {
        let base = std::env::temp_dir().join(format!("exectool_wd_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("safe")).unwrap();
        // The sibling-prefix escape, applied to working_dir.
        std::fs::create_dir_all(base.join("safe_evil")).unwrap();

        let tool = tool_allowing(ArgumentPolicy::None)
            .with_working_dirs(Sandbox::new([base.join("safe")]).unwrap());

        assert!(tool
            .validate(
                &json!({"program": echo_path(), "working_dir": base.join("safe").to_string_lossy()})
            )
            .await
            .is_ok());
        assert!(tool
            .validate(&json!({"program": echo_path(), "working_dir": base.join("safe_evil").to_string_lossy()}))
            .await
            .is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_slow_command_times_out_and_the_child_does_not_survive() {
        let sleep = ["/bin/sleep", "/usr/bin/sleep"]
            .iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(sleep) = sleep else { return };

        let tool = ShellTool::new(vec![
            AllowedCommand::new(*sleep).with_arguments(ArgumentPolicy::NoFlags)
        ])
        .with_timeout(Duration::from_millis(150));

        let started = Instant::now();
        let outcome = tool
            .execute(json!({"program": sleep, "args": ["30"]}))
            .await
            .unwrap();

        assert!(!outcome.success);
        assert_eq!(outcome.error_code.as_deref(), Some("timed_out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_a_failed_outcome_not_an_error() {
        let f = ["/usr/bin/false", "/bin/false"]
            .iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(f) = f else { return };

        let tool = ShellTool::new(vec![AllowedCommand::new(*f)]);
        let outcome = tool.execute(json!({"program": f})).await.unwrap();

        assert!(!outcome.success);
        assert_eq!(outcome.error_code.as_deref(), Some("nonzero_exit"));
        assert_ne!(outcome.summary["exit_code"], json!(0));
    }

    #[tokio::test]
    async fn non_string_arguments_are_rejected() {
        let tool = tool_allowing(ArgumentPolicy::Unrestricted);
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": [1, 2]}))
            .await
            .is_err());
        assert!(tool
            .validate(&json!({"program": echo_path(), "args": "not an array"}))
            .await
            .is_err());
    }

    #[test]
    fn argument_policies_behave_as_documented() {
        let none = ArgumentPolicy::None;
        assert!(none.permits(&[]));
        assert!(!none.permits(&["x".into()]));

        let unrestricted = ArgumentPolicy::Unrestricted;
        assert!(unrestricted.permits(&["--anything".into()]));

        let no_flags = ArgumentPolicy::NoFlags;
        assert!(no_flags.permits(&["file.txt".into()]));
        assert!(!no_flags.permits(&["-r".into()]));
    }
}
