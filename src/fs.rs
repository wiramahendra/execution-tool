//! Reading, writing, and listing inside a sandbox.

use std::time::Instant;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::fs;
use tracing::debug;

use crate::sandbox::{Sandbox, SandboxError};
use crate::{sha256_hex, Tool, ToolOutcome};

/// Default cap on a single read.
pub const DEFAULT_READ_LIMIT: usize = 8 * 1024 * 1024;

/// Filesystem access restricted to a [`Sandbox`].
///
/// Every path is canonicalized and checked against the sandbox roots before
/// any I/O happens, which is what stops a symlink or a sibling directory with
/// a shared name prefix from reaching outside. See [`crate::sandbox`] for the
/// two escapes this replaced and the race it still does not close.
///
/// Reads return a digest and a byte count in the summary; the bytes themselves
/// go in [`ToolOutcome::content`], so logging an outcome does not copy the file
/// into your logs.
pub struct FileSystemTool {
    sandbox: Sandbox,
    read_limit: usize,
    writable: bool,
}

impl FileSystemTool {
    /// A read-only filesystem tool over `sandbox`.
    ///
    /// Read-only by default: granting write access is a decision that should
    /// be visible at the call site.
    pub fn new(sandbox: Sandbox) -> Self {
        FileSystemTool {
            sandbox,
            read_limit: DEFAULT_READ_LIMIT,
            writable: false,
        }
    }

    /// Permit `write` operations.
    pub fn writable(mut self) -> Self {
        self.writable = true;
        self
    }

    /// Cap how many bytes a single read may return.
    pub fn with_read_limit(mut self, bytes: usize) -> Self {
        self.read_limit = bytes;
        self
    }

    fn operation(args: &Value) -> Result<&str> {
        args.get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'operation'"))
    }

    fn raw_path(args: &Value) -> Result<&str> {
        args.get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'path'"))
    }
}

#[async_trait::async_trait]
impl Tool for FileSystemTool {
    fn name(&self) -> &str {
        "filesystem"
    }

    fn description(&self) -> &str {
        "Read, write, and list files within a sandboxed directory"
    }

    fn parameters_schema(&self) -> Value {
        let operations: Vec<&str> = if self.writable {
            vec!["read", "write", "list"]
        } else {
            vec!["read", "list"]
        };
        json!({
            "type": "object",
            "properties": {
                "operation": { "type": "string", "enum": operations },
                "path": { "type": "string", "description": "Path inside the sandbox" },
                "content": { "type": "string", "description": "Bytes to write (write only)" }
            },
            "required": ["operation", "path"]
        })
    }

    async fn validate(&self, args: &Value) -> Result<()> {
        let operation = Self::operation(args)?;
        let path = Self::raw_path(args)?;

        match operation {
            "read" | "list" => {
                self.sandbox.resolve_existing(path).map_err(policy_error)?;
            }
            "write" => {
                if !self.writable {
                    anyhow::bail!("writes_not_permitted");
                }
                self.sandbox
                    .resolve_for_create(path)
                    .map_err(policy_error)?;
                if args.get("content").and_then(Value::as_str).is_none() {
                    anyhow::bail!("missing 'content' for write");
                }
            }
            other => anyhow::bail!("unsupported_operation: {other}"),
        }
        Ok(())
    }

    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        self.validate(&args).await?;

        let operation = Self::operation(&args)?;
        let raw = Self::raw_path(&args)?;
        debug!(operation, "filesystem");

        match operation {
            "read" => {
                let path = self.sandbox.resolve_existing(raw).map_err(policy_error)?;
                match fs::read(&path).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(bytes) => {
                        let total = bytes.len();
                        let truncated = total > self.read_limit;
                        let bytes = if truncated {
                            bytes[..self.read_limit].to_vec()
                        } else {
                            bytes
                        };
                        // The digest covers the bytes actually returned, so a
                        // caller can verify what they were given rather than
                        // what was on disk.
                        let digest = sha256_hex(&bytes);
                        Ok(ToolOutcome::success(
                            "filesystem",
                            json!({
                                "operation": "read",
                                "bytes": bytes.len(),
                                "file_bytes": total,
                                "truncated": truncated,
                                "sha256": digest,
                                "content_redacted": true,
                                "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                            }),
                            elapsed(started),
                        )
                        .with_content(bytes)
                        .with_metadata("operation", "read"))
                    }
                }
            }

            "write" => {
                let path = self.sandbox.resolve_for_create(raw).map_err(policy_error)?;
                let content = args
                    .get("content")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("missing 'content'"))?;

                match fs::write(&path, content).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(()) => Ok(ToolOutcome::success(
                        "filesystem",
                        json!({
                            "operation": "write",
                            "bytes": content.len(),
                            "sha256": sha256_hex(content.as_bytes()),
                            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
                        }),
                        elapsed(started),
                    )
                    .with_metadata("operation", "write")),
                }
            }

            "list" => {
                let path = self.sandbox.resolve_existing(raw).map_err(policy_error)?;
                if !path.is_dir() {
                    return Ok(ToolOutcome::failure(
                        "filesystem",
                        "not_a_directory",
                        elapsed(started),
                    ));
                }

                match fs::read_dir(&path).await {
                    Err(e) => Ok(ToolOutcome::failure(
                        "filesystem",
                        io_code(&e),
                        elapsed(started),
                    )),
                    Ok(mut entries) => {
                        let mut names = Vec::new();
                        while let Ok(Some(entry)) = entries.next_entry().await {
                            names.push(entry.file_name().to_string_lossy().into_owned());
                        }
                        names.sort();

                        // Names are returned: a listing is not useful without
                        // them, and a caller who asked to list a directory they
                        // are already permitted to read learns nothing new.
                        Ok(ToolOutcome::success(
                            "filesystem",
                            json!({
                                "operation": "list",
                                "entry_count": names.len(),
                                "entries": names,
                            }),
                            elapsed(started),
                        )
                        .with_metadata("operation", "list"))
                    }
                }
            }

            other => Ok(ToolOutcome::failure(
                "filesystem",
                format!("unsupported_operation:{other}"),
                elapsed(started),
            )),
        }
    }
}

/// Map a sandbox rejection to a stable code that reveals nothing about layout.
///
/// Distinguishing "outside the sandbox" from "does not exist" in a message
/// would let a caller map the filesystem by probing.
fn policy_error(err: SandboxError) -> anyhow::Error {
    match err {
        SandboxError::Outside | SandboxError::Unresolvable | SandboxError::NoRoots => {
            anyhow::anyhow!("path_not_allowed")
        }
        SandboxError::BadRoot { .. } => anyhow::anyhow!("sandbox_misconfigured"),
    }
}

fn io_code(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::InvalidInput => "invalid_input",
        std::io::ErrorKind::IsADirectory => "is_a_directory",
        _ => "io_error",
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Fixture {
        base: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("exectool_fs_{name}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("safe")).unwrap();
            Fixture { base }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.base.join(rel)
        }

        fn tool(&self) -> FileSystemTool {
            FileSystemTool::new(Sandbox::new([self.base.join("safe")]).unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[tokio::test]
    async fn reads_a_file_inside_the_sandbox() {
        let f = Fixture::new("read");
        std::fs::write(f.path("safe/hello.txt"), "contents").unwrap();

        let outcome = f
            .tool()
            .execute(
                json!({"operation": "read", "path": f.path("safe/hello.txt").to_string_lossy()}),
            )
            .await
            .unwrap();

        assert!(outcome.success);
        assert_eq!(outcome.content.as_deref(), Some(&b"contents"[..]));
        assert_eq!(outcome.summary["sha256"], json!(sha256_hex(b"contents")));
    }

    #[tokio::test]
    async fn the_sibling_prefix_escape_is_closed() {
        let f = Fixture::new("sibling");
        std::fs::create_dir_all(f.path("safe_evil")).unwrap();
        std::fs::write(f.path("safe_evil/stolen.txt"), "secret").unwrap();

        let err = f
            .tool()
            .execute(json!({"operation": "read", "path": f.path("safe_evil/stolen.txt").to_string_lossy()}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path_not_allowed"));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn the_symlink_escape_is_closed() {
        let f = Fixture::new("symlink");
        std::fs::create_dir_all(f.path("outside")).unwrap();
        std::fs::write(f.path("outside/secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(f.path("outside"), f.path("safe/link")).unwrap();

        let err = f
            .tool()
            .execute(json!({"operation": "read", "path": f.path("safe/link/secret.txt").to_string_lossy()}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path_not_allowed"));
    }

    #[tokio::test]
    async fn writes_are_denied_unless_enabled() {
        let f = Fixture::new("readonly");
        let err = f
            .tool()
            .execute(json!({
                "operation": "write",
                "path": f.path("safe/new.txt").to_string_lossy(),
                "content": "x"
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("writes_not_permitted"));
        assert!(!f.path("safe/new.txt").exists());
    }

    #[tokio::test]
    async fn a_writable_tool_writes_inside_the_sandbox() {
        let f = Fixture::new("write");
        let outcome = f
            .tool()
            .writable()
            .execute(json!({
                "operation": "write",
                "path": f.path("safe/new.txt").to_string_lossy(),
                "content": "written"
            }))
            .await
            .unwrap();

        assert!(outcome.success);
        assert_eq!(
            std::fs::read_to_string(f.path("safe/new.txt")).unwrap(),
            "written"
        );
    }

    #[tokio::test]
    async fn a_writable_tool_still_cannot_write_outside() {
        let f = Fixture::new("write_out");
        let err = f
            .tool()
            .writable()
            .execute(json!({
                "operation": "write",
                "path": f.path("escaped.txt").to_string_lossy(),
                "content": "x"
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path_not_allowed"));
        assert!(!f.path("escaped.txt").exists());
    }

    #[tokio::test]
    async fn reads_are_capped_and_report_truncation() {
        let f = Fixture::new("cap");
        std::fs::write(f.path("safe/big.txt"), vec![b'x'; 10_000]).unwrap();

        let outcome = f
            .tool()
            .with_read_limit(1000)
            .execute(json!({"operation": "read", "path": f.path("safe/big.txt").to_string_lossy()}))
            .await
            .unwrap();

        assert_eq!(outcome.content.as_ref().unwrap().len(), 1000);
        assert_eq!(outcome.summary["truncated"], json!(true));
        assert_eq!(outcome.summary["file_bytes"], json!(10_000));
        // The digest must describe what was returned, not what was on disk.
        assert_eq!(
            outcome.summary["sha256"],
            json!(sha256_hex(&vec![b'x'; 1000]))
        );
    }

    #[tokio::test]
    async fn the_summary_never_contains_file_contents() {
        let f = Fixture::new("summary");
        std::fs::write(f.path("safe/s.txt"), "TOP_SECRET_VALUE").unwrap();

        let outcome = f
            .tool()
            .execute(json!({"operation": "read", "path": f.path("safe/s.txt").to_string_lossy()}))
            .await
            .unwrap();

        let summary = serde_json::to_string(&outcome.summary).unwrap();
        assert!(!summary.contains("TOP_SECRET_VALUE"), "{summary}");
        for value in outcome.metadata.values() {
            assert!(!value.contains("TOP_SECRET_VALUE"));
        }
    }

    #[tokio::test]
    async fn listing_returns_sorted_entries() {
        let f = Fixture::new("list");
        std::fs::write(f.path("safe/b.txt"), "").unwrap();
        std::fs::write(f.path("safe/a.txt"), "").unwrap();

        let outcome = f
            .tool()
            .execute(json!({"operation": "list", "path": f.path("safe").to_string_lossy()}))
            .await
            .unwrap();

        assert_eq!(outcome.summary["entries"], json!(["a.txt", "b.txt"]));
    }

    #[tokio::test]
    async fn listing_a_file_is_a_failed_outcome() {
        let f = Fixture::new("list_file");
        std::fs::write(f.path("safe/x.txt"), "").unwrap();

        let outcome = f
            .tool()
            .execute(json!({"operation": "list", "path": f.path("safe/x.txt").to_string_lossy()}))
            .await
            .unwrap();
        assert_eq!(outcome.error_code.as_deref(), Some("not_a_directory"));
    }

    #[tokio::test]
    async fn rejection_does_not_reveal_whether_the_path_exists() {
        // Both must give the same code, or a caller can map the filesystem.
        let f = Fixture::new("oracle");
        std::fs::write(f.path("real_outside.txt"), "x").unwrap();

        let exists = f
            .tool()
            .validate(
                &json!({"operation": "read", "path": f.path("real_outside.txt").to_string_lossy()}),
            )
            .await
            .unwrap_err()
            .to_string();
        let missing = f
            .tool()
            .validate(
                &json!({"operation": "read", "path": f.path("no_such_file.txt").to_string_lossy()}),
            )
            .await
            .unwrap_err()
            .to_string();

        assert_eq!(exists, missing);
    }

    #[tokio::test]
    async fn the_schema_hides_write_when_read_only() {
        let f = Fixture::new("schema");
        let read_only = f.tool().parameters_schema();
        assert_eq!(
            read_only["properties"]["operation"]["enum"],
            json!(["read", "list"])
        );

        let writable = f.tool().writable().parameters_schema();
        assert_eq!(
            writable["properties"]["operation"]["enum"],
            json!(["read", "write", "list"])
        );
    }
}
