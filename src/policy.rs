#![allow(missing_docs)]
//! Policy as Code — `execution.yaml` (Phase 3)
//!
//! ```yaml
//! workspace: /tmp/executiond
//! concurrency: 32
//! audit_log: ./audit.jsonl
//! filesystem:
//!   writable: true
//! shell:
//!   commands:
//!     - program: /bin/echo
//!       args: NoFlags
//!     - program: /bin/cat
//!       args: { Exact: [["--help"]] }
//!     - program: /usr/bin/git
//!       args: { Exact: [["status"]] }
//! http:
//!   allowed_hosts: [api.github.com]
//!   request_body_limit: 1048576
//!   response_body_limit: 4194304
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{shell::AllowedCommand, ArgumentPolicy, Sandbox};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    #[serde(default = "default_workspace")]
    pub workspace: PathBuf,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    pub audit_log: Option<PathBuf>,
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub shell: ShellPolicy,
    #[serde(default)]
    pub http: HttpPolicy,
    #[serde(default)]
    pub code: CodePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default = "default_true")]
    pub writable: bool,
    #[serde(default = "default_read_limit")]
    pub read_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellPolicy {
    #[serde(default)]
    pub commands: Vec<ShellCommandPolicy>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_output_limit")]
    pub output_limit: usize,
    pub allowed_env: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellCommandPolicy {
    pub program: String,
    #[serde(default = "default_arg_policy")]
    pub args: ArgPolicySerde,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArgPolicySerde {
    Simple(String),
    Detailed(ArgPolicyDetailed),
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgPolicyDetailed {
    pub Exact: Option<Vec<Vec<String>>>,
    pub NoFlags: Option<bool>,
    pub Unrestricted: Option<bool>,
    pub None: Option<bool>,
}

impl ArgPolicySerde {
    pub fn into_policy(self) -> ArgumentPolicy {
        match self {
            ArgPolicySerde::Simple(s) => match s.as_str() {
                "None" => ArgumentPolicy::None,
                "NoFlags" => ArgumentPolicy::NoFlags,
                "Unrestricted" => ArgumentPolicy::Unrestricted,
                _ => ArgumentPolicy::None,
            },
            ArgPolicySerde::Detailed(d) => {
                if let Some(v) = d.Exact {
                    return ArgumentPolicy::Exact(v);
                }
                if d.NoFlags == Some(true) {
                    return ArgumentPolicy::NoFlags;
                }
                if d.Unrestricted == Some(true) {
                    return ArgumentPolicy::Unrestricted;
                }
                ArgumentPolicy::None
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPolicy {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default = "default_req_limit")]
    pub request_body_limit: usize,
    #[serde(default = "default_resp_limit")]
    pub response_body_limit: usize,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodePolicy {
    #[serde(default)]
    pub allowed_languages: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_output_limit")]
    pub output_limit: usize,
}

// defaults
fn default_workspace() -> PathBuf {
    PathBuf::from("/tmp/executiond")
}
fn default_concurrency() -> usize {
    32
}
fn default_true() -> bool {
    true
}
fn default_read_limit() -> usize {
    8 * 1024 * 1024
}
fn default_timeout() -> u64 {
    30_000
}
fn default_output_limit() -> usize {
    1024 * 1024
}
fn default_req_limit() -> usize {
    4 * 1024 * 1024
}
fn default_resp_limit() -> usize {
    4 * 1024 * 1024
}
fn default_arg_policy() -> ArgPolicySerde {
    ArgPolicySerde::Simple("None".into())
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            workspace: default_workspace(),
            concurrency: default_concurrency(),
            audit_log: None,
            filesystem: FilesystemPolicy::default(),
            shell: ShellPolicy::default(),
            http: HttpPolicy::default(),
            code: CodePolicy::default(),
        }
    }
}
impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            writable: true,
            read_limit: default_read_limit(),
        }
    }
}
impl Default for ShellPolicy {
    fn default() -> Self {
        Self {
            commands: vec![],
            timeout_ms: default_timeout(),
            output_limit: default_output_limit(),
            allowed_env: None,
        }
    }
}
impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: vec![],
            request_body_limit: default_req_limit(),
            response_body_limit: default_resp_limit(),
            timeout_ms: default_timeout(),
        }
    }
}
impl Default for CodePolicy {
    fn default() -> Self {
        Self {
            allowed_languages: vec!["python".into(), "bash".into(), "javascript".into()],
            timeout_ms: default_timeout(),
            output_limit: default_output_limit(),
        }
    }
}

impl ExecutionPolicy {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        Self::from_yaml(&s)
    }

    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        let p: Self = serde_yaml::from_str(s)?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.concurrency == 0 {
            anyhow::bail!("concurrency must be >0");
        }
        if self.concurrency > 128 {
            anyhow::bail!("concurrency too large: {}", self.concurrency);
        }
        if self.workspace.as_os_str().is_empty() {
            anyhow::bail!("workspace must not be empty");
        }
        if !self.workspace.is_absolute() {
            anyhow::bail!("workspace must be absolute");
        }
        if self.filesystem.read_limit == 0 || self.filesystem.read_limit > 64 * 1024 * 1024 {
            anyhow::bail!("read_limit must be 1..64MiB");
        }
        if self.shell.timeout_ms == 0 || self.shell.timeout_ms > 300_000 {
            anyhow::bail!("shell timeout must be 1..300000ms");
        }
        if self.shell.output_limit == 0 || self.shell.output_limit > 16 * 1024 * 1024 {
            anyhow::bail!("shell output_limit must be 1..16MiB");
        }
        if self.http.timeout_ms == 0 || self.http.timeout_ms > 120_000 {
            anyhow::bail!("http timeout must be 1..120000ms");
        }
        for c in &self.shell.commands {
            if !c.program.starts_with('/') {
                anyhow::bail!("shell program must be absolute: {}", c.program);
            }
            if !Path::new(&c.program).is_absolute() {
                anyhow::bail!("absolute path required: {}", c.program);
            }
        }
        // hosts must be lowercased, no wildcards, no whitespace/control
        for h in &self.http.allowed_hosts {
            if h.chars().any(|c| c.is_control() || c.is_whitespace()) {
                anyhow::bail!("host contains control/whitespace: {h}");
            }
            if h.contains('*') {
                anyhow::bail!("wildcard hosts not allowed: {h}");
            }
            if h.len() > 253 {
                anyhow::bail!("host too long: {h}");
            }
        }
        if self.code.timeout_ms == 0 || self.code.timeout_ms > 30_000 {
            anyhow::bail!("code timeout must be 1..30000ms");
        }
        if self.code.output_limit == 0 || self.code.output_limit > 16 * 1024 * 1024 {
            anyhow::bail!("code output_limit must be 1..16MiB");
        }
        for lang in &self.code.allowed_languages {
            if !matches!(
                lang.as_str(),
                "python" | "javascript" | "js" | "bash" | "sh"
            ) {
                anyhow::bail!("unsupported code language: {lang}");
            }
        }
        Ok(())
    }

    pub fn sandbox(&self) -> anyhow::Result<Sandbox> {
        std::fs::create_dir_all(&self.workspace)?;
        Sandbox::new([&self.workspace]).map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub fn allowed_commands(&self) -> Vec<AllowedCommand> {
        self.shell
            .commands
            .iter()
            .map(|c| {
                AllowedCommand::new(c.program.clone()).with_arguments(c.args.clone().into_policy())
            })
            .collect()
    }

    pub fn shell_timeout(&self) -> Duration {
        Duration::from_millis(self.shell.timeout_ms)
    }
    pub fn http_timeout(&self) -> Duration {
        Duration::from_millis(self.http.timeout_ms)
    }

    pub fn code_timeout(&self) -> Duration {
        Duration::from_millis(self.code.timeout_ms)
    }

    pub fn code_languages(&self) -> Vec<crate::Language> {
        self.code
            .allowed_languages
            .iter()
            .filter_map(|s| crate::Language::parse(s))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_valid() {
        ExecutionPolicy::default().validate().unwrap();
    }

    #[test]
    fn yaml_roundtrip_minimal() {
        let yaml = r#"
workspace: /tmp/test_exec
concurrency: 8
filesystem:
  writable: true
shell:
  commands:
    - program: /bin/echo
      args: NoFlags
http:
  allowed_hosts: [api.github.com]
"#;
        let p = ExecutionPolicy::from_yaml(yaml).unwrap();
        assert_eq!(p.concurrency, 8);
        assert_eq!(p.http.allowed_hosts, vec!["api.github.com"]);
        assert_eq!(p.shell.commands.len(), 1);
    }

    #[test]
    fn yaml_exact_args() {
        let yaml = r#"
shell:
  commands:
    - program: /usr/bin/git
      args:
        Exact: [["status"], ["log", "--oneline"]]
"#;
        let p = ExecutionPolicy::from_yaml(yaml).unwrap();
        let cmds = p.allowed_commands();
        assert!(matches!(cmds[0].arguments, crate::ArgumentPolicy::Exact(_)));
    }

    #[test]
    fn rejects_relative_program() {
        let yaml = r#"shell: { commands: [{program: echo, args: None}]}"#;
        assert!(ExecutionPolicy::from_yaml(yaml).is_err());
    }

    #[test]
    fn rejects_wildcard_host() {
        let yaml = r#"http: { allowed_hosts: ["*.evil.com"] }"#;
        assert!(ExecutionPolicy::from_yaml(yaml).is_err());
    }
}
