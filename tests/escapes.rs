//! Escapes that worked against the code this crate was extracted from.
//!
//! Each test here is a technique that was verified to work before the rewrite,
//! kept as a regression so a future refactor cannot quietly reintroduce it.
//! They are written as attacks rather than as unit assertions because that is
//! how they were found, and because the shape of the attack is the part worth
//! preserving.

use std::path::PathBuf;

use marshall::{
    destination::DestinationError, validate_destination, ArgumentPolicy, FileSystemTool, Sandbox,
    ShellTool, SystemTool, Tool,
};
use serde_json::json;

struct Workspace {
    base: PathBuf,
}

impl Workspace {
    fn new(name: &str) -> Self {
        let base = std::env::temp_dir().join(format!("exectool_esc_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sandbox")).unwrap();
        Workspace { base }
    }

    fn at(&self, rel: &str) -> PathBuf {
        self.base.join(rel)
    }

    fn fs_tool(&self) -> FileSystemTool {
        FileSystemTool::new(Sandbox::new([self.base.join("sandbox")]).unwrap()).writable()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

// --- filesystem --------------------------------------------------------------

/// A sibling directory whose name merely begins with the allowed root.
///
/// `"/tmp/sandbox_evil".starts_with("/tmp/sandbox")` is true for strings and
/// false for paths. The original compared strings.
#[tokio::test]
async fn sibling_directory_sharing_a_name_prefix() {
    let w = Workspace::new("sibling");
    std::fs::create_dir_all(w.at("sandbox_evil")).unwrap();
    std::fs::write(w.at("sandbox_evil/loot.txt"), "STOLEN").unwrap();

    let result = w
        .fs_tool()
        .execute(json!({
            "operation": "read",
            "path": w.at("sandbox_evil/loot.txt").to_string_lossy()
        }))
        .await;

    assert!(result.is_err(), "sibling-prefix escape succeeded");
}

/// A symlink inside the sandbox pointing out of it.
///
/// The original rejected a literal `..` and then trusted the string, so a link
/// was a legal path by inspection and an arbitrary read in practice.
#[tokio::test]
#[cfg(unix)]
async fn symlink_pointing_out_of_the_sandbox() {
    let w = Workspace::new("symlink");
    std::fs::create_dir_all(w.at("secrets")).unwrap();
    std::fs::write(w.at("secrets/key.txt"), "PRIVATE KEY").unwrap();
    std::os::unix::fs::symlink(w.at("secrets"), w.at("sandbox/escape")).unwrap();

    let result = w
        .fs_tool()
        .execute(json!({
            "operation": "read",
            "path": w.at("sandbox/escape/key.txt").to_string_lossy()
        }))
        .await;

    assert!(result.is_err(), "symlink escape succeeded");
}

/// Writing through a symlink placed in the sandbox beforehand.
///
/// The read path and the write path need the same containment rule; a check
/// applied to one and not the other is the same hole facing the other way.
#[tokio::test]
#[cfg(unix)]
async fn writing_through_a_symlink_that_leaves_the_sandbox() {
    let w = Workspace::new("write_link");
    std::fs::write(w.at("victim.txt"), "original").unwrap();
    std::os::unix::fs::symlink(w.at("victim.txt"), w.at("sandbox/link.txt")).unwrap();

    let result = w
        .fs_tool()
        .execute(json!({
            "operation": "write",
            "path": w.at("sandbox/link.txt").to_string_lossy(),
            "content": "OVERWRITTEN"
        }))
        .await;

    assert!(result.is_err(), "symlink write escape succeeded");
    assert_eq!(
        std::fs::read_to_string(w.at("victim.txt")).unwrap(),
        "original",
        "the file outside the sandbox was modified"
    );
}

/// Plain `..` traversal, which the original did catch.
#[tokio::test]
async fn parent_directory_traversal() {
    let w = Workspace::new("traversal");
    std::fs::write(w.at("outside.txt"), "SECRET").unwrap();

    let result = w
        .fs_tool()
        .execute(json!({
            "operation": "read",
            "path": w.at("sandbox/../outside.txt").to_string_lossy()
        }))
        .await;

    assert!(result.is_err(), "traversal escape succeeded");
}

// --- shell -------------------------------------------------------------------

/// A whitelisted binary reaching further through its own options.
///
/// The original allowlisted the program name and passed arguments through
/// untouched, which for most real binaries is equivalent to allowing anything
/// that binary can do.
#[tokio::test]
async fn option_injection_into_an_allowlisted_binary() {
    let echo = ["/bin/echo", "/usr/bin/echo"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists());
    let Some(echo) = echo else { return };

    let tool = ShellTool::new(vec![
        marshall::shell::AllowedCommand::new(echo).with_arguments(ArgumentPolicy::NoFlags)
    ]);

    for hostile in [
        json!({"program": echo, "args": ["--exec-path=/tmp/evil"]}),
        json!({"program": echo, "args": ["-exec", "sh", "-c", "id"]}),
        json!({"program": echo, "args": ["--to-command=/tmp/evil"]}),
    ] {
        assert!(
            tool.validate(&hostile).await.is_err(),
            "option injection permitted: {hostile}"
        );
    }
}

/// A relative program name satisfying an absolute allowlist entry.
///
/// If `echo` matches an entry of `/bin/echo`, then whoever controls `PATH`
/// chooses which binary actually runs.
#[tokio::test]
async fn path_lookup_instead_of_an_absolute_program() {
    let tool = ShellTool::new(vec![marshall::shell::AllowedCommand::new("/bin/echo")]);
    assert!(tool.validate(&json!({"program": "echo"})).await.is_err());
}

/// A `working_dir` outside the configured sandbox, via the prefix trick.
#[tokio::test]
async fn working_directory_outside_the_sandbox() {
    let w = Workspace::new("wd");
    std::fs::create_dir_all(w.at("sandbox_evil")).unwrap();

    let tool = ShellTool::new(vec![marshall::shell::AllowedCommand::new("/bin/echo")])
        .with_working_dirs(Sandbox::new([w.at("sandbox")]).unwrap());

    assert!(tool
        .validate(&json!({
            "program": "/bin/echo",
            "working_dir": w.at("sandbox_evil").to_string_lossy()
        }))
        .await
        .is_err());
}

// --- SSRF --------------------------------------------------------------------

/// Every spelling of the cloud metadata endpoint that a naive check misses.
#[test]
fn metadata_endpoint_by_every_spelling() {
    for url in [
        "https://169.254.169.254/latest/meta-data/iam/",
        "https://[::ffff:169.254.169.254]/latest/",
        "https://[::ffff:a9fe:a9fe]/latest/",
        "https://[2002:a9fe:a9fe::1]/", // 6to4 embedding the same v4 address
    ] {
        assert_eq!(
            validate_destination(url),
            Err(DestinationError::BlockedAddress),
            "reachable: {url}"
        );
    }
}

/// Credentials in the authority, which some parsers read as the host.
///
/// `https://example.com@169.254.169.254/` has host `169.254.169.254`, but a
/// parser that splits on the first `.` or takes everything before `@` sees
/// `example.com` and allows it.
#[test]
fn authority_confusion_via_embedded_credentials() {
    assert_eq!(
        validate_destination("https://example.com@169.254.169.254/"),
        Err(DestinationError::EmbeddedCredentials)
    );
}

/// Header injection through a URL carrying control characters.
#[test]
fn control_characters_in_a_url() {
    assert!(matches!(
        validate_destination("https://example.com/\r\nX-Injected: yes"),
        Err(DestinationError::Malformed(_))
    ));
}

/// Reaching an internal service on an unusual port over a permitted scheme.
#[test]
fn port_scanning_through_an_allowed_scheme() {
    for url in [
        "https://example.com:22/",
        "https://example.com:6379/",
        "https://example.com:3306/",
    ] {
        assert_eq!(
            validate_destination(url),
            Err(DestinationError::BlockedPort),
            "reachable: {url}"
        );
    }
}

/// Non-HTTP schemes, which some URL handling passes through to a generic client.
#[test]
fn alternate_schemes() {
    for url in ["file:///etc/passwd", "gopher://x:70/", "ftp://x/"] {
        assert_eq!(
            validate_destination(url),
            Err(DestinationError::Scheme),
            "accepted: {url}"
        );
    }
}

// --- system ------------------------------------------------------------------

/// Env exfiltration through an unconfigured allowlist.
///
/// A `system env_get` for `AWS_SECRET_ACCESS_KEY` must fail closed when no
/// policy enabled it — otherwise any agent prompt injection can lift
/// credentials into a transcript via the tool result.
#[tokio::test]
async fn env_exfiltration_without_an_allowlist() {
    std::env::set_var("MARSHALL_ESC_SECRET", "topsecret");
    let tool = SystemTool::new();
    assert!(tool
        .validate(&json!({"operation": "env_get", "key": "MARSHALL_ESC_SECRET"}))
        .await
        .is_err());
    // Even the key shape is validated: no `$(...)`, no `;`, no `LD_PRELOAD`.
    assert!(tool
        .validate(&json!({"operation": "env_get", "key": "$(env)"}))
        .await
        .is_err());
    assert!(tool
        .validate(&json!({"operation": "env_get", "key": "LD_PRELOAD"}))
        .await
        .is_err());
    std::env::remove_var("MARSHALL_ESC_SECRET");
}

/// Process kill without an explicit opt-in, and self-kill with one.
///
/// `process_kill` defaults to denied; and even when enabled it must refuse
/// pid 1 and the daemon's own pid — an agent that can kill either can take
/// down the host init or its own executor to escape supervision.
#[tokio::test]
async fn process_kill_defaults_to_denied_and_refuses_self() {
    let denied = SystemTool::new();
    assert!(denied
        .validate(&json!({"operation": "process_kill", "pid": 1234}))
        .await
        .is_err());
    assert!(denied
        .validate(&json!({"operation": "process_list"}))
        .await
        .is_err());

    let allowed = SystemTool::new().with_kill(true);
    assert!(allowed
        .validate(&json!({"operation": "process_kill", "pid": 1}))
        .await
        .is_err());
    let self_pid = std::process::id() as u64;
    assert!(allowed
        .validate(&json!({"operation": "process_kill", "pid": self_pid}))
        .await
        .is_err());
}
