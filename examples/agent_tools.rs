//! Wiring the three tools with deny-by-default policies.
//!
//! ```sh
//! cargo run --example agent_tools
//! ```

use std::sync::Arc;
use std::time::Duration;

use execution_tool::shell::AllowedCommand;
use execution_tool::{ArgumentPolicy, FileSystemTool, HttpTool, Sandbox, ShellTool, ToolRegistry};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let workspace = std::env::temp_dir().join("exectool_example");
    std::fs::create_dir_all(&workspace)?;
    std::fs::write(workspace.join("notes.txt"), "the quick brown fox\n")?;

    let sandbox = Sandbox::new([&workspace])?;
    println!("workspace: {}\n", workspace.display());

    let mut tools = ToolRegistry::new();
    tools.register(Arc::new(FileSystemTool::new(sandbox.clone())));
    tools.register(Arc::new(HttpTool::new(["api.github.com"])));
    tools.register(Arc::new(
        ShellTool::new(vec![
            AllowedCommand::new(echo()).with_arguments(ArgumentPolicy::NoFlags)
        ])
        .with_working_dirs(sandbox)
        .with_timeout(Duration::from_secs(5)),
    ));

    println!("registered: {:?}\n", tools.tool_names());

    // Reading returns a digest in the summary and the bytes in `content`, so
    // logging the outcome does not copy the file into the log.
    let outcome = tools
        .execute(
            "filesystem",
            json!({"operation": "read", "path": workspace.join("notes.txt").to_string_lossy()}),
        )
        .await?;
    println!("read      : {}", outcome.summary);
    println!(
        "            content held separately: {} bytes\n",
        outcome.content.as_ref().map(Vec::len).unwrap_or(0)
    );

    let outcome = tools
        .execute("shell", json!({"program": echo(), "args": ["hello"]}))
        .await?;
    println!("shell     : exit {}\n", outcome.summary["exit_code"]);

    println!("Now the things that are refused:\n");
    for (label, tool, args) in [
        (
            "read outside the sandbox",
            "filesystem",
            json!({"operation": "read", "path": "/etc/passwd"}),
        ),
        (
            "shell option injection",
            "shell",
            json!({"program": echo(), "args": ["--exec-path=/tmp/evil"]}),
        ),
        (
            "cloud metadata endpoint",
            "http",
            json!({"url": "https://169.254.169.254/latest/meta-data/"}),
        ),
        (
            "unallowlisted host",
            "http",
            json!({"url": "https://evil.example.com/"}),
        ),
    ] {
        match tools.execute(tool, args).await {
            Err(e) => println!("  refused  {label:<26} — {e}"),
            Ok(_) => println!("  ALLOWED  {label:<26} — this should not happen"),
        }
    }

    let _ = std::fs::remove_dir_all(&workspace);
    Ok(())
}

fn echo() -> &'static str {
    if std::path::Path::new("/bin/echo").exists() {
        "/bin/echo"
    } else {
        "/usr/bin/echo"
    }
}
