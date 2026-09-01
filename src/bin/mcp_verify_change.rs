#![allow(missing_docs)]
//! Minimal stdio MCP adapter exposing exactly one post-edit verification tool.

use execution_tool::experiment::verify_change::VerifyChangeTool;
use execution_tool::Tool;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config =
        std::env::var("VERIFY_CHANGE_CONFIG").unwrap_or_else(|_| "verify_change.yaml".into());
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut line = String::new();
    while reader.read_line(&mut line)? != 0 {
        let request: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => {
                line.clear();
                continue;
            }
        };
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        let mut response = json!({"jsonrpc":"2.0"});
        if let Some(id) = id {
            response["id"] = id;
        }
        match method {
            "initialize" => {
                response["result"] = json!({"protocolVersion": params.get("protocolVersion").and_then(Value::as_str).unwrap_or("2024-11-05"), "capabilities":{"tools":{"listChanged":false}}, "serverInfo":{"name":"verify_change","version":"0.1.0"}})
            }
            "notifications/initialized" => {
                line.clear();
                continue;
            }
            "tools/list" => {
                response["result"] = json!({"tools":[{"name":"verify_change","description":"Verify the current code change using repository-defined checks and return structured results. Use when you have finished making a change and do not need additional reasoning between verification checks.","inputSchema":{"type":"object","properties":{"scope":{"type":"array","items":{"type":"string"}},"checks":{"type":"array","maxItems":4,"items":{"type":"string","enum":["targeted_test","typecheck","lint","build_check","git_diff"]}}}}}]})
            }
            "tools/call" => {
                if params.get("name").and_then(Value::as_str) != Some("verify_change") {
                    response["error"] = json!({"code":-32601,"message":"unknown tool"});
                } else {
                    let cwd = std::env::current_dir()?;
                    match VerifyChangeTool::from_config_path(cwd, &config) {
                        Ok(tool) => match tool
                            .execute(
                                params
                                    .get("arguments")
                                    .cloned()
                                    .unwrap_or_else(|| json!({})),
                            )
                            .await
                        {
                            Ok(outcome) => {
                                response["result"] = json!({"content":[{"type":"text","text":serde_json::to_string(&outcome.summary)?}],"isError":!outcome.success})
                            }
                            Err(_) => {
                                response["result"] = json!({"content":[{"type":"text","text":"{\"error_code\":\"verify_change_rejected\"}"}],"isError":true})
                            }
                        },
                        Err(_) => {
                            response["result"] = json!({"content":[{"type":"text","text":"{\"error_code\":\"verify_change_unavailable\"}"}],"isError":true})
                        }
                    }
                }
            }
            "ping" => response["result"] = json!({}),
            _ if response.get("id").is_some() => {
                response["error"] = json!({"code":-32601,"message":"unknown method"})
            }
            _ => {
                line.clear();
                continue;
            }
        }
        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
        line.clear();
    }
    Ok(())
}
