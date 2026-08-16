//! Outbound HTTP, restricted by destination policy.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde_json::{json, Value};
use tracing::debug;

use crate::destination::{host_of, validate_destination, DestinationClass};
use crate::redaction::allowlisted_headers;
use crate::{sha256_hex, Tool, ToolOutcome};

/// Default cap on a response body held in memory.
pub const DEFAULT_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// Default per-request budget.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP requests to destinations that pass [`validate_destination`].
///
/// Two properties matter beyond the address checks, and both live here rather
/// than in the policy module because only the client can enforce them:
///
/// **Redirects are never followed.** A destination check applies to the URL you
/// validated. A 302 to `http://169.254.169.254/` is a *different* request, and
/// following it silently discards the check — along with forwarding whatever
/// headers you set to a host you never approved.
///
/// **The validated addresses are pinned.** The client connects to the addresses
/// the policy actually inspected rather than resolving the host again. Without
/// this, a name that resolved public during validation can resolve private a
/// millisecond later, which is the whole DNS rebinding technique.
pub struct HttpTool {
    allowed_hosts: HashSet<String>,
    timeout: Duration,
    body_limit: usize,
}

impl HttpTool {
    /// An HTTP tool permitting exactly these hosts.
    ///
    /// Hosts are matched exactly after lowercasing; there is no wildcard, and
    /// an empty set denies everything.
    pub fn new<I, S>(allowed_hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        HttpTool {
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|h| h.as_ref().to_ascii_lowercase())
                .collect(),
            timeout: DEFAULT_TIMEOUT,
            body_limit: DEFAULT_BODY_LIMIT,
        }
    }

    /// Set the per-request budget.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the response body cap.
    pub fn with_body_limit(mut self, bytes: usize) -> Self {
        self.body_limit = bytes;
        self
    }

    fn check(&self, args: &Value) -> Result<(String, String, Option<String>)> {
        let url = args
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing 'url'"))?;

        let method = args
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
        ) {
            bail!("method_not_allowed");
        }

        // Allowlist before resolution: a rejected request must not still cause
        // a DNS lookup for whatever hostname the caller supplied.
        let host = host_of(url).map_err(|e| anyhow::anyhow!("{e}"))?;
        if self.allowed_hosts.is_empty() || !self.allowed_hosts.contains(&host) {
            bail!("host_not_allowed");
        }

        validate_destination(url).map_err(|e| anyhow::anyhow!("{e}"))?;

        let body = args.get("body").and_then(Value::as_str).map(str::to_owned);

        Ok((method, url.to_string(), body))
    }
}

#[async_trait::async_trait]
impl Tool for HttpTool {
    fn name(&self) -> &str {
        "http"
    }

    fn description(&self) -> &str {
        "Make an HTTP request to an allowlisted host"
    }

    fn parameters_schema(&self) -> Value {
        let mut hosts: Vec<&String> = self.allowed_hosts.iter().collect();
        hosts.sort();
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": format!("Target URL. Allowed hosts: {hosts:?}")
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
                    "default": "GET"
                },
                "body": { "type": "string", "description": "Request body" }
            },
            "required": ["url"]
        })
    }

    async fn validate(&self, args: &Value) -> Result<()> {
        self.check(args).map(|_| ())
    }

    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        let (method, url, body) = self.check(&args)?;

        // Re-validated rather than carried from `check`, so the addresses the
        // client is pinned to are the ones just inspected.
        let destination = validate_destination(&url).map_err(|e| anyhow::anyhow!("{e}"))?;
        debug!(host = %destination.host, %method, "http request");

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            // A redirect is a request to a destination that was never checked.
            .redirect(reqwest::redirect::Policy::none())
            // Connect to what was validated; do not resolve the name again.
            .resolve_to_addrs(&destination.host, &destination.addrs)
            .https_only(destination.class == DestinationClass::PublicHttps)
            .build()?;

        let method = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut request = client.request(method, &url);
        if let Some(body) = body {
            request = request.body(body);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(e) => {
                return Ok(ToolOutcome::failure(
                    "http",
                    request_error(&e),
                    elapsed(started),
                ))
            }
        };

        let status = response.status();
        let headers = allowlisted_headers(response.headers());

        if status.is_redirection() {
            // Reported rather than followed, so a caller can see it happened.
            return Ok(
                ToolOutcome::failure("http", "redirect_refused", elapsed(started))
                    .with_metadata("status", status.as_u16().to_string()),
            );
        }

        let bytes = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(ToolOutcome::failure(
                    "http",
                    "body_read_failed",
                    elapsed(started),
                ))
            }
        };

        let total = bytes.len();
        let truncated = total > self.body_limit;
        let body = if truncated {
            bytes[..self.body_limit].to_vec()
        } else {
            bytes.to_vec()
        };

        let summary = json!({
            "status": status.as_u16(),
            "headers": headers,
            "body_bytes": body.len(),
            "response_bytes": total,
            "truncated": truncated,
            "sha256": sha256_hex(&body),
            "body_redacted": true,
            "redaction_policy_version": crate::REDACTION_POLICY_VERSION,
        });

        let outcome = if status.is_success() {
            ToolOutcome::success("http", summary, elapsed(started))
        } else {
            let mut failed = ToolOutcome::failure("http", "http_status", elapsed(started));
            failed.summary = summary;
            failed
        };

        Ok(outcome
            .with_content(body)
            .with_metadata("status", status.as_u16().to_string()))
    }
}

fn request_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect_failed"
    } else if error.is_request() {
        "bad_request"
    } else {
        "request_failed"
    }
}

fn elapsed(started: Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_empty_allowlist_denies_everything() {
        let tool = HttpTool::new(Vec::<String>::new());
        let err = tool
            .validate(&json!({"url": "https://example.com/"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("host_not_allowed"));
    }

    #[tokio::test]
    async fn a_non_allowlisted_host_is_denied() {
        let tool = HttpTool::new(["example.com"]);
        assert!(tool
            .validate(&json!({"url": "https://elsewhere.com/"}))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn an_allowlisted_host_still_goes_through_destination_policy() {
        // Allowlisting a name must not bypass the address checks: the name is
        // attacker-influenced if it resolves somewhere unexpected.
        let tool = HttpTool::new(["169.254.169.254"]);
        let err = tool
            .validate(&json!({"url": "https://169.254.169.254/latest/"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("blocked address"), "{err}");
    }

    #[tokio::test]
    async fn a_rejected_host_is_never_resolved() {
        // The host allowlist must be consulted before DNS, or a refused
        // request still leaks the hostname to a resolver.
        let tool = HttpTool::new(["example.com"]);
        let err = tool
            .validate(&json!({"url": "https://exfiltrated-data.attacker.invalid/"}))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("host_not_allowed"),
            "resolution ran first: {err}"
        );
    }

    #[tokio::test]
    async fn host_matching_is_case_insensitive() {
        let tool = HttpTool::new(["Example.COM"]);
        // Resolution may fail offline; the host check must pass either way.
        let err = tool
            .validate(&json!({"url": "https://EXAMPLE.com/"}))
            .await
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(!err.contains("host_not_allowed"), "{err}");
    }

    #[tokio::test]
    async fn unusual_methods_are_denied() {
        let tool = HttpTool::new(["example.com"]);
        let err = tool
            .validate(&json!({"url": "https://example.com/", "method": "TRACE"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("method_not_allowed"));
    }

    #[tokio::test]
    async fn plain_http_to_a_remote_host_is_denied_even_when_allowlisted() {
        let tool = HttpTool::new(["example.com"]);
        let err = tool
            .validate(&json!({"url": "http://example.com/"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("loopback"), "{err}");
    }

    #[test]
    fn the_schema_lists_the_allowed_hosts() {
        let tool = HttpTool::new(["b.example.com", "a.example.com"]);
        let schema = tool.parameters_schema();
        let description = schema["properties"]["url"]["description"].as_str().unwrap();
        // Sorted, so the schema is stable across runs and diffs cleanly.
        assert!(description.find("a.example.com") < description.find("b.example.com"));
    }
}
