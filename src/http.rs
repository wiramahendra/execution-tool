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
    request_body_limit: usize,
    allowed_request_headers: Option<HashSet<String>>,
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
            request_body_limit: DEFAULT_BODY_LIMIT,
            allowed_request_headers: None,
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

    /// Set the request body cap.
    pub fn with_request_body_limit(mut self, bytes: usize) -> Self {
        self.request_body_limit = bytes;
        self
    }

    /// Allow only these request headers to be sent.
    pub fn with_allowed_request_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allowed_request_headers = Some(
            headers
                .into_iter()
                .map(|h| h.as_ref().to_ascii_lowercase())
                .collect(),
        );
        self
    }

    fn check(
        &self,
        args: &Value,
    ) -> Result<(
        String,
        String,
        Option<String>,
        crate::destination::ValidatedDestination,
    )> {
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

        let destination = validate_destination(url).map_err(|e| anyhow::anyhow!("{e}"))?;

        let body = args.get("body").and_then(Value::as_str).map(str::to_owned);
        if let Some(ref b) = body {
            if b.len() > self.request_body_limit {
                bail!("request_body_too_large");
            }
        }

        if let Some(headers) = args.get("headers") {
            if !headers.is_object() {
                bail!("headers_must_be_object");
            }
            // Validate header names and values: CRLF injection prevention
            for (k, v) in headers.as_object().unwrap() {
                if k.chars().any(|c| c == '\r' || c == '\n' || c == ':') {
                    bail!("header_not_allowed: {k}");
                }
                if let Some(s) = v.as_str() {
                    if s.chars().any(|c| c == '\r' || c == '\n') {
                        bail!("header_not_allowed: {k}");
                    }
                }
            }
            if let Some(allowed) = &self.allowed_request_headers {
                for key in headers.as_object().unwrap().keys() {
                    if !allowed.contains(&key.to_ascii_lowercase()) {
                        bail!("header_not_allowed: {key}");
                    }
                    if matches!(
                        key.to_ascii_lowercase().as_str(),
                        "authorization" | "cookie" | "host" | "content-length"
                    ) {
                        bail!("header_not_allowed: {key}");
                    }
                }
            } else if !headers.as_object().unwrap().is_empty() {
                // by default no extra headers are allowed to avoid smuggling
                bail!("headers_not_allowed");
            }
        }

        Ok((method, url.to_string(), body, destination))
    }
}

#[async_trait::async_trait]
impl Tool for HttpTool {
    fn name(&self) -> &str {
        "http"
    }

    fn description(&self) -> &str {
        "HTTP fetch to allowlisted hosts with SSRF protection (private ranges blocked, redirects not followed, DNS pinned, ports 443/8443). Allowlist checked before DNS to avoid exfiltration."
    }

    fn parameters_schema(&self) -> Value {
        let mut hosts: Vec<&String> = self.allowed_hosts.iter().collect();
        hosts.sort();
        let header_desc = if let Some(allowed) = &self.allowed_request_headers {
            let mut v: Vec<&String> = allowed.iter().collect();
            v.sort();
            format!("Allowed request headers: {v:?}. Blocked: authorization, cookie, host, content-length.")
        } else {
            "Custom headers not allowed by default (use with_allowed_request_headers). Blocked: authorization, cookie.".into()
        };
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": format!("Target URL. Allowed hosts: {hosts:?}. Must be https for public hosts (443/8443) or http for loopback (80/3000/8080 etc). Example: https://api.github.com/repos/foo/bar")
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
                    "default": "GET",
                    "description": "HTTP method. TRACE/CONNECT denied."
                },
                "body": { "type": "string", "description": "Request body (max 4MiB, checked via request_body_limit). Example: JSON payload for POST." },
                "headers": { "type": "object", "description": header_desc, "additionalProperties": { "type": "string" } }
            },
            "required": ["url"],
            "examples": [
                {"url":"https://api.github.com/repos/foo/bar"},
                {"url":"https://api.github.com/repos/foo/bar","method":"POST","body":"{\"query\":\"hi\"}"}
            ]
        })
    }

    async fn validate(&self, args: &Value) -> Result<()> {
        self.check(args).map(|_| ())
    }

    async fn execute(&self, args: Value) -> Result<ToolOutcome> {
        let started = Instant::now();
        let (method, url, body, destination) = self.check(&args)?;
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
        if let Some(headers) = args.get("headers").and_then(|v| v.as_object()) {
            for (k, v) in headers {
                if let Some(s) = v.as_str() {
                    request = request.header(k.as_str(), s);
                }
            }
        }
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

        // Streaming read with cap to avoid OOM: respect Content-Length pre-check plus incremental limit.
        if let Some(cl) = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
        {
            if cl > self.body_limit * 8 {
                // Very large advertised length — still stream but we know we'll truncate
                debug!(
                    content_length = cl,
                    body_limit = self.body_limit,
                    "large content-length, will truncate streaming"
                );
            }
        }
        let mut body = Vec::new();
        let mut total: usize = 0;
        let mut truncated = false;
        {
            use futures_util::StreamExt;
            let mut stream = response.bytes_stream();
            while let Some(chunk_res) = stream.next().await {
                match chunk_res {
                    Ok(chunk) => {
                        total = total.saturating_add(chunk.len());
                        if body.len() < self.body_limit {
                            let remaining = self.body_limit - body.len();
                            if chunk.len() <= remaining {
                                body.extend_from_slice(&chunk);
                            } else {
                                body.extend_from_slice(&chunk[..remaining]);
                                truncated = true;
                            }
                        } else {
                            truncated = true;
                        }
                        // If we've already exceeded limit by a lot, stop reading further to save bandwidth
                        if total > self.body_limit && body.len() >= self.body_limit {
                            // Drain remaining stream but don't buffer
                            // We continue to count total but not store
                            // To avoid DoS, break after counting one extra chunk beyond limit*2
                            if total > self.body_limit * 2 {
                                // consume remainder without storing
                                while let Some(_extra) = stream.next().await {
                                    if let Ok(c) = _extra {
                                        total = total.saturating_add(c.len());
                                        if total > self.body_limit * 4 {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        return Ok(ToolOutcome::failure(
                            "http",
                            "body_read_failed",
                            elapsed(started),
                        ))
                    }
                }
            }
            if total > self.body_limit {
                truncated = true;
            }
        }

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
