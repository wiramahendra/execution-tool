#![allow(missing_docs)]
//! Egress proxy — server-side SSRF enforcement (Phase 3)
//!
//! `HttpTool` already validates `destination` client-side, but a compromised
//! tool or direct `reqwest` usage could bypass it. The egress proxy enforces
//! `validate_destination` + `host allowlist` centrally, so even if a tool
//! is tricked into `https://169.254.169.254/` or `example.com@169.254.169.254`
//! the request never leaves the host.
//!
//! In production this would be a sidecar SQUID/envoy; here it's a library
//! wrapper that `marshalld` calls before any outbound `reqwest`.

use std::collections::HashSet;

use crate::destination::{host_of, validate_destination};

#[derive(Debug, Clone)]
pub struct EgressPolicy {
    allowed_hosts: HashSet<String>,
}

impl EgressPolicy {
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            allowed_hosts: hosts
                .into_iter()
                .map(|h| h.as_ref().to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        self.allowed_hosts.contains(&host.to_ascii_lowercase())
    }

    /// Validate `url` against allowlist + destination policy. Returns `ValidatedDestination`
    /// on success, stable `code` string on failure (never leaks addrs).
    pub fn check(
        &self,
        url: &str,
    ) -> Result<crate::destination::ValidatedDestination, EgressError> {
        let host = host_of(url).map_err(|e| EgressError {
            code: e.to_string(),
            url_redacted: redacted_url(url),
        })?;
        if !self.allows_host(&host) {
            return Err(EgressError {
                code: "host_not_allowed".into(),
                url_redacted: redacted_url(url),
            });
        }
        validate_destination(url).map_err(|e| EgressError {
            code: e.to_string(),
            url_redacted: redacted_url(url),
        })
    }

    /// Whether the policy is empty (deny-all).
    pub fn is_empty(&self) -> bool {
        self.allowed_hosts.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct EgressError {
    pub code: String,
    /// Host only, no path/query — safe to log.
    pub url_redacted: String,
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.url_redacted)
    }
}
impl std::error::Error for EgressError {}

fn redacted_url(url: &str) -> String {
    // Keep scheme + host, drop path/query which may contain secrets.
    crate::destination::host_of(url).unwrap_or_else(|_| "invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_before_ssrf() {
        let p = EgressPolicy::new(["api.github.com"]);
        // Host not allowed never reaches DNS — stable code.
        assert!(p.check("https://evil.com/").is_err());
        let e = p.check("https://evil.com/").unwrap_err();
        assert_eq!(e.code, "host_not_allowed");
    }

    #[test]
    fn blocked_address_even_if_allowlisted() {
        let p = EgressPolicy::new(["169.254.169.254"]);
        let e = p.check("https://169.254.169.254/").unwrap_err();
        assert!(e.code.contains("blocked") || e.code.contains("Blocked"));
    }

    #[test]
    fn redacted_url_does_not_leak_path() {
        assert_eq!(
            redacted_url("https://api.github.com/secret?token=abc"),
            "api.github.com"
        );
    }
}
