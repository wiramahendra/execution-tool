//! Keeping payloads out of the places that get logged.
//!
//! A tool result travels further than the call that produced it: into an agent
//! transcript, a log line, a trace span, sometimes an evidence record. If the
//! result carries file contents or a response body, every one of those becomes
//! a copy.
//!
//! So [`crate::ToolOutcome`] splits the two. `summary` is structured, bounded,
//! and safe to log; `content` holds the bytes and is only populated when the
//! caller asked. This module holds the helpers for building summaries and the
//! header allowlist.

use serde_json::{Map, Value};

/// Identifies the redaction rules a summary was built under.
///
/// Recorded in summaries so a stored result stays interpretable after the
/// rules change.
pub const REDACTION_POLICY_VERSION: &str = "marshall-redaction-v1";

/// Longest string kept verbatim in a summary.
pub const MAX_SUMMARY_STRING: usize = 512;

/// Response headers safe to record.
///
/// An allowlist: `set-cookie`, `authorization`, and `www-authenticate` all
/// carry credentials, and a blocklist would have to keep up with every header
/// that turns out to as well.
pub const SAFE_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "content-encoding",
    "cache-control",
    "date",
    "etag",
    "last-modified",
    "retry-after",
    "server",
];

/// Keep only allowlisted headers, lowercased.
pub fn allowlisted_headers(headers: &reqwest::header::HeaderMap) -> Value {
    let mut kept = Map::new();
    for name in SAFE_RESPONSE_HEADERS {
        if let Some(value) = headers.get(*name) {
            if let Ok(text) = value.to_str() {
                kept.insert((*name).to_string(), Value::String(truncate(text)));
            }
        }
    }
    Value::Object(kept)
}

/// Truncate a string to [`MAX_SUMMARY_STRING`], marking that it was cut.
pub fn truncate(text: &str) -> String {
    if text.len() <= MAX_SUMMARY_STRING {
        return text.to_string();
    }
    // Cut on a character boundary; slicing a multi-byte sequence panics.
    let mut end = MAX_SUMMARY_STRING;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…(truncated)", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn credential_bearing_headers_are_dropped() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("set-cookie", HeaderValue::from_static("session=SECRET"));
        headers.insert("authorization", HeaderValue::from_static("Bearer SECRET"));

        let kept = allowlisted_headers(&headers);
        let text = serde_json::to_string(&kept).unwrap();

        assert!(text.contains("application/json"));
        assert!(!text.contains("SECRET"), "{text}");
        assert!(!text.contains("set-cookie"));
    }

    #[test]
    fn long_values_are_truncated() {
        let long = "a".repeat(MAX_SUMMARY_STRING + 100);
        let out = truncate(&long);
        assert!(out.len() < long.len());
        assert!(out.ends_with("(truncated)"));
    }

    #[test]
    fn truncation_does_not_split_a_character() {
        // Slicing mid-sequence would panic; this is the regression guard.
        let text = "é".repeat(MAX_SUMMARY_STRING);
        let out = truncate(&text);
        assert!(out.ends_with("(truncated)"));
    }

    #[test]
    fn short_values_are_untouched() {
        assert_eq!(truncate("short"), "short");
    }
}
