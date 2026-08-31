#![allow(missing_docs)]
//! Typed error codes for tool policy rejections.

use thiserror::Error;

/// Stable, log-safe error code. Never contains paths/hosts/payloads.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ToolError {
    #[error("tool_not_found: {0}")]
    ToolNotFound(String),
    #[error("path_not_allowed")]
    PathNotAllowed,
    #[error("sandbox_misconfigured")]
    SandboxMisconfigured,
    #[error("writes_not_permitted")]
    WritesNotPermitted,
    #[error("command_not_allowed")]
    CommandNotAllowed,
    #[error("arguments_not_allowed")]
    ArgumentsNotAllowed,
    #[error("working_dir_not_allowed")]
    WorkingDirNotAllowed,
    #[error("host_not_allowed")]
    HostNotAllowed,
    #[error("blocked_address")]
    BlockedAddress,
    #[error("blocked_port")]
    BlockedPort,
    #[error("unsupported_operation: {0}")]
    UnsupportedOperation(String),
    #[error("invalid_base64")]
    InvalidBase64,
    #[error("request_body_too_large")]
    RequestBodyTooLarge,
    #[error("header_not_allowed: {0}")]
    HeaderNotAllowed(String),
    #[error("headers_not_allowed")]
    HeadersNotAllowed,
    #[error("{0}")]
    Other(String),
}

impl ToolError {
    /// Stable snake_case code for `ToolOutcome.error_code`.
    pub fn code(&self) -> String {
        match self {
            ToolError::ToolNotFound(_) => "tool_not_found".into(),
            ToolError::PathNotAllowed => "path_not_allowed".into(),
            ToolError::SandboxMisconfigured => "sandbox_misconfigured".into(),
            ToolError::WritesNotPermitted => "writes_not_permitted".into(),
            ToolError::CommandNotAllowed => "command_not_allowed".into(),
            ToolError::ArgumentsNotAllowed => "arguments_not_allowed".into(),
            ToolError::WorkingDirNotAllowed => "working_dir_not_allowed".into(),
            ToolError::HostNotAllowed => "host_not_allowed".into(),
            ToolError::BlockedAddress => "blocked_address".into(),
            ToolError::BlockedPort => "blocked_port".into(),
            ToolError::UnsupportedOperation(s) => format!("unsupported_operation:{s}"),
            ToolError::InvalidBase64 => "invalid_base64".into(),
            ToolError::RequestBodyTooLarge => "request_body_too_large".into(),
            ToolError::HeaderNotAllowed(_) => "header_not_allowed".into(),
            ToolError::HeadersNotAllowed => "headers_not_allowed".into(),
            ToolError::Other(s) => s.clone(),
        }
    }
}
