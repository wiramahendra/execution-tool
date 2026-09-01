#![allow(missing_docs)]
//! Validation experiment harness — Phase 0 baseline measurement.
//!
//! This module is measurement-only. It does not alter tool results,
//! does not control success/failure, and has no database/queue/cloud deps.
//! See `validation/README.md` for metric definitions.

pub mod analyzer;
pub mod collector;
pub mod instrumentation;
pub mod manifest;
pub mod patterns;
pub mod recorder;
pub mod schema;
pub mod treatment;
pub mod verify_change;

pub use analyzer::{analyze_file, analyze_files, PerTaskMetrics};
pub use collector::{DiffStats, RepoState};
pub use manifest::{TaskCategory, TaskManifest, TaskSpec};
pub use patterns::{mine_bigrams, mine_trigrams, normalize, NormOp};
pub use recorder::{ExperimentRecorder, TaskRecorder};
pub use schema::{
    EventType, ExperimentEvent, TaskOutcome, TokenUsage, VerificationRecord, SCHEMA_VERSION,
};
