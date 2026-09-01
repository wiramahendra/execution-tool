#![allow(missing_docs)]
use std::collections::{BTreeMap, HashMap, HashSet};

use super::schema::{EventType, ExperimentEvent};

/// Normalized operation categories for pattern mining.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NormOp {
    Read,
    Write,
    Search,
    Test,
    Typecheck,
    Lint,
    Build,
    GitStatus,
    GitDiff,
    Shell,
    Http,
    Other(String),
}

impl NormOp {
    pub fn as_str(&self) -> String {
        match self {
            Self::Read => "read".into(),
            Self::Write => "write".into(),
            Self::Search => "search".into(),
            Self::Test => "test".into(),
            Self::Typecheck => "typecheck".into(),
            Self::Lint => "lint".into(),
            Self::Build => "build".into(),
            Self::GitStatus => "git_status".into(),
            Self::GitDiff => "git_diff".into(),
            Self::Shell => "shell".into(),
            Self::Http => "http".into(),
            Self::Other(s) => s.clone(),
        }
    }
}

/// Normalize a tool-call event to a NormOp.
pub fn normalize(event: &ExperimentEvent) -> Option<NormOp> {
    if event.event_type != EventType::ToolCallCompleted {
        return None;
    }
    let tool = event.tool.as_deref().unwrap_or("");
    let op = event
        .operation
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let cmd = event.command.as_deref().unwrap_or("").to_ascii_lowercase();

    // filesystem
    if tool == "filesystem" {
        match op.as_str() {
            "read" => return Some(NormOp::Read),
            "write" | "append" | "patch" | "copy" | "move" | "delete" | "mkdir" => {
                return Some(NormOp::Write)
            }
            "search" | "glob" | "list" | "stat" => return Some(NormOp::Search),
            _ => return Some(NormOp::Other(format!("fs:{op}"))),
        }
    }
    if tool == "http" {
        return Some(NormOp::Http);
    }
    if tool == "code" {
        return Some(NormOp::Shell);
    }
    if tool == "shell" {
        // Check command/program
        let prog = op.clone();
        let full = if cmd.is_empty() { prog } else { cmd };
        if full.contains("git status") {
            return Some(NormOp::GitStatus);
        }
        if full.contains("git diff") {
            return Some(NormOp::GitDiff);
        }
        if full.contains("cargo test")
            || full.contains("npm test")
            || full.contains("pnpm test")
            || full.contains("yarn test")
        {
            return Some(NormOp::Test);
        }
        if full.contains("cargo check")
            || full.contains("tsc ")
            || full.contains("mypy")
            || full.contains("typecheck")
        {
            return Some(NormOp::Typecheck);
        }
        if full.contains("cargo clippy")
            || full.contains("eslint")
            || full.contains("cargo fmt")
            || full.contains("lint")
        {
            return Some(NormOp::Lint);
        }
        if full.contains("cargo build") || full.contains("build") {
            return Some(NormOp::Build);
        }
        // also check shell operation which may be program path like /bin/echo etc.
        if op.contains("git") && op.contains("status") {
            return Some(NormOp::GitStatus);
        }
        return Some(NormOp::Shell);
    }
    // generic fallback: map tool name
    match tool {
        "read" => Some(NormOp::Read),
        "write" => Some(NormOp::Write),
        "search" => Some(NormOp::Search),
        _ => Some(NormOp::Other(tool.to_string())),
    }
}

/// Extract ordered normalized ops per task.
pub fn extract_sequence(events: &[ExperimentEvent]) -> Vec<(NormOp, usize)> {
    // returns (op, original_index)
    let mut out = Vec::new();
    for (idx, e) in events.iter().enumerate() {
        if let Some(op) = normalize(e) {
            out.push((op, idx));
        }
    }
    out
}

/// Bigram: (a→b, count, task_coverage, examples)
#[derive(Debug, Clone)]
pub struct BigramStats {
    pub bigram: String,
    pub count: usize,
    pub task_coverage: usize,
    pub tasks: Vec<String>,
    pub median_turns_between: f64,
}

/// Trigram stats
#[derive(Debug, Clone)]
pub struct TrigramStats {
    pub trigram: String,
    pub count: usize,
    pub task_coverage: usize,
}

fn median(mut v: Vec<usize>) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_unstable();
    let mid = v.len() / 2;
    if v.len() % 2 == 1 {
        v[mid] as f64
    } else {
        (v[mid - 1] as f64 + v[mid] as f64) / 2.0
    }
}

/// Mine bigrams across all task traces.
pub fn mine_bigrams(all: &HashMap<String, Vec<ExperimentEvent>>) -> Vec<BigramStats> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut task_sets: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut turns_between: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for (task_id, events) in all {
        let seq = extract_sequence(events);
        for w in seq.windows(2) {
            let a = w[0].0.as_str();
            let b = w[1].0.as_str();
            let key = format!("{a}→{b}");
            *counts.entry(key.clone()).or_default() += 1;
            task_sets
                .entry(key.clone())
                .or_default()
                .insert(task_id.clone());
            // turns between: compare turn_id of the two underlying events
            let e1 = &events[w[0].1];
            let e2 = &events[w[1].1];
            let between = if e1.turn_id != e2.turn_id { 1 } else { 0 };
            turns_between.entry(key.clone()).or_default().push(between);
        }
    }
    let mut out: Vec<BigramStats> = counts
        .into_iter()
        .map(|(k, c)| {
            let cov = task_sets.get(&k).map(|s| s.len()).unwrap_or(0);
            let mt = median(turns_between.get(&k).cloned().unwrap_or_default());
            BigramStats {
                bigram: k.clone(),
                count: c,
                task_coverage: cov,
                tasks: task_sets
                    .get(&k)
                    .map(|s| {
                        let mut v: Vec<_> = s.iter().cloned().collect();
                        v.sort();
                        v
                    })
                    .unwrap_or_default(),
                median_turns_between: mt,
            }
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.bigram.cmp(&b.bigram)));
    out
}

pub fn mine_trigrams(all: &HashMap<String, Vec<ExperimentEvent>>) -> Vec<TrigramStats> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut task_sets: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for (task_id, events) in all {
        let seq = extract_sequence(events);
        for w in seq.windows(3) {
            let a = w[0].0.as_str();
            let b = w[1].0.as_str();
            let c = w[2].0.as_str();
            let key = format!("{a}→{b}→{c}");
            *counts.entry(key.clone()).or_default() += 1;
            task_sets
                .entry(key.clone())
                .or_default()
                .insert(task_id.clone());
        }
    }
    let mut out: Vec<TrigramStats> = counts
        .into_iter()
        .map(|(k, c)| TrigramStats {
            trigram: k.clone(),
            count: c,
            task_coverage: task_sets.get(&k).map(|s| s.len()).unwrap_or(0),
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then(a.trigram.cmp(&b.trigram)));
    out
}

/// Volume dominance: which normalized ops dominate tool calls
pub fn volume_dominance(all: &HashMap<String, Vec<ExperimentEvent>>) -> BTreeMap<String, usize> {
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for events in all.values() {
        for e in events {
            if let Some(op) = normalize(e) {
                *m.entry(op.as_str()).or_default() += 1;
            }
        }
    }
    m
}

/// Wall-clock dominance per op (sum duration)
pub fn duration_dominance(all: &HashMap<String, Vec<ExperimentEvent>>) -> BTreeMap<String, u64> {
    let mut m: BTreeMap<String, u64> = BTreeMap::new();
    for events in all.values() {
        for e in events {
            if let Some(op) = normalize(e) {
                if let Some(d) = e.duration_ms {
                    *m.entry(op.as_str()).or_default() += d;
                }
            }
        }
    }
    m
}

/// Success/failure after op
pub fn success_after(
    all: &HashMap<String, Vec<ExperimentEvent>>,
) -> BTreeMap<String, (usize, usize)> {
    let mut m: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for events in all.values() {
        for e in events
            .iter()
            .filter(|e| e.event_type == EventType::ToolCallCompleted)
        {
            if let Some(op) = normalize(e) {
                let entry = m.entry(op.as_str()).or_default();
                if e.success == Some(true) {
                    entry.0 += 1;
                } else if e.success == Some(false) {
                    entry.1 += 1;
                }
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::schema::{EventType, ExperimentEvent};

    fn mk(tool: &str, op: &str, turn: &str) -> ExperimentEvent {
        let mut e = ExperimentEvent::new("exp", "t", "baseline", EventType::ToolCallCompleted);
        e.tool = Some(tool.into());
        e.operation = Some(op.into());
        e.turn_id = Some(turn.into());
        e.success = Some(true);
        e.duration_ms = Some(10);
        e
    }

    #[test]
    fn normalization() {
        assert_eq!(
            normalize(&mk("filesystem", "read", "t1")).unwrap().as_str(),
            "read"
        );
        assert_eq!(
            normalize(&mk("filesystem", "write", "t1"))
                .unwrap()
                .as_str(),
            "write"
        );
        assert_eq!(
            normalize(&mk("filesystem", "search", "t1"))
                .unwrap()
                .as_str(),
            "search"
        );
        assert_eq!(
            normalize(&mk("shell", "/bin/echo", "t1")).unwrap().as_str(),
            "shell"
        );
    }

    #[test]
    fn bigram_mine() {
        let mut all: HashMap<String, Vec<ExperimentEvent>> = HashMap::new();
        all.insert(
            "t1".into(),
            vec![
                mk("filesystem", "read", "turn1"),
                mk("filesystem", "read", "turn1"),
                mk("shell", "/bin/echo", "turn2"),
            ],
        );
        all.insert(
            "t2".into(),
            vec![
                mk("filesystem", "read", "turn1"),
                mk("filesystem", "search", "turn1"),
            ],
        );
        let b = mine_bigrams(&all);
        assert!(b.iter().any(|x| x.bigram == "read→read"));
    }
}
