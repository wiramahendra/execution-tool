#![allow(missing_docs)]
use std::path::{Path, PathBuf};
use std::process::Command;

use super::schema::RepoStateSnapshot;

/// Lightweight repo-state collector. Never mutates git.
#[derive(Debug, Clone)]
pub struct RepoState(pub RepoStateSnapshot);

/// Diff stats (insertions/deletions) — small helper.
#[derive(Debug, Clone, Default)]
pub struct DiffStats {
    pub insertions: u64,
    pub deletions: u64,
}

/// Collect repo state for `workdir` (defaults to current dir).
/// Fails gracefully when not inside a git repo: returns `dirty=false`,
/// empty `changed_files`, and `head=None`.
pub fn collect_repo_state(workdir: Option<&Path>) -> RepoStateSnapshot {
    let cwd = workdir
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Helper to run git command in cwd.
    let run = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(&cwd)
            .output()
            .ok()?;
        if out.status.success() {
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            None
        }
    };

    let head = run(&["rev-parse", "HEAD"]);
    let branch = run(&["rev-parse", "--abbrev-ref", "HEAD"]);
    let status = run(&["status", "--porcelain"]).unwrap_or_default();

    // Truncate porcelain to 8 KiB to avoid giant trace (no secrets — but still bounded).
    let mut status_porcelain = status.clone();
    if status_porcelain.len() > 8192 {
        status_porcelain.truncate(8192);
        status_porcelain.push_str("\n…(truncated)");
    }

    let dirty = !status.trim().is_empty();
    let mut changed_files = Vec::new();
    for line in status.lines() {
        // porcelain: XY<space>path  or  XY<space>old -> new
        if line.len() >= 3 {
            let path = line[3..].trim();
            // Handle renames: "old -> new"
            let file = if let Some((_, after)) = path.split_once(" -> ") {
                after
            } else {
                path
            };
            if !file.is_empty() {
                changed_files.push(file.to_string());
            }
        }
    }
    let changed_count = changed_files.len();

    // Diff stats via `git diff --numstat HEAD` if head available, else `git diff --numstat`.
    let diff_raw = if head.is_some() {
        run(&["diff", "--numstat", "HEAD"]).unwrap_or_default()
    } else {
        run(&["diff", "--numstat"]).unwrap_or_default()
    };
    let mut insertions: u64 = 0;
    let mut deletions: u64 = 0;
    let mut have_stats = false;
    for line in diff_raw.lines() {
        // format: added<TAB>deleted<TAB>path
        let mut parts = line.split('\t');
        if let (Some(a), Some(d)) = (parts.next(), parts.next()) {
            if let (Ok(ia), Ok(id)) = (a.parse::<u64>(), d.parse::<u64>()) {
                insertions += ia;
                deletions += id;
                have_stats = true;
            }
        }
    }

    // Also include staged? `git diff --numstat` covers unstaged only.
    // Add `git diff --cached --numstat` for staged.
    let cached_raw = run(&["diff", "--cached", "--numstat"]).unwrap_or_default();
    for line in cached_raw.lines() {
        let mut parts = line.split('\t');
        if let (Some(a), Some(d)) = (parts.next(), parts.next()) {
            if let (Ok(ia), Ok(id)) = (a.parse::<u64>(), d.parse::<u64>()) {
                insertions += ia;
                deletions += id;
                have_stats = true;
            }
        }
    }

    RepoStateSnapshot {
        head,
        branch,
        dirty,
        changed_count,
        changed_files,
        lines_added: if have_stats || dirty {
            Some(insertions)
        } else {
            None
        },
        lines_deleted: if have_stats || dirty {
            Some(deletions)
        } else {
            None
        },
        status_porcelain,
    }
}

/// Collect insertions/deletions between two revisions using `git diff --numstat`.
/// Returns None if not a git repo or git fails.
pub fn collect_diff_stats(
    _workdir: Option<&Path>,
    _before: &str,
    _after: &str,
) -> Option<DiffStats> {
    // Placeholder for future `git diff before..after --numstat` helper.
    // Not needed for Phase 0.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn git_cmd(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn repo_collector_inside_git_fixture() {
        let dir = std::env::temp_dir().join(format!("val_git_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        git_cmd(&dir, &["init"]);
        git_cmd(&dir, &["config", "user.email", "t@t.com"]);
        git_cmd(&dir, &["config", "user.name", "t"]);
        fs::write(dir.join("a.txt"), "hello").unwrap();
        git_cmd(&dir, &["add", "a.txt"]);
        git_cmd(&dir, &["commit", "-m", "init"]);
        let s1 = collect_repo_state(Some(&dir));
        assert!(s1.head.is_some());
        assert!(!s1.dirty);
        assert_eq!(s1.changed_count, 0);

        fs::write(dir.join("a.txt"), "hello world").unwrap();
        fs::write(dir.join("b.txt"), "new").unwrap();
        let s2 = collect_repo_state(Some(&dir));
        assert!(s2.dirty);
        assert!(s2.changed_count >= 1);
        assert!(s2
            .changed_files
            .iter()
            .any(|p| p.contains("a.txt") || p.contains("b.txt")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn repo_collector_non_git_gracefully() {
        let dir = std::env::temp_dir().join(format!("val_nogit_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let s = collect_repo_state(Some(&dir));
        assert_eq!(s.head, None);
        assert!(!s.dirty);
        assert_eq!(s.changed_count, 0);
        let _ = fs::remove_dir_all(&dir);
    }
}
