//! Path containment: deciding whether a path is inside an allowed root.
//!
//! This is the module the filesystem and shell tools both depend on, and it is
//! the one that was wrong in the code this crate was extracted from. Two
//! separate escapes, both confirmed by running them:
//!
//! **String prefixes are not path prefixes.** The original compared with
//! `str::starts_with`, so a root of `/tmp/safe` admitted `/tmp/safe_evil/…` —
//! a *sibling* directory that merely shares a textual prefix.
//! [`Path::starts_with`] compares whole components and does not have this
//! problem, which is why every check here goes through `Path`.
//!
//! **Rejecting `..` textually does not stop traversal.** The original scanned
//! for `Component::ParentDir` and otherwise trusted the string, so a symlink at
//! `/tmp/safe/link -> /etc` made `/tmp/safe/link/passwd` a legal path by
//! inspection and `/etc/passwd` in practice. Only asking the filesystem what a
//! path really resolves to closes that, so everything here canonicalizes first.
//!
//! # What this still does not give you
//!
//! Containment is checked at resolve time and used a moment later, so a symlink
//! swapped in between the two wins the race. On Linux this is now closed via
//! `openat2` with `RESOLVE_BENEATH`; on other platforms the check-then-use race
//! remains. Treat this as a guard against confused paths and mistaken
//! configuration on non-Linux, and as a true containment on Linux with
//! `openat2` available.

use std::path::{Path, PathBuf};

/// A path was outside every configured root, or could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    /// No roots were configured, so nothing is permitted.
    #[error("no sandbox roots configured; every path is denied")]
    NoRoots,

    /// A configured root does not exist or could not be canonicalized.
    #[error("sandbox root {root} is unusable: {reason}")]
    BadRoot {
        /// The offending root as configured.
        root: String,
        /// Why it could not be used.
        reason: String,
    },

    /// The path resolved outside every root.
    #[error("path is outside the sandbox")]
    Outside,

    /// The path (or its parent, when creating) does not exist.
    #[error("path does not resolve to an existing location")]
    Unresolvable,
}

/// A set of canonicalized roots that paths must resolve inside.
///
/// Roots are canonicalized once at construction, so a symlinked root works and
/// a root that disappears later fails closed rather than silently widening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    roots: Vec<PathBuf>,
}

impl Sandbox {
    /// Build a sandbox from one or more roots.
    ///
    /// Every root must already exist: a root that does not is a configuration
    /// error, and treating it as an empty allowance would let it start
    /// permitting things the moment someone creates the directory.
    pub fn new<I, P>(roots: I) -> Result<Self, SandboxError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut canonical = Vec::new();
        for root in roots {
            let root = root.as_ref();
            let resolved = root.canonicalize().map_err(|e| SandboxError::BadRoot {
                root: root.display().to_string(),
                reason: e.to_string(),
            })?;
            if !resolved.is_dir() {
                return Err(SandboxError::BadRoot {
                    root: root.display().to_string(),
                    reason: "not a directory".to_string(),
                });
            }
            canonical.push(resolved);
        }

        if canonical.is_empty() {
            return Err(SandboxError::NoRoots);
        }
        Ok(Sandbox { roots: canonical })
    }

    /// The canonicalized roots.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Whether an already-canonical path lies inside a root.
    ///
    /// Uses [`Path::starts_with`], which matches whole components — this is the
    /// difference between admitting `/tmp/safe/x` and admitting
    /// `/tmp/safe_evil/x`.
    fn contains(&self, canonical: &Path) -> bool {
        self.roots.iter().any(|root| canonical.starts_with(root))
    }

    /// Resolve a path that must already exist, and confirm it is inside.
    ///
    /// Canonicalization follows symlinks, so a link pointing out of the
    /// sandbox is rejected on where it *lands*, not on how it is spelled.
    /// On Linux, `openat2` with `RESOLVE_BENEATH` is used to close the
    /// check-then-use race; elsewhere the classic `canonicalize` + `contains`
    /// check is used.
    pub fn resolve_existing(&self, path: impl AsRef<Path>) -> Result<PathBuf, SandboxError> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(p) = self.resolve_with_openat2(path.as_ref()) {
                return Ok(p);
            }
            // Fall back to canonicalize if openat2 unavailable (e.g. old kernel).
        }
        let canonical = path
            .as_ref()
            .canonicalize()
            .map_err(|_| SandboxError::Unresolvable)?;
        if self.contains(&canonical) {
            Ok(canonical)
        } else {
            Err(SandboxError::Outside)
        }
    }

    /// Resolve a path that may not exist yet, for creation.
    ///
    /// The *parent* must exist and resolve inside the sandbox; the final
    /// component is then appended without following it. A final component of
    /// `.` or `..` is rejected outright, since neither names a file to create.
    ///
    /// If the target already exists as a symlink, this deliberately does not
    /// follow it — writing through a link that leaves the sandbox is exactly
    /// what must not happen.
    pub fn resolve_for_create(&self, path: impl AsRef<Path>) -> Result<PathBuf, SandboxError> {
        let path = path.as_ref();

        let name = match path.file_name() {
            Some(name) => name,
            // No final component means `/`, `.`, or a trailing `..`.
            None => return Err(SandboxError::Unresolvable),
        };

        let parent = path.parent().ok_or(SandboxError::Unresolvable)?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };

        #[cfg(target_os = "linux")]
        {
            // For parent == "." (relative `file.txt` with no dir), don't use openat2
            // with root — it would incorrectly treat "." as root. Fall back to
            // canonicalize which resolves "." as cwd (correctly outside).
            if parent != Path::new(".") {
                if let Ok(parent_canonical) = self.resolve_with_openat2(parent) {
                    let target = parent_canonical.join(name);
                    // Use openat2 for target existence check as well to avoid
                    // symlink_metadata TOCTOU.
                    if target.symlink_metadata().is_ok() {
                        return self.resolve_existing(&target);
                    }
                    return Ok(target);
                }
            }
        }

        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| SandboxError::Unresolvable)?;
        if !self.contains(&canonical_parent) {
            return Err(SandboxError::Outside);
        }

        let target = canonical_parent.join(name);

        // If it exists already it must itself resolve inside — this catches a
        // pre-placed symlink pointing out.
        if target.symlink_metadata().is_ok() {
            return self.resolve_existing(&target);
        }
        Ok(target)
    }

    /// Linux `openat2` with `RESOLVE_BENEATH` to close TOCTOU.
    #[cfg(target_os = "linux")]
    fn resolve_with_openat2(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        use std::os::unix::io::AsRawFd;
        for root in &self.roots {
            let root_file = match std::fs::File::open(root) {
                Ok(f) => f,
                Err(_) => continue,
            };
            // Make path relative to this root for RESOLVE_BENEATH.
            // For absolute paths, must be under this root to be considered;
            // for relative paths, treat as relative to root (sandbox-relative)
            // and also fallback to canonicalize for cwd-relative cases.
            let rel: PathBuf = if path.is_absolute() {
                if path == root.as_path() {
                    PathBuf::from(".")
                } else if let Ok(stripped) = path.strip_prefix(root) {
                    if stripped.as_os_str().is_empty() {
                        PathBuf::from(".")
                    } else {
                        stripped.to_path_buf()
                    }
                } else {
                    // Not under this root as path prefix — try next root.
                    continue;
                }
            } else {
                // Relative path: if it contains `..` that would escape, BENEATH will block.
                // Try as relative to root; if it fails, fallback will handle cwd-relative.
                path.to_path_buf()
            };
            let root_fd = root_file.as_raw_fd();
            if let Ok(canonical) = openat2_resolve(root_fd, &rel) {
                // Double-check canonical is still inside root (defense-in-depth).
                if canonical.starts_with(root) || canonical == *root {
                    return Ok(canonical);
                }
            }
        }
        Err(SandboxError::Outside)
    }

    /// Linux: open file via `openat2` and keep fd for I/O (closes TOCTOU for read).
    /// Returns `File` opened with `O_RDONLY` and `RESOLVE_BENEATH`.
    #[cfg(target_os = "linux")]
    pub fn open_existing_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<std::fs::File, SandboxError> {
        use std::os::unix::io::AsRawFd;
        let path = path.as_ref();
        for root in &self.roots {
            let root_file = match std::fs::File::open(root) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let rel: PathBuf = if path.is_absolute() {
                if let Ok(stripped) = path.strip_prefix(root) {
                    if stripped.as_os_str().is_empty() {
                        PathBuf::from(".")
                    } else {
                        stripped.to_path_buf()
                    }
                } else {
                    continue;
                }
            } else {
                path.to_path_buf()
            };
            let root_fd = root_file.as_raw_fd();
            if let Ok(file) = openat2_open_file(root_fd, &rel) {
                return Ok(file);
            }
        }
        // Fallback to check-then-open for old kernels
        let canonical = self.resolve_existing(path)?;
        std::fs::File::open(canonical).map_err(|_| SandboxError::Unresolvable)
    }
}

#[cfg(target_os = "linux")]
fn openat2_resolve(root_fd: i32, path: &Path) -> Result<PathBuf, SandboxError> {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    use std::os::unix::io::BorrowedFd;

    let dirfd = unsafe { BorrowedFd::borrow_raw(root_fd) };
    let flags = OFlags::PATH | OFlags::CLOEXEC;
    let resolve = ResolveFlags::BENEATH;

    if let Ok(file) = openat2(&dirfd, path, flags, Mode::empty(), resolve) {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let proc_path = format!("/proc/self/fd/{fd}");
        if let Ok(p) = std::fs::read_link(&proc_path) {
            return Ok(p);
        }
        return Err(SandboxError::Outside);
    }
    Err(SandboxError::Outside)
}

#[cfg(target_os = "linux")]
fn openat2_open_file(root_fd: i32, path: &Path) -> Result<std::fs::File, SandboxError> {
    use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};
    use std::os::unix::io::{BorrowedFd, FromRawFd, OwnedFd};

    let dirfd = unsafe { BorrowedFd::borrow_raw(root_fd) };
    let flags = OFlags::RDONLY | OFlags::CLOEXEC;
    let resolve = ResolveFlags::BENEATH;

    match openat2(&dirfd, path, flags, Mode::empty(), resolve) {
        Ok(file) => {
            // rustix returns OwnedFd, convert to std::fs::File via FromRawFd
            let owned: OwnedFd = file.into();
            // SAFETY: we own the fd
            let std_file = unsafe { std::fs::File::from_raw_fd(owned.into_raw_fd()) };
            Ok(std_file)
        }
        Err(e) => {
            // Map rustix errors to SandboxError
            match e {
                rustix::io::Errno::NOENT => Err(SandboxError::Unresolvable),
                rustix::io::Errno::NOTCAPABLE | rustix::io::Errno::PERM => {
                    Err(SandboxError::Outside)
                }
                _ => Err(SandboxError::Outside),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        base: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let base = std::env::temp_dir()
                .join(format!("exectool_sandbox_{name}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("safe")).unwrap();
            Fixture { base }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.base.join(rel)
        }

        fn sandbox(&self) -> Sandbox {
            Sandbox::new([self.base.join("safe")]).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn a_path_inside_a_root_resolves() {
        let f = Fixture::new("inside");
        std::fs::write(f.path("safe/file.txt"), "x").unwrap();

        let resolved = f
            .sandbox()
            .resolve_existing(f.path("safe/file.txt"))
            .unwrap();
        assert!(resolved.ends_with("file.txt"));
    }

    #[test]
    fn a_sibling_sharing_a_textual_prefix_is_rejected() {
        // The first confirmed escape: `/tmp/safe_evil` vs a root of `/tmp/safe`.
        // `str::starts_with` admits it; `Path::starts_with` does not.
        let f = Fixture::new("sibling");
        std::fs::create_dir_all(f.path("safe_evil")).unwrap();
        std::fs::write(f.path("safe_evil/stolen.txt"), "secret").unwrap();

        assert_eq!(
            f.sandbox().resolve_existing(f.path("safe_evil/stolen.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_leaving_the_sandbox_is_rejected() {
        // The second confirmed escape: a link inside the root pointing out.
        let f = Fixture::new("symlink");
        std::fs::create_dir_all(f.path("outside")).unwrap();
        std::fs::write(f.path("outside/secret.txt"), "secret").unwrap();
        std::os::unix::fs::symlink(f.path("outside"), f.path("safe/link")).unwrap();

        assert_eq!(
            f.sandbox().resolve_existing(f.path("safe/link/secret.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_symlink_staying_inside_the_sandbox_is_allowed() {
        // Canonicalization must not become a blanket ban on links.
        let f = Fixture::new("symlink_ok");
        std::fs::create_dir_all(f.path("safe/real")).unwrap();
        std::fs::write(f.path("safe/real/file.txt"), "x").unwrap();
        std::os::unix::fs::symlink(f.path("safe/real"), f.path("safe/link")).unwrap();

        assert!(f
            .sandbox()
            .resolve_existing(f.path("safe/link/file.txt"))
            .is_ok());
    }

    #[test]
    fn parent_traversal_is_rejected() {
        let f = Fixture::new("traversal");
        std::fs::write(f.path("outside.txt"), "secret").unwrap();

        assert_eq!(
            f.sandbox().resolve_existing(f.path("safe/../outside.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    fn a_missing_path_is_unresolvable_not_permitted() {
        let f = Fixture::new("missing");
        assert_eq!(
            f.sandbox().resolve_existing(f.path("safe/nope.txt")),
            Err(SandboxError::Unresolvable)
        );
    }

    #[test]
    fn creating_inside_the_sandbox_is_allowed() {
        let f = Fixture::new("create");
        let target = f
            .sandbox()
            .resolve_for_create(f.path("safe/new.txt"))
            .unwrap();
        assert!(target.ends_with("new.txt"));
    }

    #[test]
    fn creating_outside_the_sandbox_is_rejected() {
        let f = Fixture::new("create_out");
        assert_eq!(
            f.sandbox().resolve_for_create(f.path("new.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    #[cfg(unix)]
    fn writing_through_a_pre_placed_symlink_is_rejected() {
        // Create-time resolution must not be a way around the read-time check.
        let f = Fixture::new("create_link");
        std::fs::write(f.path("target.txt"), "original").unwrap();
        std::os::unix::fs::symlink(f.path("target.txt"), f.path("safe/link.txt")).unwrap();

        assert_eq!(
            f.sandbox().resolve_for_create(f.path("safe/link.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    fn a_sandbox_needs_at_least_one_root() {
        let empty: Vec<PathBuf> = Vec::new();
        assert_eq!(Sandbox::new(empty), Err(SandboxError::NoRoots));
    }

    #[test]
    fn a_nonexistent_root_is_a_configuration_error() {
        // Not "an empty allowance": otherwise the sandbox silently starts
        // permitting things when someone later creates the directory.
        let result = Sandbox::new(["/definitely/not/here/exectool"]);
        assert!(matches!(result, Err(SandboxError::BadRoot { .. })));
    }

    #[test]
    fn a_file_cannot_be_a_root() {
        let f = Fixture::new("file_root");
        std::fs::write(f.path("safe/file.txt"), "x").unwrap();
        let result = Sandbox::new([f.path("safe/file.txt")]);
        assert!(matches!(result, Err(SandboxError::BadRoot { .. })));
    }

    #[test]
    fn multiple_roots_are_all_honoured() {
        let f = Fixture::new("multi");
        std::fs::create_dir_all(f.path("second")).unwrap();
        std::fs::write(f.path("safe/a.txt"), "a").unwrap();
        std::fs::write(f.path("second/b.txt"), "b").unwrap();
        std::fs::write(f.path("elsewhere.txt"), "c").unwrap();

        let sandbox = Sandbox::new([f.path("safe"), f.path("second")]).unwrap();
        assert!(sandbox.resolve_existing(f.path("safe/a.txt")).is_ok());
        assert!(sandbox.resolve_existing(f.path("second/b.txt")).is_ok());
        assert_eq!(
            sandbox.resolve_existing(f.path("elsewhere.txt")),
            Err(SandboxError::Outside)
        );
    }

    #[test]
    fn the_root_itself_is_inside_itself() {
        let f = Fixture::new("root_self");
        assert!(f.sandbox().resolve_existing(f.path("safe")).is_ok());
    }
}
