//! Path gate.
//!
//! Upstream `resolve_under` allows absolute paths outside the root, and that is a contract
//! pinned three ways — docs, unit tests, integration tests ("the root is a default, not a jail").
//! Without this layer the configured `roots` are decoration.
//!
//! **This gate stops accidents, not intruders.** As long as `terminal` is offered the agent can
//! open any file through the shell anyway. The one exception is the credential directory: the
//! refresh token inside it re-issues the node identity without this machine, so its blast radius
//! is of a different kind.

use std::path::{Component, Path, PathBuf};

use zyris::{ErrorCode, WireError};

pub struct PathGate {
    roots: Vec<PathBuf>,
    deny: Vec<PathBuf>,
}

impl PathGate {
    pub fn new(roots: Vec<PathBuf>, deny: Vec<PathBuf>) -> PathGate {
        // Compare canonical against canonical or symlinks route around it. Doing it once here
        // saves doing it on every call.
        let canon = |v: Vec<PathBuf>| -> Vec<PathBuf> {
            v.into_iter().map(|p| p.canonicalize().unwrap_or(p)).collect()
        };
        PathGate { roots: canon(roots), deny: canon(deny) }
    }

    /// Base for relative paths and the PTY cwd. Upstream takes one root, so only this goes down.
    pub fn root(&self) -> &Path {
        self.roots.first().map(PathBuf::as_path).unwrap_or_else(|| Path::new("/"))
    }

    pub fn check(&self, requested: &str) -> zyris::Result<PathBuf> {
        let joined = join_like_upstream(self.root(), requested);
        let resolved = canonicalize_deepest(&joined);

        if self.deny.iter().any(|d| is_under(&resolved, d)) {
            return Err(self.refuse(requested, "is on the deny list"));
        }
        if !self.roots.iter().any(|r| is_under(&resolved, r)) {
            return Err(self.refuse(requested, "is outside the allowed roots"));
        }
        Ok(resolved)
    }

    /// Puts the allowed roots in the error message.
    fn refuse(&self, requested: &str, why: &str) -> WireError {
        let roots: Vec<String> = self.roots.iter().map(|r| r.display().to_string()).collect();
        WireError::new(
            ErrorCode::ForbiddenScope,
            format!("{requested}: {why}. Paths this node allows: {}", roots.join(", ")),
        )
    }
}

/// Joins by the same rules as upstream `resolve_under` — if the path the gate checked differs
/// from the path the layer below opens, the check means nothing.
fn join_like_upstream(root: &Path, path: &str) -> PathBuf {
    let requested = Path::new(path);
    let mut out = if requested.has_root() { PathBuf::new() } else { root.to_path_buf() };
    for component in requested.components() {
        match component {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !out.has_root() {
                    out.push("..");
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// Really resolves the deepest ancestor that exists, then appends the rest logically.
///
/// `write`/`mkdir` legitimately target paths that do not exist yet (upstream `create_dir_all`s
/// the parent), so a plain `canonicalize` fails with `NotFound` and blocks every write. Resolving
/// only the ancestor still stops symlink escapes while letting new files through.
fn canonicalize_deepest(path: &Path) -> PathBuf {
    let mut existing = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = existing.canonicalize() {
            let mut out = real;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match existing.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                if !existing.pop() {
                    return path.to_path_buf();
                }
            }
            None => return path.to_path_buf(),
        }
    }
}

fn is_under(path: &Path, base: &Path) -> bool {
    path == base || path.starts_with(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(root: &Path) -> PathGate {
        PathGate::new(vec![root.to_path_buf()], vec![root.join("secret")])
    }

    /// A relative path joins the root. Only by matching upstream resolve_under does a path that
    /// passed the gate point at the same place one layer down.
    #[test]
    fn a_relative_path_joins_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        assert_eq!(gate(&root).check("a.txt").unwrap(), root.join("a.txt"));
    }

    /// This is why the layer exists. Upstream resolve_under allows absolute paths outside the
    /// root, and that is a contract pinned three ways ("the root is a default, not a jail").
    #[test]
    fn an_absolute_path_outside_the_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let err = gate(&root).check("/etc/hosts").unwrap_err();
        assert_eq!(err.code, ErrorCode::ForbiddenScope);
        assert!(err.to_string().contains(&root.display().to_string()), "{err}");
    }

    /// Escaping with `..` is the same.
    #[test]
    fn a_parent_traversal_out_of_the_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        assert!(gate(&root).check("../../etc/hosts").is_err());
    }

    /// Upstream never resolves symlinks at all, so this layer does.
    #[cfg(unix)]
    #[test]
    fn a_symlink_pointing_out_of_the_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::os::unix::fs::symlink("/etc", root.join("escape")).unwrap();
        assert!(gate(&root).check("escape/hosts").is_err());
    }

    /// write and mkdir legitimately target **paths that do not exist yet** (upstream
    /// create_dir_alls the parent). A plain canonicalize fails with NotFound and blocks writes.
    #[test]
    fn a_path_that_does_not_exist_yet_still_passes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        assert_eq!(
            gate(&root).check("new/deep/file.txt").unwrap(),
            root.join("new/deep/file.txt")
        );
    }

    /// deny wins over roots.
    #[test]
    fn deny_wins_over_roots() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("secret")).unwrap();
        assert!(gate(&root).check("secret/key").is_err());
        assert!(gate(&root).check("secret").is_err());
    }

    /// A sibling sharing a prefix must not be mistaken for being inside the root.
    /// `/tmp/root` and `/tmp/root-evil` satisfy starts_with as plain strings.
    #[test]
    fn a_sibling_sharing_a_prefix_is_not_inside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("root")).unwrap();
        std::fs::create_dir(base.join("root-evil")).unwrap();
        let g = PathGate::new(vec![base.join("root")], vec![]);
        assert!(g.check(&base.join("root-evil/x").display().to_string()).is_err());
    }
}
