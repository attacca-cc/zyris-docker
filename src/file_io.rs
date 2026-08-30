//! Wraps `FileIo` to confine paths to the configured roots.
//!
//! Why wrap at the `FileIo` layer and not `ServeCapability`: the only thing that implements
//! `ServeCapability` is the macro's `FileIoServer<T>`, and `LocalFileIo` implements only `FileIo`.
//! Wrapping at the `ServeCapability` layer would mean taking `dispatch(IncomingCall)` and decoding
//! each tool's payload by hand.

use zyris::{Chunk, Datum, Streaming};
// `zyris-capkit` split into one crate per reference implementation; this is the same type
// under its own name. Taking the crate rather than the re-export shell is what keeps
// `zyris-input`'s forked `enigo` and `zyris-screen`'s X11/Wayland stack out of this image.
use zyris_fs::LocalFileIo;
use zyris_caps::{DirEntry, FileEdit, FileIo, FileRead, FileStat};

use crate::gate::PathGate;

pub struct GatedFileIo {
    gate: PathGate,
    inner: LocalFileIo,
}

impl GatedFileIo {
    pub fn new(gate: PathGate) -> GatedFileIo {
        let inner = LocalFileIo::rooted(gate.root().to_path_buf());
        GatedFileIo { gate, inner }
    }

    /// Returns the gate-approved canonical absolute path as a string.
    fn ok(&self, path: &str) -> zyris::Result<String> {
        Ok(self.gate.check(path)?.to_string_lossy().to_string())
    }
}

#[zyris::async_trait]
impl FileIo for GatedFileIo {
    async fn stat(&self, path: String) -> zyris::Result<FileStat> {
        self.inner.stat(self.ok(&path)?).await
    }

    async fn list(&self, path: String) -> zyris::Result<Vec<DirEntry>> {
        self.inner.list(self.ok(&path)?).await
    }

    async fn read(
        &self,
        path: String,
        offset: Option<u64>,
        len: Option<u64>,
    ) -> zyris::Result<FileRead> {
        self.inner.read(self.ok(&path)?, offset, len).await
    }

    async fn read_stream(
        &self,
        path: String,
        offset: Option<u64>,
        len: Option<u64>,
    ) -> zyris::Result<Streaming<FileStat, Chunk>> {
        self.inner.read_stream(self.ok(&path)?, offset, len).await
    }

    async fn write(&self, path: String, data: Datum, overwrite: bool) -> zyris::Result<FileStat> {
        self.inner.write(self.ok(&path)?, data, overwrite).await
    }

    async fn remove(&self, path: String, recursive: Option<bool>) -> zyris::Result<()> {
        self.inner.remove(self.ok(&path)?, recursive).await
    }

    async fn edit(
        &self,
        path: String,
        old_string: String,
        new_string: String,
        replace_all: bool,
    ) -> zyris::Result<FileEdit> {
        self.inner.edit(self.ok(&path)?, old_string, new_string, replace_all).await
    }

    async fn mkdir(&self, path: String) -> zyris::Result<()> {
        self.inner.mkdir(self.ok(&path)?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn gated(root: &Path) -> GatedFileIo {
        GatedFileIo::new(PathGate::new(vec![root.to_path_buf()], vec![]))
    }

    fn text(s: &str) -> Datum {
        Datum::Text { text: s.to_string(), format: None }
    }

    /// A path the gate lets through reaches the layer below as a canonical absolute path.
    #[tokio::test]
    async fn a_file_under_the_root_reads() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join("a.txt"), b"hello").unwrap();
        let got = gated(&root).read("a.txt".into(), None, None).await.unwrap();
        assert_eq!(got.content, "hello");
    }

    /// All seven methods go through the gate. Miss one and that method becomes a way around it.
    #[tokio::test]
    async fn every_method_refuses_a_path_outside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let g = gated(&root);
        let out = "/etc/hosts".to_string();

        assert!(g.stat(out.clone()).await.is_err(), "stat");
        assert!(g.list("/etc".into()).await.is_err(), "list");
        assert!(g.read(out.clone(), None, None).await.is_err(), "read");
        assert!(g.read_stream(out.clone(), None, None).await.is_err(), "read_stream");
        assert!(g.remove(out.clone(), None).await.is_err(), "remove");
        assert!(g.mkdir("/etc/zyris-docker-should-not-exist".into()).await.is_err(), "mkdir");
        assert!(g.write("/etc/zyris-docker-nope".into(), text("x"), true).await.is_err(), "write");

        // Also check that the refusal actually prevented the side effect.
        assert!(!Path::new("/etc/zyris-docker-should-not-exist").exists());
        assert!(!Path::new("/etc/zyris-docker-nope").exists());
    }

    /// Writes must pass — gating out paths that don't exist yet would make the product useless.
    #[tokio::test]
    async fn writing_a_new_file_under_the_root_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        gated(&root).write("sub/new.txt".into(), text("hi"), true).await.unwrap();
        assert_eq!(std::fs::read_to_string(root.join("sub/new.txt")).unwrap(), "hi");
    }
}
