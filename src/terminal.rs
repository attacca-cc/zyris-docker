//! Wraps `Terminal`. Delegates the PTY calls and rewrites only `exec`.
//!
//! **Why exec is not delegated:** upstream `PtyTerminal::exec` spawns the child inside itself,
//! reads to EOF with `cmd.output()` and hands back a finished string — no pid, no `Child`, no
//! stream ever reaches the caller, and the timeout branch returns without killing anything. A
//! decorator cannot kill the process group at all, and an output cap could only trim a string
//! that is already fully in memory.

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zyris::{Blob, Streaming};
use zyris_capkit::PtyTerminal;
use zyris_caps::{ExecOutput, PtyChunk, PtyId, PtyOpened, PtyRead, PtyScreen, Settle, Terminal};

use crate::gate::PathGate;

/// Grace between SIGTERM and SIGKILL.
#[cfg(unix)]
const KILL_GRACE: Duration = Duration::from_millis(200);

pub struct GatedTerminal {
    gate: PathGate,
    /// Hard cap on `exec` output per stream and on how long a command may run.
    max_output_bytes: usize,
    exec_timeout: Duration,
    /// **Built once, never rebuilt.** The session cap is per instance and the reaper sweeper
    /// holds a `Weak`, so dropping this loses every open PTY session at once.
    inner: PtyTerminal,
}

impl GatedTerminal {
    pub fn new(gate: PathGate, max_output_bytes: usize, exec_timeout: Duration) -> GatedTerminal {
        let inner = PtyTerminal::rooted(gate.root().to_path_buf());
        GatedTerminal { gate, max_output_bytes, exec_timeout, inner }
    }

    /// Effective timeout = `min(what the caller asked for, config)`. Config acts as the cap.
    fn effective_timeout(&self, caller_ms: Option<u64>) -> Duration {
        let cap_ms = self.exec_timeout.as_millis() as u64;
        Duration::from_millis(caller_ms.map(|c| c.min(cap_ms)).unwrap_or(cap_ms))
    }
}

/// **Keeps** only up to the cap, but keeps reading to EOF.
///
/// Never stop reading just because the cap was hit. The child fills the pipe buffer and blocks
/// in write, `child.wait()` never returns, and the call hangs until the effective timeout. Only
/// by draining and discarding the excess does the command exit cleanly with a real exit code.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(r: &mut R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut capped = false;
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return (out, capped),
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                if room > 0 {
                    out.extend_from_slice(&buf[..n.min(room)]);
                }
                if n > room {
                    capped = true;
                }
            }
        }
    }
}

/// A negative pid means the whole process group. Spawned with `process_group(0)`, so the child's
/// pid is the group id and every grandchild under it dies with it.
#[cfg(unix)]
fn kill_group(pid: i32, sig: i32) {
    if pid > 0 {
        unsafe { libc::kill(-pid, sig) };
    }
}

fn finish(bytes: Vec<u8>, capped: bool) -> String {
    let mut s = String::from_utf8_lossy(&bytes).to_string();
    if capped {
        s.push_str("\n… output truncated at the cap");
    }
    s
}

#[zyris::async_trait]
impl Terminal for GatedTerminal {
    async fn open(&self, shell: Option<String>, cols: u16, rows: u16) -> zyris::Result<PtyOpened> {
        self.inner.open(shell, cols, rows).await
    }

    async fn open_stream(
        &self,
        shell: Option<String>,
        cols: u16,
        rows: u16,
    ) -> zyris::Result<Streaming<PtyOpened, PtyChunk>> {
        self.inner.open_stream(shell, cols, rows).await
    }

    async fn read(
        &self,
        pty: PtyId,
        input: Option<String>,
        settle: Option<Settle>,
    ) -> zyris::Result<PtyRead> {
        self.inner.read(pty, input, settle).await
    }

    async fn screen(
        &self,
        pty: PtyId,
        input: Option<String>,
        settle: Option<Settle>,
    ) -> zyris::Result<PtyScreen> {
        self.inner.screen(pty, input, settle).await
    }

    async fn write(&self, pty: PtyId, data: Blob) -> zyris::Result<()> {
        self.inner.write(pty, data).await
    }

    async fn resize(&self, pty: PtyId, cols: u16, rows: u16) -> zyris::Result<()> {
        self.inner.resize(pty, cols, rows).await
    }

    async fn close(&self, pty: PtyId) -> zyris::Result<()> {
        self.inner.close(pty).await
    }

    /// Implemented here rather than delegated, because `PtyTerminal::exec` reads the child to
    /// completion inside itself and leaves no handle to kill the process group from outside. The
    /// timeout below has to reach the whole tree, not just the shell that was spawned.
    #[allow(clippy::too_many_arguments)]
    async fn exec(
        &self,
        command: Option<String>,
        argv: Option<Vec<String>>,
        cwd: Option<String>,
        timeout_ms: Option<u64>,
        stdin: Option<String>,
        env: Option<HashMap<String, String>>,
        shell: Option<String>,
    ) -> zyris::Result<ExecOutput> {
        let argv = match argv {
            Some(a) if a.is_empty() => {
                return Err(zyris::WireError::invalid_params("argv must not be empty"))
            }
            other => other,
        };
        let has_command = matches!(command.as_deref(), Some(c) if !c.trim().is_empty());
        match (has_command, argv.is_some()) {
            (false, false) => {
                return Err(zyris::WireError::invalid_params("give `command` or `argv`, not neither"))
            }
            (true, true) => {
                return Err(zyris::WireError::invalid_params("give `command` or `argv`, not both"))
            }
            _ => {}
        }

        let dir = match cwd {
            Some(c) => self.gate.check(&c)?,
            None => self.gate.root().to_path_buf(),
        };

        let mut cmd = match argv {
            // No shell at all: the arguments reach the program exactly as given.
            Some(argv) => {
                let mut c = tokio::process::Command::new(&argv[0]);
                c.args(&argv[1..]);
                c
            }
            None => {
                let line = command.unwrap_or_default();
                let mut c = tokio::process::Command::new(shell.unwrap_or_else(|| "/bin/sh".to_string()));
                c.arg("-c").arg(&line);
                c
            }
        };

        let wants_stdin = stdin.is_some();
        cmd.current_dir(&dir)
            .stdin(if wants_stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(env) = env {
            for (k, v) in env {
                cmd.env(k, v);
            }
        }
        #[cfg(unix)]
        cmd.process_group(0);

        let mut child = cmd.spawn().map_err(|e| {
            zyris::WireError::new(zyris::ErrorCode::Internal, format!("could not run: {e}"))
        })?;
        let pid = child.id().unwrap_or(0) as i32;
        let cap = self.max_output_bytes;

        // Written and closed before the output is gathered. Left open, a child that reads its
        // stdin to EOF never gets one and the call waits out the timeout for no reason.
        if let Some(text) = stdin {
            if let Some(mut pipe) = child.stdin.take() {
                let _ = pipe.write_all(text.as_bytes()).await;
                let _ = pipe.shutdown().await;
            }
        }

        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");

        let collect = async {
            // Read both at once, or a child that fills the stderr pipe buffer blocks before
            // stdout hits EOF and it deadlocks.
            let (out, err) =
                tokio::join!(read_capped(&mut stdout, cap), read_capped(&mut stderr, cap));
            let status = child.wait().await;
            (out, err, status)
        };

        let outcome = tokio::time::timeout(self.effective_timeout(timeout_ms), collect).await;
        match outcome {
            Ok(((o, oc), (e, ec), status)) => Ok(ExecOutput {
                exit_code: status.ok().and_then(|s| s.code()).unwrap_or(-1),
                stdout: finish(o, oc),
                stderr: finish(e, ec),
                timed_out: false,
                stdout_truncated: oc,
                stderr_truncated: ec,
            }),
            Err(_) => {
                #[cfg(unix)]
                {
                    kill_group(pid, libc::SIGTERM);
                    tokio::time::sleep(KILL_GRACE).await;
                    kill_group(pid, libc::SIGKILL);
                }
                #[cfg(windows)]
                let _ = child.start_kill().await;
                let _ = pid;
                Ok(ExecOutput {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: "command timed out; the whole process tree was killed".into(),
                    timed_out: true,
                    stdout_truncated: false,
                    stderr_truncated: false,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn term(root: &Path) -> GatedTerminal {
        GatedTerminal::new(
            PathGate::new(vec![root.to_path_buf()], vec![]),
            64,
            Duration::from_secs(5),
        )
    }

    async fn run(
        t: &GatedTerminal,
        command: &str,
        cwd: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> zyris::Result<ExecOutput> {
        t.exec(Some(command.to_string()), None, cwd.map(str::to_string), timeout_ms, None, None, None)
            .await
    }

    #[tokio::test]
    async fn exec_runs_and_captures() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let t = term(&root);
        let out = run(&t, "echo hello", None, None).await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("hello"), "{}", out.stdout);
    }

    /// The cap trims the bytes but the exit code and completion stay real.
    #[tokio::test]
    async fn exec_output_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let t = term(&root);
        let out = run(&t, "printf 'a%.0s' {1..500}", None, None).await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout_truncated, "expected a truncated flag");
        assert!(out.stdout.len() <= 64 + 64, "{}", out.stdout.len());
    }

    /// `cwd` outside the gate is refused.
    #[tokio::test]
    async fn exec_refuses_a_cwd_outside_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let t = term(&root);
        let err = run(&t, "pwd", Some("/etc"), None).await.unwrap_err();
        assert_eq!(err.code, zyris::ErrorCode::ForbiddenScope);
    }
}
