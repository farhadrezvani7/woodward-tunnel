//! Run an engine as a child process: private config file, redacted output lines, hard stop.

use core_log::Redactor;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

/// A config file readable only by the current user, deleted on drop. Engines get secrets from
/// here, never from argv (visible in `ps`).
pub struct PrivateFile {
    path: PathBuf,
}

impl PrivateFile {
    pub fn write(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<Self> {
        use std::io::Write;
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            let path = dir.join(name);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(bytes)?;
            Ok(Self { path })
        }
        #[cfg(not(unix))]
        {
            let path = dir.join(name);
            std::fs::File::create(&path)?.write_all(bytes)?;
            Ok(Self { path })
        }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for PrivateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct SidecarSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub redactor: Redactor,
}

/// A running child. `lines` yields already-redacted stdout/stderr lines.
pub struct Sidecar {
    child: Child,
    pub lines: mpsc::Receiver<String>,
}

impl Sidecar {
    pub fn spawn(spec: SidecarSpec) -> io::Result<Self> {
        let mut child = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let (tx, rx) = mpsc::channel(256);
        if let Some(out) = child.stdout.take() {
            pump(out, spec.redactor.clone(), tx.clone());
        }
        if let Some(err) = child.stderr.take() {
            pump(err, spec.redactor, tx);
        }
        Ok(Self { child, lines: rx })
    }

    /// Returns the exit status if the process already ended.
    pub fn try_exit(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Ask the process to end and force-kill after `grace`.
    pub async fn stop(mut self, grace: Duration) -> io::Result<()> {
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            // SIGTERM via the kill command avoids unsafe libc calls.
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status();
        }
        match tokio::time::timeout(grace, self.child.wait()).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => {
                self.child.kill().await?;
                Ok(())
            }
        }
    }
}

fn pump<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    r: R,
    red: Redactor,
    tx: mpsc::Sender<String>,
) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if tx.send(red.redact(&l)).await.is_err() {
                break;
            }
        }
    });
}
