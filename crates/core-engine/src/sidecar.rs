//! Run an engine as a child process: private config file, redacted output lines, hard stop.

use core_log::Redactor;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

/// Prefix that ties every file this process creates in the work dir to its pid, so a later run
/// can tell leftovers of a crashed process from files of a live second instance.
pub fn instance_prefix() -> String {
    format!("p{}-", std::process::id())
}

/// Create `dir` (and parents) readable only by the current user and make sure an existing one is
/// tightened too. Refuses a symlink in place of the directory.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let meta = std::fs::symlink_metadata(dir)?;
        if !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "work dir is not a directory",
            ));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
        // Best effort: drop inherited ACL entries so only the current user keeps access.
        // UNTESTED ON THE REAL OS: %LOCALAPPDATA% is already user-private by default.
        if let Some(user) = std::env::var_os("USERNAME") {
            let grant = format!("{}:(OI)(CI)F", user.to_string_lossy());
            let _ = std::process::Command::new("icacls")
                .arg(dir)
                .args(["/inheritance:r", "/grant:r", &grant])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        Ok(())
    }
}

/// A config file readable only by the current user, deleted on drop. Engines get secrets from
/// here, never from argv (visible in `ps`).
pub struct PrivateFile {
    path: PathBuf,
}

impl PrivateFile {
    pub fn write(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<Self> {
        use std::io::Write;
        private_dir(dir)?;
        let path = dir.join(name);
        // Remove first so a pre-planted symlink or a file with loose permissions is never reused.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        f.write_all(bytes)?;
        Ok(Self { path })
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

fn pid_alive(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        return Path::new(&format!("/proc/{pid}")).exists();
    }
    if cfg!(unix) {
        return std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(true);
    }
    // Windows: cannot tell cheaply and safely without unsafe; assume alive (never kill, never delete).
    true
}

/// Does process `pid` look like the engine `exe` (basename match on its command line)?
fn pid_is_engine(pid: u32, exe: &str) -> bool {
    if cfg!(target_os = "linux") {
        return std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| {
                let first = b.split(|c| *c == 0).next().unwrap_or(&[]);
                String::from_utf8_lossy(first)
                    .rsplit('/')
                    .next()
                    .map(|n| n == exe)
                    .unwrap_or(false)
                    || String::from_utf8_lossy(&b).contains(exe)
            })
            .unwrap_or(false);
    }
    if cfg!(unix) {
        return std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(exe))
            .unwrap_or(false);
    }
    false
}

/// Record a started engine so a later run can clean up after a crash of this process.
pub fn write_pidfile(dir: &Path, tag: &str, pid: u32, exe: &str) -> io::Result<PrivateFile> {
    let name = format!("{}{tag}.pid", instance_prefix());
    PrivateFile::write(dir, &name, format!("{pid}\n{exe}\n").as_bytes())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Engine processes left behind by a dead instance that were stopped.
    pub killed: Vec<u32>,
    /// Leftover files removed (configs with secrets, pid files).
    pub removed: usize,
}

/// Remove what a crashed (SIGKILL, power loss) earlier instance left in `dir`: engine processes
/// recorded in pid files (only if the pid still runs that engine) and config files that contain
/// secrets. Files of a live second instance are left alone. Call before starting an engine.
pub fn sweep_stale(dir: &Path) -> SweepReport {
    let mut rep = SweepReport::default();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return rep;
    };
    let me = std::process::id();
    let mut entries: Vec<_> = rd.flatten().collect();
    // Pid files first so engines are stopped before their configs disappear.
    entries.sort_by_key(|e| !e.file_name().to_string_lossy().ends_with(".pid"));
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix('p') else {
            continue;
        };
        let Some((num, _)) = rest.split_once('-') else {
            continue;
        };
        let Ok(owner) = num.parse::<u32>() else {
            continue;
        };
        if owner == me || pid_alive(owner) {
            continue;
        }
        let path = e.path();
        if name.ends_with(".pid") {
            if let Ok(t) = std::fs::read_to_string(&path) {
                let mut l = t.lines();
                if let (Some(Ok(pid)), Some(exe)) = (l.next().map(|x| x.parse::<u32>()), l.next()) {
                    if pid_alive(pid) && pid_is_engine(pid, exe) {
                        let _ = std::process::Command::new("kill")
                            .args(["-TERM", &pid.to_string()])
                            .status();
                        std::thread::sleep(Duration::from_millis(500));
                        if pid_alive(pid) && pid_is_engine(pid, exe) {
                            let _ = std::process::Command::new("kill")
                                .args(["-KILL", &pid.to_string()])
                                .status();
                        }
                        rep.killed.push(pid);
                    }
                }
            }
        }
        if std::fs::remove_file(&path).is_ok() {
            rep.removed += 1;
        }
    }
    rep
}

/// Human description of how a process ended, for logs and failure classification.
pub fn describe_exit(s: &std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = s.signal() {
            return format!("killed by signal {sig}");
        }
    }
    match s.code() {
        Some(c) => format!("exit code {c}"),
        None => "ended".into(),
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
    pub lines: Lines,
}

const RING: usize = 2048;

struct Shared {
    q: std::sync::Mutex<std::collections::VecDeque<String>>,
    notify: tokio::sync::Notify,
    pumps: std::sync::atomic::AtomicUsize,
    dropped: std::sync::atomic::AtomicU64,
}

/// Bounded queue of engine output lines. When nobody reads fast enough the OLDEST lines are
/// dropped: the engine is never blocked and the newest lines (the ones that matter, e.g. the
/// ready marker or the error before an exit) survive.
pub struct Lines(Arc<Shared>);

impl Lines {
    fn pop(&self) -> Option<String> {
        self.0.q.lock().ok().and_then(|mut q| q.pop_front())
    }
    fn closed(&self) -> bool {
        self.0.pumps.load(std::sync::atomic::Ordering::SeqCst) == 0
    }
    /// Next line, or `None` once the process closed its output and everything was read.
    pub async fn recv(&mut self) -> Option<String> {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(l) = self.pop() {
                return Some(l);
            }
            if self.closed() {
                // A line may have been pushed between the pop and the closed check.
                return self.pop();
            }
            notified.await;
        }
    }
    pub fn try_recv(&mut self) -> Result<String, mpsc::error::TryRecvError> {
        match self.pop() {
            Some(l) => Ok(l),
            None if self.closed() => Err(mpsc::error::TryRecvError::Disconnected),
            None => Err(mpsc::error::TryRecvError::Empty),
        }
    }
    /// Lines discarded because the reader was too slow.
    pub fn dropped(&self) -> u64 {
        self.0.dropped.load(std::sync::atomic::Ordering::SeqCst)
    }
}

struct PumpGuard(Arc<Shared>);
impl Drop for PumpGuard {
    fn drop(&mut self) {
        self.0
            .pumps
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.0.notify.notify_waiters();
        self.0.notify.notify_one();
    }
}

impl Sidecar {
    /// OS process id while running.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn spawn(spec: SidecarSpec) -> io::Result<Self> {
        let mut child = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let shared = Arc::new(Shared {
            q: Default::default(),
            notify: tokio::sync::Notify::new(),
            pumps: std::sync::atomic::AtomicUsize::new(0),
            dropped: Default::default(),
        });
        if let Some(out) = child.stdout.take() {
            pump(out, spec.redactor.clone(), shared.clone());
        }
        if let Some(err) = child.stderr.take() {
            pump(err, spec.redactor, shared.clone());
        }
        Ok(Self {
            child,
            lines: Lines(shared),
        })
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

/// Longest line kept; the rest of an over-long line is discarded so a hostile or broken engine
/// cannot make us buffer without bound.
const MAX_LINE: usize = 8 * 1024;

/// Read lines forever. Never blocks on a slow consumer: a blocked reader would fill the pipe and
/// freeze the engine itself, so the oldest queued line is dropped instead.
fn pump<R: tokio::io::AsyncRead + Unpin + Send + 'static>(r: R, red: Redactor, sh: Arc<Shared>) {
    sh.pumps.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let guard = PumpGuard(sh.clone());
    let push = move |text: String| {
        if let Ok(mut q) = sh.q.lock() {
            if q.len() >= RING {
                q.pop_front();
                sh.dropped.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            q.push_back(text);
        }
        sh.notify.notify_waiters();
        sh.notify.notify_one();
    };
    tokio::spawn(async move {
        let _guard = guard;
        let mut rd = BufReader::new(r);
        let mut line: Vec<u8> = Vec::new();
        let mut skipping = false;
        loop {
            let chunk = match rd.fill_buf().await {
                Ok([]) | Err(_) => break,
                Ok(c) => c,
            };
            let (used, done) = match chunk.iter().position(|b| *b == b'\n') {
                Some(i) => (i + 1, true),
                None => (chunk.len(), false),
            };
            if !skipping {
                let room = MAX_LINE - line.len();
                let n = used.min(room);
                line.extend_from_slice(&chunk[..n]);
                if n < used && !done {
                    skipping = true;
                }
            }
            rd.consume(used);
            if done {
                let text = String::from_utf8_lossy(&line).trim_end().to_string();
                line.clear();
                skipping = false;
                push(red.redact(&text));
            }
        }
        if !line.is_empty() {
            push(red.redact(&String::from_utf8_lossy(&line)));
        }
    });
}
