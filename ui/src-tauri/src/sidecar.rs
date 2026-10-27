//! Python sidecar lifecycle and JSON-over-stdio request/response.
//!
//! Release / pendrive builds spawn `dft-sidecar/dft-sidecar.exe` next to the
//! app binary. From the source tree we spawn `<repo>/.venv/Scripts/python.exe
//! -m core` with the repo root as cwd so `core` resolves. Override with env
//! vars `DFT_SIDECAR_PYTHON` and `DFT_SIDECAR_CWD` when needed.

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

const DEFAULT_TIMEOUT_SECS: u64 = 600;
const LOG_FILE_NAME: &str = "dft-sidecar.log";

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("failed to spawn sidecar: {0}")]
    Spawn(String),
    #[error("sidecar stdin closed")]
    StdinClosed,
    #[error("sidecar stdout closed")]
    StdoutClosed,
    #[error("sidecar did not answer '{op}' within {secs}s; it was restarted")]
    Timeout { op: String, secs: u64 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

struct Inner {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

pub struct Sidecar {
    // Serialises requests: the protocol is strictly one-in-one-out.
    inner: Mutex<Option<Inner>>,
    // Kept apart from `inner` so shutdown() can kill the process even while a
    // request holds the async lock.
    child: std::sync::Mutex<Option<Child>>,
}

impl Sidecar {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
            child: std::sync::Mutex::new(None),
        }
    }

    pub async fn request(&self, op: &str, extra: Value) -> Result<Value, SidecarError> {
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            let (child, io) = spawn().await?;
            *self.child.lock().unwrap() = Some(child);
            *guard = Some(io);
        }
        let inner = guard.as_mut().expect("just initialized");

        let secs = request_timeout_secs();
        let result = match tokio::time::timeout(Duration::from_secs(secs), exchange(inner, op, extra)).await {
            Ok(r) => r,
            Err(_) => Err(SidecarError::Timeout { op: op.to_string(), secs }),
        };
        if result.is_err() {
            // The stream is unusable (dead process, or a late reply would
            // desync later requests): drop it so the next call respawns.
            *guard = None;
            self.kill_child();
        }
        result
    }

    /// Kills the child; the next request respawns it.
    pub fn shutdown(&self) {
        self.kill_child();
    }

    fn kill_child(&self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.start_kill();
        }
    }
}

async fn exchange(inner: &mut Inner, op: &str, extra: Value) -> Result<Value, SidecarError> {
    inner.next_id += 1;
    let request_id = inner.next_id.to_string();
    let mut payload = match extra {
        Value::Object(map) => map,
        Value::Null => serde_json::Map::new(),
        other => {
            let mut m = serde_json::Map::new();
            m.insert("args".into(), other);
            m
        }
    };
    payload.insert("op".into(), json!(op));
    payload.insert("request_id".into(), json!(request_id));

    let mut line = serde_json::to_string(&Value::Object(payload))?;
    line.push('\n');
    inner.stdin.write_all(line.as_bytes()).await?;
    inner.stdin.flush().await?;

    let mut response_line = String::new();
    loop {
        response_line.clear();
        if inner.stdout.read_line(&mut response_line).await? == 0 {
            return Err(SidecarError::StdoutClosed);
        }
        let text = response_line.trim_end();
        let value = match serde_json::from_str::<Value>(text) {
            Ok(v) if v.is_object() => v,
            _ => {
                log::warn!("sidecar: ignoring non-protocol stdout line: {text}");
                continue;
            }
        };
        match value.get("request_id").and_then(Value::as_str) {
            Some(id) if id == request_id => return Ok(value),
            other => log::warn!("sidecar: dropping response for request_id {other:?} (waiting for {request_id})"),
        }
    }
}

fn request_timeout_secs() -> u64 {
    std::env::var("DFT_SIDECAR_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
}

async fn spawn() -> Result<(Child, Inner), SidecarError> {
    let (python, cwd) = resolve_paths()?;

    // Bundled dft-sidecar.exe is self-contained — its argv0 already entry-points
    // to core/__main__.py. Only the dev Python interpreter needs `-m core`.
    let is_bundled = python
        .file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n.contains("dft-sidecar"));

    let mut command = Command::new(&python);
    if !is_bundled {
        command.arg("-m").arg("core");
    }
    // Debug builds have a console, so Python logging goes straight there;
    // release builds (windows_subsystem) have none, so it is drained to a file.
    let stderr = if cfg!(debug_assertions) { Stdio::inherit() } else { Stdio::piped() };
    command
        .current_dir(&cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .kill_on_drop(true);

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = command
        .spawn()
        .map_err(|e| SidecarError::Spawn(format!("python={} cwd={} err={}", python.display(), cwd.display(), e)))?;

    let stdin = child.stdin.take().ok_or(SidecarError::StdinClosed)?;
    let stdout = child.stdout.take().ok_or(SidecarError::StdoutClosed)?;
    if let Some(stderr) = child.stderr.take() {
        tauri::async_runtime::spawn(drain_stderr(stderr, child.id()));
    }

    Ok((
        child,
        Inner {
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 0,
        },
    ))
}

/// Copies the child's stderr to `dft-sidecar.log` (next to the exe, else the
/// OS temp dir) until the pipe closes. Something must always read the pipe or
/// the child blocks once the pipe buffer fills.
async fn drain_stderr(mut stderr: ChildStderr, pid: Option<u32>) {
    match open_log_file(pid) {
        Some(file) => {
            let mut file = tokio::fs::File::from_std(file);
            let _ = tokio::io::copy(&mut stderr, &mut file).await;
        }
        None => {
            let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        }
    }
}

fn open_log_file(pid: Option<u32>) -> Option<std::fs::File> {
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from));
    let candidates = exe_dir.into_iter().chain(std::iter::once(std::env::temp_dir()));
    for dir in candidates {
        let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(LOG_FILE_NAME)) else {
            continue;
        };
        let _ = writeln!(file, "--- sidecar started (pid {}) ---", pid.map_or("?".to_string(), |p| p.to_string()));
        return Some(file);
    }
    None
}

/// Directory the sidecar runs in: next to the app in release, the repo root in dev.
/// Collections default to `<this>/collected/<timestamp>`.
pub fn working_dir() -> Result<PathBuf, SidecarError> {
    resolve_paths().map(|(_, cwd)| cwd)
}

fn resolve_paths() -> Result<(PathBuf, PathBuf), SidecarError> {
    // Resolution order, first match wins:
    //   1. DFT_SIDECAR_PYTHON env (lets ops override anywhere)
    //   2. dft-sidecar.exe next to the running app.exe — release / pendrive
    //   3. .venv/Scripts/python.exe at the repo root — source-tree dev
    // CWD analogous: DFT_SIDECAR_CWD env → app.exe parent → repo root.

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir.clone());

    let dev_python = if cfg!(windows) {
        repo_root.join(".venv").join("Scripts").join("python.exe")
    } else {
        repo_root.join(".venv").join("bin").join("python")
    };

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    let bundled_sidecar = exe_dir.as_ref().map(|d| {
        if cfg!(windows) {
            d.join("dft-sidecar").join("dft-sidecar.exe")
        } else {
            d.join("dft-sidecar").join("dft-sidecar")
        }
    });

    let python = if let Ok(env_path) = std::env::var("DFT_SIDECAR_PYTHON") {
        PathBuf::from(env_path)
    } else if let Some(p) = bundled_sidecar.as_ref().filter(|p| p.exists()) {
        p.clone()
    } else if dev_python.exists() {
        dev_python.clone()
    } else {
        let expected = bundled_sidecar
            .as_ref()
            .map_or("dft-sidecar/dft-sidecar.exe".to_string(), |p| p.display().to_string());
        return Err(SidecarError::Spawn(format!(
            "sidecar folder not found: expected {expected} next to the app (set DFT_SIDECAR_PYTHON to override)"
        )));
    };

    let cwd = if let Ok(env_cwd) = std::env::var("DFT_SIDECAR_CWD") {
        PathBuf::from(env_cwd)
    } else if let Some(d) = exe_dir.filter(|_| python != dev_python) {
        d
    } else {
        repo_root
    };

    Ok((python, cwd))
}
