//! Python sidecar lifecycle and JSON-over-stdio request/response.
//!
//! In dev we spawn `<repo>/.venv/Scripts/python.exe -m core` with the repo
//! root as cwd so `core` resolves. Override with env vars `DFT_SIDECAR_PYTHON`
//! and `DFT_SIDECAR_CWD` when needed. Production bundling (PyInstaller) lands
//! in M13.

use std::path::PathBuf;
use std::process::Stdio;

use serde_json::{json, Value};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("failed to spawn sidecar: {0}")]
    Spawn(String),
    #[error("sidecar stdin closed")]
    StdinClosed,
    #[error("sidecar stdout closed")]
    StdoutClosed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

struct Inner {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

pub struct Sidecar {
    inner: Mutex<Option<Inner>>,
}

impl Sidecar {
    pub fn new() -> Self {
        Self { inner: Mutex::new(None) }
    }

    async fn ensure_started(&self) -> Result<tokio::sync::MutexGuard<'_, Option<Inner>>, SidecarError> {
        let mut guard = self.inner.lock().await;
        if guard.is_none() {
            *guard = Some(spawn().await?);
        }
        Ok(guard)
    }

    pub async fn request(&self, op: &str, extra: Value) -> Result<Value, SidecarError> {
        let mut guard = self.ensure_started().await?;
        let inner = guard.as_mut().expect("just initialized");

        inner.next_id += 1;
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
        payload.insert("request_id".into(), json!(inner.next_id.to_string()));

        let mut line = serde_json::to_string(&Value::Object(payload))?;
        line.push('\n');
        inner.stdin.write_all(line.as_bytes()).await?;
        inner.stdin.flush().await?;

        let mut response_line = String::new();
        let n = inner.stdout.read_line(&mut response_line).await?;
        if n == 0 {
            return Err(SidecarError::StdoutClosed);
        }
        Ok(serde_json::from_str(response_line.trim_end())?)
    }
}

async fn spawn() -> Result<Inner, SidecarError> {
    let (python, cwd) = resolve_paths();

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
    command
        .current_dir(&cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
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

    Ok(Inner {
        _child: child,
        stdin,
        stdout: BufReader::new(stdout),
        next_id: 0,
    })
}

fn resolve_paths() -> (PathBuf, PathBuf) {
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
    } else if bundled_sidecar.as_ref().is_some_and(|p| p.exists()) {
        bundled_sidecar.clone().unwrap()
    } else {
        dev_python.clone()
    };

    let cwd = if let Ok(env_cwd) = std::env::var("DFT_SIDECAR_CWD") {
        PathBuf::from(env_cwd)
    } else if let Some(d) = exe_dir.clone().filter(|_| python != dev_python) {
        d
    } else {
        repo_root
    };

    (python, cwd)
}
