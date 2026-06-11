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

    let mut command = Command::new(&python);
    command
        .arg("-m")
        .arg("core")
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
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir.clone());

    let default_python = if cfg!(windows) {
        repo_root.join(".venv").join("Scripts").join("python.exe")
    } else {
        repo_root.join(".venv").join("bin").join("python")
    };

    let python = std::env::var("DFT_SIDECAR_PYTHON")
        .map(PathBuf::from)
        .unwrap_or(default_python);
    let cwd = std::env::var("DFT_SIDECAR_CWD")
        .map(PathBuf::from)
        .unwrap_or(repo_root);

    (python, cwd)
}
