mod sidecar;

use serde_json::{json, Value};
use tauri::{Manager, State};

use crate::sidecar::Sidecar;

#[tauri::command]
async fn ping_sidecar(sidecar: State<'_, Sidecar>) -> Result<Value, String> {
    sidecar
        .request("ping", Value::Null)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn run_triage_system_hive(
    sidecar: State<'_, Sidecar>,
    hive_path: String,
) -> Result<Value, String> {
    sidecar
        .request("run_triage_system_hive", json!({ "hive_path": hive_path }))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn run_triage_hive(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("run_triage_hive", args)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn run_triage_directory(
    sidecar: State<'_, Sidecar>,
    dir_path: String,
) -> Result<Value, String> {
    sidecar
        .request("run_triage_directory", json!({ "dir_path": dir_path }))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn query_events(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("query_events", args)
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            app.manage(Sidecar::new());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ping_sidecar,
            run_triage_system_hive,
            run_triage_hive,
            run_triage_directory,
            query_events,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
