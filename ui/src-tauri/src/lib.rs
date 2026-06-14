mod elevation;
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

#[tauri::command]
async fn query_program_execution_composite(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("query_program_execution_composite", args)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn query_timeline(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("query_timeline", args)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_event(
    sidecar: State<'_, Sidecar>,
    event_id: String,
) -> Result<Value, String> {
    sidecar
        .request("get_event", json!({ "event_id": event_id }))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn evaluate_rules(
    sidecar: State<'_, Sidecar>,
    collection_id: String,
) -> Result<Value, String> {
    sidecar
        .request("evaluate_rules", json!({ "collection_id": collection_id }))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn query_findings(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("query_findings", args)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn query_usb_devices(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("query_usb_devices", args)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn query_browser_domains(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("query_browser_domains", args)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn generate_report(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("generate_report", args)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn enumerate_drives(sidecar: State<'_, Sidecar>) -> Result<Value, String> {
    sidecar
        .request("enumerate_drives", Value::Null)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn run_live_collection(
    sidecar: State<'_, Sidecar>,
    args: Value,
) -> Result<Value, String> {
    sidecar
        .request("run_live_collection", args)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_progress(
    sidecar: State<'_, Sidecar>,
    collection_id: String,
) -> Result<Value, String> {
    sidecar
        .request("get_progress", json!({ "collection_id": collection_id }))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn is_elevated() -> bool {
    elevation::is_elevated()
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
            query_program_execution_composite,
            query_timeline,
            get_event,
            evaluate_rules,
            query_findings,
            query_usb_devices,
            query_browser_domains,
            generate_report,
            enumerate_drives,
            run_live_collection,
            get_progress,
            is_elevated,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
