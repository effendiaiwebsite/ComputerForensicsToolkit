mod sidecar;

use serde_json::Value;
use tauri::{Manager, State};

use crate::sidecar::Sidecar;

#[tauri::command]
async fn ping_sidecar(sidecar: State<'_, Sidecar>) -> Result<Value, String> {
    sidecar
        .request("ping", Value::Null)
        .await
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
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
        .invoke_handler(tauri::generate_handler![ping_sidecar])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
