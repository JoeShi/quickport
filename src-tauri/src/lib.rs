/// QuickPort Tauri application library
///
/// Architecture: Light-solution approach (ADR-002)
/// - Tauri shell provides cross-platform UI + sidecar management
/// - Node.js sidecar (MCP server) handles Feishu/email integration
/// - install-orchestrator (TypeScript) handles credential governance
///
/// Rust layer responsibilities (minimal, per light-solution principle):
/// - Spawn / supervise Node.js MCP server sidecar (HF-7: only this crate can spawn MCP server)
/// - OS tray icon management
/// - Native notification dispatch
/// - Preflight check (Node.js ≥ 18 presence)

use tauri::Manager;

/// Tauri commands exposed to frontend TypeScript

/// Check if Node.js ≥ 18 is installed (preflight requirement per ADR-002 §deploy-constraints)
#[tauri::command]
async fn check_nodejs_version() -> Result<String, String> {
    let output = std::process::Command::new("node")
        .arg("--version")
        .output()
        .map_err(|_| "Node.js not found. Please install Node.js ≥ 18 from https://nodejs.org".to_string())?;

    let version_str = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Parse vMAJOR.MINOR.PATCH
    let major: u32 = version_str
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if major >= 18 {
        Ok(version_str)
    } else {
        Err(format!(
            "Node.js {} is installed but QuickPort requires ≥ 18. Please upgrade: https://nodejs.org",
            version_str
        ))
    }
}

/// Get the platform identifier (for keychain-adapter platform branching)
#[tauri::command]
fn get_platform() -> String {
    std::env::consts::OS.to_string()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            check_nodejs_version,
            get_platform,
        ])
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                let window = app.get_webview_window("main").unwrap();
                window.open_devtools();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
