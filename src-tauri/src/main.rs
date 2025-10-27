// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct VTResponse {
    status: u16,
    body: String,
}

/// Fetch data from VirusTotal API
/// This runs in the Rust backend, so no CORS issues!
#[tauri::command]
async fn vt_fetch(endpoint: String, api_key: String) -> Result<VTResponse, String> {
    let url = format!("https://www.virustotal.com/api/v3{}", endpoint);
    
    println!("Fetching from VT: {}", url);
    
    let client = reqwest::Client::new();
    
    match client
        .get(&url)
        .header("x-apikey", api_key)
        .header("User-Agent", "VTproxy-Desktop/1.0")
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.map_err(|e| e.to_string())?;
            
            Ok(VTResponse { status, body })
        }
        Err(e) => {
            eprintln!("Error fetching from VT: {}", e);
            Err(format!("Network error: {}", e))
        }
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![vt_fetch])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
