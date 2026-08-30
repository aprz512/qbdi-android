fn main() {
    let _ = qtrace_service::ANALYSIS_CRATE;
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("failed to run qtrace-ui");
}
