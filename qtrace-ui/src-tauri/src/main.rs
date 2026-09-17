use std::sync::Arc;

use qtrace_ui::{
    CommandAdapter, TauriNativePicker, cancel_job, close_workspace, create_projection,
    delete_annotation, delete_highlight, delete_local_symbol_name, get_annotation, get_call_tree,
    get_event_detail, get_local_symbol_name, get_memory_history, get_memory_state,
    get_register_state, get_workspace_summary, list_jobs, list_symbols, pick_and_attach_elf,
    pick_and_open_artifact, pick_and_open_session, query_timeline, upsert_annotation,
    upsert_highlight, upsert_local_symbol_name,
};
use tauri::Manager;

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_home = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_home)?;
            app.manage(CommandAdapter::new(
                Arc::new(qtrace_service::QtraceService::new()),
                TauriNativePicker(app.handle().clone()),
                data_home,
            ));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pick_and_open_session,
            pick_and_open_artifact,
            close_workspace,
            get_workspace_summary,
            create_projection,
            query_timeline,
            get_event_detail,
            get_register_state,
            get_memory_state,
            get_memory_history,
            get_call_tree,
            pick_and_attach_elf,
            list_symbols,
            upsert_annotation,
            delete_annotation,
            get_annotation,
            upsert_highlight,
            delete_highlight,
            get_local_symbol_name,
            upsert_local_symbol_name,
            delete_local_symbol_name,
            list_jobs,
            cancel_job,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build qtrace-ui");
    app.run(|handle, event| {
        if matches!(
            event,
            tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }
        ) {
            handle
                .state::<qtrace_ui::state::DesktopState>()
                .cancel_all();
        }
    });
}
