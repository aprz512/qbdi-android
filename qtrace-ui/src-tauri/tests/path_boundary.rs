use std::{path::PathBuf, sync::Mutex};

use qtrace_service::AppError;
use qtrace_ui::{
    AttachElfRequest, CommandAdapter, EmptyPickerRequest, NativePicker, WorkspaceRequest,
};

#[derive(Default)]
struct FakePicker {
    session: Option<PathBuf>,
    artifact: Option<PathBuf>,
    elf: Option<PathBuf>,
    calls: Mutex<Vec<&'static str>>,
}

impl NativePicker for FakePicker {
    fn pick_session(&self) -> Result<Option<PathBuf>, AppError> {
        self.calls.lock().unwrap().push("session");
        Ok(self.session.clone())
    }
    fn pick_artifact(&self) -> Result<Option<PathBuf>, AppError> {
        self.calls.lock().unwrap().push("artifact");
        Ok(self.artifact.clone())
    }
    fn pick_elf(&self) -> Result<Option<PathBuf>, AppError> {
        self.calls.lock().unwrap().push("elf");
        Ok(self.elf.clone())
    }
}

#[test]
fn picker_cancel_is_a_typed_non_error() {
    let root = tempfile::tempdir().unwrap();
    let adapter = CommandAdapter::new(
        std::sync::Arc::new(qtrace_service::QtraceService::new()),
        FakePicker::default(),
        root.path().to_owned(),
    );
    assert!(adapter.pick_and_open_session().unwrap().is_none());
    assert!(adapter.pick_and_open_artifact().unwrap().is_none());
}

#[test]
fn hostile_path_fields_are_rejected_before_any_picker_call() {
    for field in ["path", "file", "directory"] {
        let payload = format!(r#"{{"{field}":"/etc/passwd"}}"#);
        assert!(serde_json::from_str::<EmptyPickerRequest>(&payload).is_err());
    }
    assert!(
        serde_json::from_value::<AttachElfRequest>(serde_json::json!({
            "workspace_id": "1",
            "module_name": "x",
            "module_digest": "00".repeat(32),
            "expected_build_id": null,
            "path": "/tmp/evil"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<WorkspaceRequest>(serde_json::json!({
            "workspace_id": "1", "directory": "/tmp"
        }))
        .is_err()
    );
}
