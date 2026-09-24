use std::{path::PathBuf, sync::Arc};

use qtrace_service::{EventFilterDto, HexU64Dto, QtraceService};
use qtrace_ui::*;

struct FakePicker {
    session: PathBuf,
    elf: PathBuf,
}

impl NativePicker for FakePicker {
    fn pick_session(&self) -> Result<Option<PathBuf>, qtrace_service::AppError> {
        Ok(Some(self.session.clone()))
    }
    fn pick_artifact(&self) -> Result<Option<PathBuf>, qtrace_service::AppError> {
        Ok(Some(self.session.join("artifacts/main.trace.bin")))
    }
    fn pick_elf(&self) -> Result<Option<PathBuf>, qtrace_service::AppError> {
        Ok(Some(self.elf.clone()))
    }
}

fn fixture(path: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("fixtures")
        .join(path)
}

#[test]
fn adapter_mirrors_the_service_contract() {
    let data = tempfile::tempdir().unwrap();
    let picker = FakePicker {
        session: fixture("sessions/valid-mixed"),
        elf: fixture("elf/minimal-aarch64.elf"),
    };
    let adapter = CommandAdapter::new(Arc::new(QtraceService::new()), picker, data.path().into());
    let opened = adapter.pick_and_open_session().unwrap().unwrap();
    let workspace_id = opened.workspace.id;
    assert_eq!(
        adapter
            .get_workspace_summary(WorkspaceRequest {
                workspace_id: workspace_id.clone(),
            })
            .unwrap()
            .id,
        workspace_id
    );
    let projection = adapter
        .create_projection(CreateProjectionRequest {
            workspace_id: workspace_id.clone(),
            artifact_index: 0,
            filter: EventFilterDto::default(),
        })
        .unwrap();
    let page = adapter
        .query_timeline(QueryTimelineRequest {
            workspace_id: workspace_id.clone(),
            projection_id: projection.projection_id.clone(),
            cursor: None,
            limit: 10,
        })
        .unwrap();
    let row = page.rows.first().unwrap();
    let location = adapter
        .locate_timeline(LocateTimelineRequest {
            workspace_id: workspace_id.clone(),
            projection_id: projection.projection_id.clone(),
            source_row: row.source_row,
            limit: 10,
        })
        .unwrap()
        .expect("visible row location");
    assert_eq!(location.start, 0);
    let offset_location = adapter
        .locate_timeline_offset(LocateTimelineOffsetRequest {
            workspace_id: workspace_id.clone(),
            projection_id: projection.projection_id.clone(),
            offset: 0,
            limit: 10,
        })
        .unwrap()
        .expect("visible offset location");
    assert_eq!(offset_location, location);
    let event = EventRequest {
        workspace_id: workspace_id.clone(),
        artifact_index: 0,
        row: row.source_row,
    };
    adapter.get_event_detail(event.clone()).unwrap();
    adapter.get_register_state(event.clone()).unwrap();
    let memory = MemoryRequest {
        workspace_id: workspace_id.clone(),
        artifact_index: 0,
        row: row.source_row,
        start: HexU64Dto::new(0),
        end_exclusive: HexU64Dto::new(1),
    };
    adapter.get_memory_state(memory.clone()).unwrap();
    adapter.get_memory_history(memory).unwrap();
    if let Some(tid) = row.key.tid {
        adapter
            .get_call_tree(CallTreeRequest {
                workspace_id: workspace_id.clone(),
                artifact_index: 0,
                timeline_id: row.key.timeline_id.clone(),
                tid,
                parent: None,
                offset: 0,
                expected_identity: None,
            })
            .unwrap();
    }
    let attach_error = adapter
        .pick_and_attach_elf(AttachElfRequest {
            workspace_id: workspace_id.clone(),
            module_name: "minimal-aarch64.elf".into(),
            module_digest: "1937c7eca9fda7e3fdef82fc7a1785b6205f5fcdc2a070c9664d2c634556d4a0"
                .into(),
            expected_build_id: None,
        })
        .unwrap_err();
    assert_eq!(attach_error.stage, "symbol");
    let symbol_error = adapter
        .list_symbols(ListSymbolsRequest {
            workspace_id: workspace_id.clone(),
            module_name: "minimal-aarch64.elf".into(),
            relative_pcs: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(symbol_error.code, "symbol.not_attached");
    adapter
        .upsert_annotation(UpsertAnnotationRequest {
            workspace_id: workspace_id.clone(),
            artifact_index: 0,
            row: row.source_row,
            comment: "note".into(),
        })
        .unwrap();
    assert_eq!(
        adapter
            .get_annotation(event.clone())
            .unwrap()
            .unwrap()
            .comment,
        "note"
    );
    adapter.delete_annotation(event).unwrap();
    let jobs = adapter.list_jobs();
    adapter
        .cancel_job(CancelJobRequest {
            job_id: jobs[0].id.clone(),
        })
        .unwrap();
    adapter
        .close_workspace(WorkspaceRequest { workspace_id })
        .unwrap();
}

#[test]
fn malformed_non_picker_requests_are_rejected_with_stable_errors() {
    assert!(
        serde_json::from_value::<MemoryRequest>(serde_json::json!({
            "workspace_id": "1", "artifact_index": 0, "row": 0,
            "start": "0x00", "end_exclusive": "0x1"
        }))
        .is_err()
    );
    let root = tempfile::tempdir().unwrap();
    let picker = FakePicker {
        session: fixture("sessions/valid-mixed"),
        elf: fixture("elf/minimal-aarch64.elf"),
    };
    let adapter = CommandAdapter::new(Arc::new(QtraceService::new()), picker, root.path().into());
    let error = adapter
        .get_workspace_summary(WorkspaceRequest {
            workspace_id: qtrace_service::WorkspaceId::from_u64(999),
        })
        .unwrap_err();
    assert_eq!(error.code, "workspace.stale");
    assert_eq!(error.stage, "workspace");
}
