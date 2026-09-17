use qtrace_service::{EventFilterDto, QtraceService, WorkspaceId};
use qtrace_store::AuthorizedPath;

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap()
        .join("fixtures/sessions")
        .join(name)
}

#[tokio::test]
async fn newer_projection_generation_wins_over_late_completion() {
    let service = QtraceService::new_for_tests();
    let workspace = service.insert_empty_workspace();
    let first = service
        .create_projection_for_tests(&workspace, EventFilterDto::default())
        .unwrap();
    let mut changed = EventFilterDto::default();
    changed.tids.push(7);
    let second = service
        .create_projection_for_tests(&workspace, changed)
        .unwrap();
    service.complete_projection_for_tests(&first).unwrap();
    assert_eq!(
        service.current_projection(&workspace).unwrap(),
        second.projection_id
    );
    assert_ne!(first.projection_id, second.projection_id);
}

#[test]
fn close_invalidates_workspace_and_active_generation() {
    let service = QtraceService::new_for_tests();
    let workspace = service.insert_empty_workspace();
    service.close_workspace(&workspace).unwrap();
    let error = service.workspace_summary(&workspace).unwrap_err();
    assert_eq!(error.code, "workspace.stale");
    assert!(
        service
            .workspace_summary(&WorkspaceId::from_u64(999))
            .is_err()
    );
}

#[test]
fn real_workspace_exposes_bounded_analysis_without_store_handles() {
    let service = QtraceService::new();
    let opened = service
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    assert!(!opened.artifacts.is_empty());
    let workspace = opened.workspace.id;
    let projection = service
        .create_projection(&workspace, 0, EventFilterDto::default())
        .unwrap();
    let page = service
        .query_timeline(&workspace, &projection.projection_id, None, 10)
        .unwrap();
    assert!(!page.rows.is_empty());
    assert!(page.rows.len() <= 10);

    let row = &page.rows[0];
    let detail = service
        .get_event_detail(&workspace, 0, row.source_row)
        .unwrap();
    assert_eq!(detail.key, row.key);
    let registers = service
        .get_register_state(&workspace, 0, row.source_row)
        .unwrap();
    assert_eq!(registers.before.len(), 34);
    assert_eq!(registers.after.len(), 34);

    let data = tempfile::tempdir().unwrap();
    service
        .upsert_annotation(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
            "reviewed".into(),
        )
        .unwrap();
    let annotation = service
        .get_annotation(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
        )
        .unwrap()
        .unwrap();
    assert_eq!(annotation.comment, "reviewed");
    assert_eq!(annotation.highlight, None);
    service
        .upsert_highlight(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
            "#ffcc00".into(),
        )
        .unwrap();
    let highlighted = service
        .get_annotation(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
        )
        .unwrap()
        .unwrap();
    assert_eq!(highlighted.comment, "reviewed");
    assert_eq!(highlighted.highlight.as_deref(), Some("#ffcc00"));

    let module_digest = "11".repeat(32);
    service
        .upsert_local_symbol_name(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            module_digest.clone(),
            0x120,
            "local_entry".into(),
        )
        .unwrap();
    let local = service
        .get_local_symbol_name(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            module_digest,
            0x120,
        )
        .unwrap()
        .unwrap();
    assert_eq!(local.name, "local_entry");
    assert_eq!(local.relative_pc.value(), 0x120);
    service
        .delete_annotation(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
        )
        .unwrap();
}
