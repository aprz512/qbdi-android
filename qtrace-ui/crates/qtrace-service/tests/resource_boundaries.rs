use qtrace_service::{CallTreePageQuery, EventFilterDto, QtraceService, WorkspaceId};
use qtrace_store::AuthorizedPath;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[test]
fn attaching_a_loadable_elf_refreshes_existing_projection_symbols() {
    let root = TempDir::new().unwrap();
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures");
    let service = QtraceService::with_cache_root(root.path().join("cache"));
    let opened = service
        .open_session(AuthorizedPath::new(fixtures.join("sessions/valid-mixed")))
        .unwrap();
    let workspace = opened.workspace.id;
    let projection = service
        .create_projection(&workspace, 0, EventFilterDto::default())
        .unwrap();
    let before = service
        .query_timeline(&workspace, &projection.projection_id, None, 100)
        .unwrap();
    assert!(before.rows.iter().all(|row| row.symbol.is_none()));
    let elf = fixtures.join("elf/lib.so");
    let digest = format!("{:x}", Sha256::digest(std::fs::read(&elf).unwrap()));
    service
        .attach_elf(
            &workspace,
            AuthorizedPath::new(elf),
            "lib.so".into(),
            digest,
            Some(vec![0x42; 20]),
        )
        .unwrap();
    let symbols = service
        .list_symbols(&workspace, "lib.so", &[0x2345])
        .unwrap();
    assert_eq!(symbols[0].name, "native_work");
    assert_eq!(symbols[0].offset.value(), 5);
    let after = service
        .query_timeline(&workspace, &projection.projection_id, None, 100)
        .unwrap();
    let instruction = after
        .rows
        .iter()
        .find(|row| row.kind == "instruction")
        .unwrap();
    assert_eq!(instruction.symbol.as_deref(), Some("native_work+0x5"));
}

#[test]
fn oversized_filter_is_rejected_before_generation_or_job_changes() {
    let root = TempDir::new().unwrap();
    let service = QtraceService::with_cache_root(root.path().join("cache"));
    let workspace = service.insert_empty_workspace();
    let before = service.workspace_summary(&workspace).unwrap();
    let error = service
        .create_projection(
            &workspace,
            0,
            EventFilterDto {
                tids: vec![1; qtrace_service::ipc::MAX_FILTER_TERMS + 1],
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "ipc.input_too_large");
    assert_eq!(service.workspace_summary(&workspace).unwrap(), before);
    assert!(service.list_jobs().is_empty());
}

#[test]
fn excessive_inputs_are_rejected_before_state_lookup_or_file_access() {
    let root = TempDir::new().unwrap();
    let service = QtraceService::with_cache_root(root.path().join("cache"));
    let workspace = WorkspaceId::from_u64(123);
    let error = service
        .list_symbols(&workspace, "lib.so", &vec![0; 2001])
        .unwrap_err();
    assert_eq!(error.code, "ipc.input_too_large");
    let error = service
        .get_call_tree(
            &workspace,
            0,
            1,
            1,
            CallTreePageQuery {
                expected_identity: Some("x".repeat(257)),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "ipc.input_too_large");
    let error = service
        .upsert_annotation(
            &workspace,
            AuthorizedPath::new(root.path().join("unopened")),
            0,
            0,
            "x".repeat(65537),
        )
        .unwrap_err();
    assert_eq!(error.code, "ipc.input_too_large");
    let error = service
        .upsert_highlight(
            &workspace,
            AuthorizedPath::new(root.path().join("unopened")),
            0,
            0,
            "x".repeat(257),
        )
        .unwrap_err();
    assert_eq!(error.code, "ipc.input_too_large");
    assert!(!root.path().join("unopened").exists());
}
