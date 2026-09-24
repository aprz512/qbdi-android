use std::path::{Path, PathBuf};

use qtrace_service::{EventFilterDto, QtraceService};
use qtrace_store::AuthorizedPath;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures/sessions")
        .join(name)
}

#[test]
fn real_mixed_session_crosses_provider_store_analysis_and_persistent_annotations() {
    let data = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let service = QtraceService::with_cache_root(cache.path().join("indexes"));
    let opened = service
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    assert_eq!(opened.artifacts.len(), 3);
    let context = opened.context.as_ref().unwrap();
    assert_eq!(context.package.as_deref(), Some("com.example.fixture"));
    assert_eq!(context.device_serial.as_deref(), Some("fixture-device"));
    assert_eq!(context.device_access_mode.as_deref(), Some("run-as"));
    assert_eq!(context.target_module.as_deref(), Some("libtarget.so"));
    assert!(
        opened
            .missing_capabilities
            .contains(&"effective_config".to_owned())
    );
    assert!(
        opened
            .artifacts
            .iter()
            .all(|artifact| artifact.status == "indexed")
    );
    assert!(
        opened
            .artifacts
            .iter()
            .any(|artifact| !artifact.completeness.is_empty())
    );
    let artifact_tids = opened.artifacts[0].tids.clone();
    let workspace = opened.workspace.id;
    let projection = service
        .create_projection(&workspace, 0, EventFilterDto::default())
        .unwrap();
    let page = service
        .query_timeline(&workspace, &projection.projection_id, None, 2_000)
        .unwrap();
    assert!(page.rows.len() <= 2_000 && !page.rows.is_empty());
    let row = &page.rows[0];
    if let Some(tid) = row.key.tid {
        assert!(artifact_tids.contains(&tid));
    }
    let location = service
        .locate_timeline(&workspace, &projection.projection_id, row.source_row, 2_000)
        .unwrap()
        .expect("visible row location");
    assert_eq!(location.start, 0);
    assert!(location.cursor.is_none());
    let offset_location = service
        .locate_timeline_offset(&workspace, &projection.projection_id, 0, 2_000)
        .unwrap()
        .expect("visible offset location");
    assert_eq!(offset_location, location);
    service
        .get_event_detail(&workspace, 0, row.source_row)
        .unwrap();
    service
        .get_register_state(&workspace, 0, row.source_row)
        .unwrap();
    service
        .get_memory_state(&workspace, 0, row.source_row, 0, 1)
        .unwrap();
    service
        .upsert_annotation(
            &workspace,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
            "persistent".into(),
        )
        .unwrap();

    drop(service);
    assert!(
        cache
            .path()
            .join("indexes")
            .read_dir()
            .unwrap()
            .next()
            .is_some()
    );
    let restarted = QtraceService::with_cache_root(cache.path().join("indexes"));
    let reopened = restarted
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    let annotation = restarted
        .get_annotation(
            &reopened.workspace.id,
            AuthorizedPath::new(data.path().to_owned()),
            0,
            row.source_row,
        )
        .unwrap()
        .unwrap();
    assert_eq!(annotation.comment, "persistent");
}

#[test]
fn invalid_artifact_is_isolated_while_healthy_timelines_remain_queryable() {
    let service = QtraceService::new();
    let opened = service
        .open_session(AuthorizedPath::new(fixture("one-invalid-artifact")))
        .unwrap();
    assert!(!opened.warnings.is_empty());
    assert!(!opened.artifacts.is_empty());
    let projection = service
        .create_projection(&opened.workspace.id, 0, EventFilterDto::default())
        .unwrap();
    let page = service
        .query_timeline(&opened.workspace.id, &projection.projection_id, None, 32)
        .unwrap();
    assert!(!page.rows.is_empty());
}

#[test]
fn single_artifact_exposes_missing_session_context() {
    let service = QtraceService::new();
    let opened = service
        .open_artifact(AuthorizedPath::new(
            fixture("valid-mixed").join("artifacts/main.trace.bin"),
        ))
        .unwrap();
    assert!(opened.context.is_none());
    assert_eq!(
        opened.missing_capabilities,
        ["package", "device", "target", "effective_config"]
    );
    assert_eq!(opened.artifacts.len(), 1);
    assert_eq!(opened.artifacts[0].status, "indexed");
}
