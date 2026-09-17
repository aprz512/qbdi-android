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
    assert!(
        opened
            .artifacts
            .iter()
            .any(|artifact| !artifact.completeness.is_empty())
    );
    let workspace = opened.workspace.id;
    let projection = service
        .create_projection(&workspace, 0, EventFilterDto::default())
        .unwrap();
    let page = service
        .query_timeline(&workspace, &projection.projection_id, None, 2_000)
        .unwrap();
    assert!(page.rows.len() <= 2_000 && !page.rows.is_empty());
    let row = &page.rows[0];
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
