use qtrace_service::{CallTreePageQuery, EventFilterDto, JobState, QtraceService, WorkspaceId};
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
    assert!(
        service
            .list_jobs()
            .iter()
            .all(|job| job.workspace_id != workspace)
    );
    let error = service.workspace_summary(&workspace).unwrap_err();
    assert_eq!(error.code, "workspace.stale");
    assert!(
        service
            .workspace_summary(&WorkspaceId::from_u64(999))
            .is_err()
    );
}

#[test]
fn projection_retention_is_bounded_and_keeps_the_current_generation() {
    let service = QtraceService::new();
    let opened = service
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    let mut first = None;
    let mut latest = None;
    for tid in 0..20 {
        let filter = EventFilterDto {
            tids: vec![tid],
            ..EventFilterDto::default()
        };
        let projection = service
            .create_projection(&opened.workspace.id, 0, filter)
            .unwrap();
        first.get_or_insert_with(|| projection.projection_id.clone());
        latest = Some(projection.projection_id);
    }
    let first_error = service
        .query_timeline(&opened.workspace.id, &first.unwrap(), None, 1)
        .unwrap_err();
    assert_eq!(first_error.code, "workspace.stale");
    service
        .query_timeline(&opened.workspace.id, &latest.unwrap(), None, 1)
        .unwrap();
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

#[test]
fn call_tree_pages_preserve_identity_and_reject_stale_or_invalid_parents() {
    let service = QtraceService::new();
    let opened = service
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    let workspace = opened.workspace.id;
    let projection = service
        .create_projection(&workspace, 0, EventFilterDto::default())
        .unwrap();
    let row = service
        .query_timeline(&workspace, &projection.projection_id, None, 1)
        .unwrap()
        .rows
        .remove(0);
    let tid = row.key.tid.unwrap();
    let timeline = row.key.timeline_id.value();
    let roots = service
        .get_call_tree(&workspace, 0, timeline, tid, CallTreePageQuery::default())
        .unwrap();
    assert_eq!(roots.parent, None);
    assert_eq!(roots.offset, 0);
    assert!(roots.nodes.len() <= 100);
    assert!(roots.nodes.len() <= roots.total as usize);
    let same = service
        .get_call_tree(
            &workspace,
            0,
            timeline,
            tid,
            CallTreePageQuery {
                expected_identity: Some(roots.identity.clone()),
                ..CallTreePageQuery::default()
            },
        )
        .unwrap();
    assert_eq!(same, roots);
    let stale = service
        .get_call_tree(
            &workspace,
            0,
            timeline,
            tid,
            CallTreePageQuery {
                expected_identity: Some("wrong".into()),
                ..CallTreePageQuery::default()
            },
        )
        .unwrap_err();
    assert_eq!(stale.code, "call_tree.stale");
    let invalid = service
        .get_call_tree(
            &workspace,
            0,
            timeline,
            tid,
            CallTreePageQuery {
                parent: Some(u32::MAX),
                expected_identity: Some(roots.identity.clone()),
                ..CallTreePageQuery::default()
            },
        )
        .unwrap_err();
    assert_eq!(invalid.code, "call_tree.parent_invalid");
    let missing_identity = service
        .get_call_tree(
            &workspace,
            0,
            timeline,
            tid,
            CallTreePageQuery {
                offset: 1,
                ..CallTreePageQuery::default()
            },
        )
        .unwrap_err();
    assert_eq!(missing_identity.code, "call_tree.identity_required");
    let other = service
        .get_call_tree(
            &workspace,
            0,
            timeline,
            tid + 1,
            CallTreePageQuery::default(),
        )
        .unwrap();
    assert_ne!(other.identity, roots.identity);
    let previous = service
        .get_call_tree(
            &workspace,
            0,
            timeline,
            tid,
            CallTreePageQuery {
                expected_identity: Some(roots.identity.clone()),
                ..CallTreePageQuery::default()
            },
        )
        .unwrap_err();
    assert_eq!(previous.code, "call_tree.stale");
    service.close_workspace(&workspace).unwrap();
    assert_eq!(
        service
            .get_call_tree(&workspace, 0, timeline, tid, CallTreePageQuery::default())
            .unwrap_err()
            .code,
        "workspace.stale"
    );
}

#[tokio::test]
async fn async_projection_returns_an_observable_job_before_querying() {
    let service = std::sync::Arc::new(QtraceService::new());
    let opened = service
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    let projection = service
        .clone()
        .create_projection_task(opened.workspace.id.clone(), 0, EventFilterDto::default())
        .await
        .unwrap();
    assert!(
        service
            .list_jobs()
            .iter()
            .any(|job| job.id == projection.job_id)
    );
    loop {
        let job = service
            .list_jobs()
            .into_iter()
            .find(|job| job.id == projection.job_id)
            .unwrap();
        match job.state {
            JobState::Completed => break,
            JobState::Queued | JobState::Running => tokio::task::yield_now().await,
            JobState::Cancelled | JobState::Failed => panic!("projection job did not complete"),
        }
    }
    service
        .query_timeline(&opened.workspace.id, &projection.projection_id, None, 10)
        .unwrap();
}

#[tokio::test]
async fn async_semantic_projection_honors_job_cancellation() {
    let service = std::sync::Arc::new(QtraceService::new());
    let opened = service
        .open_session(AuthorizedPath::new(fixture("valid-mixed")))
        .unwrap();
    let projection = service
        .clone()
        .create_projection_task(
            opened.workspace.id.clone(),
            0,
            EventFilterDto {
                semantic_detail_contains: vec!["never-match".into()],
                ..EventFilterDto::default()
            },
        )
        .await
        .unwrap();
    service.cancel_job(&projection.job_id).unwrap();
    loop {
        let job = service
            .list_jobs()
            .into_iter()
            .find(|job| job.id == projection.job_id)
            .unwrap();
        match job.state {
            JobState::Cancelled => break,
            JobState::Queued | JobState::Running => tokio::task::yield_now().await,
            JobState::Completed | JobState::Failed => {
                panic!("cancelled projection job reached {:?}", job.state)
            }
        }
    }
}
