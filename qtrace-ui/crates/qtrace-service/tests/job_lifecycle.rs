use std::time::{Duration, Instant};

use qtrace_provider::{BudgetDimension, WorkDelta, WorkGuard};
use qtrace_service::{JobRegistry, JobState, ServiceBudget, ServiceLimits, WorkspaceId};

#[test]
fn every_budget_dimension_and_deadline_is_enforced_monotonically() {
    let limits = ServiceLimits {
        deadline: Instant::now() + Duration::from_secs(30),
        input_bytes: 1,
        decompressed_bytes: 2,
        events: 3,
        nodes: 4,
        rows: 5,
        resident_bytes: 6,
    };
    for (delta, dimension) in [
        (
            WorkDelta {
                input_bytes: 2,
                ..Default::default()
            },
            BudgetDimension::InputBytes,
        ),
        (
            WorkDelta {
                decompressed_bytes: 3,
                ..Default::default()
            },
            BudgetDimension::DecompressedBytes,
        ),
        (
            WorkDelta {
                events: 4,
                ..Default::default()
            },
            BudgetDimension::Events,
        ),
        (
            WorkDelta {
                nodes: 5,
                ..Default::default()
            },
            BudgetDimension::Nodes,
        ),
        (
            WorkDelta {
                rows: 6,
                ..Default::default()
            },
            BudgetDimension::Rows,
        ),
        (
            WorkDelta {
                resident_bytes: 7,
                ..Default::default()
            },
            BudgetDimension::ResidentBytes,
        ),
    ] {
        let budget = ServiceBudget::new(limits);
        let error = budget.consume(delta).unwrap_err();
        assert!(
            matches!(error, qtrace_provider::OperationAbort::BudgetExceeded { dimension: actual, .. } if actual == dimension)
        );
    }
    let expired = ServiceBudget::new(ServiceLimits {
        deadline: Instant::now() - Duration::from_millis(1),
        ..limits
    });
    assert_eq!(
        expired.consume(WorkDelta::default()).unwrap_err(),
        qtrace_provider::OperationAbort::Cancelled
    );
}

#[tokio::test]
async fn jobs_publish_terminal_state_and_workspace_cancel_is_scoped() {
    let jobs = JobRegistry::default();
    let first_workspace = WorkspaceId::from_u64(1);
    let second_workspace = WorkspaceId::from_u64(2);
    let first = jobs.spawn(first_workspace.clone(), "index", |guard| async move {
        while !guard.is_cancelled() {
            tokio::task::yield_now().await;
        }
        Err(qtrace_service::AppError::cancelled())
    });
    let second = jobs.spawn(second_workspace, "index", |_guard| async move { Ok(()) });
    jobs.cancel_workspace(&first_workspace);
    jobs.wait(first.clone()).await.unwrap();
    jobs.wait(second.clone()).await.unwrap();
    assert_eq!(jobs.get(&first).unwrap().state, JobState::Cancelled);
    assert_eq!(jobs.get(&second).unwrap().state, JobState::Completed);
}

#[tokio::test]
async fn worker_panic_is_contained_and_progress_is_bounded() {
    let jobs = JobRegistry::default();
    let workspace = WorkspaceId::from_u64(3);
    let job = jobs.spawn(workspace, "panic", |_guard| async move {
        panic!("private panic detail")
    });
    jobs.set_progress(&job, 20, Some(10)).unwrap();
    jobs.wait(job.clone()).await.unwrap();
    let dto = jobs.get(&job).unwrap();
    assert_eq!(dto.state, JobState::Failed);
    assert_eq!(dto.progress.completed.value(), 10);
    let error = dto.error.unwrap();
    assert_eq!(error.code, "internal.worker_failed");
    assert!(!error.detail.contains("private"));
}

#[test]
fn terminal_job_pruning_uses_numeric_age() {
    let jobs = JobRegistry::default();
    let workspace = WorkspaceId::from_u64(4);
    for _ in 0..110 {
        jobs.record_completed(workspace.clone(), "test");
    }
    jobs.prune_terminal(8);
    let retained = jobs.list();
    assert_eq!(retained.len(), 8);
    assert!(retained.iter().any(|job| job.id.as_str() == "103"));
    assert!(retained.iter().any(|job| job.id.as_str() == "110"));
}
