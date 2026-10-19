use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;

use qtrace_provider::{OperationAbort, WorkDelta, WorkGuard, WorkPhase};
use qtrace_store::{AuthorizedPath, BuildOptions, OpenPolicy, SessionLoader, TraceStore};

#[derive(Default)]
struct Progress {
    stages: Mutex<Vec<WorkPhase>>,
    cancel_at: Option<WorkPhase>,
    workers: usize,
}

impl WorkGuard for Progress {
    fn parallelism(&self) -> usize {
        self.workers.max(1)
    }
    fn begin_phase(&self, phase: WorkPhase) {
        self.stages.lock().unwrap().push(phase);
    }

    fn consume(&self, _: WorkDelta) -> Result<(), OperationAbort> {
        if self
            .cancel_at
            .is_some_and(|phase| self.stages.lock().unwrap().last() == Some(&phase))
        {
            Err(OperationAbort::Cancelled)
        } else {
            Ok(())
        }
    }
}

fn source_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures/sessions/valid-mixed/artifacts/main.trace.bin")
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn contains_cache(path: &std::path::Path) -> bool {
    path.read_dir().unwrap().any(|entry| {
        let path = entry.unwrap().path();
        path.file_name().unwrap() == "index.qtc" || (path.is_dir() && contains_cache(&path))
    })
}

#[test]
fn cold_and_warm_open_report_actual_stages() {
    let root = private_root();
    let progress = Progress {
        workers: 2,
        ..Progress::default()
    };
    let source = SessionLoader::open_artifact(
        AuthorizedPath::new(source_path()),
        OpenPolicy::cache_aware(),
        &progress,
    )
    .unwrap();
    let artifact = &source.artifacts()[0];
    TraceStore::open_or_build(root.path(), artifact, &BuildOptions::default(), &progress).unwrap();
    assert_eq!(
        *progress.stages.lock().unwrap(),
        [
            WorkPhase::VerifySource,
            WorkPhase::OpenCache,
            WorkPhase::BuildIndex,
            WorkPhase::PublishCache,
            WorkPhase::ReopenCache
        ]
    );
    progress.stages.lock().unwrap().clear();
    TraceStore::open_or_build(root.path(), artifact, &BuildOptions::default(), &progress).unwrap();
    assert_eq!(*progress.stages.lock().unwrap(), [WorkPhase::OpenCache]);
}

#[test]
fn cancelling_each_store_phase_preserves_transactional_publication() {
    for phase in [
        WorkPhase::OpenCache,
        WorkPhase::BuildIndex,
        WorkPhase::PublishCache,
        WorkPhase::ReopenCache,
    ] {
        let root = private_root();
        let progress = Progress {
            cancel_at: Some(phase),
            workers: 2,
            ..Progress::default()
        };
        let source = SessionLoader::open_artifact(
            AuthorizedPath::new(source_path()),
            OpenPolicy::cache_aware(),
            &progress,
        )
        .unwrap();
        let error = TraceStore::open_or_build(
            root.path(),
            &source.artifacts()[0],
            &BuildOptions::default(),
            &progress,
        )
        .unwrap_err();
        assert!(
            matches!(error.operation_abort(), Some(OperationAbort::Cancelled)),
            "{phase:?}: {error}"
        );
        assert!(
            !contains_cache(root.path()),
            "{phase:?} published a cache after cancellation"
        );
    }
}
