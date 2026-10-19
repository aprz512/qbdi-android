//! Artifact preparation owns bounded workers; workspace publication remains atomic in service.
use crate::{
    AppError, JobId, JobRegistry, ipc, progress::OpenProgress, workspace::ArtifactWorkspace,
};
use qtrace_analysis::QueryContext;
use qtrace_provider::{OperationAbort, WorkDelta, WorkGuard, WorkPhase};
use qtrace_store::{ArtifactFormat, ArtifactSource, BuildOptions, TraceStore};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

pub(crate) struct OpenedArtifacts {
    pub artifacts: Vec<ArtifactWorkspace>,
    pub warnings: Vec<String>,
}

enum ArtifactOutcome {
    Indexed(ArtifactWorkspace),
    Rejected(String),
}

pub(crate) fn open_artifacts(
    cache_root: &Path,
    sources: &[ArtifactSource],
    source_guard: &dyn WorkGuard,
    cache_guard: &dyn WorkGuard,
    progress: &OpenProgress,
    jobs: &JobRegistry,
    job: &JobId,
) -> Result<OpenedArtifacts, AppError> {
    // All workers share the caller's cumulative source/cache budgets and cancellation.
    // Join before returning any error; a worker cannot outlive a failed open request.
    let mut opened = OpenedArtifacts {
        artifacts: Vec::new(),
        warnings: Vec::new(),
    };
    let total = sources.len() as u64;
    for (chunk_index, chunk) in sources.chunks(2).enumerate() {
        source_guard.consume(WorkDelta::default())?;
        progress.artifact(if chunk.len() == 1 {
            Some(chunk[0].local_path())
        } else {
            None
        });
        let outcomes = join_pair(chunk, |source| {
            prepare_artifact(cache_root, source, source_guard, cache_guard)
        })?;
        // Preserve report order and per-artifact rejection diagnostics independently of completion order.
        for outcome in outcomes {
            match outcome {
                ArtifactOutcome::Indexed(artifact) => opened.artifacts.push(artifact),
                ArtifactOutcome::Rejected(warning) => opened.warnings.push(warning),
            }
        }
        jobs.set_progress(
            job,
            ((chunk_index * 2 + chunk.len()) as u64).min(total),
            Some(total),
        )?;
    }
    Ok(opened)
}

fn join_pair<T: Sync, R: Send>(
    items: &[T],
    operation: impl Fn(&T) -> Result<R, AppError> + Sync,
) -> Result<Vec<R>, AppError> {
    join_pair_with_spawn_hook(items, operation, |_| Ok(()))
}

fn join_pair_with_spawn_hook<T: Sync, R: Send>(
    items: &[T],
    operation: impl Fn(&T) -> Result<R, AppError> + Sync,
    before_spawn: impl Fn(usize) -> std::io::Result<()>,
) -> Result<Vec<R>, AppError> {
    assert!(items.len() <= 2);
    if items.len() < 2 {
        return items.iter().map(operation).collect();
    }
    std::thread::scope(|scope| {
        let operation = &operation;
        let mut handles = Vec::new();
        let mut admission_error = None;
        for (index, item) in items.iter().enumerate() {
            match before_spawn(index).and_then(|()| {
                std::thread::Builder::new().spawn_scoped(scope, move || operation(item))
            }) {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    admission_error = Some(AppError::worker_failed());
                    break;
                }
            }
        }
        // Collect every join before propagating an error, including panics.
        let results = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| AppError::worker_failed())
                    .and_then(|value| value)
            })
            .collect::<Vec<_>>();
        if let Some(error) = admission_error {
            return Err(error);
        }
        results.into_iter().collect()
    })
}

fn prepare_artifact(
    cache_root: &Path,
    source: &ArtifactSource,
    source_guard: &dyn WorkGuard,
    cache_guard: &dyn WorkGuard,
) -> Result<ArtifactOutcome, AppError> {
    source_guard.consume(WorkDelta::default())?;
    let probe_adjusted = InputProbeAdjustedGuard::new(source_guard);
    let artifact_guard: &dyn WorkGuard = if matches!(source.format(), ArtifactFormat::QtrbLz4) {
        &probe_adjusted
    } else {
        source_guard
    };
    match TraceStore::open_or_build_with_guards(
        cache_root,
        source,
        &BuildOptions::default(),
        artifact_guard,
        cache_guard,
    ) {
        Ok(store) => {
            ipc::view_event_count(&store)?;
            let store = Arc::new(store);
            cache_guard.begin_phase(WorkPhase::PrepareAnalysis);
            let context = Arc::new(QueryContext::new_with_guard(store.clone(), cache_guard)?);
            Ok(ArtifactOutcome::Indexed(ArtifactWorkspace {
                name: source.local_path().to_owned(),
                store,
                context,
                register_replay: Arc::new(Mutex::new(None)),
            }))
        }
        Err(error) if error.code() == "job.cancelled" || error.code().starts_with("control.") => {
            Err(error.into())
        }
        Err(error) => Ok(ArtifactOutcome::Rejected(format!(
            "{}: {error}",
            source.local_path()
        ))),
    }
}

/// Removes LZ4's pre-authorized EOF probe from transport accounting. The source
/// budget separately includes compressed transport bytes and logical QTRB reads.
struct InputProbeAdjustedGuard<'a> {
    inner: &'a dyn WorkGuard,
    pending_probe: AtomicU64,
}

impl<'a> InputProbeAdjustedGuard<'a> {
    fn new(inner: &'a dyn WorkGuard) -> Self {
        Self {
            inner,
            pending_probe: AtomicU64::new(1),
        }
    }
}

impl WorkGuard for InputProbeAdjustedGuard<'_> {
    fn begin_phase(&self, phase: qtrace_provider::WorkPhase) {
        self.inner.begin_phase(phase);
    }

    fn consume(&self, mut delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.input_bytes != 0
            && self
                .pending_probe
                .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            delta.input_bytes -= 1;
        }
        self.inner.consume(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Barrier, atomic::AtomicBool};

    #[test]
    fn pair_workers_overlap_but_keep_input_order() {
        let barrier = Barrier::new(2);
        assert_eq!(
            join_pair(&[10, 20], |value| {
                barrier.wait();
                Ok(*value)
            })
            .unwrap(),
            [10, 20]
        );
    }

    #[test]
    fn failure_and_panic_join_the_other_worker_before_returning() {
        for panic in [false, true] {
            let barrier = Barrier::new(2);
            let completed = AtomicBool::new(false);
            let result = join_pair(&[0, 1], |value| {
                barrier.wait();
                if *value == 0 {
                    assert!(!panic, "injected worker panic");
                    return Err(AppError::cancelled());
                }
                completed.store(true, Ordering::Release);
                Ok(())
            });
            assert!(result.is_err());
            assert!(completed.load(Ordering::Acquire));
        }
    }

    #[test]
    fn single_artifact_needs_no_additional_thread() {
        let caller = std::thread::current().id();
        join_pair(&[1], |_| {
            assert_eq!(std::thread::current().id(), caller);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn spawn_failure_joins_already_started_work_and_returns_a_typed_error() {
        for failing_at in [0, 1] {
            let completed = AtomicBool::new(false);
            let result = join_pair_with_spawn_hook(
                &[0, 1],
                |_| {
                    completed.store(true, Ordering::Release);
                    Ok(())
                },
                |index| {
                    if index == failing_at {
                        Err(std::io::Error::other("injected spawn failure"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(result.unwrap_err().code, "internal.worker_failed");
            assert_eq!(completed.load(Ordering::Acquire), failing_at == 1);
        }
    }
}
