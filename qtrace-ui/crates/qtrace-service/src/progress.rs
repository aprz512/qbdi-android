use std::{
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use qtrace_provider::{OperationAbort, WorkDelta, WorkGuard, WorkPhase};

use crate::{DecimalU64Dto, JobId, JobProgressDetailDto, JobRegistry, OpenStageDto};

/// Counts authorized work, without retaining per-event notifications or estimating an ETA.
pub(crate) struct OpenProgress {
    jobs: JobRegistry,
    job: JobId,
    bytes: AtomicU64,
    events: AtomicU64,
    rows: AtomicU64,
    state: Mutex<ProgressState>,
}

struct ProgressState {
    stage: OpenStageDto,
    artifact: Option<String>,
    published: Instant,
}

impl OpenProgress {
    pub fn new(jobs: JobRegistry, job: JobId) -> Self {
        let progress = Self {
            jobs,
            job,
            bytes: AtomicU64::new(0),
            events: AtomicU64::new(0),
            rows: AtomicU64::new(0),
            state: Mutex::new(ProgressState {
                stage: OpenStageDto::VerifySource,
                artifact: None,
                published: Instant::now(),
            }),
        };
        progress.flush();
        progress
    }

    pub fn artifact(&self, name: Option<&str>) {
        self.state.lock().unwrap().artifact = name.map(str::to_owned);
    }

    pub fn phase(&self, phase: WorkPhase) {
        let mut state = self.state.lock().unwrap();
        state.stage = match phase {
            WorkPhase::VerifySource => OpenStageDto::VerifySource,
            WorkPhase::OpenCache => OpenStageDto::OpenCache,
            WorkPhase::BuildIndex => OpenStageDto::BuildIndex,
            WorkPhase::PublishCache => OpenStageDto::PublishCache,
            WorkPhase::ReopenCache => OpenStageDto::ReopenCache,
            WorkPhase::PrepareAnalysis => OpenStageDto::PrepareAnalysis,
            WorkPhase::PublishWorkspace => OpenStageDto::PublishWorkspace,
        };
        self.bytes.store(0, Ordering::Relaxed);
        self.events.store(0, Ordering::Relaxed);
        self.rows.store(0, Ordering::Relaxed);
        self.publish(&mut state);
    }

    fn record(&self, delta: WorkDelta, publish: bool) {
        // Check time only after a work block. Allocation and cancellation polls are free.
        let bytes = delta.input_bytes;
        let boundary = |counter: &AtomicU64, increment: u64, block: u64| {
            if increment == 0 {
                return false;
            }
            let before = counter.fetch_add(increment, Ordering::Relaxed);
            before / block != before.saturating_add(increment) / block
        };
        let bytes_ready = boundary(&self.bytes, bytes, 1024 * 1024);
        let events_ready = boundary(&self.events, delta.events, 4096);
        let rows_ready = boundary(&self.rows, delta.rows, 4096);
        if publish && (bytes_ready || events_ready || rows_ready) {
            let mut state = self.state.lock().unwrap();
            if state.published.elapsed() >= Duration::from_millis(100) {
                self.publish(&mut state);
            }
        }
    }

    pub fn flush(&self) {
        self.publish(&mut self.state.lock().unwrap());
    }

    fn publish(&self, state: &mut ProgressState) {
        self.jobs.set_open_progress(
            &self.job,
            JobProgressDetailDto {
                stage: state.stage,
                artifact: state.artifact.clone(),
                processed_bytes: DecimalU64Dto::new(self.bytes.load(Ordering::Relaxed)),
                processed_events: DecimalU64Dto::new(self.events.load(Ordering::Relaxed)),
                processed_rows: DecimalU64Dto::new(self.rows.load(Ordering::Relaxed)),
            },
        );
        state.published = Instant::now();
    }
}

pub(crate) struct ProgressGuard<'a> {
    pub inner: &'a dyn WorkGuard,
    pub progress: &'a OpenProgress,
}

impl WorkGuard for ProgressGuard<'_> {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        self.inner.consume(delta)?;
        self.progress.record(delta, true);
        Ok(())
    }

    fn begin_phase(&self, phase: WorkPhase) {
        self.inner.begin_phase(phase);
        self.progress.phase(phase);
    }

    fn parallelism(&self) -> usize {
        self.inner.parallelism()
    }

    fn begin_allocation_scope(
        &self,
        delta: WorkDelta,
        allowed_slack: u64,
    ) -> Result<(), OperationAbort> {
        self.inner.begin_allocation_scope(delta, allowed_slack)?;
        // Only atomics may run between authorization and the caller's allocation.
        self.progress.record(delta, false);
        Ok(())
    }

    fn end_allocation_scope(&self) {
        self.inner.end_allocation_scope();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceBudget, ServiceLimits, WorkspaceId};

    #[test]
    fn allocation_authorization_never_publishes_an_allocating_notification() {
        let jobs = JobRegistry::default();
        let (job, _) = jobs.begin(WorkspaceId::from_u64(1), "open");
        let progress = OpenProgress::new(jobs.clone(), job.clone());
        progress.state.lock().unwrap().published = Instant::now() - Duration::from_secs(1);
        let budget = ServiceBudget::new(ServiceLimits::interactive());
        let guard = ProgressGuard {
            inner: &budget,
            progress: &progress,
        };
        guard
            .begin_allocation_scope(
                WorkDelta {
                    input_bytes: 1024 * 1024,
                    resident_bytes: 64,
                    ..WorkDelta::default()
                },
                0,
            )
            .unwrap();
        assert_eq!(
            jobs.get(&job)
                .unwrap()
                .progress
                .detail
                .unwrap()
                .processed_bytes
                .value(),
            0
        );
        guard.end_allocation_scope();
        progress.flush();
        assert_eq!(
            jobs.get(&job)
                .unwrap()
                .progress
                .detail
                .unwrap()
                .processed_bytes
                .value(),
            1024 * 1024
        );
    }

    #[test]
    fn progress_reports_stages_without_changing_artifact_totals_or_budget() {
        let jobs = JobRegistry::default();
        let (job, cancellation) = jobs.begin(WorkspaceId::from_u64(1), "open");
        jobs.set_progress(&job, 0, Some(2)).unwrap();
        let progress = OpenProgress::new(jobs.clone(), job.clone());
        let budget =
            ServiceBudget::with_cancellation(ServiceLimits::interactive(), cancellation.clone());
        let guard = ProgressGuard {
            inner: &budget,
            progress: &progress,
        };
        progress.artifact(Some("trace.qtrb"));
        guard.begin_phase(WorkPhase::BuildIndex);
        guard
            .consume(WorkDelta {
                input_bytes: 128,
                events: 3,
                ..WorkDelta::default()
            })
            .unwrap();
        progress.flush();
        let dto = jobs.get(&job).unwrap();
        assert_eq!(dto.progress.completed.value(), 0);
        assert_eq!(dto.progress.total.unwrap().value(), 2);
        let detail = dto.progress.detail.unwrap();
        assert_eq!(detail.stage, OpenStageDto::BuildIndex);
        assert_eq!(detail.artifact.as_deref(), Some("trace.qtrb"));
        assert_eq!(detail.processed_bytes.value(), 128);
        assert_eq!(detail.processed_events.value(), 3);
        guard.begin_phase(WorkPhase::ReopenCache);
        assert_eq!(
            jobs.get(&job)
                .unwrap()
                .progress
                .detail
                .unwrap()
                .processed_bytes
                .value(),
            0
        );
        guard.begin_phase(WorkPhase::PrepareAnalysis);
        guard
            .consume(WorkDelta {
                rows: 1024,
                ..WorkDelta::default()
            })
            .unwrap();
        progress.flush();
        assert_eq!(
            jobs.get(&job)
                .unwrap()
                .progress
                .detail
                .unwrap()
                .processed_rows
                .value(),
            1024
        );
        cancellation.cancel();
        assert!(matches!(
            guard.consume(WorkDelta::default()),
            Err(OperationAbort::Cancelled)
        ));
    }
}
