use crate::{AppError, DecimalU64Dto, JobDto, JobId, JobProgressDto, JobState, WorkspaceId};
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::Notify;
#[derive(Clone, Default)]
pub struct JobCancellation(Arc<AtomicBool>);
impl JobCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release)
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub(crate) fn token(&self) -> Arc<AtomicBool> {
        self.0.clone()
    }
}
#[derive(Clone, Default)]
pub struct JobRegistry {
    inner: Arc<Inner>,
}
#[derive(Default)]
struct Inner {
    next: AtomicU64,
    jobs: Mutex<HashMap<JobId, Entry>>,
    changed: Notify,
}
struct Entry {
    dto: JobDto,
    cancel: JobCancellation,
}

impl JobRegistry {
    pub(crate) fn begin_bounded(
        &self,
        workspace: WorkspaceId,
        kind: impl Into<String>,
    ) -> Result<(JobId, JobCancellation), AppError> {
        const MAX_ACTIVE: usize = 8;
        const MAX_RETAINED: usize = 512;
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| AppError::worker_failed())?;
        let active =
            |entry: &Entry| matches!(entry.dto.state, JobState::Queued | JobState::Running);
        if jobs.values().filter(|entry| active(entry)).count() >= MAX_ACTIVE {
            return Err(AppError::new(
                "control.too_many_jobs",
                "control",
                "at most 8 open/projection jobs may run concurrently",
            ));
        }
        while jobs.len() >= MAX_RETAINED {
            let oldest = jobs
                .iter()
                .filter(|(_, entry)| !active(entry))
                .min_by_key(|(id, _)| id.as_str().parse::<u64>().unwrap_or(u64::MAX))
                .map(|(id, _)| id.clone())
                .ok_or_else(|| {
                    AppError::new("control.too_many_jobs", "control", "job registry is full")
                })?;
            jobs.remove(&oldest);
        }
        let id = JobId::from_u64(self.inner.next.fetch_add(1, Ordering::Relaxed) + 1);
        let cancel = JobCancellation::default();
        jobs.insert(
            id.clone(),
            Entry {
                dto: JobDto {
                    id: id.clone(),
                    workspace_id: workspace,
                    kind: kind.into(),
                    state: JobState::Running,
                    progress: JobProgressDto {
                        completed: DecimalU64Dto::new(0),
                        total: None,
                        detail: None,
                    },
                    error: None,
                },
                cancel: cancel.clone(),
            },
        );
        drop(jobs);
        self.inner.changed.notify_waiters();
        Ok((id, cancel))
    }

    pub(crate) fn begin(
        &self,
        workspace: WorkspaceId,
        kind: impl Into<String>,
    ) -> (JobId, JobCancellation) {
        let id = JobId::from_u64(self.inner.next.fetch_add(1, Ordering::Relaxed) + 1);
        let cancel = JobCancellation::default();
        self.inner.jobs.lock().unwrap().insert(
            id.clone(),
            Entry {
                dto: JobDto {
                    id: id.clone(),
                    workspace_id: workspace,
                    kind: kind.into(),
                    state: JobState::Queued,
                    progress: JobProgressDto {
                        completed: DecimalU64Dto::new(0),
                        total: None,
                        detail: None,
                    },
                    error: None,
                },
                cancel: cancel.clone(),
            },
        );
        self.inner.changed.notify_waiters();
        set_state(&self.inner, &id, JobState::Running, None);
        (id, cancel)
    }
    pub(crate) fn finish(&self, id: &JobId, result: Result<(), AppError>, cancelled: bool) {
        let (state, error) = match result {
            Ok(()) if cancelled => (JobState::Cancelled, None),
            Ok(()) => (JobState::Completed, None),
            Err(error) if error.code == "job.cancelled" => (JobState::Cancelled, Some(error)),
            Err(error) => (JobState::Failed, Some(error)),
        };
        set_state(&self.inner, id, state, error);
    }
    pub fn record_completed(&self, workspace: WorkspaceId, kind: impl Into<String>) -> JobId {
        let (id, cancel) = self.begin(workspace, kind);
        self.finish(&id, Ok(()), cancel.is_cancelled());
        id
    }
    pub fn spawn<F, Fut>(&self, workspace: WorkspaceId, kind: impl Into<String>, task: F) -> JobId
    where
        F: FnOnce(JobCancellation) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), AppError>> + Send + 'static,
    {
        let id = JobId::from_u64(self.inner.next.fetch_add(1, Ordering::Relaxed) + 1);
        let cancel = JobCancellation::default();
        self.inner.jobs.lock().unwrap().insert(
            id.clone(),
            Entry {
                dto: JobDto {
                    id: id.clone(),
                    workspace_id: workspace,
                    kind: kind.into(),
                    state: JobState::Queued,
                    progress: JobProgressDto {
                        completed: DecimalU64Dto::new(0),
                        total: None,
                        detail: None,
                    },
                    error: None,
                },
                cancel: cancel.clone(),
            },
        );
        let inner = self.inner.clone();
        let task_id = id.clone();
        tokio::spawn(async move {
            set_state(&inner, &task_id, JobState::Running, None);
            let joined = tokio::spawn(task(cancel.clone())).await;
            let (state, error) = match joined {
                Ok(Ok(())) if cancel.is_cancelled() => (JobState::Cancelled, None),
                Ok(Ok(())) => (JobState::Completed, None),
                Ok(Err(e)) if e.code == "job.cancelled" => (JobState::Cancelled, Some(e)),
                Ok(Err(e)) => (JobState::Failed, Some(e)),
                Err(_) => (JobState::Failed, Some(AppError::worker_failed())),
            };
            set_state(&inner, &task_id, state, error)
        });
        id
    }
    pub fn cancel_workspace(&self, w: &WorkspaceId) {
        for e in self.inner.jobs.lock().unwrap().values() {
            if &e.dto.workspace_id == w {
                e.cancel.cancel()
            }
        }
    }
    pub fn remove_workspace(&self, workspace: &WorkspaceId) {
        self.inner
            .jobs
            .lock()
            .unwrap()
            .retain(|_, entry| &entry.dto.workspace_id != workspace);
    }
    pub fn prune_workspace(&self, workspace: &WorkspaceId, keep: usize) {
        let mut jobs = self.inner.jobs.lock().unwrap();
        let mut terminal = jobs
            .iter()
            .filter(|(_, entry)| {
                &entry.dto.workspace_id == workspace
                    && matches!(
                        entry.dto.state,
                        JobState::Completed | JobState::Cancelled | JobState::Failed
                    )
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        terminal.sort_by_key(|id| id.as_str().parse::<u64>().unwrap_or(u64::MAX));
        let remove = terminal.len().saturating_sub(keep);
        for id in terminal.into_iter().take(remove) {
            jobs.remove(&id);
        }
    }
    pub fn prune_terminal(&self, keep: usize) {
        let mut jobs = self.inner.jobs.lock().unwrap();
        let mut terminal = jobs
            .iter()
            .filter(|(_, entry)| {
                matches!(
                    entry.dto.state,
                    JobState::Completed | JobState::Cancelled | JobState::Failed
                )
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        terminal.sort_by_key(|id| id.as_str().parse::<u64>().unwrap_or(u64::MAX));
        let remove = terminal.len().saturating_sub(keep);
        for id in terminal.into_iter().take(remove) {
            jobs.remove(&id);
        }
    }
    pub fn cancel_all(&self) {
        for entry in self.inner.jobs.lock().unwrap().values() {
            entry.cancel.cancel();
        }
    }
    pub fn get(&self, id: &JobId) -> Option<JobDto> {
        self.inner
            .jobs
            .lock()
            .unwrap()
            .get(id)
            .map(|e| e.dto.clone())
    }
    pub fn list(&self) -> Vec<JobDto> {
        self.inner
            .jobs
            .lock()
            .unwrap()
            .values()
            .map(|entry| entry.dto.clone())
            .collect()
    }
    pub fn cancel(&self, id: &JobId) -> Result<(), AppError> {
        let jobs = self.inner.jobs.lock().unwrap();
        let entry = jobs
            .get(id)
            .ok_or_else(|| AppError::new("job.stale", "job", "job not found"))?;
        entry.cancel.cancel();
        Ok(())
    }
    pub fn set_progress(
        &self,
        id: &JobId,
        completed: u64,
        total: Option<u64>,
    ) -> Result<(), AppError> {
        let mut jobs = self
            .inner
            .jobs
            .lock()
            .map_err(|_| AppError::worker_failed())?;
        let entry = jobs
            .get_mut(id)
            .ok_or_else(|| AppError::new("job.stale", "job", "job not found"))?;
        let bounded = total.map_or(completed, |value| completed.min(value));
        entry.dto.progress.completed = DecimalU64Dto::new(bounded);
        entry.dto.progress.total = total.map(DecimalU64Dto::new);
        Ok(())
    }

    pub(crate) fn set_open_progress(&self, id: &JobId, detail: crate::JobProgressDetailDto) {
        if let Ok(mut jobs) = self.inner.jobs.lock() {
            if let Some(entry) = jobs.get_mut(id) {
                if matches!(entry.dto.state, JobState::Queued | JobState::Running) {
                    entry.dto.progress.detail = Some(detail);
                }
            }
        }
    }
    pub async fn wait(&self, id: JobId) -> Result<(), AppError> {
        loop {
            let dto = self
                .get(&id)
                .ok_or_else(|| AppError::new("job.stale", "job", "job not found"))?;
            if matches!(
                dto.state,
                JobState::Completed | JobState::Cancelled | JobState::Failed
            ) {
                return Ok(());
            }
            self.inner.changed.notified().await
        }
    }
}
fn set_state(inner: &Inner, id: &JobId, state: JobState, error: Option<AppError>) {
    if let Some(e) = inner.jobs.lock().unwrap().get_mut(id) {
        e.dto.state = state;
        if state == JobState::Completed {
            let total = e
                .dto
                .progress
                .total
                .clone()
                .unwrap_or_else(|| DecimalU64Dto::new(1));
            e.dto.progress.completed = total.clone();
            e.dto.progress.total = Some(total);
        }
        e.dto.error = error
    }
    inner.changed.notify_waiters()
}

#[cfg(test)]
mod resource_tests {
    use super::*;

    #[test]
    fn bounded_jobs_reject_excess_active_work_and_reuse_finished_capacity() {
        let jobs = JobRegistry::default();
        let workspace = WorkspaceId::from_u64(1);
        let active = (0..8)
            .map(|_| jobs.begin_bounded(workspace.clone(), "open").unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            jobs.begin_bounded(workspace.clone(), "open")
                .err()
                .expect("active limit")
                .code,
            "control.too_many_jobs"
        );
        jobs.finish(&active[0].0, Ok(()), false);
        jobs.begin_bounded(workspace, "projection").unwrap();
    }

    #[test]
    fn bounded_retention_keeps_active_jobs_visible() {
        let jobs = JobRegistry::default();
        let workspace = WorkspaceId::from_u64(1);
        let (active, _) = jobs.begin_bounded(workspace.clone(), "open").unwrap();
        for _ in 0..600 {
            let (id, _) = jobs.begin_bounded(workspace.clone(), "projection").unwrap();
            jobs.finish(&id, Ok(()), false);
        }
        let retained = jobs.list();
        assert!(retained.len() <= 512);
        assert!(retained.iter().any(|job| job.id == active));
    }

    #[test]
    fn concurrent_admission_obeys_the_same_active_limit() {
        let jobs = JobRegistry::default();
        let successes = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..32 {
                let jobs = &jobs;
                let successes = &successes;
                scope.spawn(move || {
                    if jobs.begin_bounded(WorkspaceId::from_u64(1), "open").is_ok() {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(successes.load(Ordering::Relaxed), 8);
        assert_eq!(jobs.list().len(), 8);
    }
}
