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
}
#[derive(Default)]
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
    pub fn record_completed(&self, workspace: WorkspaceId, kind: impl Into<String>) -> JobId {
        let id = JobId::from_u64(self.inner.next.fetch_add(1, Ordering::Relaxed) + 1);
        self.inner.jobs.lock().unwrap().insert(
            id.clone(),
            Entry {
                dto: JobDto {
                    id: id.clone(),
                    workspace_id: workspace,
                    kind: kind.into(),
                    state: JobState::Completed,
                    progress: JobProgressDto {
                        completed: DecimalU64Dto::new(1),
                        total: Some(DecimalU64Dto::new(1)),
                    },
                    error: None,
                },
                cancel: JobCancellation::default(),
            },
        );
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
        entry.dto.progress = JobProgressDto {
            completed: DecimalU64Dto::new(bounded),
            total: total.map(DecimalU64Dto::new),
        };
        Ok(())
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
