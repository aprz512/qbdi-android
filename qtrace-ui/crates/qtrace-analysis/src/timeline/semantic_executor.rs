//! Bounded semantic jobs own worker startup, panic isolation, queue rejection and shutdown.

use std::{
    sync::{
        Arc, Mutex, OnceLock,
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
};

use super::AnalysisError;

const SEMANTIC_WORKERS: usize = 4;
const MAX_PENDING_SEMANTIC_JOBS: usize = 32;

pub(super) struct SemanticJob {
    run: Option<Box<dyn FnOnce() + Send + 'static>>,
    on_failure: Option<Box<dyn FnOnce(AnalysisError) + Send + 'static>>,
}

impl SemanticJob {
    pub(super) fn new(
        run: impl FnOnce() + Send + 'static,
        on_failure: impl FnOnce(AnalysisError) + Send + 'static,
    ) -> Self {
        Self {
            run: Some(Box::new(run)),
            on_failure: Some(Box::new(on_failure)),
        }
    }

    #[cfg(test)]
    fn plain(run: impl FnOnce() + Send + 'static) -> Self {
        Self::new(run, |_| {})
    }

    fn execute(mut self) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run.take().expect("semantic job is run once")();
        }));
        if result.is_err()
            && let Some(on_failure) = self.on_failure.take()
        {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                on_failure(AnalysisError::worker_panicked());
            }));
        }
    }

    fn fail(mut self, error: AnalysisError) {
        if let Some(on_failure) = self.on_failure.take() {
            on_failure(error);
        }
    }
}

pub(super) struct SemanticExecutor {
    sender: Option<SyncSender<SemanticJob>>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl SemanticExecutor {
    fn new(workers: usize, queue_capacity: usize) -> Result<Self, AnalysisError> {
        let (sender, receiver) = mpsc::sync_channel::<SemanticJob>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut handles = Vec::new();
        handles.try_reserve_exact(workers).map_err(|_| {
            AnalysisError::resource_exhausted("semantic worker handle allocation failed")
        })?;
        for worker in 0..workers {
            let receiver = receiver.clone();
            match thread::Builder::new()
                .name(format!("qtrace-semantic-{worker}"))
                .spawn(move || {
                    loop {
                        let job = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        match job {
                            Ok(job) => job.execute(),
                            Err(_) => break,
                        }
                    }
                }) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    drop(sender);
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(AnalysisError::resource_exhausted(format!(
                        "semantic executor thread creation failed: {error}"
                    )));
                }
            }
        }
        Ok(Self {
            sender: Some(sender),
            workers: handles,
        })
    }

    pub(super) fn global() -> Result<&'static Self, AnalysisError> {
        static EXECUTOR: OnceLock<Result<SemanticExecutor, AnalysisError>> = OnceLock::new();
        match EXECUTOR.get_or_init(|| Self::new(SEMANTIC_WORKERS, MAX_PENDING_SEMANTIC_JOBS)) {
            Ok(executor) => Ok(executor),
            Err(error) => Err(error.clone()),
        }
    }

    pub(super) fn submit(&self, job: SemanticJob) -> Result<(), AnalysisError> {
        let Some(sender) = &self.sender else {
            let error = AnalysisError::resource_exhausted("semantic executor is shut down");
            job.fail(error.clone());
            return Err(error);
        };
        sender.try_send(job).map_err(|error| match error {
            TrySendError::Full(_) => {
                AnalysisError::resource_exhausted("semantic executor queue is full")
            }
            TrySendError::Disconnected(job) => {
                let analysis_error =
                    AnalysisError::resource_exhausted("semantic executor is unavailable");
                job.fail(analysis_error.clone());
                analysis_error
            }
        })
    }

    #[cfg(test)]
    fn shutdown(mut self) -> Result<(), AnalysisError> {
        self.join_workers()
    }

    fn join_workers(&mut self) -> Result<(), AnalysisError> {
        self.sender.take();
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                return Err(AnalysisError::worker_panicked());
            }
        }
        Ok(())
    }
}

impl Drop for SemanticExecutor {
    fn drop(&mut self) {
        let _ = self.join_workers();
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Condvar, time::Duration};

    use super::super::{ProjectionState, ProjectionTerminalizer, terminalize_projection};
    use super::*;

    #[derive(Default)]
    struct WorkerState {
        active: usize,
        max_active: usize,
        completed: usize,
        released: bool,
    }

    #[test]
    fn semantic_executor_caps_workers_and_queue_without_timing_assumptions() {
        let executor = SemanticExecutor::new(2, 4).unwrap();
        let state = Arc::new((Mutex::new(WorkerState::default()), Condvar::new()));
        let job = || {
            let state = state.clone();
            SemanticJob::plain(move || {
                let mut guard = state.0.lock().unwrap();
                guard.active += 1;
                guard.max_active = guard.max_active.max(guard.active);
                state.1.notify_all();
                while !guard.released {
                    guard = state.1.wait(guard).unwrap();
                }
                guard.active -= 1;
                guard.completed += 1;
                state.1.notify_all();
            })
        };

        executor.submit(job()).unwrap();
        executor.submit(job()).unwrap();
        let guard = state.0.lock().unwrap();
        let (guard, result) = state
            .1
            .wait_timeout_while(guard, Duration::from_secs(2), |state| state.active < 2)
            .unwrap();
        assert!(!result.timed_out());
        drop(guard);
        for _ in 0..4 {
            executor.submit(job()).unwrap();
        }
        assert_eq!(
            executor.submit(job()).unwrap_err().code(),
            "analysis.resource_exhausted"
        );
        let mut guard = state.0.lock().unwrap();
        guard.released = true;
        state.1.notify_all();
        let (guard, result) = state
            .1
            .wait_timeout_while(guard, Duration::from_secs(2), |state| state.completed < 6)
            .unwrap();
        assert!(!result.timed_out());
        assert_eq!(guard.max_active, 2);
    }

    #[test]
    fn semantic_executor_survives_a_panicking_job_and_joins_on_shutdown() {
        let executor = SemanticExecutor::new(1, 2).unwrap();
        let projection = Arc::new((Mutex::new(ProjectionState::default()), Condvar::new()));
        let failed = projection.clone();
        let running = projection.clone();
        executor
            .submit(SemanticJob::new(
                move || {
                    let _terminal = ProjectionTerminalizer::new(running);
                    panic!("deterministic worker panic");
                },
                move |error| terminalize_projection(&failed, false, Some(error)),
            ))
            .unwrap();
        let state = projection.0.lock().unwrap();
        let (state, timeout) = projection
            .1
            .wait_timeout_while(state, Duration::from_millis(100), |state| !state.completed)
            .unwrap();
        assert!(!timeout.timed_out());
        assert_eq!(
            state.error.as_ref().unwrap().code(),
            "analysis.worker_panicked"
        );
        drop(state);
        let completed = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = completed.clone();
        executor
            .submit(SemanticJob::plain(move || {
                *signal.0.lock().unwrap() = true;
                signal.1.notify_all();
            }))
            .unwrap();
        let done = completed.0.lock().unwrap();
        let (done, timeout) = completed
            .1
            .wait_timeout_while(done, Duration::from_millis(100), |done| !*done)
            .unwrap();
        assert!(!timeout.timed_out() && *done, "worker retired after panic");
        drop(done);
        executor.shutdown().unwrap();
    }

    #[test]
    fn disconnected_executor_terminalizes_the_rejected_job() {
        let executor = SemanticExecutor {
            sender: None,
            workers: Vec::new(),
        };
        let failure = Arc::new(Mutex::new(None));
        let observed = failure.clone();
        let error = executor
            .submit(SemanticJob::new(
                || panic!("disconnected jobs must not run"),
                move |error| *observed.lock().unwrap() = Some(error),
            ))
            .unwrap_err();
        assert_eq!(error.code(), "analysis.resource_exhausted");
        assert_eq!(
            failure.lock().unwrap().as_ref().unwrap().code(),
            "analysis.resource_exhausted"
        );
    }
}
