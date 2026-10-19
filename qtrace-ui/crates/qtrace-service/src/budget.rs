use crate::JobCancellation;
use qtrace_provider::{BudgetDimension, OperationAbort, WorkDelta, WorkGuard};
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug)]
pub struct ServiceLimits {
    pub deadline: Instant,
    pub input_bytes: u64,
    pub decompressed_bytes: u64,
    pub events: u64,
    pub nodes: u64,
    pub rows: u64,
    pub resident_bytes: u64,
}
impl ServiceLimits {
    pub fn interactive() -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(5),
            input_bytes: u64::MAX,
            decompressed_bytes: u64::MAX,
            events: u64::MAX,
            nodes: 100_000,
            rows: 2_000,
            resident_bytes: 256 * 1024 * 1024,
        }
    }
}
pub struct ServiceBudget {
    limits: ServiceLimits,
    cancelled: AtomicBool,
    external_cancel: Option<JobCancellation>,
    used: [AtomicU64; 6],
    validation_workers: usize,
}
impl ServiceBudget {
    pub fn new(limits: ServiceLimits) -> Self {
        Self {
            limits,
            cancelled: AtomicBool::new(false),
            external_cancel: None,
            used: std::array::from_fn(|_| AtomicU64::new(0)),
            validation_workers: 1,
        }
    }
    pub fn with_cancellation(limits: ServiceLimits, external_cancel: JobCancellation) -> Self {
        Self {
            limits,
            cancelled: AtomicBool::new(false),
            external_cancel: Some(external_cancel),
            used: std::array::from_fn(|_| AtomicU64::new(0)),
            validation_workers: 1,
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release)
    }
    pub(crate) fn with_cache_validation_workers(mut self) -> Self {
        self.validation_workers = 2;
        self
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self
                .external_cancel
                .as_ref()
                .is_some_and(JobCancellation::is_cancelled)
    }
}
impl WorkGuard for ServiceBudget {
    fn parallelism(&self) -> usize {
        self.validation_workers
    }

    fn consume(&self, d: WorkDelta) -> Result<(), OperationAbort> {
        if self.is_cancelled() || Instant::now() > self.limits.deadline {
            return Err(OperationAbort::Cancelled);
        }
        let values = [
            d.input_bytes,
            d.decompressed_bytes,
            d.events,
            d.nodes,
            d.rows,
            d.resident_bytes,
        ];
        let limits = [
            self.limits.input_bytes,
            self.limits.decompressed_bytes,
            self.limits.events,
            self.limits.nodes,
            self.limits.rows,
            self.limits.resident_bytes,
        ];
        let dims = [
            BudgetDimension::InputBytes,
            BudgetDimension::DecompressedBytes,
            BudgetDimension::Events,
            BudgetDimension::Nodes,
            BudgetDimension::Rows,
            BudgetDimension::ResidentBytes,
        ];
        for i in 0..6 {
            let total = self.used[i]
                .fetch_add(values[i], Ordering::AcqRel)
                .saturating_add(values[i]);
            if total > limits[i] {
                return Err(OperationAbort::budget_exceeded(dims[i], limits[i], total));
            }
        }
        Ok(())
    }
}

/// Memory posting scans and sorts are internal work, not returned evidence rows.
/// Keep that work bounded by Nodes while reserving Rows for the response.
pub(crate) struct MemoryWorkGuard<'a>(pub(crate) &'a dyn WorkGuard);

impl MemoryWorkGuard<'_> {
    fn work(mut delta: WorkDelta) -> WorkDelta {
        delta.nodes = delta.nodes.saturating_add(delta.rows);
        delta.rows = 0;
        delta
    }
}

impl WorkGuard for MemoryWorkGuard<'_> {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        self.0.consume(Self::work(delta))
    }

    fn parallelism(&self) -> usize {
        self.0.parallelism()
    }

    fn begin_allocation_scope(
        &self,
        delta: WorkDelta,
        allowed_slack: u64,
    ) -> Result<(), OperationAbort> {
        self.0
            .begin_allocation_scope(Self::work(delta), allowed_slack)
    }

    fn end_allocation_scope(&self) {
        self.0.end_allocation_scope();
    }
}
