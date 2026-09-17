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
    used: [AtomicU64; 6],
}
impl ServiceBudget {
    pub fn new(limits: ServiceLimits) -> Self {
        Self {
            limits,
            cancelled: AtomicBool::new(false),
            used: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release)
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}
impl WorkGuard for ServiceBudget {
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
