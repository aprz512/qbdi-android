use qtrace_provider::{WorkDelta, WorkGuard};
use serde::{Deserialize, Serialize};

use super::IndexError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct IntervalEntry {
    pub start: u64,
    pub end_exclusive: u64,
    pub row: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct IntervalIndex {
    entries: Vec<IntervalEntry>,
    prefix_max_end: Vec<u64>,
    block_prefix_max_end: Vec<u64>,
    block_rows: usize,
}

impl IntervalIndex {
    pub(crate) fn overlap_count_bounded(
        &self,
        start: u64,
        end: u64,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<usize, IndexError> {
        if start > end {
            return Err(IndexError::invalid(
                "memory query is not a valid half-open range",
            ));
        }
        if start == end {
            return Ok(0);
        }
        let upper =
            super::guarded_partition_point(&self.entries, guard, |entry| entry.start < end)?;
        if upper == 0 {
            return Ok(0);
        }
        let first_block =
            super::guarded_partition_point(&self.block_prefix_max_end, guard, |maximum| {
                *maximum <= start
            })?;
        let mut first = first_block.saturating_mul(self.block_rows).min(upper);
        while first < upper {
            super::consume_row_work(guard, 1)?;
            if self.prefix_max_end[first] > start {
                break;
            }
            first += 1;
        }
        let mut count = 0_usize;
        for chunk in self.entries[first..upper].chunks(4096) {
            super::consume_row_work(guard, chunk.len())?;
            for entry in chunk {
                if entry.end_exclusive > start {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| IndexError::resource("memory result count overflow"))?;
                    if count > max_rows {
                        return Err(IndexError::resource(
                            "bounded memory result exceeds row limit",
                        ));
                    }
                }
            }
        }
        Ok(count)
    }

    pub(super) fn encoded_parts(&self) -> (&[IntervalEntry], &[u64], &[u64]) {
        (
            &self.entries,
            &self.prefix_max_end,
            &self.block_prefix_max_end,
        )
    }

    pub(super) fn from_encoded_parts(
        entries: Vec<IntervalEntry>,
        prefix_max_end: Vec<u64>,
        block_prefix_max_end: Vec<u64>,
        block_rows: usize,
    ) -> Self {
        Self {
            entries,
            prefix_max_end,
            block_prefix_max_end,
            block_rows,
        }
    }

    pub(super) fn block_rows(&self) -> usize {
        self.block_rows
    }

    pub(crate) fn build(
        mut entries: Vec<IntervalEntry>,
        block_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<Self, IndexError> {
        if block_rows == 0 || !block_rows.is_power_of_two() {
            return Err(IndexError::invalid(
                "interval block rows must be a non-zero power of two",
            ));
        }
        super::builder::cancellable_sort_by(&mut entries, guard, |left, right| {
            (left.start, left.end_exclusive, left.row).cmp(&(
                right.start,
                right.end_exclusive,
                right.row,
            ))
        })?;
        let mut prefix_max_end = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut prefix_max_end,
            entries.len(),
            guard,
            "interval prefix allocation",
        )?;
        let mut maximum = 0_u64;
        for (ordinal, entry) in entries.iter().enumerate() {
            if ordinal % 4096 == 0 {
                guard.consume(WorkDelta::default())?;
            }
            if entry.start >= entry.end_exclusive {
                return Err(IndexError::invalid(
                    "empty interval entered the overlap index",
                ));
            }
            maximum = maximum.max(entry.end_exclusive);
            prefix_max_end.push(maximum);
        }
        let blocks = entries.len().div_ceil(block_rows);
        let mut block_prefix_max_end = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut block_prefix_max_end,
            blocks,
            guard,
            "interval block allocation",
        )?;
        for block in 0..blocks {
            if block % 4096 == 0 {
                guard.consume(WorkDelta::default())?;
            }
            let end = ((block + 1) * block_rows).min(entries.len());
            block_prefix_max_end.push(prefix_max_end[end - 1]);
        }
        Ok(Self {
            entries,
            prefix_max_end,
            block_prefix_max_end,
            block_rows,
        })
    }

    pub(crate) fn overlaps(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        if start > end {
            return Err(IndexError::invalid(
                "memory query is not a valid half-open range",
            ));
        }
        if start == end {
            return Ok(Vec::new());
        }
        let upper = self.entries.partition_point(|entry| entry.start < end);
        if upper == 0 {
            return Ok(Vec::new());
        }
        let first_block = self
            .block_prefix_max_end
            .partition_point(|maximum| *maximum <= start);
        let mut first = first_block.saturating_mul(self.block_rows);
        if first > upper {
            first = upper;
        }
        while first < upper && self.prefix_max_end[first] <= start {
            first += 1;
        }
        let mut rows = self.entries[first..upper]
            .iter()
            .filter(|entry| entry.end_exclusive > start)
            .map(|entry| entry.row)
            .collect::<Vec<_>>();
        rows.sort_unstable();
        rows.dedup();
        Ok(rows)
    }

    pub(crate) fn overlaps_bounded(
        &self,
        start: u64,
        end: u64,
        max_rows: usize,
        guard: &dyn WorkGuard,
    ) -> Result<Vec<usize>, IndexError> {
        if start > end {
            return Err(IndexError::invalid(
                "memory query is not a valid half-open range",
            ));
        }
        if start == end {
            return Ok(Vec::new());
        }
        let upper =
            super::guarded_partition_point(&self.entries, guard, |entry| entry.start < end)?;
        if upper == 0 {
            return Ok(Vec::new());
        }
        let first_block =
            super::guarded_partition_point(&self.block_prefix_max_end, guard, |maximum| {
                *maximum <= start
            })?;
        let mut first = first_block.saturating_mul(self.block_rows).min(upper);
        while first < upper {
            super::consume_row_work(guard, 1)?;
            if self.prefix_max_end[first] > start {
                break;
            }
            first += 1;
        }
        let count = self.overlap_count_bounded(start, end, max_rows, guard)?;
        let mut rows = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut rows,
            count,
            guard,
            "bounded memory result allocation",
        )?;
        for chunk in self.entries[first..upper].chunks(4096) {
            super::consume_row_work(guard, chunk.len())?;
            for entry in chunk {
                if entry.end_exclusive > start {
                    rows.push(entry.row);
                }
            }
        }
        super::radix_sort_unique_rows(&mut rows, guard)?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use qtrace_provider::{BudgetDimension, OperationAbort};

    use super::*;

    struct RowBudget {
        limit: u64,
        consumed: AtomicU64,
    }

    impl WorkGuard for RowBudget {
        fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
            let next = self.consumed.fetch_add(delta.rows, Ordering::SeqCst) + delta.rows;
            if next > self.limit {
                return Err(OperationAbort::budget_exceeded(
                    BudgetDimension::Rows,
                    self.limit,
                    next,
                ));
            }
            Ok(())
        }
    }

    fn dense_reverse_rows(count: usize) -> IntervalIndex {
        let entries = (0..count)
            .map(|index| IntervalEntry {
                start: index as u64,
                end_exclusive: index as u64 + count as u64 + 1,
                row: count - index - 1,
            })
            .collect::<Vec<_>>();
        let prefix_max_end: Vec<u64> = entries
            .iter()
            .scan(0_u64, |maximum, entry| {
                *maximum = (*maximum).max(entry.end_exclusive);
                Some(*maximum)
            })
            .collect();
        let block_rows = 256;
        let block_prefix_max_end = prefix_max_end
            .chunks(block_rows)
            .map(|block| *block.last().expect("non-empty interval block"))
            .collect();
        IntervalIndex::from_encoded_parts(entries, prefix_max_end, block_prefix_max_end, block_rows)
    }

    fn measured_overlap_work(count: usize) -> u64 {
        let index = dense_reverse_rows(count);
        let guard = RowBudget {
            limit: u64::MAX,
            consumed: AtomicU64::new(0),
        };
        let rows = index
            .overlaps_bounded(0, count as u64, count, &guard)
            .expect("bounded overlap query");
        assert_eq!(rows, (0..count).collect::<Vec<_>>());
        guard.consumed.load(Ordering::SeqCst)
    }

    #[test]
    fn bounded_overlap_charges_real_linear_work_and_rejects_one_below_exact() {
        let probes = [8_192, 16_384, 32_768].map(measured_overlap_work);
        assert!(probes[0] > 8_192, "all production passes must charge work");
        assert!(probes[1] <= probes[0] * 2 + 64);
        assert!(probes[2] <= probes[1] * 2 + 64);

        let count = 8_192;
        let index = dense_reverse_rows(count);
        let guard = RowBudget {
            limit: probes[0] - 1,
            consumed: AtomicU64::new(0),
        };
        let error = index
            .overlaps_bounded(0, count as u64, count, &guard)
            .expect_err("one unit below exact work must fail");
        assert_eq!(error.code(), "control.budget_exceeded");
    }
}
