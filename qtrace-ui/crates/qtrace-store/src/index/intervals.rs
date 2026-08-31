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
        prefix_max_end
            .try_reserve_exact(entries.len())
            .map_err(|_| IndexError::resource("interval prefix allocation failed"))?;
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
        block_prefix_max_end
            .try_reserve_exact(blocks)
            .map_err(|_| IndexError::resource("interval block allocation failed"))?;
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
}
