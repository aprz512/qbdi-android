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
    pub(super) fn block_rows(&self) -> usize {
        self.block_rows
    }

    pub(crate) fn build(
        mut entries: Vec<IntervalEntry>,
        block_rows: usize,
    ) -> Result<Self, IndexError> {
        if block_rows == 0 || !block_rows.is_power_of_two() {
            return Err(IndexError::invalid(
                "interval block rows must be a non-zero power of two",
            ));
        }
        entries.sort_unstable_by_key(|entry| (entry.start, entry.end_exclusive, entry.row));
        let mut prefix_max_end = Vec::new();
        prefix_max_end
            .try_reserve_exact(entries.len())
            .map_err(|_| IndexError::resource("interval prefix allocation failed"))?;
        let mut maximum = 0_u64;
        for entry in &entries {
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

    pub(crate) fn validate(&self, event_count: usize) -> Result<(), IndexError> {
        if self.prefix_max_end.len() != self.entries.len()
            || self.block_rows == 0
            || !self.block_rows.is_power_of_two()
            || self.block_prefix_max_end.len() != self.entries.len().div_ceil(self.block_rows)
        {
            return Err(IndexError::corrupt("invalid interval augmentation shape"));
        }
        let rebuilt = Self::build(self.entries.clone(), self.block_rows)?;
        if rebuilt != *self || self.entries.iter().any(|entry| entry.row >= event_count) {
            return Err(IndexError::corrupt("invalid interval augmentation payload"));
        }
        Ok(())
    }
}
