use serde::{Deserialize, Serialize};

use qtrace_provider::WorkGuard;

use super::IndexError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct DeltaRun {
    pub(super) delta: u64,
    pub(super) count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PostingList {
    runs: Vec<DeltaRun>,
    row_count: usize,
}

impl PostingList {
    pub(super) fn runs(&self) -> &[DeltaRun] {
        &self.runs
    }

    pub(super) const fn row_count(&self) -> usize {
        self.row_count
    }

    pub(super) fn from_runs(runs: Vec<DeltaRun>) -> Result<Self, IndexError> {
        let mut row_count = 0usize;
        for (index, run) in runs.iter().enumerate() {
            if run.delta == 0 || run.count == 0 {
                return Err(IndexError::corrupt("posting run contains zero"));
            }
            if index > 0 && runs[index - 1].delta == run.delta {
                return Err(IndexError::corrupt("posting runs are not canonical"));
            }
            row_count = row_count
                .checked_add(
                    usize::try_from(run.count)
                        .map_err(|_| IndexError::corrupt("posting run count does not fit usize"))?,
                )
                .ok_or_else(|| IndexError::corrupt("posting row count overflow"))?;
        }
        Ok(Self { runs, row_count })
    }

    pub(crate) fn from_rows(rows: &[usize], guard: &dyn WorkGuard) -> Result<Self, IndexError> {
        let mut runs = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut runs,
            rows.len().min(1024),
            guard,
            "posting-run allocation",
        )?;
        let mut previous: Option<u64> = None;
        for row in rows {
            let row = u64::try_from(*row)
                .map_err(|_| IndexError::invalid("posting row does not fit u64"))?;
            let delta = match previous {
                None => row
                    .checked_add(1)
                    .ok_or_else(|| IndexError::invalid("first posting delta overflow"))?,
                Some(previous) if row > previous => row - previous,
                Some(_) => {
                    return Err(IndexError::invalid(
                        "posting rows must be strictly increasing",
                    ));
                }
            };
            if let Some(run) = runs.last_mut() {
                let run: &mut DeltaRun = run;
                if run.delta == delta {
                    run.count = run
                        .count
                        .checked_add(1)
                        .ok_or_else(|| IndexError::resource("posting run overflow"))?;
                    previous = Some(row);
                    continue;
                }
            }
            crate::allocation::try_reserve_vec(&mut runs, 1, guard, "posting-run allocation")?;
            runs.push(DeltaRun { delta, count: 1 });
            previous = Some(row);
        }
        Ok(Self {
            runs,
            row_count: rows.len(),
        })
    }

    pub fn rows(&self) -> Result<Vec<usize>, IndexError> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.row_count)
            .map_err(|_| IndexError::resource("posting decode allocation failed"))?;
        self.visit_deltas(|delta| {
            let row = match rows.last().copied() {
                None => delta
                    .checked_sub(1)
                    .ok_or_else(|| IndexError::corrupt("first posting delta underflow"))?,
                Some(previous) => (previous as u64)
                    .checked_add(delta)
                    .ok_or_else(|| IndexError::corrupt("posting delta overflow"))?,
            };
            rows.push(
                usize::try_from(row)
                    .map_err(|_| IndexError::corrupt("posting row does not fit usize"))?,
            );
            Ok(())
        })?;
        Ok(rows)
    }

    pub(super) fn visit_deltas(
        &self,
        mut visit: impl FnMut(u64) -> Result<(), IndexError>,
    ) -> Result<(), IndexError> {
        for run in &self.runs {
            for _ in 0..run.count {
                visit(run.delta)?;
            }
        }
        Ok(())
    }
}

pub fn union_rows(lists: &[Vec<usize>]) -> Vec<usize> {
    let mut output = lists.iter().flatten().copied().collect::<Vec<_>>();
    output.sort_unstable();
    output.dedup();
    output
}

pub fn intersect_rows(left: &[usize], right: &[usize]) -> Vec<usize> {
    let mut output = Vec::new();
    let mut left_index = 0;
    let mut right_index = 0;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => {
                output.push(left[left_index]);
                left_index += 1;
                right_index += 1;
            }
        }
    }
    output
}
