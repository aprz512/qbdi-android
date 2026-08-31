use serde::{Deserialize, Serialize};

use super::IndexError;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PostingList {
    deltas: Vec<u64>,
}

impl PostingList {
    pub(crate) fn from_rows(rows: &[usize]) -> Result<Self, IndexError> {
        let mut deltas = Vec::new();
        deltas
            .try_reserve_exact(rows.len())
            .map_err(|_| IndexError::resource("posting-list allocation failed"))?;
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
            deltas.push(delta);
            previous = Some(row);
        }
        Ok(Self { deltas })
    }

    pub fn rows(&self) -> Result<Vec<usize>, IndexError> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.deltas.len())
            .map_err(|_| IndexError::resource("posting decode allocation failed"))?;
        let mut previous: Option<u64> = None;
        for delta in &self.deltas {
            if *delta == 0 {
                return Err(IndexError::corrupt("posting delta is zero"));
            }
            let row = match previous {
                None => delta
                    .checked_sub(1)
                    .ok_or_else(|| IndexError::corrupt("first posting delta underflow"))?,
                Some(previous) => previous
                    .checked_add(*delta)
                    .ok_or_else(|| IndexError::corrupt("posting delta overflow"))?,
            };
            rows.push(
                usize::try_from(row)
                    .map_err(|_| IndexError::corrupt("posting row does not fit usize"))?,
            );
            previous = Some(row);
        }
        Ok(rows)
    }

    pub(crate) fn validate(&self, event_count: usize) -> Result<(), IndexError> {
        if self.rows()?.iter().any(|row| *row >= event_count) {
            return Err(IndexError::corrupt(
                "posting row is outside the event table",
            ));
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
