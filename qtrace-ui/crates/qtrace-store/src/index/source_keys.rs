use qtrace_provider::{EventKey, WorkDelta, WorkGuard};
use serde::{Deserialize, Serialize};

use super::{IndexError, compare_event_keys, sorting::cancellable_sort_by};

/// Sorted source-key positions. Monotonic event tables need no row allocation.
/// The wire representation remains the existing sequence of u64 row numbers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum SourceKeyIndex {
    Identity(usize),
    Permutation(Vec<usize>),
}

impl SourceKeyIndex {
    pub(super) fn build(keys: &[EventKey], guard: &dyn WorkGuard) -> Result<Self, IndexError> {
        let mut monotonic = true;
        for (index, pair) in keys.windows(2).enumerate() {
            checkpoint(guard, index)?;
            match compare_event_keys(&pair[0], &pair[1]) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(IndexError::duplicate_key("duplicate source EventKey"));
                }
                std::cmp::Ordering::Greater => monotonic = false,
            }
        }
        guard.consume(WorkDelta::default())?;
        if monotonic {
            return Ok(Self::Identity(keys.len()));
        }
        let mut rows = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut rows,
            keys.len(),
            guard,
            "source-key index allocation",
        )?;
        append_identity(&mut rows, keys.len(), guard)?;
        cancellable_sort_by(&mut rows, guard, |left, right| {
            compare_event_keys(&keys[*left], &keys[*right])
        })?;
        for (index, pair) in rows.windows(2).enumerate() {
            checkpoint(guard, index)?;
            if compare_event_keys(&keys[pair[0]], &keys[pair[1]]).is_eq() {
                return Err(IndexError::duplicate_key("duplicate source EventKey"));
            }
        }
        Ok(Self::Permutation(rows))
    }

    pub(super) fn read(
        count: usize,
        mut row_at: impl FnMut(usize) -> Result<usize, IndexError>,
        guard: &dyn WorkGuard,
    ) -> Result<Self, IndexError> {
        let mut permutation = None;
        for position in 0..count {
            checkpoint(guard, position)?;
            let row = row_at(position)?;
            if row >= count {
                return Err(IndexError::corrupt("source row outside keys"));
            }
            if row != position && permutation.is_none() {
                let mut rows = Vec::new();
                crate::allocation::try_reserve_vec(&mut rows, count, guard, "source rows")?;
                append_identity(&mut rows, position, guard)?;
                permutation = Some(rows);
            }
            if let Some(rows) = &mut permutation {
                rows.push(row);
            }
        }
        guard.consume(WorkDelta::default())?;
        Ok(permutation.map_or(Self::Identity(count), Self::Permutation))
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Identity(count) => *count,
            Self::Permutation(rows) => rows.len(),
        }
    }

    pub(super) fn row(&self, position: usize) -> Option<usize> {
        match self {
            Self::Identity(count) => (position < *count).then_some(position),
            Self::Permutation(rows) => rows.get(position).copied(),
        }
    }

    pub(super) fn rows(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        (0..self.len()).map(|position| self.row(position).expect("source-key position in range"))
    }

    pub(super) fn find(
        &self,
        key: &EventKey,
        key_at: impl Fn(usize) -> Result<EventKey, IndexError>,
    ) -> Option<usize> {
        let (mut left, mut right) = (0, self.len());
        while left < right {
            let middle = left + (right - left) / 2;
            let row = self.row(middle)?;
            match compare_event_keys(&key_at(row).ok()?, key) {
                std::cmp::Ordering::Less => left = middle + 1,
                std::cmp::Ordering::Greater => right = middle,
                std::cmp::Ordering::Equal => return Some(row),
            }
        }
        None
    }
}

fn append_identity(
    rows: &mut Vec<usize>,
    count: usize,
    guard: &dyn WorkGuard,
) -> Result<(), IndexError> {
    for start in (0..count).step_by(4096) {
        guard.consume(WorkDelta::default())?;
        rows.extend(start..start.saturating_add(4096).min(count));
    }
    Ok(())
}

fn checkpoint(guard: &dyn WorkGuard, index: usize) -> Result<(), IndexError> {
    if index % 4096 == 0 {
        guard.consume(WorkDelta::default())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use qtrace_provider::{ArtifactDigest, BudgetDimension, OperationAbort, TimelineId};

    use super::*;

    struct NoAllocation;

    impl WorkGuard for NoAllocation {
        fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
            if delta.resident_bytes == 0 {
                Ok(())
            } else {
                Err(OperationAbort::budget_exceeded(
                    BudgetDimension::ResidentBytes,
                    0,
                    delta.resident_bytes,
                ))
            }
        }
    }

    struct AllowAll;

    impl WorkGuard for AllowAll {
        fn consume(&self, _: WorkDelta) -> Result<(), OperationAbort> {
            Ok(())
        }
    }

    fn key(ordinal: u64) -> EventKey {
        EventKey::new(
            ArtifactDigest::new([0x11; 32]),
            TimelineId(1),
            ordinal,
            ordinal * 8,
            None,
            None,
        )
    }

    #[test]
    fn monotonic_keys_and_existing_wire_rows_need_no_row_allocation() {
        let keys = (0..10_000).map(key).collect::<Vec<_>>();
        let built = SourceKeyIndex::build(&keys, &NoAllocation).unwrap();
        let reopened = SourceKeyIndex::read(keys.len(), Ok, &NoAllocation).unwrap();
        assert_eq!(built, reopened);
        assert_eq!(
            built.rows().collect::<Vec<_>>(),
            (0..keys.len()).collect::<Vec<_>>()
        );
        assert_eq!(built.row(keys.len()), None);
    }

    #[test]
    fn nonmonotonic_keys_keep_an_explicit_sorted_permutation() {
        let keys = [key(3), key(1), key(2)];
        let index = SourceKeyIndex::build(&keys, &AllowAll).unwrap();
        assert_eq!(index.rows().collect::<Vec<_>>(), [1, 2, 0]);
        let reopened =
            SourceKeyIndex::read(3, |position| Ok([1, 2, 0][position]), &AllowAll).unwrap();
        assert_eq!(index, reopened);
        assert!(
            SourceKeyIndex::build(&keys, &NoAllocation)
                .unwrap_err()
                .operation_abort()
                .is_some()
        );
    }

    #[test]
    fn adjacent_and_nonadjacent_duplicate_source_keys_are_rejected() {
        for keys in [[key(1), key(1), key(2)], [key(1), key(2), key(1)]] {
            assert_eq!(
                SourceKeyIndex::build(&keys, &AllowAll).unwrap_err().code(),
                "index.duplicate_source_key"
            );
        }
    }

    #[test]
    fn a_late_wire_deviation_requests_its_entire_allocation_before_filling() {
        let error = SourceKeyIndex::read(
            10_000,
            |position| Ok(if position == 9_999 { 9_998 } else { position }),
            &NoAllocation,
        )
        .unwrap_err();
        assert!(error.operation_abort().is_some());
        let error = SourceKeyIndex::read(
            3,
            |position| Ok(if position == 2 { 3 } else { position }),
            &AllowAll,
        )
        .unwrap_err();
        assert_eq!(error.code(), "cache.normalized_corrupt");
    }

    #[test]
    fn implicit_paths_check_cancellation_without_allocating() {
        struct CancelAfter(AtomicUsize);
        impl WorkGuard for CancelAfter {
            fn consume(&self, _: WorkDelta) -> Result<(), OperationAbort> {
                if self.0.fetch_add(1, Ordering::Relaxed) >= 1 {
                    Err(OperationAbort::Cancelled)
                } else {
                    Ok(())
                }
            }
        }
        let keys = (0..10_000).map(key).collect::<Vec<_>>();
        let build_error =
            SourceKeyIndex::build(&keys, &CancelAfter(AtomicUsize::new(0))).unwrap_err();
        assert_eq!(
            build_error.operation_abort(),
            Some(&OperationAbort::Cancelled)
        );
        let read_error =
            SourceKeyIndex::read(keys.len(), Ok, &CancelAfter(AtomicUsize::new(0))).unwrap_err();
        assert_eq!(
            read_error.operation_abort(),
            Some(&OperationAbort::Cancelled)
        );
    }
}
