use super::allocation;
use crate::{MAX_UNGUARDED_RECORDS, ProviderError, WorkDelta, WorkGuard};

/// Sort compact row numbers, then apply their permutation to the owned values.
/// Scratch space is two row numbers per value, independent of payload size.
pub(super) fn guarded_radix_sort<T, F>(
    mut values: Vec<T>,
    passes: usize,
    key_byte: F,
    guard: &dyn WorkGuard,
) -> Result<Vec<T>, ProviderError>
where
    F: Fn(&T, usize) -> Result<u8, ProviderError>,
{
    checkpoint(guard, 0)?;
    let length = values.len();
    if length < 2 {
        return Ok(values);
    }
    let mut order =
        allocation::try_vec_with_capacity(length, guard, "Flight sort order allocation failed")?;
    let mut scratch =
        allocation::try_vec_with_capacity(length, guard, "Flight sort scratch allocation failed")?;
    for index in 0..length {
        checkpoint(guard, index)?;
        order.push(index);
        scratch.push(0);
    }

    for pass in 0..passes {
        let mut counts = [0_usize; 256];
        for (index, source) in order.iter().copied().enumerate() {
            checkpoint(guard, index)?;
            counts[usize::from(key_byte(&values[source], pass)?)] += 1;
        }
        let mut positions = [0_usize; 256];
        for index in 1..256 {
            positions[index] = positions[index - 1] + counts[index - 1];
        }
        for (index, source) in order.iter().copied().enumerate() {
            checkpoint(guard, index)?;
            let bucket = usize::from(key_byte(&values[source], pass)?);
            scratch[positions[bucket]] = source;
            positions[bucket] += 1;
        }
        std::mem::swap(&mut order, &mut scratch);
    }
    drop(scratch);

    // order[destination] identifies its original source. Follow each cycle,
    // marking visited slots with the identity permutation. Share one work
    // counter across cycle traversal and the scan over already visited slots.
    let mut reorder_work = 0;
    for start in 0..length {
        checkpoint(guard, reorder_work)?;
        reorder_work += 1;
        let mut current = start;
        loop {
            let source = std::mem::replace(&mut order[current], current);
            if source == start {
                break;
            }
            checkpoint(guard, reorder_work)?;
            reorder_work += 1;
            values.swap(current, source);
            current = source;
        }
    }
    Ok(values)
}

fn checkpoint(guard: &dyn WorkGuard, index: usize) -> Result<(), ProviderError> {
    if index as u64 % MAX_UNGUARDED_RECORDS == 0 {
        guard.consume(WorkDelta::default())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BudgetDimension, OperationAbort};
    use proptest::prelude::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct ScratchBudget(AtomicUsize, usize);

    impl WorkGuard for ScratchBudget {
        fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
            let used = self
                .0
                .fetch_add(delta.resident_bytes as usize, Ordering::Relaxed)
                + delta.resident_bytes as usize;
            if used > self.1 {
                return Err(OperationAbort::budget_exceeded(
                    BudgetDimension::ResidentBytes,
                    self.1 as u64,
                    used as u64,
                ));
            }
            Ok(())
        }
    }

    proptest! {
        #[test]
        fn stable_order_matches_reference_with_bounded_scratch(
            keys in prop::collection::vec(prop_oneof![any::<u64>(), 0_u64..16], 0..1_000),
        ) {
            let values: Vec<_> = keys.into_iter().enumerate().map(|(index, key)| (key, index, [0; 256])).collect();
            let mut expected = values.clone();
            expected.sort_by_key(|value| value.0);
            let budget = ScratchBudget(AtomicUsize::new(0), 2 * values.len() * size_of::<usize>());
            let actual = guarded_radix_sort(values, 8, |value, pass| Ok(value.0.to_le_bytes()[pass]), &budget).unwrap();
            prop_assert_eq!(actual, expected);
        }
    }

    struct DropItem(u64, Arc<AtomicUsize>);

    impl Drop for DropItem {
        fn drop(&mut self) {
            self.1.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct CancelPermutation {
        key_reads: AtomicUsize,
        sorted_reads: usize,
        checkpoints: AtomicUsize,
    }

    impl WorkGuard for CancelPermutation {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            if self.key_reads.load(Ordering::Relaxed) == self.sorted_reads
                && self.checkpoints.fetch_add(1, Ordering::Relaxed) == 2
            {
                return Err(OperationAbort::Cancelled);
            }
            Ok(())
        }
    }

    #[test]
    fn a_long_permutation_cycle_can_cancel_and_drops_each_value_once() {
        let length = 8_193;
        let drops = Arc::new(AtomicUsize::new(0));
        let values = (0..length)
            .map(|index| DropItem(((index + 1) % length) as u64, drops.clone()))
            .collect();
        let guard = CancelPermutation {
            key_reads: AtomicUsize::new(0),
            sorted_reads: 2 * 8 * length,
            checkpoints: AtomicUsize::new(0),
        };
        let result = guarded_radix_sort(
            values,
            8,
            |value, pass| {
                guard.key_reads.fetch_add(1, Ordering::Relaxed);
                Ok(value.0.to_le_bytes()[pass])
            },
            &guard,
        );
        assert_eq!(result.err().unwrap().code(), "control.cancelled");
        assert_eq!(guard.checkpoints.load(Ordering::Relaxed), 3);
        assert_eq!(drops.load(Ordering::Relaxed), length);
    }
}
