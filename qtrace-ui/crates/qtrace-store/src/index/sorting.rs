use qtrace_provider::{WorkDelta, WorkGuard};

use super::IndexError;

pub(super) fn cancellable_sort<T: Ord + Clone>(
    rows: &mut Vec<T>,
    guard: &dyn WorkGuard,
) -> Result<(), IndexError> {
    cancellable_sort_by(rows, guard, Ord::cmp)
}

pub(super) fn cancellable_sort_by<T: Clone>(
    rows: &mut Vec<T>,
    guard: &dyn WorkGuard,
    compare: impl Fn(&T, &T) -> std::cmp::Ordering + Copy,
) -> Result<(), IndexError> {
    const CHUNK: usize = 4096;
    for chunk in rows.chunks_mut(CHUNK) {
        guard.consume(WorkDelta::default())?;
        chunk.sort_unstable_by(compare);
    }
    if rows.len() <= CHUNK {
        return Ok(());
    }
    let mut scratch = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut scratch,
        rows.len(),
        guard,
        "merge-sort scratch allocation",
    )?;
    let mut width = CHUNK;
    while width < rows.len() {
        scratch.clear();
        for first in (0..rows.len()).step_by(width.saturating_mul(2)) {
            guard.consume(WorkDelta::default())?;
            let middle = first.saturating_add(width).min(rows.len());
            let end = middle.saturating_add(width).min(rows.len());
            let (mut left, mut right) = (first, middle);
            let mut output_since_checkpoint = 0_usize;
            while left < middle && right < end {
                if compare(&rows[left], &rows[right]).is_le() {
                    scratch.push(rows[left].clone());
                    left += 1;
                } else {
                    scratch.push(rows[right].clone());
                    right += 1;
                }
                output_since_checkpoint += 1;
                if output_since_checkpoint == 4096 {
                    guard.consume(WorkDelta::default())?;
                    output_since_checkpoint = 0;
                }
            }
            while left < middle {
                scratch.push(rows[left].clone());
                left += 1;
                output_since_checkpoint += 1;
                if output_since_checkpoint == 4096 {
                    guard.consume(WorkDelta::default())?;
                    output_since_checkpoint = 0;
                }
            }
            while right < end {
                scratch.push(rows[right].clone());
                right += 1;
                output_since_checkpoint += 1;
                if output_since_checkpoint == 4096 {
                    guard.consume(WorkDelta::default())?;
                    output_since_checkpoint = 0;
                }
            }
        }
        std::mem::swap(rows, &mut scratch);
        width = width.saturating_mul(2);
    }
    Ok(())
}
