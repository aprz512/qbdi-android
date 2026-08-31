use std::{
    collections::HashMap,
    hash::{BuildHasher, Hash},
    mem::{align_of, size_of},
};

use crate::{AllocationScope, OperationAbort, WorkGuard};

pub(crate) fn allocation_abort(error: OperationAbort) -> crate::ProviderError {
    error.into()
}

pub(crate) fn checked_array_bytes<T>(count: usize) -> Result<u64, crate::ProviderError> {
    count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| resource_error("allocation byte count overflow"))
}

pub(crate) fn try_reserve_vec_exact<T>(
    values: &mut Vec<T>,
    capacity: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<(), crate::ProviderError> {
    if capacity <= values.capacity() {
        return Ok(());
    }
    let bytes = checked_array_bytes::<T>(capacity)?;
    let _scope = AllocationScope::begin(guard, bytes, 0).map_err(allocation_abort)?;
    values
        .try_reserve_exact(capacity.saturating_sub(values.len()))
        .map_err(|_| resource_error(detail))
}

pub(crate) fn try_copy_bytes(
    bytes: &[u8],
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<Vec<u8>, crate::ProviderError> {
    let mut output = Vec::new();
    try_reserve_vec_exact(&mut output, bytes.len(), guard, detail)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

pub(crate) fn try_copy_string(
    value: &str,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<String, crate::ProviderError> {
    let bytes = u64::try_from(value.len()).map_err(|_| resource_error(detail))?;
    let _scope = AllocationScope::begin(guard, bytes, 0).map_err(allocation_abort)?;
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| resource_error(detail))?;
    output.push_str(value);
    Ok(output)
}

fn hash_table_layout<K, V>(required: usize) -> Result<(u64, u64), crate::ProviderError> {
    if required == 0 {
        return Ok((0, 0));
    }
    let buckets = if required < 4 {
        4
    } else if required < 8 {
        8
    } else {
        required
            .checked_mul(8)
            .and_then(|scaled| scaled.checked_add(6))
            .map(|scaled| scaled / 7)
            .and_then(usize::checked_next_power_of_two)
            .ok_or_else(|| resource_error("hash bucket count overflow"))?
    };
    let alignment_slack = align_of::<(K, V)>().saturating_sub(1);
    let bytes = buckets
        .checked_mul(size_of::<(K, V)>())
        .and_then(|bytes| bytes.checked_add(alignment_slack))
        .and_then(|bytes| bytes.checked_add(buckets))
        .and_then(|bytes| bytes.checked_add(16))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| resource_error("hash allocation size overflow"))?;
    Ok((bytes, alignment_slack as u64))
}

pub(crate) fn try_reserve_hash_map<K, V, S>(
    values: &mut HashMap<K, V, S>,
    additional: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<(), crate::ProviderError>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    if additional == 0 || values.capacity().saturating_sub(values.len()) >= additional {
        return Ok(());
    }
    let required = values
        .len()
        .checked_add(additional)
        .ok_or_else(|| resource_error("hash entry count overflow"))?;
    let (bytes, slack) = hash_table_layout::<K, V>(required)?;
    let _scope = AllocationScope::begin(guard, bytes, slack).map_err(allocation_abort)?;
    values
        .try_reserve(additional)
        .map_err(|_| resource_error(detail))
}

fn resource_error(detail: &'static str) -> crate::ProviderError {
    crate::ProviderError::new(
        "control.resource_exhausted",
        "provider.allocation",
        None,
        false,
        detail,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{OperationAbort, WorkDelta};

    #[derive(Default)]
    struct CountingGuard(AtomicU64);

    impl WorkGuard for CountingGuard {
        fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
            self.0.fetch_add(delta.resident_bytes, Ordering::Relaxed);
            Ok(())
        }
    }

    fn vector_charge(count: usize) -> u64 {
        let guard = CountingGuard::default();
        let mut values = Vec::<u64>::new();
        try_reserve_vec_exact(&mut values, count, &guard, "test allocation").unwrap();
        guard.0.load(Ordering::Relaxed)
    }

    fn hash_charge(count: usize) -> u64 {
        let guard = CountingGuard::default();
        let mut values = HashMap::<u32, u64>::new();
        try_reserve_hash_map(&mut values, count, &guard, "test allocation").unwrap();
        guard.0.load(Ordering::Relaxed)
    }

    #[test]
    fn exact_and_hash_layout_work_scale_linearly_at_n_2n_4n() {
        let n = 1_024;
        let vector = [vector_charge(n), vector_charge(2 * n), vector_charge(4 * n)];
        assert_eq!(vector[1], vector[0] * 2);
        assert_eq!(vector[2], vector[0] * 4);

        let hash = [hash_charge(n), hash_charge(2 * n), hash_charge(4 * n)];
        assert!(hash[1] <= hash[0] * 2 + 32);
        assert!(hash[2] <= hash[0] * 4 + 96);
    }

    #[test]
    fn ten_million_sparse_shape_uses_checked_host_sized_layouts() {
        const ROWS: usize = 10_000_000;
        assert_eq!(checked_array_bytes::<u64>(ROWS).unwrap(), 80_000_000);
        let (map_bytes, alignment_slack) = hash_table_layout::<u32, u64>(ROWS).unwrap();
        assert!(map_bytes < 512 * 1024 * 1024);
        assert!(alignment_slack < std::mem::align_of::<(u32, u64)>() as u64);
    }
}
