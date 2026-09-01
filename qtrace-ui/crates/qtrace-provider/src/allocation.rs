use std::{
    collections::HashMap,
    hash::{BuildHasher, Hash},
    mem::{align_of, size_of},
};

use crate::{AllocationScope, OperationAbort, WorkGuard};

#[derive(Clone, Copy)]
pub(crate) struct AllocationErrorContext {
    code: &'static str,
    stage: &'static str,
}

impl AllocationErrorContext {
    pub(crate) const fn new(code: &'static str, stage: &'static str) -> Self {
        Self { code, stage }
    }

    fn error(self, detail: &'static str) -> crate::ProviderError {
        crate::ProviderError::new(self.code, self.stage, None, false, detail)
    }
}

pub(crate) const PROVIDER_ALLOCATION: AllocationErrorContext =
    AllocationErrorContext::new("control.resource_exhausted", "provider.allocation");
pub(crate) const FLIGHT_OPEN_ALLOCATION: AllocationErrorContext =
    AllocationErrorContext::new("source.flight.resource", "flight.open");
pub(crate) const FLIGHT_RECOVERY_ALLOCATION: AllocationErrorContext =
    AllocationErrorContext::new("source.flight.resource", "flight.recovery");

pub(crate) fn allocation_abort(error: OperationAbort) -> crate::ProviderError {
    error.into()
}

fn checked_array_bytes_in<T>(
    count: usize,
    error_context: AllocationErrorContext,
) -> Result<u64, crate::ProviderError> {
    count
        .checked_mul(size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| error_context.error("allocation byte count overflow"))
}

fn checked_vec_capacity_in<T>(
    count: usize,
    error_context: AllocationErrorContext,
) -> Result<usize, crate::ProviderError> {
    checked_array_bytes_in::<T>(count, error_context)?;
    Ok(count)
}

pub fn checked_geometric_capacity(
    current: usize,
    required: usize,
    minimum: usize,
) -> Result<usize, crate::ProviderError> {
    checked_geometric_capacity_in(current, required, minimum, PROVIDER_ALLOCATION)
}

pub(crate) fn checked_geometric_capacity_in(
    current: usize,
    required: usize,
    minimum: usize,
    error_context: AllocationErrorContext,
) -> Result<usize, crate::ProviderError> {
    current
        .checked_mul(2)
        .map(|doubled| required.max(minimum.max(doubled)))
        .ok_or_else(|| error_context.error("vector capacity overflow"))
}

pub(crate) fn try_reserve_vec_exact<T>(
    values: &mut Vec<T>,
    capacity: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<(), crate::ProviderError> {
    try_reserve_vec_exact_in(values, capacity, guard, detail, PROVIDER_ALLOCATION)
}

pub(crate) fn try_reserve_vec_exact_in<T>(
    values: &mut Vec<T>,
    capacity: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
    error_context: AllocationErrorContext,
) -> Result<(), crate::ProviderError> {
    if capacity <= values.capacity() {
        return Ok(());
    }
    let capacity = checked_vec_capacity_in::<T>(capacity, error_context)?;
    let bytes = checked_array_bytes_in::<T>(capacity, error_context)?;
    let _scope = AllocationScope::begin(guard, bytes, 0).map_err(allocation_abort)?;
    values
        .try_reserve_exact(capacity.saturating_sub(values.len()))
        .map_err(|_| error_context.error(detail))
}

pub(crate) fn try_vec_with_capacity_in<T>(
    capacity: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
    error_context: AllocationErrorContext,
) -> Result<Vec<T>, crate::ProviderError> {
    let mut output = Vec::new();
    try_reserve_vec_exact_in(&mut output, capacity, guard, detail, error_context)?;
    Ok(output)
}

pub(crate) fn try_push_vec_in<T>(
    output: &mut Vec<T>,
    value: T,
    guard: &dyn WorkGuard,
    detail: &'static str,
    error_context: AllocationErrorContext,
) -> Result<(), crate::ProviderError> {
    if output.len() == output.capacity() {
        let required = output
            .len()
            .checked_add(1)
            .ok_or_else(|| error_context.error("vector length overflow"))?;
        let capacity =
            checked_geometric_capacity_in(output.capacity(), required, 4, error_context)?;
        try_reserve_vec_exact_in(output, capacity, guard, detail, error_context)?;
    }
    output.push(value);
    Ok(())
}

pub(crate) fn try_copy_bytes(
    bytes: &[u8],
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<Vec<u8>, crate::ProviderError> {
    try_copy_bytes_in(bytes, guard, detail, PROVIDER_ALLOCATION)
}

pub(crate) fn try_copy_bytes_in(
    bytes: &[u8],
    guard: &dyn WorkGuard,
    detail: &'static str,
    error_context: AllocationErrorContext,
) -> Result<Vec<u8>, crate::ProviderError> {
    let mut output = Vec::new();
    try_reserve_vec_exact_in(&mut output, bytes.len(), guard, detail, error_context)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

pub(crate) fn try_copy_string(
    value: &str,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<String, crate::ProviderError> {
    try_copy_string_in(value, guard, detail, PROVIDER_ALLOCATION)
}

pub(crate) fn try_copy_string_in(
    value: &str,
    guard: &dyn WorkGuard,
    detail: &'static str,
    error_context: AllocationErrorContext,
) -> Result<String, crate::ProviderError> {
    let bytes = u64::try_from(value.len()).map_err(|_| error_context.error(detail))?;
    let _scope = AllocationScope::begin(guard, bytes, 0).map_err(allocation_abort)?;
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| error_context.error(detail))?;
    output.push_str(value);
    Ok(output)
}

fn hash_table_layout_in<K, V>(
    required: usize,
    error_context: AllocationErrorContext,
) -> Result<(u64, u64), crate::ProviderError> {
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
            .ok_or_else(|| error_context.error("hash bucket count overflow"))?
    };
    let alignment_slack = align_of::<(K, V)>().saturating_sub(1);
    let bytes = buckets
        .checked_mul(size_of::<(K, V)>())
        .and_then(|bytes| bytes.checked_add(alignment_slack))
        .and_then(|bytes| bytes.checked_add(buckets))
        .and_then(|bytes| bytes.checked_add(16))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| error_context.error("hash allocation size overflow"))?;
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
    try_reserve_hash_map_in(values, additional, guard, detail, PROVIDER_ALLOCATION)
}

pub(crate) fn try_reserve_hash_map_in<K, V, S>(
    values: &mut HashMap<K, V, S>,
    additional: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
    error_context: AllocationErrorContext,
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
        .ok_or_else(|| error_context.error("hash entry count overflow"))?;
    let (bytes, slack) = hash_table_layout_in::<K, V>(required, error_context)?;
    let _scope = AllocationScope::begin(guard, bytes, slack).map_err(allocation_abort)?;
    values
        .try_reserve(additional)
        .map_err(|_| error_context.error(detail))
}

pub(crate) fn try_hash_map_with_capacity_in<K, V>(
    capacity: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
    error_context: AllocationErrorContext,
) -> Result<HashMap<K, V>, crate::ProviderError>
where
    K: Eq + Hash,
{
    let mut output = HashMap::new();
    try_reserve_hash_map_in(&mut output, capacity, guard, detail, error_context)?;
    Ok(output)
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
        assert_eq!(
            checked_array_bytes_in::<u64>(ROWS, PROVIDER_ALLOCATION).unwrap(),
            80_000_000
        );
        let (map_bytes, alignment_slack) =
            hash_table_layout_in::<u32, u64>(ROWS, PROVIDER_ALLOCATION).unwrap();
        assert!(map_bytes < 512 * 1024 * 1024);
        assert!(alignment_slack < std::mem::align_of::<(u32, u64)>() as u64);
    }

    #[test]
    fn production_push_planner_accepts_ten_million_and_uses_the_same_capacity() {
        const ROWS: usize = 10_000_000;
        assert_eq!(
            checked_vec_capacity_in::<u64>(ROWS, PROVIDER_ALLOCATION).unwrap(),
            ROWS
        );
        let terminal = checked_geometric_capacity(8_388_608, ROWS, 4).unwrap();
        assert_eq!(terminal, 16_777_216);
        assert!(terminal < ROWS * 2);

        for required in [8, 16, 32] {
            let mut capacity = 0;
            while capacity < required {
                capacity = checked_geometric_capacity(capacity, capacity + 1, 4).unwrap();
            }
            assert!(capacity < required * 2);
        }

        let guard = CountingGuard::default();
        let mut values =
            try_vec_with_capacity_in::<u64>(4, &guard, "test vector", PROVIDER_ALLOCATION).unwrap();
        values.extend(0_u64..4);
        try_push_vec_in(&mut values, 4, &guard, "test push", PROVIDER_ALLOCATION).unwrap();
        assert_eq!(
            values.capacity(),
            checked_geometric_capacity(4, 5, 4).unwrap()
        );
        assert_eq!(values, [0, 1, 2, 3, 4]);

        let map =
            try_hash_map_with_capacity_in::<u32, u64>(32, &guard, "test map", PROVIDER_ALLOCATION)
                .unwrap();
        assert!(map.capacity() >= 32);
    }

    #[test]
    fn geometric_overflow_preserves_flight_open_error_context() {
        let error = checked_geometric_capacity_in(
            usize::MAX,
            usize::MAX,
            4,
            AllocationErrorContext::new("source.flight.resource", "flight.open"),
        )
        .expect_err("overflow succeeded");
        assert_eq!(error.code(), "source.flight.resource");
        assert_eq!(error.stage(), "flight.open");
    }

    #[test]
    fn reserve_failure_preserves_flight_recovery_error_context() {
        let guard = CountingGuard::default();
        let error = try_vec_with_capacity_in::<u8>(
            usize::MAX,
            &guard,
            "Flight recovery allocation failed",
            AllocationErrorContext::new("source.flight.resource", "flight.recovery"),
        )
        .expect_err("impossible reserve succeeded");
        assert_eq!(error.code(), "source.flight.resource");
        assert_eq!(error.stage(), "flight.recovery");
    }
}
