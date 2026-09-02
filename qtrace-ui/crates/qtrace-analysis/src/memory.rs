use std::{ops::Range, sync::Arc};

use qtrace_provider::{
    AllocationScope, CaptureBytes, EventKey, MemoryDirection, OperationAbort, Provenance,
    RangeBounds, RangeDomain, WorkDelta, WorkGuard,
};
use qtrace_store::{NormalizedBulkView, NormalizedPostingQuery};

use crate::AnalysisError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryEvidence {
    pub key: EventKey,
    pub tid: Option<u32>,
    pub direction: MemoryDirection,
    pub provenance: Provenance,
    pub address: u64,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteState {
    pub address: u64,
    pub value: Option<u8>,
    pub provenance: Provenance,
    pub evidence: Option<MemoryEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryStateAtEvent {
    pub key: EventKey,
    pub range: Range<u64>,
    pub observed: Vec<ByteState>,
    pub before: Vec<ByteState>,
    pub after: Vec<ByteState>,
    pub last_written: Vec<ByteState>,
}

pub struct MemoryAnalyzer {
    store: Arc<dyn NormalizedBulkView + Send + Sync>,
}

pub const MAX_MEMORY_STATE_BYTES: usize = 1024 * 1024;
pub const MAX_MEMORY_HISTORY_ROWS: usize = 10_000;

struct AllowStateWork;

impl WorkGuard for AllowStateWork {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

impl MemoryAnalyzer {
    pub fn new<T>(store: Arc<T>) -> Result<Self, AnalysisError>
    where
        T: NormalizedBulkView + Send + Sync + 'static,
    {
        Self::new_with_guard(store, &AllowStateWork)
    }

    pub fn from_arc(
        store: Arc<dyn NormalizedBulkView + Send + Sync>,
    ) -> Result<Self, AnalysisError> {
        Self::from_arc_with_guard(store, &AllowStateWork)
    }

    pub fn new_with_guard<T>(store: Arc<T>, guard: &dyn WorkGuard) -> Result<Self, AnalysisError>
    where
        T: NormalizedBulkView + Send + Sync + 'static,
    {
        Self::from_arc_with_guard(store, guard)
    }

    pub fn from_arc_with_guard(
        store: Arc<dyn NormalizedBulkView + Send + Sync>,
        guard: &dyn WorkGuard,
    ) -> Result<Self, AnalysisError> {
        guard
            .consume(WorkDelta {
                nodes: 1,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        Ok(Self { store })
    }

    pub fn state_at(
        &self,
        key: &EventKey,
        range: Range<u64>,
    ) -> Result<MemoryStateAtEvent, AnalysisError> {
        self.state_at_with_guard(key, range, &AllowStateWork)
    }

    pub fn state_at_with_guard(
        &self,
        key: &EventKey,
        range: Range<u64>,
        guard: &dyn WorkGuard,
    ) -> Result<MemoryStateAtEvent, AnalysisError> {
        if range.start > range.end {
            return Err(AnalysisError::state_invalid("memory range is reversed"));
        }
        let length_u64 = range.end - range.start;
        let length = usize::try_from(length_u64).map_err(|_| {
            AnalysisError::state_invalid("memory range length is not representable")
        })?;
        if length > MAX_MEMORY_STATE_BYTES {
            return Err(AnalysisError::state_hard_limit(
                "memory range exceeds 1 MiB",
            ));
        }
        let target = self
            .store
            .row_for_source_key(key)
            .ok_or_else(|| AnalysisError::state_invalid("event key is not in this trace"))?;
        let query = NormalizedPostingQuery::Memory {
            start: range.start,
            end_exclusive: range.end,
        };
        let estimate = self
            .store
            .bounded_row_estimate(query, MAX_MEMORY_HISTORY_ROWS, guard)
            .map_err(AnalysisError::state_store)?;
        enforce_history_limit(estimate.rows)?;
        let rows = self
            .store
            .bounded_rows(query, MAX_MEMORY_HISTORY_ROWS, guard)
            .map_err(AnalysisError::state_store)?;
        enforce_history_limit(rows.len())?;
        validate_history_rows(&rows, guard)?;
        let discontinuity_kinds = [qtrace_provider::EventKind::Discontinuity];
        let discontinuity_query = NormalizedPostingQuery::Kinds(&discontinuity_kinds);
        let discontinuity_estimate = self
            .store
            .bounded_row_estimate(discontinuity_query, MAX_MEMORY_HISTORY_ROWS, guard)
            .map_err(AnalysisError::state_store)?;
        enforce_history_limit(discontinuity_estimate.rows)?;
        let discontinuities = self
            .store
            .bounded_rows(discontinuity_query, MAX_MEMORY_HISTORY_ROWS, guard)
            .map_err(AnalysisError::state_store)?;
        enforce_history_limit(discontinuities.len())?;
        validate_history_rows(&discontinuities, guard)?;

        let mut observed = unknown_bytes(&range, guard)?;
        let mut before = unknown_bytes(&range, guard)?;
        let mut after = unknown_bytes(&range, guard)?;
        let mut last_written = unknown_bytes(&range, guard)?;
        let conflict_bytes = length
            .checked_mul(std::mem::size_of::<Option<MemoryEvidence>>())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| AnalysisError::state_hard_limit("memory conflict layout overflows"))?;
        let conflict_scope = AllocationScope::begin(guard, conflict_bytes, 0)
            .map_err(AnalysisError::state_budget)?;
        let mut unordered_cross_tid = Vec::new();
        unordered_cross_tid
            .try_reserve_exact(length)
            .map_err(|_| AnalysisError::state_hard_limit("memory conflict allocation failed"))?;
        for start in (0..length).step_by(4_096) {
            let end = start.saturating_add(4_096).min(length);
            guard
                .consume(WorkDelta {
                    nodes: (end - start) as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::state_budget)?;
            unordered_cross_tid.resize(end, None::<MemoryEvidence>);
        }
        drop(conflict_scope);

        if !self.store.capabilities().global_ordering {
            for chunk in rows.chunks(4_096) {
                guard
                    .consume(WorkDelta {
                        rows: chunk.len() as u64,
                        nodes: chunk.len() as u64,
                        ..WorkDelta::default()
                    })
                    .map_err(AnalysisError::state_budget)?;
                for &row_index in chunk {
                    let Some(row_key) = self
                        .store
                        .event_key(row_index)
                        .map_err(AnalysisError::state_store)?
                    else {
                        continue;
                    };
                    let Some(row) = self.store.memory(row_index) else {
                        continue;
                    };
                    if row_key.artifact == key.artifact
                        && row_key.timeline == key.timeline
                        && row_key.tid != key.tid
                        && matches!(
                            row.direction,
                            MemoryDirection::Write | MemoryDirection::ReadWrite
                        )
                    {
                        let evidence =
                            memory_evidence(self.store.as_ref(), row_index, row_key, row)?;
                        record_unordered_overlap(
                            &mut unordered_cross_tid,
                            &range,
                            &row,
                            &evidence,
                            guard,
                        )?;
                    }
                }
            }
        }

        let mut memory_index = 0_usize;
        let mut discontinuity_index = 0_usize;
        let mut target_seen = false;
        while memory_index < rows.len() || discontinuity_index < discontinuities.len() {
            let next_memory = rows.get(memory_index).copied().unwrap_or(usize::MAX);
            let next_discontinuity = discontinuities
                .get(discontinuity_index)
                .copied()
                .unwrap_or(usize::MAX);
            guard
                .consume(WorkDelta {
                    rows: 1,
                    nodes: 1,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::state_budget)?;
            if next_discontinuity < next_memory {
                discontinuity_index += 1;
                if next_discontinuity > target {
                    continue;
                }
                apply_temporal_discontinuity(
                    self.store.as_ref(),
                    next_discontinuity,
                    key,
                    &range,
                    &mut last_written,
                    guard,
                )?;
                continue;
            }
            memory_index += 1;
            let row_index = next_memory;
            if row_index == usize::MAX {
                continue;
            }
            let row_key = self
                .store
                .event_key(row_index)
                .map_err(AnalysisError::state_store)?
                .ok_or_else(|| AnalysisError::state_invalid("memory event has no key"))?;
            if row_key.artifact != key.artifact || row_key.timeline != key.timeline {
                continue;
            }
            let Some(row) = self.store.memory(row_index) else {
                continue;
            };
            if !self.store.capabilities().global_ordering && row_key.tid != key.tid {
                continue;
            }
            if row_index > target {
                continue;
            }
            let evidence = memory_evidence(self.store.as_ref(), row_index, row_key, row)?;
            if row_index < target
                && matches!(
                    row.direction,
                    MemoryDirection::Write | MemoryDirection::ReadWrite
                )
            {
                match capture_bytes(
                    self.store
                        .memory_after_bytes(row_index)
                        .map_err(AnalysisError::state_store)?,
                    guard,
                )? {
                    CaptureState::Captured(bytes) => overlay(
                        &mut last_written,
                        &range,
                        row.address,
                        capture_extent(&bytes, row.size),
                        Provenance::Derived,
                        &evidence,
                        guard,
                    )?,
                    CaptureState::Unavailable => mark_damaged(
                        &mut last_written,
                        &range,
                        row.address,
                        row.end_exclusive,
                        &evidence,
                        guard,
                    )?,
                    CaptureState::NotCaptured => {}
                }
                continue;
            }
            if row_index != target {
                continue;
            }
            target_seen = true;
            overlay_value(&mut observed, &range, &row, &evidence, guard)?;
            guarded_clone_from(&mut before, &last_written, guard)?;
            match capture_bytes(
                self.store
                    .memory_before_bytes(row_index)
                    .map_err(AnalysisError::state_store)?,
                guard,
            )? {
                CaptureState::Captured(bytes) => overlay(
                    &mut before,
                    &range,
                    row.address,
                    capture_extent(&bytes, row.size),
                    evidence.provenance,
                    &evidence,
                    guard,
                )?,
                CaptureState::Unavailable => mark_damaged(
                    &mut before,
                    &range,
                    row.address,
                    row.end_exclusive,
                    &evidence,
                    guard,
                )?,
                CaptureState::NotCaptured => {}
            }
            guarded_clone_from(&mut after, &before, guard)?;
            if matches!(
                row.direction,
                MemoryDirection::Write | MemoryDirection::ReadWrite
            ) {
                match capture_bytes(
                    self.store
                        .memory_after_bytes(row_index)
                        .map_err(AnalysisError::state_store)?,
                    guard,
                )? {
                    CaptureState::Captured(bytes) => overlay(
                        &mut after,
                        &range,
                        row.address,
                        capture_extent(&bytes, row.size),
                        evidence.provenance,
                        &evidence,
                        guard,
                    )?,
                    CaptureState::Unavailable => mark_damaged(
                        &mut after,
                        &range,
                        row.address,
                        row.end_exclusive,
                        &evidence,
                        guard,
                    )?,
                    CaptureState::NotCaptured => {}
                }
            }
        }
        if !target_seen {
            guarded_clone_from(&mut before, &last_written, guard)?;
            guarded_clone_from(&mut after, &before, guard)?;
        }
        apply_unordered_conflicts(
            &unordered_cross_tid,
            [&mut before, &mut after, &mut last_written],
            guard,
        )?;
        Ok(MemoryStateAtEvent {
            key: key.clone(),
            range,
            observed,
            before,
            after,
            last_written,
        })
    }

    pub fn history(
        &self,
        key: &EventKey,
        range: Range<u64>,
    ) -> Result<Vec<MemoryEvidence>, AnalysisError> {
        self.history_with_guard(key, range, &AllowStateWork)
    }

    pub fn history_with_guard(
        &self,
        key: &EventKey,
        range: Range<u64>,
        guard: &dyn WorkGuard,
    ) -> Result<Vec<MemoryEvidence>, AnalysisError> {
        if range.start > range.end || range.end - range.start > MAX_MEMORY_STATE_BYTES as u64 {
            return Err(AnalysisError::state_hard_limit(
                "memory history range exceeds 1 MiB",
            ));
        }
        let target = self
            .store
            .row_for_source_key(key)
            .ok_or_else(|| AnalysisError::state_invalid("event key is not in this trace"))?;
        let query = NormalizedPostingQuery::Memory {
            start: range.start,
            end_exclusive: range.end,
        };
        let estimate = self
            .store
            .bounded_row_estimate(query, MAX_MEMORY_HISTORY_ROWS, guard)
            .map_err(AnalysisError::state_store)?;
        enforce_history_limit(estimate.rows)?;
        let rows = self
            .store
            .bounded_rows(query, MAX_MEMORY_HISTORY_ROWS, guard)
            .map_err(AnalysisError::state_store)?;
        enforce_history_limit(rows.len())?;
        validate_history_rows(&rows, guard)?;
        let bytes = rows
            .len()
            .checked_mul(std::mem::size_of::<MemoryEvidence>())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| {
                AnalysisError::state_hard_limit("memory history allocation overflows")
            })?;
        let scope = AllocationScope::begin(guard, bytes, 0).map_err(AnalysisError::state_budget)?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(rows.len())
            .map_err(|_| AnalysisError::state_hard_limit("memory history allocation failed"))?;
        for chunk in rows.chunks(4_096) {
            guard
                .consume(WorkDelta {
                    rows: chunk.len() as u64,
                    nodes: chunk.len() as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::state_budget)?;
            for &row_index in chunk {
                if row_index > target {
                    continue;
                }
                let Some(row_key) = self
                    .store
                    .event_key(row_index)
                    .map_err(AnalysisError::state_store)?
                else {
                    continue;
                };
                if row_key.artifact != key.artifact || row_key.timeline != key.timeline {
                    continue;
                }
                let Some(row) = self.store.memory(row_index) else {
                    continue;
                };
                result.push(MemoryEvidence {
                    key: row_key.clone(),
                    tid: row_key.tid,
                    direction: row.direction,
                    provenance: self
                        .store
                        .provenance(row_index)
                        .map_err(AnalysisError::state_store)?
                        .unwrap_or(Provenance::Unknown),
                    address: row.address,
                    size: row.size,
                });
            }
        }
        drop(scope);
        Ok(result)
    }
}

fn enforce_history_limit(rows: usize) -> Result<(), AnalysisError> {
    if rows > MAX_MEMORY_HISTORY_ROWS {
        return Err(AnalysisError::state_hard_limit(
            "memory history exceeds 10,000 rows",
        ));
    }
    Ok(())
}

fn memory_evidence(
    store: &dyn NormalizedBulkView,
    row_index: usize,
    key: EventKey,
    row: qtrace_store::MemoryRow,
) -> Result<MemoryEvidence, AnalysisError> {
    Ok(MemoryEvidence {
        tid: key.tid,
        key,
        direction: row.direction,
        provenance: store
            .provenance(row_index)
            .map_err(AnalysisError::state_store)?
            .unwrap_or(Provenance::Unknown),
        address: row.address,
        size: row.size,
    })
}

fn apply_temporal_discontinuity(
    store: &dyn NormalizedBulkView,
    row: usize,
    target_key: &EventKey,
    query: &Range<u64>,
    last_written: &mut [ByteState],
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    let Some(key) = store.event_key(row).map_err(AnalysisError::state_store)? else {
        return Ok(());
    };
    if key.artifact != target_key.artifact
        || key.timeline != target_key.timeline
        || key.tid.is_some_and(|tid| Some(tid) != target_key.tid)
    {
        return Ok(());
    }
    let bytes = store
        .payload_bytes(row)
        .map_err(AnalysisError::state_store)?;
    for chunk in bytes.chunks(4_096) {
        guard
            .consume(WorkDelta {
                input_bytes: chunk.len() as u64,
                nodes: chunk.len() as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
    }
    let discontinuity = crate::timeline::decode_discontinuity_payload(bytes)?;
    let affected = match (
        discontinuity.evidence.domain(),
        discontinuity.evidence.bounds(),
    ) {
        (
            RangeDomain::MemoryAddresses,
            RangeBounds::HalfOpen {
                start,
                end_exclusive,
            },
        ) => start.max(query.start)..end_exclusive.min(query.end),
        (RangeDomain::CapturedSequence | RangeDomain::SourceBytes, _) => query.clone(),
        _ => return Ok(()),
    };
    for start in (affected.start..affected.end).step_by(4_096) {
        let end = start.saturating_add(4_096).min(affected.end);
        guard
            .consume(WorkDelta {
                nodes: end - start,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        for address in start..end {
            let cell = &mut last_written[(address - query.start) as usize];
            if key.tid.is_none()
                || cell
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.tid == key.tid)
                || cell.evidence.is_none()
            {
                cell.value = None;
                cell.provenance = Provenance::Damaged;
                cell.evidence = None;
            }
        }
    }
    Ok(())
}

fn guarded_clone_from(
    target: &mut [ByteState],
    source: &[ByteState],
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    for start in (0..target.len()).step_by(4_096) {
        let end = start.saturating_add(4_096).min(target.len());
        guard
            .consume(WorkDelta {
                nodes: (end - start) as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        target[start..end].clone_from_slice(&source[start..end]);
    }
    Ok(())
}

fn unknown_bytes(
    range: &Range<u64>,
    guard: &dyn WorkGuard,
) -> Result<Vec<ByteState>, AnalysisError> {
    let length = usize::try_from(range.end - range.start)
        .map_err(|_| AnalysisError::state_invalid("memory range length is not representable"))?;
    let bytes = length
        .checked_mul(std::mem::size_of::<ByteState>())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| AnalysisError::state_invalid("memory state allocation overflows"))?;
    let scope = AllocationScope::begin(guard, bytes, 0).map_err(AnalysisError::state_budget)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| AnalysisError::state_invalid("memory state allocation failed"))?;
    for start in (0..length).step_by(4_096) {
        let end = start.saturating_add(4_096).min(length);
        guard
            .consume(WorkDelta {
                nodes: (end - start) as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        result.extend((start..end).map(|offset| ByteState {
            address: range.start + offset as u64,
            value: None,
            provenance: Provenance::Unknown,
            evidence: None,
        }));
    }
    drop(scope);
    Ok(result)
}

enum CaptureState {
    NotCaptured,
    Unavailable,
    Captured(Vec<u8>),
}

fn capture_bytes(
    bytes: Option<&[u8]>,
    guard: &dyn WorkGuard,
) -> Result<CaptureState, AnalysisError> {
    let Some(bytes) = bytes else {
        return Ok(CaptureState::NotCaptured);
    };
    for chunk in bytes.chunks(4_096) {
        guard
            .consume(WorkDelta {
                input_bytes: chunk.len() as u64,
                nodes: chunk.len() as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
    }
    let scope = AllocationScope::begin(guard, bytes.len() as u64, 0)
        .map_err(AnalysisError::state_budget)?;
    let capture: CaptureBytes = serde_json::from_slice(bytes)
        .map_err(|_| AnalysisError::state_invalid("memory capture payload is malformed"))?;
    drop(scope);
    Ok(match capture {
        CaptureBytes::Captured(bytes) => CaptureState::Captured(bytes),
        CaptureBytes::NotCaptured => CaptureState::NotCaptured,
        CaptureBytes::Unavailable => CaptureState::Unavailable,
    })
}

fn capture_extent(bytes: &[u8], size: u32) -> &[u8] {
    &bytes[..bytes.len().min(size as usize)]
}

fn validate_history_rows(rows: &[usize], guard: &dyn WorkGuard) -> Result<(), AnalysisError> {
    let comparisons = rows.len().saturating_sub(1);
    for start in (0..comparisons).step_by(4_096) {
        let end = start.saturating_add(4_096).min(comparisons);
        guard
            .consume(WorkDelta {
                nodes: (end - start) as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        if (start..end).any(|index| rows[index] >= rows[index + 1]) {
            return Err(AnalysisError::state_invalid(
                "memory posting rows are not strictly ordered",
            ));
        }
    }
    Ok(())
}

fn overlay(
    target: &mut [ByteState],
    query: &Range<u64>,
    address: u64,
    bytes: &[u8],
    provenance: Provenance,
    evidence: &MemoryEvidence,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    for (chunk_index, chunk) in bytes.chunks(4_096).enumerate() {
        guard
            .consume(WorkDelta {
                nodes: chunk.len() as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        let base = chunk_index * 4_096;
        for (chunk_offset, value) in chunk.iter().copied().enumerate() {
            let Some(byte_address) = address.checked_add((base + chunk_offset) as u64) else {
                return Err(AnalysisError::state_invalid(
                    "memory capture address overflows",
                ));
            };
            if query.contains(&byte_address) {
                let cell = &mut target[(byte_address - query.start) as usize];
                cell.value = Some(value);
                cell.provenance = provenance;
                cell.evidence = Some(evidence.clone());
            }
        }
    }
    Ok(())
}

fn overlay_value(
    target: &mut [ByteState],
    query: &Range<u64>,
    row: &qtrace_store::MemoryRow,
    evidence: &MemoryEvidence,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    if !row.metadata_available {
        return Ok(());
    }
    let bytes = row.value.to_le_bytes();
    overlay(
        target,
        query,
        row.address,
        &bytes[..usize::try_from(row.size)
            .unwrap_or(usize::MAX)
            .min(bytes.len())],
        evidence.provenance,
        evidence,
        guard,
    )
}

fn mark_damaged(
    target: &mut [ByteState],
    query: &Range<u64>,
    start: u64,
    end: u64,
    evidence: &MemoryEvidence,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    let affected = start.max(query.start)..end.min(query.end);
    for start in (affected.start..affected.end).step_by(4_096) {
        let end = start.saturating_add(4_096).min(affected.end);
        guard
            .consume(WorkDelta {
                nodes: end - start,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        for address in start..end {
            let cell = &mut target[(address - query.start) as usize];
            cell.value = None;
            cell.provenance = Provenance::Damaged;
            cell.evidence = Some(evidence.clone());
        }
    }
    Ok(())
}

fn record_unordered_overlap(
    target: &mut [Option<MemoryEvidence>],
    query: &Range<u64>,
    row: &qtrace_store::MemoryRow,
    evidence: &MemoryEvidence,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    let start = row.address.max(query.start);
    let end = row.end_exclusive.min(query.end);
    for start in (start..end).step_by(4_096) {
        let chunk_end = start.saturating_add(4_096).min(end);
        guard
            .consume(WorkDelta {
                nodes: chunk_end - start,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        for address in start..chunk_end {
            target[(address - query.start) as usize] = Some(evidence.clone());
        }
    }
    Ok(())
}

fn apply_unordered_conflicts(
    conflicts: &[Option<MemoryEvidence>],
    targets: [&mut Vec<ByteState>; 3],
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    let mut targets = targets;
    for start in (0..conflicts.len()).step_by(4_096) {
        let end = start.saturating_add(4_096).min(conflicts.len());
        guard
            .consume(WorkDelta {
                nodes: (end - start) as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        for (index, evidence) in conflicts[start..end].iter().enumerate() {
            let Some(evidence) = evidence else { continue };
            for target in &mut targets {
                let cell = &mut target[start + index];
                cell.value = None;
                cell.provenance = Provenance::Damaged;
                cell.evidence = Some(evidence.clone());
            }
        }
    }
    Ok(())
}
