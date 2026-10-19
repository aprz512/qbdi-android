//! Emergency-slot recovery owns publication validation, history selection and pinned pairs.
//! It never lets an emergency cell replace a committed regular sequence.

use std::collections::HashMap;

use super::super::wire::{
    EMERGENCY_COMMITTED, EmergencyCell, FLIGHT_EMERGENCY_RECORD_BYTES, FLIGHT_EMERGENCY_SLOT_BYTES,
    KNOWN_INCOMPLETE_FLAGS, Superblock, emergency_checksum, fnv32_update, parse_emergency_cell,
};
use super::{
    FNV_OFFSET_BASIS, MERGED_TIMELINE_ID, PhysicalRecord, RecoveryContext, allocation,
    allocation_error, fallible_vec, guarded_push, indexed_offset, push_source_range,
};
use crate::{
    CompletenessCause, CompletenessRange, EventKey, EventScope, OpaqueOptionalRecord, Provenance,
    ProviderError, WorkDelta,
};

#[derive(Clone, Copy, Default)]
pub(super) struct EmergencyStatus {
    pub(super) has_coverage: bool,
    pub(super) has_damage: bool,
    pub(super) has_incomplete: bool,
}

#[derive(Clone, Copy)]
struct EmergencyCandidate {
    cell: EmergencyCell,
    offset: u64,
    raw: [u8; FLIGHT_EMERGENCY_RECORD_BYTES],
}

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_emergencies(
    context: &mut RecoveryContext<'_>,
    superblock: &Superblock,
    artifact: crate::ArtifactDigest,
    events: &mut Vec<PhysicalRecord>,
    completeness: &mut Vec<CompletenessRange>,
    tids: &mut Vec<u32>,
    known_tids: &mut HashMap<u32, ()>,
    regular_sequences: &HashMap<u64, ()>,
) -> Result<EmergencyStatus, ProviderError> {
    let mut status = EmergencyStatus::default();
    for index in 0..superblock.emergency_count {
        context.guard.consume(WorkDelta::default())?;
        let slot_offset = indexed_offset(
            superblock.emergencies.offset,
            index,
            FLIGHT_EMERGENCY_SLOT_BYTES as u64,
            "emergency slot offset overflow",
        )?;
        let slot = context.read_array::<FLIGHT_EMERGENCY_SLOT_BYTES>(
            slot_offset,
            "flight.emergency",
            None,
        )?;
        if slot.iter().all(|byte| *byte == 0) {
            continue;
        }
        let first = evaluate_emergency_cell(
            context,
            &slot,
            0,
            slot_offset,
            superblock,
            completeness,
            &mut status,
        )?;
        let second = evaluate_emergency_cell(
            context,
            &slot,
            FLIGHT_EMERGENCY_RECORD_BYTES,
            slot_offset + FLIGHT_EMERGENCY_RECORD_BYTES as u64,
            superblock,
            completeness,
            &mut status,
        )?;
        let selected = select_emergency(first, second, completeness, context, &mut status)?;
        for candidate in selected.into_iter().flatten() {
            if regular_sequences.contains_key(&candidate.cell.sequence) {
                push_source_range(
                    completeness,
                    candidate.offset,
                    candidate
                        .offset
                        .checked_add(FLIGHT_EMERGENCY_RECORD_BYTES as u64)
                        .ok_or_else(|| allocation_error("emergency stale range overflow"))?,
                    Provenance::Unknown,
                    CompletenessCause::Stale,
                    context,
                )?;
                continue;
            }
            if candidate.cell.kind == 15 {
                status.has_coverage = true;
            }
            if !known_tids.contains_key(&candidate.cell.tid) {
                allocation::try_reserve_hash_map(
                    known_tids,
                    1,
                    context.guard,
                    "Flight emergency TID allocation failed",
                )?;
                known_tids.insert(candidate.cell.tid, ());
                guarded_push(tids, candidate.cell.tid, context)?;
            }
            context.guard.consume(WorkDelta {
                events: 1,
                ..WorkDelta::default()
            })?;
            let mut payload = fallible_vec(52, context)?;
            let logical = candidate
                .raw
                .get(..52)
                .ok_or_else(|| allocation_error("invalid emergency payload bounds"))?;
            payload.extend_from_slice(logical);
            let kind = u16::try_from(candidate.cell.kind)
                .map_err(|_| allocation_error("emergency type conversion failed"))?;
            let event = PhysicalRecord {
                key: EventKey::new(
                    artifact,
                    MERGED_TIMELINE_ID,
                    context.next_ordinal,
                    candidate.offset,
                    Some(candidate.cell.sequence),
                    Some(candidate.cell.tid),
                ),
                scope: EventScope::Artifact,
                raw: OpaqueOptionalRecord {
                    record_type: kind,
                    flags: 0,
                    bytes: payload,
                },
            };
            context.next_ordinal = context
                .next_ordinal
                .checked_add(1)
                .ok_or_else(|| allocation_error("emergency ordinal overflow"))?;
            guarded_push(events, event, context)?;
            context.counters.records_seen = context.counters.records_seen.saturating_add(1);
        }
    }
    Ok(status)
}

fn evaluate_emergency_cell(
    context: &RecoveryContext<'_>,
    slot: &[u8; FLIGHT_EMERGENCY_SLOT_BYTES],
    start: usize,
    offset: u64,
    superblock: &Superblock,
    completeness: &mut Vec<CompletenessRange>,
    status: &mut EmergencyStatus,
) -> Result<Option<EmergencyCandidate>, ProviderError> {
    let end = start
        .checked_add(FLIGHT_EMERGENCY_RECORD_BYTES)
        .ok_or_else(|| allocation_error("emergency cell bounds overflow"))?;
    let raw = slot
        .get(start..end)
        .ok_or_else(|| allocation_error("invalid emergency cell bounds"))?;
    if raw.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let mut copy = [0; FLIGHT_EMERGENCY_RECORD_BYTES];
    copy.copy_from_slice(raw);
    let cell = parse_emergency_cell(raw, offset)?;
    if cell.flags & EMERGENCY_COMMITTED == 0 || cell.version == 0 || cell.version % 2 != 0 {
        status.has_incomplete = true;
        push_source_range(
            completeness,
            offset,
            offset + FLIGHT_EMERGENCY_RECORD_BYTES as u64,
            Provenance::Unknown,
            CompletenessCause::Incomplete,
            context,
        )?;
        return Ok(None);
    }
    let checksum_matches = cell.checksum_inverse == !cell.checksum
        && (cell.checksum == emergency_checksum(&cell)
            || cell.checksum == emergency_legacy_checksum(&cell));
    if !checksum_matches {
        status.has_damage = true;
        push_source_range(
            completeness,
            offset,
            offset + FLIGHT_EMERGENCY_RECORD_BYTES as u64,
            Provenance::Damaged,
            CompletenessCause::Checksum,
            context,
        )?;
        return Ok(None);
    }
    let flags = cell.flags & !EMERGENCY_COMMITTED;
    let pointer_maximum = if superblock.pointer_width == 4 {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    };
    if !(1..=15).contains(&cell.kind)
        || cell.tid == 0
        || cell.sequence == 0
        || (cell.kind == 15 && flags & !KNOWN_INCOMPLETE_FLAGS != 0)
        || cell.pc > pointer_maximum
        || cell.sp > pointer_maximum
        || cell.fault_address > pointer_maximum
    {
        status.has_damage = true;
        status.has_incomplete = true;
        push_source_range(
            completeness,
            offset,
            offset + FLIGHT_EMERGENCY_RECORD_BYTES as u64,
            Provenance::Damaged,
            CompletenessCause::Incomplete,
            context,
        )?;
        return Ok(None);
    }
    Ok(Some(EmergencyCandidate {
        cell,
        offset,
        raw: copy,
    }))
}

fn select_emergency(
    first: Option<EmergencyCandidate>,
    second: Option<EmergencyCandidate>,
    completeness: &mut Vec<CompletenessRange>,
    context: &RecoveryContext<'_>,
    status: &mut EmergencyStatus,
) -> Result<[Option<EmergencyCandidate>; 2], ProviderError> {
    let (Some(left), Some(right)) = (first, second) else {
        return Ok([first.or(second), None]);
    };
    if left.cell.version == right.cell.version {
        status.has_damage = true;
        status.has_incomplete = true;
        for candidate in [left, right] {
            push_source_range(
                completeness,
                candidate.offset,
                candidate.offset + FLIGHT_EMERGENCY_RECORD_BYTES as u64,
                Provenance::Damaged,
                CompletenessCause::Incomplete,
                context,
            )?;
        }
        return Ok([None, None]);
    }
    let (older, newer) = if left.cell.version <= right.cell.version {
        (left, right)
    } else {
        (right, left)
    };
    let consecutive = newer.cell.version == older.cell.version.saturating_add(2);
    let pinned = pinned_termination_pair(&older.cell, &newer.cell);
    if newer.cell.sequence > older.cell.sequence && (consecutive || pinned) {
        Ok([Some(older), Some(newer)])
    } else {
        push_source_range(
            completeness,
            older.offset,
            older.offset + FLIGHT_EMERGENCY_RECORD_BYTES as u64,
            Provenance::Unknown,
            CompletenessCause::Stale,
            context,
        )?;
        Ok([Some(newer), None])
    }
}

fn pinned_termination_pair(older: &EmergencyCell, newer: &EmergencyCell) -> bool {
    let intended_signal = match older.signal_number {
        129 | 130 | 138 => u32::try_from(older.fault_address).ok(),
        131 => Some(older.signal_code),
        _ => None,
    };
    older.kind == 14
        && matches!(newer.kind, 11..=13)
        && older.tid == newer.tid
        && intended_signal == Some(newer.signal_number)
        && (newer.flags & !EMERGENCY_COMMITTED) & 0xffff == 1
}

fn emergency_legacy_checksum(cell: &EmergencyCell) -> u32 {
    let mut value = FNV_OFFSET_BASIS;
    value = fnv32_update(value, &cell.kind.to_le_bytes());
    value = fnv32_update(value, &cell.tid.to_le_bytes());
    value = fnv32_update(value, &cell.sequence.to_le_bytes());
    value = fnv32_update(value, &cell.pc.to_le_bytes());
    value = fnv32_update(value, &cell.sp.to_le_bytes());
    value = fnv32_update(value, &cell.fault_address.to_le_bytes());
    value = fnv32_update(value, &cell.signal_number.to_le_bytes());
    value = fnv32_update(value, &cell.signal_code.to_le_bytes());
    fnv32_update(value, &(cell.flags & !EMERGENCY_COMMITTED).to_le_bytes())
}
