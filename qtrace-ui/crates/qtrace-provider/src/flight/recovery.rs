use std::{cmp::Ordering, mem::size_of, sync::Arc};

use crate::{
    CompletenessCause, CompletenessRange, EventKey, EventPayload, EventRecord,
    OpaqueOptionalRecord, Provenance, ProviderCounters, ProviderError, RangeBounds, RangeDomain,
    ReadAtSource, SourceCoordinate, TimelineId, WorkDelta, WorkGuard,
};

use super::wire::{
    ChunkHeader, EMERGENCY_COMMITTED, EmergencyCell, FLIGHT_CHUNK_HEADER_BYTES,
    FLIGHT_DIRECTORY_ENTRY_BYTES, FLIGHT_EMERGENCY_RECORD_BYTES, FLIGHT_EMERGENCY_SLOT_BYTES,
    FLIGHT_RECORD_HEADER_BYTES, FLIGHT_SUPERBLOCK_BYTES, INVALID_INDEX, KNOWN_INCOMPLETE_FLAGS,
    RECORD_COMMIT, Superblock, emergency_checksum, fnv32_update, parse_chunk_header,
    parse_directory, parse_emergency_cell, parse_record_header, parse_superblock, record_checksum,
    record_error, valid_record_flags,
};

pub(super) const MERGED_TIMELINE_ID: TimelineId = TimelineId(0);
const FNV_OFFSET_BASIS: u32 = 2_166_136_261;

pub(super) struct RecoveredFlight {
    pub(super) source_bytes: u64,
    pub(super) events: Vec<EventRecord>,
    pub(super) tids: Vec<u32>,
    pub(super) completeness: Vec<CompletenessRange>,
    pub(super) counters: ProviderCounters,
}

#[derive(Clone, Copy)]
struct ChunkIdentity {
    index: u32,
    tid: u32,
    generation: u32,
    state: u32,
}

#[derive(Clone, Copy)]
struct SequenceRange {
    first: u64,
    last: u64,
}

#[derive(Clone, Copy)]
struct RecoveryStatus {
    flags: u32,
    has_damage: bool,
    has_coverage: bool,
    has_incomplete: bool,
}

#[derive(Clone, Copy)]
struct LifecycleBalance {
    tid: u32,
    balance: i64,
    first_begin: u64,
}

struct RecordScan {
    events: Vec<EventRecord>,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    lifecycle: Vec<LifecycleBalance>,
}

#[derive(Clone, Copy, Default)]
struct EmergencyStatus {
    has_coverage: bool,
    has_damage: bool,
    has_incomplete: bool,
}

#[derive(Clone, Copy)]
struct EmergencyCandidate {
    cell: EmergencyCell,
    offset: u64,
    raw: [u8; FLIGHT_EMERGENCY_RECORD_BYTES],
}

struct RecoveryContext<'a> {
    source: &'a dyn ReadAtSource,
    guard: &'a dyn WorkGuard,
    counters: ProviderCounters,
    next_ordinal: u64,
}

pub(super) fn recover(
    source: Arc<dyn ReadAtSource>,
    artifact: crate::ArtifactDigest,
    guard: &dyn WorkGuard,
) -> Result<RecoveredFlight, ProviderError> {
    guard.consume(WorkDelta::default())?;
    let source_size = source.len();
    let mut context = RecoveryContext {
        source: source.as_ref(),
        guard,
        counters: ProviderCounters::default(),
        next_ordinal: 0,
    };
    let superblock_bytes =
        context.read_array::<FLIGHT_SUPERBLOCK_BYTES>(0, "flight.superblock", None)?;
    let superblock = parse_superblock(&superblock_bytes, source_size)?;
    authorize_metadata(&context, &superblock)?;

    let directory_capacity = usize::try_from(superblock.directory_entries)
        .map_err(|_| allocation_error("directory count does not fit this host"))?;
    let chunk_capacity = usize::try_from(superblock.chunk_count)
        .map_err(|_| allocation_error("chunk count does not fit this host"))?;
    let mut directories = fallible_vec(directory_capacity)?;
    let mut chunks = fallible_vec(chunk_capacity)?;
    let mut tids = fallible_vec(directory_capacity)?;
    let mut hints = fallible_vec(directory_capacity.saturating_add(chunk_capacity))?;
    let emergency_capacity = usize::try_from(superblock.emergency_count)
        .map_err(|_| allocation_error("emergency count does not fit this host"))?;
    let completeness_capacity = directory_capacity
        .saturating_mul(3)
        .saturating_add(chunk_capacity.saturating_mul(3))
        .saturating_add(emergency_capacity);
    let mut completeness = fallible_vec(completeness_capacity)?;
    let mut has_directory_uncertainty = false;

    for index in 0..superblock.directory_entries {
        let offset = indexed_offset(
            superblock.directory.offset,
            index,
            FLIGHT_DIRECTORY_ENTRY_BYTES as u64,
            "directory offset overflow",
        )?;
        let bytes =
            context.read_array::<FLIGHT_DIRECTORY_ENTRY_BYTES>(offset, "flight.directory", None)?;
        if let Some(entry) = parse_directory(&bytes, index, superblock.chunk_count, offset)? {
            if tids.binary_search(&entry.tid).is_ok() {
                return Err(super::wire::directory_error(
                    offset,
                    "duplicate directory TID",
                ));
            }
            insert_sorted(&mut tids, entry.tid, &context)?;
            if entry.range_reliable && entry.first_sequence != 0 {
                guarded_push(
                    &mut hints,
                    SequenceRange {
                        first: entry.first_sequence,
                        last: entry.last_sequence,
                    },
                    &context,
                )?;
            }
            if entry.state == 2 {
                has_directory_uncertainty = true;
                push_source_range(
                    &mut completeness,
                    offset,
                    offset + FLIGHT_DIRECTORY_ENTRY_BYTES as u64,
                    Provenance::Unknown,
                    CompletenessCause::Rotating,
                    &context,
                )?;
                push_source_range(
                    &mut completeness,
                    offset,
                    offset + FLIGHT_DIRECTORY_ENTRY_BYTES as u64,
                    Provenance::Unknown,
                    CompletenessCause::Unreliable,
                    &context,
                )?;
            } else if !entry.range_reliable {
                has_directory_uncertainty = true;
                push_source_range(
                    &mut completeness,
                    offset,
                    offset + FLIGHT_DIRECTORY_ENTRY_BYTES as u64,
                    Provenance::Unknown,
                    CompletenessCause::Unreliable,
                    &context,
                )?;
            }
            guarded_push(&mut directories, entry, &context)?;
        }
    }

    let mut events = Vec::new();
    let mut lifecycle = fallible_vec(directory_capacity)?;
    let mut damage_ranges = fallible_vec(chunk_capacity)?;
    let mut has_damage = false;
    let mut has_incomplete = superblock.flags != 0 || has_directory_uncertainty;
    for index in 0..superblock.chunk_count {
        context.guard.consume(WorkDelta::default())?;
        let offset = indexed_offset(
            superblock.chunks.offset,
            index,
            u64::from(superblock.chunk_bytes),
            "chunk offset overflow",
        )?;
        let bytes =
            context.read_array::<FLIGHT_CHUNK_HEADER_BYTES>(offset, "flight.chunk", None)?;
        let Some(header) = parse_chunk_header(&bytes, index, offset)? else {
            continue;
        };
        if directories.iter().all(|entry| entry.tid != header.tid) {
            return Err(super::wire::chunk_error(
                offset,
                "chunk TID has no directory owner",
            ));
        }
        guarded_push(
            &mut chunks,
            ChunkIdentity {
                index,
                tid: header.tid,
                generation: header.generation,
                state: header.state,
            },
            &context,
        )?;
        let capacity = u64::from(superblock.chunk_bytes)
            .checked_sub(FLIGHT_CHUNK_HEADER_BYTES as u64)
            .ok_or_else(|| super::wire::chunk_error(offset, "invalid chunk capacity"))?;
        let data_offset = offset
            .checked_add(FLIGHT_CHUNK_HEADER_BYTES as u64)
            .ok_or_else(|| super::wire::chunk_error(offset, "chunk data offset overflow"))?;

        if header.state == 2 {
            let header_range = valid_sealed_range(&header);
            if let Some(range) = header_range {
                guarded_push(&mut hints, range, &context)?;
            }
            let committed = u64::from(header.committed_bytes);
            if committed > capacity || committed % 8 != 0 {
                mark_chunk_damage(
                    &mut completeness,
                    &mut damage_ranges,
                    header_range,
                    offset,
                    u64::from(superblock.chunk_bytes),
                    CompletenessCause::Incomplete,
                    &context,
                )?;
                has_damage = true;
                continue;
            }
            let checksum = context.checksum_region(data_offset, committed)?;
            if checksum != header.checksum {
                mark_chunk_damage(
                    &mut completeness,
                    &mut damage_ranges,
                    header_range,
                    offset,
                    u64::from(superblock.chunk_bytes),
                    CompletenessCause::Checksum,
                    &context,
                )?;
                has_damage = true;
                context.counters.damaged_records =
                    context.counters.damaged_records.saturating_add(1);
                continue;
            }
            let scan = match scan_records(
                &mut context,
                artifact,
                &header,
                data_offset,
                committed,
                false,
            ) {
                Ok(scan) => scan,
                Err(error)
                    if matches!(
                        error.code(),
                        "source.flight.record" | "source.flight.record_checksum"
                    ) =>
                {
                    let cause = if error.code() == "source.flight.record_checksum" {
                        CompletenessCause::Checksum
                    } else {
                        CompletenessCause::Incomplete
                    };
                    mark_chunk_damage(
                        &mut completeness,
                        &mut damage_ranges,
                        header_range,
                        offset,
                        u64::from(superblock.chunk_bytes),
                        cause,
                        &context,
                    )?;
                    has_damage = true;
                    context.counters.damaged_records =
                        context.counters.damaged_records.saturating_add(1);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let count_matches = usize::try_from(header.record_count)
                .ok()
                .is_some_and(|count| count == scan.events.len());
            let endpoints_match = match (scan.first_sequence, scan.last_sequence) {
                (Some(first), Some(last)) => {
                    first == header.first_sequence && last == header.last_sequence
                }
                (None, None) => header.first_sequence == 0 && header.last_sequence == 0,
                _ => false,
            };
            if scan.events.is_empty() || !count_matches || !endpoints_match {
                mark_chunk_damage(
                    &mut completeness,
                    &mut damage_ranges,
                    header_range,
                    offset,
                    u64::from(superblock.chunk_bytes),
                    CompletenessCause::Incomplete,
                    &context,
                )?;
                has_damage = true;
                continue;
            }
            merge_lifecycle(&mut lifecycle, &scan.lifecycle, &context)?;
            append_events(&mut events, scan.events, &context)?;
        } else {
            push_source_range(
                &mut completeness,
                offset,
                data_offset,
                Provenance::Captured,
                CompletenessCause::Active,
                &context,
            )?;
            let scan = scan_records(&mut context, artifact, &header, data_offset, capacity, true)?;
            merge_lifecycle(&mut lifecycle, &scan.lifecycle, &context)?;
            append_events(&mut events, scan.events, &context)?;
        }
    }

    for entry in &directories {
        context.guard.consume(WorkDelta::default())?;
        if entry.state == 2 || entry.chunk_index == INVALID_INDEX {
            continue;
        }
        let current = chunks.iter().find(|chunk| chunk.index == entry.chunk_index);
        if !current.is_some_and(|chunk| {
            chunk.tid == entry.tid
                && chunk.generation == entry.generation
                && matches!(chunk.state, 1 | 2)
        }) {
            let offset = indexed_offset(
                superblock.directory.offset,
                entry.index,
                FLIGHT_DIRECTORY_ENTRY_BYTES as u64,
                "directory offset overflow",
            )?;
            push_source_range(
                &mut completeness,
                offset,
                offset + FLIGHT_DIRECTORY_ENTRY_BYTES as u64,
                Provenance::Unknown,
                CompletenessCause::Stale,
                &context,
            )?;
            has_incomplete = true;
        }
    }

    context.guard.consume(WorkDelta::default())?;
    events.sort_by(event_order);
    reject_duplicate_sequences(&events, &context)?;
    let emergency_status = scan_emergencies(
        &mut context,
        &superblock,
        artifact,
        &mut events,
        &mut completeness,
        &mut tids,
    )?;
    has_damage |= emergency_status.has_damage;
    has_incomplete |= emergency_status.has_incomplete;
    let mut has_coverage = emergency_status.has_coverage;
    for event in &events {
        context.guard.consume(WorkDelta::default())?;
        if matches!(
            &event.payload,
            EventPayload::OpaqueOptional(record) if record.record_type == 15
        ) {
            let sequence = event
                .key
                .sequence
                .ok_or_else(|| allocation_error("Flight coverage gap has no sequence"))?;
            push_sequence_range(
                &mut completeness,
                sequence,
                sequence,
                Provenance::Captured,
                CompletenessCause::CoverageGap,
                &context,
            )?;
            has_coverage = true;
        }
    }

    context.guard.consume(WorkDelta::default())?;
    if source.len() != source_size || source_size != superblock.artifact_bytes {
        return Err(super::wire::superblock_error(
            "source size changed during Flight recovery",
        ));
    }
    if superblock.flags != 0 {
        push_source_range(
            &mut completeness,
            72,
            76,
            Provenance::Unknown,
            CompletenessCause::Incomplete,
            &context,
        )?;
    }
    for item in &lifecycle {
        context.guard.consume(WorkDelta::default())?;
        if item.balance > 0 {
            push_sequence_range(
                &mut completeness,
                item.first_begin,
                item.first_begin,
                Provenance::Unknown,
                CompletenessCause::UnterminatedThread,
                &context,
            )?;
            has_incomplete = true;
        }
    }

    context.guard.consume(WorkDelta::default())?;
    damage_ranges.sort_by_key(|range| (range.first, range.last));
    add_sequence_completeness(
        &events,
        &hints,
        &damage_ranges,
        RecoveryStatus {
            flags: superblock.flags,
            has_damage,
            has_coverage,
            has_incomplete,
        },
        &mut completeness,
        &context,
    )?;
    normalize_completeness(&mut completeness, &context)?;
    context.counters.events_emitted = events.len() as u64;
    context.counters.opaque_records = events.len() as u64;
    Ok(RecoveredFlight {
        source_bytes: source_size,
        events,
        tids,
        completeness,
        counters: context.counters,
    })
}

fn authorize_metadata(
    context: &RecoveryContext<'_>,
    superblock: &Superblock,
) -> Result<(), ProviderError> {
    let nodes = u64::from(superblock.directory_entries)
        .checked_add(u64::from(superblock.chunk_count))
        .and_then(|value| value.checked_add(u64::from(superblock.emergency_count)))
        .ok_or_else(|| allocation_error("Flight metadata node count overflow"))?;
    let resident_bytes = nodes
        .checked_mul(256)
        .ok_or_else(|| allocation_error("Flight metadata size overflow"))?;
    context.guard.consume(WorkDelta {
        nodes,
        resident_bytes,
        ..WorkDelta::default()
    })?;
    Ok(())
}

fn scan_records(
    context: &mut RecoveryContext<'_>,
    artifact: crate::ArtifactDigest,
    header: &ChunkHeader,
    data_offset: u64,
    limit: u64,
    active: bool,
) -> Result<RecordScan, ProviderError> {
    let mut events = Vec::new();
    let mut lifecycle = Vec::new();
    let mut relative = 0_u64;
    let mut first_sequence = None;
    let mut last_sequence = None;
    while relative < limit {
        context.guard.consume(WorkDelta::default())?;
        let remaining = limit
            .checked_sub(relative)
            .ok_or_else(|| allocation_error("record extent underflow"))?;
        if remaining < FLIGHT_RECORD_HEADER_BYTES as u64 {
            if active {
                break;
            }
            return Err(record_error(
                SourceCoordinate {
                    offset: data_offset + relative,
                    record_ordinal: Some(context.next_ordinal),
                },
                "truncated sealed record header",
            ));
        }
        let record_offset = data_offset
            .checked_add(relative)
            .ok_or_else(|| allocation_error("record offset overflow"))?;
        let coordinate = SourceCoordinate {
            offset: record_offset,
            record_ordinal: Some(context.next_ordinal),
        };
        let raw_header = context.read_array::<FLIGHT_RECORD_HEADER_BYTES>(
            record_offset,
            "flight.record",
            Some(context.next_ordinal),
        )?;
        let record = parse_record_header(&raw_header, coordinate)?;
        let expected_commit = RECORD_COMMIT ^ record.total_bytes ^ header.generation;
        if record.commit != expected_commit {
            if active {
                // Active chunk reuse clears only its first header; bytes after
                // the new committed prefix can be valid records from an older
                // generation.  A mismatched commit therefore terminates the
                // recoverable prefix without classifying the suffix.
                break;
            }
            return Err(record_error(coordinate, "sealed record commit mismatch"));
        }
        if record.total_bytes < FLIGHT_RECORD_HEADER_BYTES as u32 {
            return Err(record_error(coordinate, "invalid committed record length"));
        }
        let storage = record
            .total_bytes
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or_else(|| record_error(coordinate, "record storage overflow"))?;
        if u64::from(storage) > remaining {
            return Err(record_error(coordinate, "invalid committed record extent"));
        }
        if !valid_record_flags(record.kind, record.flags) {
            return Err(record_error(
                coordinate,
                "unknown committed record type or flags",
            ));
        }
        if record.sequence == 0 || last_sequence.is_some_and(|last| record.sequence <= last) {
            return Err(record_error(coordinate, "invalid chunk sequence order"));
        }
        let payload_bytes = record.total_bytes - FLIGHT_RECORD_HEADER_BYTES as u32;
        let payload_offset = record_offset
            .checked_add(FLIGHT_RECORD_HEADER_BYTES as u64)
            .ok_or_else(|| record_error(coordinate, "record payload offset overflow"))?;
        let payload = context.read_event_payload(payload_offset, payload_bytes, coordinate)?;
        if record_checksum(&raw_header, &payload) != Some(record.checksum) {
            return Err(ProviderError::new(
                "source.flight.record_checksum",
                "flight.record",
                Some(coordinate),
                false,
                "committed record checksum mismatch",
            ));
        }
        let padding_bytes = storage - record.total_bytes;
        if padding_bytes != 0 {
            let padding_offset = record_offset
                .checked_add(u64::from(record.total_bytes))
                .ok_or_else(|| record_error(coordinate, "padding offset overflow"))?;
            let mut padding = [0_u8; 7];
            let requested = padding
                .get_mut(
                    ..usize::try_from(padding_bytes).map_err(|_| {
                        record_error(coordinate, "padding length does not fit this host")
                    })?,
                )
                .ok_or_else(|| record_error(coordinate, "invalid padding length"))?;
            context.read_into(
                padding_offset,
                requested,
                "flight.record",
                Some(context.next_ordinal),
            )?;
            if requested.iter().any(|byte| *byte != 0) {
                return Err(record_error(coordinate, "nonzero record alignment padding"));
            }
        }
        let key = EventKey::new(
            artifact,
            MERGED_TIMELINE_ID,
            context.next_ordinal,
            record_offset,
            Some(record.sequence),
            Some(header.tid),
        );
        let event = EventRecord::new(
            key,
            Provenance::Captured,
            EventPayload::OpaqueOptional(OpaqueOptionalRecord {
                record_type: record.kind,
                flags: record.flags,
                bytes: payload,
            }),
        );
        guarded_push_without_charge(&mut events, event)?;
        context.next_ordinal = context
            .next_ordinal
            .checked_add(1)
            .ok_or_else(|| record_error(coordinate, "record ordinal overflow"))?;
        context.counters.records_seen = context.counters.records_seen.saturating_add(1);
        if first_sequence.is_none() {
            first_sequence = Some(record.sequence);
        }
        last_sequence = Some(record.sequence);
        update_lifecycle(
            &mut lifecycle,
            header.tid,
            record.kind,
            record.sequence,
            context,
        )?;
        relative = relative
            .checked_add(u64::from(storage))
            .ok_or_else(|| record_error(coordinate, "record cursor overflow"))?;
    }
    if !active && relative != limit {
        return Err(record_error(
            SourceCoordinate {
                offset: data_offset + relative,
                record_ordinal: Some(context.next_ordinal),
            },
            "sealed chunk has an invalid suffix",
        ));
    }
    Ok(RecordScan {
        events,
        first_sequence,
        last_sequence,
        lifecycle,
    })
}

fn scan_emergencies(
    context: &mut RecoveryContext<'_>,
    superblock: &Superblock,
    artifact: crate::ArtifactDigest,
    events: &mut Vec<EventRecord>,
    completeness: &mut Vec<CompletenessRange>,
    tids: &mut Vec<u32>,
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
            if events
                .binary_search_by_key(&candidate.cell.sequence, |event| {
                    event.key.sequence.unwrap_or(0)
                })
                .is_ok()
            {
                push_source_range(
                    completeness,
                    candidate.offset,
                    candidate.offset + FLIGHT_EMERGENCY_RECORD_BYTES as u64,
                    Provenance::Unknown,
                    CompletenessCause::Stale,
                    context,
                )?;
                continue;
            }
            if candidate.cell.kind == 15 {
                status.has_coverage = true;
            }
            if tids.binary_search(&candidate.cell.tid).is_err() {
                insert_sorted(tids, candidate.cell.tid, context)?;
            }
            context.guard.consume(WorkDelta {
                events: 1,
                resident_bytes: (FLIGHT_EMERGENCY_RECORD_BYTES as u64)
                    .saturating_add((size_of::<EventRecord>() as u64).saturating_mul(4)),
                ..WorkDelta::default()
            })?;
            let mut payload = fallible_vec(52)?;
            let logical = candidate
                .raw
                .get(..52)
                .ok_or_else(|| allocation_error("invalid emergency payload bounds"))?;
            payload.extend_from_slice(logical);
            let kind = u16::try_from(candidate.cell.kind)
                .map_err(|_| allocation_error("emergency type conversion failed"))?;
            let event = EventRecord::new(
                EventKey::new(
                    artifact,
                    MERGED_TIMELINE_ID,
                    context.next_ordinal,
                    candidate.offset,
                    Some(candidate.cell.sequence),
                    Some(candidate.cell.tid),
                ),
                Provenance::Captured,
                EventPayload::OpaqueOptional(OpaqueOptionalRecord {
                    record_type: kind,
                    flags: 0,
                    bytes: payload,
                }),
            );
            context.next_ordinal = context
                .next_ordinal
                .checked_add(1)
                .ok_or_else(|| allocation_error("emergency ordinal overflow"))?;
            let position = events
                .binary_search_by_key(&candidate.cell.sequence, |event| {
                    event.key.sequence.unwrap_or(0)
                })
                .unwrap_or_else(|position| position);
            guarded_insert_without_charge(events, position, event)?;
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

fn add_sequence_completeness(
    events: &[EventRecord],
    hints: &[SequenceRange],
    damage_ranges: &[SequenceRange],
    status: RecoveryStatus,
    completeness: &mut Vec<CompletenessRange>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    if events.is_empty() && hints.is_empty() {
        return Ok(());
    }
    let mut first = events
        .first()
        .and_then(|event| event.key.sequence)
        .unwrap_or(u64::MAX);
    let mut last = events
        .last()
        .and_then(|event| event.key.sequence)
        .unwrap_or(0);
    for hint in hints {
        context.guard.consume(WorkDelta::default())?;
        first = first.min(hint.first);
        last = last.max(hint.last);
    }
    if first == u64::MAX && last == 0 {
        return Ok(());
    }

    let mut retained_start = None;
    let mut retained_last = 0;
    for event in events {
        context.guard.consume(WorkDelta::default())?;
        let sequence = event
            .key
            .sequence
            .ok_or_else(|| allocation_error("Flight event has no sequence"))?;
        match retained_start {
            None => {
                retained_start = Some(sequence);
                retained_last = sequence;
            }
            Some(start) if retained_last.checked_add(1) == Some(sequence) => {
                retained_last = sequence;
                let _ = start;
            }
            Some(start) => {
                push_sequence_range(
                    completeness,
                    start,
                    retained_last,
                    Provenance::Captured,
                    CompletenessCause::Retained,
                    context,
                )?;
                retained_start = Some(sequence);
                retained_last = sequence;
            }
        }
    }
    if let Some(start) = retained_start {
        push_sequence_range(
            completeness,
            start,
            retained_last,
            Provenance::Captured,
            CompletenessCause::Retained,
            context,
        )?;
    }

    let missing_cause = if status.flags == 0
        && !status.has_damage
        && !status.has_coverage
        && !status.has_incomplete
    {
        CompletenessCause::Overwritten
    } else {
        CompletenessCause::Lost
    };
    let mut cursor = Some(first);
    for event in events {
        context.guard.consume(WorkDelta::default())?;
        let sequence = event.key.sequence.unwrap_or(0);
        let Some(current) = cursor else {
            break;
        };
        if sequence < current || sequence > last {
            continue;
        }
        if sequence > current {
            add_missing_without_damage(
                current,
                sequence - 1,
                damage_ranges,
                missing_cause,
                completeness,
                context,
            )?;
        }
        cursor = sequence.checked_add(1);
    }
    if let Some(current) = cursor {
        if current <= last {
            add_missing_without_damage(
                current,
                last,
                damage_ranges,
                missing_cause,
                completeness,
                context,
            )?;
        }
    }
    Ok(())
}

fn add_missing_without_damage(
    first: u64,
    last: u64,
    damage_ranges: &[SequenceRange],
    cause: CompletenessCause,
    completeness: &mut Vec<CompletenessRange>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    let mut cursor = Some(first);
    for damage in damage_ranges {
        context.guard.consume(WorkDelta::default())?;
        let Some(current) = cursor else {
            break;
        };
        if damage.last < current || damage.first > last {
            continue;
        }
        if damage.first > current {
            push_sequence_range(
                completeness,
                current,
                damage.first - 1,
                Provenance::Unknown,
                cause,
                context,
            )?;
        }
        cursor = damage.last.checked_add(1);
    }
    if let Some(current) = cursor {
        if current <= last {
            push_sequence_range(
                completeness,
                current,
                last,
                Provenance::Unknown,
                cause,
                context,
            )?;
        }
    }
    Ok(())
}

fn valid_sealed_range(header: &ChunkHeader) -> Option<SequenceRange> {
    if (header.first_sequence == 0) != (header.last_sequence == 0)
        || (header.first_sequence != 0 && header.first_sequence > header.last_sequence)
        || header.first_sequence == 0
    {
        None
    } else {
        Some(SequenceRange {
            first: header.first_sequence,
            last: header.last_sequence,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn mark_chunk_damage(
    completeness: &mut Vec<CompletenessRange>,
    damage_ranges: &mut Vec<SequenceRange>,
    range: Option<SequenceRange>,
    offset: u64,
    chunk_bytes: u64,
    cause: CompletenessCause,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    if let Some(range) = range {
        push_sequence_range(
            completeness,
            range.first,
            range.last,
            Provenance::Damaged,
            cause,
            context,
        )?;
        guarded_push(damage_ranges, range, context)
    } else {
        push_source_range(
            completeness,
            offset,
            offset.saturating_add(chunk_bytes),
            Provenance::Damaged,
            cause,
            context,
        )
    }
}

fn update_lifecycle(
    lifecycle: &mut Vec<LifecycleBalance>,
    tid: u32,
    kind: u16,
    sequence: u64,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    let delta = match kind {
        2 => 1,
        3 => -1,
        _ => return Ok(()),
    };
    if let Some(item) = lifecycle.iter_mut().find(|item| item.tid == tid) {
        item.balance = item.balance.saturating_add(delta);
        if delta > 0 && item.balance == delta {
            item.first_begin = sequence;
        }
    } else {
        guarded_push(
            lifecycle,
            LifecycleBalance {
                tid,
                balance: delta,
                first_begin: sequence,
            },
            context,
        )?;
    }
    Ok(())
}

fn merge_lifecycle(
    target: &mut Vec<LifecycleBalance>,
    source: &[LifecycleBalance],
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    for incoming in source {
        context.guard.consume(WorkDelta::default())?;
        if let Some(item) = target.iter_mut().find(|item| item.tid == incoming.tid) {
            if item.balance <= 0 && incoming.balance > 0 {
                item.first_begin = incoming.first_begin;
            }
            item.balance = item.balance.saturating_add(incoming.balance);
        } else {
            guarded_push(target, *incoming, context)?;
        }
    }
    Ok(())
}

fn append_events(
    target: &mut Vec<EventRecord>,
    source: Vec<EventRecord>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    for event in source {
        context.guard.consume(WorkDelta {
            resident_bytes: (size_of::<EventRecord>() as u64).saturating_mul(4),
            ..WorkDelta::default()
        })?;
        guarded_push_without_charge(target, event)?;
    }
    Ok(())
}

fn reject_duplicate_sequences(
    events: &[EventRecord],
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    for pair in events.windows(2) {
        context.guard.consume(WorkDelta::default())?;
        let Some(first) = pair.first().and_then(|event| event.key.sequence) else {
            continue;
        };
        let Some(second) = pair.last().and_then(|event| event.key.sequence) else {
            continue;
        };
        if first == second {
            return Err(ProviderError::new(
                "source.flight.sequence",
                "flight.recovery",
                pair.last().map(|event| SourceCoordinate {
                    offset: event.key.source_offset,
                    record_ordinal: Some(event.key.record_ordinal),
                }),
                false,
                "duplicate Flight global sequence",
            ));
        }
    }
    Ok(())
}

fn event_order(left: &EventRecord, right: &EventRecord) -> Ordering {
    left.key
        .sequence
        .cmp(&right.key.sequence)
        .then_with(|| left.key.source_offset.cmp(&right.key.source_offset))
        .then_with(|| left.key.record_ordinal.cmp(&right.key.record_ordinal))
}

fn normalize_completeness(
    ranges: &mut Vec<CompletenessRange>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    context.guard.consume(WorkDelta {
        resident_bytes: (ranges.len() as u64).saturating_mul(size_of::<CompletenessRange>() as u64),
        ..WorkDelta::default()
    })?;
    ranges.sort_by_key(completeness_key);
    let mut output = fallible_vec(ranges.len())?;
    for range in ranges.drain(..) {
        context.guard.consume(WorkDelta::default())?;
        if let Some(previous) = output.last().copied() {
            if let Some(merged) = merge_range(previous, range) {
                if let Some(last) = output.last_mut() {
                    *last = merged;
                    continue;
                }
            }
        }
        output.push(range);
    }
    *ranges = output;
    Ok(())
}

fn completeness_key(range: &CompletenessRange) -> (u8, u8, u64, u64, u8) {
    let domain = match range.domain() {
        RangeDomain::CapturedSequence => 0,
        RangeDomain::SourceBytes => 1,
        RangeDomain::MemoryAddresses => 2,
    };
    let (first, last) = match range.bounds() {
        RangeBounds::InclusiveSequence { first, last } => (first, last),
        RangeBounds::HalfOpen {
            start,
            end_exclusive,
        } => (start, end_exclusive),
    };
    (
        domain,
        cause_order(range.cause()),
        first,
        last,
        provenance_order(range.provenance()),
    )
}

fn cause_order(cause: CompletenessCause) -> u8 {
    match cause {
        CompletenessCause::Retained => 0,
        CompletenessCause::Active => 1,
        CompletenessCause::Rotating => 2,
        CompletenessCause::Stale => 3,
        CompletenessCause::Unreliable => 4,
        CompletenessCause::Incomplete => 5,
        CompletenessCause::Lost => 6,
        CompletenessCause::Overwritten => 7,
        CompletenessCause::CoverageGap => 8,
        CompletenessCause::Checksum => 9,
        CompletenessCause::UnterminatedThread => 10,
        CompletenessCause::MissingTerminal => 11,
        CompletenessCause::Truncation => 12,
        CompletenessCause::Unknown => 13,
    }
}

fn provenance_order(provenance: Provenance) -> u8 {
    match provenance {
        Provenance::Captured => 0,
        Provenance::Derived => 1,
        Provenance::Heuristic => 2,
        Provenance::Unknown => 3,
        Provenance::Damaged => 4,
    }
}

fn merge_range(left: CompletenessRange, right: CompletenessRange) -> Option<CompletenessRange> {
    if left.domain() != right.domain()
        || left.cause() != right.cause()
        || left.provenance() != right.provenance()
    {
        return None;
    }
    match (left.bounds(), right.bounds()) {
        (
            RangeBounds::InclusiveSequence {
                first: left_first,
                last: left_last,
            },
            RangeBounds::InclusiveSequence {
                first: right_first,
                last: right_last,
            },
        ) if right_first <= left_last.saturating_add(1) => {
            CompletenessRange::captured_sequence_with_cause(
                left_first,
                left_last.max(right_last),
                left.provenance(),
                left.cause(),
            )
        }
        (
            RangeBounds::HalfOpen {
                start: left_start,
                end_exclusive: left_end,
            },
            RangeBounds::HalfOpen {
                start: right_start,
                end_exclusive: right_end,
            },
        ) if right_start <= left_end => match left.domain() {
            RangeDomain::SourceBytes => CompletenessRange::source_bytes_with_cause(
                left_start,
                left_end.max(right_end),
                left.provenance(),
                left.cause(),
            ),
            RangeDomain::MemoryAddresses => CompletenessRange::memory_addresses_with_cause(
                left_start,
                left_end.max(right_end),
                left.provenance(),
                left.cause(),
            ),
            RangeDomain::CapturedSequence => None,
        },
        _ => None,
    }
}

fn push_sequence_range(
    output: &mut Vec<CompletenessRange>,
    first: u64,
    last: u64,
    provenance: Provenance,
    cause: CompletenessCause,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    let range = CompletenessRange::captured_sequence_with_cause(first, last, provenance, cause)
        .ok_or_else(|| allocation_error("invalid sequence completeness range"))?;
    guarded_push(output, range, context)
}

fn push_source_range(
    output: &mut Vec<CompletenessRange>,
    start: u64,
    end: u64,
    provenance: Provenance,
    cause: CompletenessCause,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    let range = CompletenessRange::source_bytes_with_cause(start, end, provenance, cause)
        .ok_or_else(|| allocation_error("invalid source completeness range"))?;
    guarded_push(output, range, context)
}

fn guarded_push<T>(
    output: &mut Vec<T>,
    value: T,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    context.guard.consume(WorkDelta {
        resident_bytes: (size_of::<T>() as u64).saturating_mul(4),
        ..WorkDelta::default()
    })?;
    guarded_push_without_charge(output, value)
}

fn guarded_push_without_charge<T>(output: &mut Vec<T>, value: T) -> Result<(), ProviderError> {
    if output.len() == output.capacity() {
        let additional = output.capacity().max(4);
        output
            .try_reserve_exact(additional)
            .map_err(|_| allocation_error("Flight recovery allocation failed"))?;
    }
    output.push(value);
    Ok(())
}

fn guarded_insert_without_charge<T>(
    output: &mut Vec<T>,
    index: usize,
    value: T,
) -> Result<(), ProviderError> {
    if output.len() == output.capacity() {
        let additional = output.capacity().max(4);
        output
            .try_reserve_exact(additional)
            .map_err(|_| allocation_error("Flight recovery allocation failed"))?;
    }
    output.insert(index, value);
    Ok(())
}

fn fallible_vec<T>(capacity: usize) -> Result<Vec<T>, ProviderError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| allocation_error("Flight recovery allocation failed"))?;
    Ok(output)
}

fn insert_sorted<T: Ord>(
    output: &mut Vec<T>,
    value: T,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    context.guard.consume(WorkDelta {
        resident_bytes: (size_of::<T>() as u64).saturating_mul(4),
        ..WorkDelta::default()
    })?;
    let position = output
        .binary_search(&value)
        .unwrap_or_else(|position| position);
    if output.len() == output.capacity() {
        let additional = output.capacity().max(4);
        output
            .try_reserve_exact(additional)
            .map_err(|_| allocation_error("Flight recovery allocation failed"))?;
    }
    output.insert(position, value);
    Ok(())
}

fn indexed_offset(
    base: u64,
    index: u32,
    stride: u64,
    detail: &'static str,
) -> Result<u64, ProviderError> {
    u64::from(index)
        .checked_mul(stride)
        .and_then(|value| base.checked_add(value))
        .ok_or_else(|| allocation_error(detail))
}

fn allocation_error(detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(
        "source.flight.resource",
        "flight.recovery",
        None,
        false,
        detail,
    )
}

impl RecoveryContext<'_> {
    fn read_array<const N: usize>(
        &mut self,
        offset: u64,
        stage: &'static str,
        ordinal: Option<u64>,
    ) -> Result<[u8; N], ProviderError> {
        let mut output = [0; N];
        self.read_into(offset, &mut output, stage, ordinal)?;
        Ok(output)
    }

    fn read_into(
        &mut self,
        offset: u64,
        output: &mut [u8],
        stage: &'static str,
        ordinal: Option<u64>,
    ) -> Result<(), ProviderError> {
        self.guard.consume(WorkDelta {
            input_bytes: output.len() as u64,
            ..WorkDelta::default()
        })?;
        self.source.read_exact_at(offset, output).map_err(|error| {
            ProviderError::new(
                error.code(),
                stage,
                Some(SourceCoordinate {
                    offset,
                    record_ordinal: ordinal,
                }),
                error.retryable(),
                error.detail(),
            )
        })?;
        self.counters.input_bytes = self
            .counters
            .input_bytes
            .saturating_add(output.len() as u64);
        Ok(())
    }

    fn read_event_payload(
        &mut self,
        offset: u64,
        size: u32,
        coordinate: SourceCoordinate,
    ) -> Result<Vec<u8>, ProviderError> {
        let length = usize::try_from(size)
            .map_err(|_| record_error(coordinate, "payload does not fit this host"))?;
        self.guard.consume(WorkDelta {
            input_bytes: u64::from(size),
            events: 1,
            resident_bytes: u64::from(size)
                .saturating_add((size_of::<EventRecord>() as u64).saturating_mul(4)),
            ..WorkDelta::default()
        })?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| record_error(coordinate, "payload allocation failed"))?;
        output.resize(length, 0);
        self.source
            .read_exact_at(offset, &mut output)
            .map_err(|error| {
                ProviderError::new(
                    error.code(),
                    "flight.record",
                    Some(coordinate),
                    error.retryable(),
                    error.detail(),
                )
            })?;
        self.counters.input_bytes = self.counters.input_bytes.saturating_add(u64::from(size));
        Ok(output)
    }

    fn checksum_region(&mut self, offset: u64, size: u64) -> Result<u32, ProviderError> {
        let mut checksum = FNV_OFFSET_BASIS;
        let mut relative = 0_u64;
        let mut buffer = [0_u8; 4096];
        while relative < size {
            self.guard.consume(WorkDelta::default())?;
            let remaining = size - relative;
            let amount = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| allocation_error("checksum block length overflow"))?;
            let destination = buffer
                .get_mut(..amount)
                .ok_or_else(|| allocation_error("checksum block bounds invalid"))?;
            self.read_into(
                offset + relative,
                destination,
                "flight.chunk.checksum",
                None,
            )?;
            checksum = fnv32_update(checksum, destination);
            relative = relative
                .checked_add(amount as u64)
                .ok_or_else(|| allocation_error("checksum cursor overflow"))?;
        }
        Ok(checksum)
    }
}
