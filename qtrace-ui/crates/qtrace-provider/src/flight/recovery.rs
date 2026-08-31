use std::{collections::HashMap, sync::Arc};

use crate::{
    CompletenessCause, CompletenessRange, Discontinuity, DiscontinuityCause, EventKey,
    EventPayload, EventRecord, MAX_UNGUARDED_RECORDS, OpaqueOptionalRecord, Provenance,
    ProviderCounters, ProviderError, RangeBounds, ReadAtSource, SourceCoordinate, TimelineId,
    WorkDelta, WorkGuard, allocation, completeness_canonical_key, merge_canonical_completeness,
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
    pub(super) final_registers: HashMap<u32, crate::RegisterSnapshot>,
    pub(super) termination: Option<crate::Termination>,
    pub(super) recovery_summary: super::FlightRecoverySummary,
}

#[derive(Clone, Copy)]
pub(super) struct ChunkIdentity {
    pub(super) tid: u32,
    pub(super) generation: u32,
    pub(super) state: u32,
}

#[derive(Clone, Copy)]
struct SequenceRange {
    first: u64,
    last: u64,
}

#[derive(Clone, Copy)]
struct SequenceFact {
    range: SequenceRange,
    coordinate: ProofCoordinate,
}

#[derive(Clone, Copy)]
struct MissingRange {
    range: SequenceRange,
    cause: CompletenessCause,
}

#[derive(Clone, Copy)]
struct SequenceProof {
    range: SequenceRange,
    cause: CompletenessCause,
    provenance: Provenance,
    coordinate: ProofCoordinate,
}

#[derive(Clone, Copy)]
enum ProofCoordinate {
    Source(u64),
    Eof,
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
    balance: i64,
    first_begin: u64,
}

struct RecordScan {
    events: Vec<EventRecord>,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    lifecycle_balance: i64,
    lifecycle_first_begin: Option<u64>,
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
    let metadata_delta = metadata_work(&superblock)?;
    context.guard.consume(metadata_delta)?;

    let chunk_capacity = usize::try_from(superblock.chunk_count)
        .map_err(|_| allocation_error("chunk count does not fit this host"))?;
    let mut directories = Vec::new();
    let mut chunks = fallible_none_vec(chunk_capacity, &context)?;
    let mut tids = Vec::new();
    let mut directory_by_tid = HashMap::new();
    let mut known_tids = HashMap::new();
    let mut hints = Vec::new();
    let mut completeness = Vec::new();
    let mut has_directory_uncertainty = false;
    let mut rotating_directory_entries = Vec::new();

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
            if directory_by_tid.contains_key(&entry.tid) {
                return Err(super::wire::directory_error(
                    offset,
                    "duplicate directory TID",
                ));
            }
            let directory_index = directories.len();
            allocation::try_reserve_hash_map(
                &mut directory_by_tid,
                1,
                context.guard,
                "Flight directory map allocation failed",
            )?;
            allocation::try_reserve_hash_map(
                &mut known_tids,
                1,
                context.guard,
                "Flight TID set allocation failed",
            )?;
            directory_by_tid.insert(entry.tid, directory_index);
            known_tids.insert(entry.tid, ());
            guarded_push(&mut tids, entry.tid, &context)?;
            if entry.range_reliable && entry.first_sequence != 0 {
                guarded_push(
                    &mut hints,
                    SequenceFact {
                        range: SequenceRange {
                            first: entry.first_sequence,
                            last: entry.last_sequence,
                        },
                        coordinate: ProofCoordinate::Source(offset),
                    },
                    &context,
                )?;
            }
            if entry.state == 2 {
                guarded_push(&mut rotating_directory_entries, entry.index, &context)?;
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
    let mut lifecycle = HashMap::new();
    let mut damage_ranges = Vec::new();
    let mut sequence_proofs = Vec::new();
    let mut has_damage = false;
    let mut has_incomplete = superblock.flags != 0 || has_directory_uncertainty;
    let mut active_chunks = Vec::new();
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
        if !directory_by_tid.contains_key(&header.tid) {
            return Err(super::wire::chunk_error(
                offset,
                "chunk TID has no directory owner",
            ));
        }
        let chunk_slot = usize::try_from(index)
            .ok()
            .and_then(|position| chunks.get_mut(position))
            .ok_or_else(|| super::wire::chunk_error(offset, "chunk index does not fit host"))?;
        *chunk_slot = Some(ChunkIdentity {
            tid: header.tid,
            generation: header.generation,
            state: header.state,
        });
        let capacity = u64::from(superblock.chunk_bytes)
            .checked_sub(FLIGHT_CHUNK_HEADER_BYTES as u64)
            .ok_or_else(|| super::wire::chunk_error(offset, "invalid chunk capacity"))?;
        let data_offset = offset
            .checked_add(FLIGHT_CHUNK_HEADER_BYTES as u64)
            .ok_or_else(|| super::wire::chunk_error(offset, "chunk data offset overflow"))?;

        if header.state == 2 {
            let header_range = valid_sealed_range(&header);
            if let Some(range) = header_range {
                guarded_push(
                    &mut hints,
                    SequenceFact {
                        range,
                        coordinate: ProofCoordinate::Source(offset),
                    },
                    &context,
                )?;
            }
            let committed = u64::from(header.committed_bytes);
            if committed > capacity || committed % 8 != 0 {
                mark_chunk_damage(
                    &mut completeness,
                    &mut damage_ranges,
                    &mut sequence_proofs,
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
                    &mut sequence_proofs,
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
                index,
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
                        &mut sequence_proofs,
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
                    &mut sequence_proofs,
                    header_range,
                    offset,
                    u64::from(superblock.chunk_bytes),
                    CompletenessCause::Incomplete,
                    &context,
                )?;
                has_damage = true;
                continue;
            }
            merge_lifecycle(
                &mut lifecycle,
                header.tid,
                scan.lifecycle_balance,
                scan.lifecycle_first_begin,
                &context,
            )?;
            append_events(&mut events, scan.events, &context)?;
        } else {
            guarded_push(&mut active_chunks, index, &context)?;
            push_source_range(
                &mut completeness,
                offset,
                data_offset,
                Provenance::Captured,
                CompletenessCause::Active,
                &context,
            )?;
            let scan = scan_records(
                &mut context,
                artifact,
                index,
                &header,
                data_offset,
                capacity,
                true,
            )?;
            merge_lifecycle(
                &mut lifecycle,
                header.tid,
                scan.lifecycle_balance,
                scan.lifecycle_first_begin,
                &context,
            )?;
            append_events(&mut events, scan.events, &context)?;
        }
    }

    let mut stale_directory_entries = Vec::new();
    for (index, entry) in directories.iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        if entry.state == 2 || entry.chunk_index == INVALID_INDEX {
            continue;
        }
        let current = usize::try_from(entry.chunk_index)
            .ok()
            .and_then(|position| chunks.get(position))
            .and_then(Option::as_ref);
        if !current.is_some_and(|chunk| {
            chunk.tid == entry.tid
                && chunk.generation == entry.generation
                && matches!(chunk.state, 1 | 2)
        }) {
            guarded_push(&mut stale_directory_entries, entry.index, &context)?;
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

    let regular_sequences = index_regular_sequences(&events, &context)?;
    let emergency_status = scan_emergencies(
        &mut context,
        &superblock,
        artifact,
        &mut events,
        &mut completeness,
        &mut tids,
        &mut known_tids,
        &regular_sequences,
    )?;
    events = guarded_radix_sort(events, 8, event_sequence_byte, &context)?;
    events = resolve_sequence_collisions(
        events,
        superblock.emergencies.offset,
        superblock.emergencies.end,
        &mut completeness,
        &context,
    )?;
    tids = guarded_radix_sort(tids, 4, u32_byte, &context)?;
    has_damage |= emergency_status.has_damage;
    has_incomplete |= emergency_status.has_incomplete;
    let mut has_coverage = emergency_status.has_coverage;
    for (index, event) in events.iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
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
            guarded_push(
                &mut sequence_proofs,
                SequenceProof {
                    range: SequenceRange {
                        first: sequence,
                        last: sequence,
                    },
                    cause: CompletenessCause::CoverageGap,
                    provenance: Provenance::Captured,
                    coordinate: ProofCoordinate::Source(event.key.source_offset),
                },
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
    for (index, tid) in tids.iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        let Some(item) = lifecycle.get(tid) else {
            continue;
        };
        if item.balance > 0 {
            push_sequence_range(
                &mut completeness,
                item.first_begin,
                item.first_begin,
                Provenance::Unknown,
                CompletenessCause::UnterminatedThread,
                &context,
            )?;
            guarded_push(
                &mut sequence_proofs,
                SequenceProof {
                    range: SequenceRange {
                        first: item.first_begin,
                        last: item.first_begin,
                    },
                    cause: CompletenessCause::UnterminatedThread,
                    provenance: Provenance::Unknown,
                    coordinate: ProofCoordinate::Eof,
                },
                &context,
            )?;
            has_incomplete = true;
        }
    }

    damage_ranges = guarded_radix_sort(damage_ranges, 16, sequence_range_byte, &context)?;
    hints = guarded_radix_sort(hints, 8, sequence_fact_byte, &context)?;
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
        &mut sequence_proofs,
        &context,
    )?;
    let decoded = super::events::decode(events, &superblock, &chunks, artifact, context.guard)?;
    events = decoded.events;
    let decoded_damage_count = decoded.damaged_sequences.len();
    let completeness_target = completeness
        .len()
        .checked_add(decoded_damage_count)
        .ok_or_else(|| allocation_error("decoded completeness count overflow"))?;
    allocation::try_reserve_vec_exact(
        &mut completeness,
        completeness_target,
        context.guard,
        "Flight decoded completeness allocation failed",
    )?;
    let proofs_target = sequence_proofs
        .len()
        .checked_add(decoded_damage_count)
        .ok_or_else(|| allocation_error("decoded proof count overflow"))?;
    allocation::try_reserve_vec_exact(
        &mut sequence_proofs,
        proofs_target,
        context.guard,
        "Flight decoded proof allocation failed",
    )?;
    for (index, sequence) in decoded.damaged_sequences.iter().copied().enumerate() {
        guard_checkpoint(context.guard, index)?;
        let evidence = CompletenessRange::captured_sequence_with_cause(
            sequence,
            sequence,
            Provenance::Damaged,
            CompletenessCause::Incomplete,
        )
        .ok_or_else(|| allocation_error("invalid decoded damage sequence range"))?;
        guarded_push_without_charge(&mut completeness, evidence)?;
        if let Some(source_offset) = decoded.damaged_source_offsets.get(index).copied() {
            guarded_push_without_charge(
                &mut sequence_proofs,
                SequenceProof {
                    range: SequenceRange {
                        first: sequence,
                        last: sequence,
                    },
                    cause: CompletenessCause::Incomplete,
                    provenance: Provenance::Damaged,
                    coordinate: ProofCoordinate::Source(source_offset),
                },
            )?;
        }
    }
    let mut damaged_source_offsets = fallible_vec(decoded.damaged_source_offsets.len(), &context)?;
    for (index, offset) in decoded.damaged_source_offsets.iter().copied().enumerate() {
        guard_checkpoint(context.guard, index)?;
        damaged_source_offsets.push(offset);
    }
    damaged_source_offsets = guarded_radix_sort(damaged_source_offsets, 8, u64_byte, &context)?;
    let mut previous_chunk = None;
    for (index, offset) in damaged_source_offsets.into_iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        let chunk_index =
            offset.saturating_sub(superblock.chunks.offset) / u64::from(superblock.chunk_bytes);
        if previous_chunk == Some(chunk_index) {
            continue;
        }
        previous_chunk = Some(chunk_index);
        let start = superblock
            .chunks
            .offset
            .saturating_add(chunk_index.saturating_mul(u64::from(superblock.chunk_bytes)));
        push_source_range(
            &mut completeness,
            start,
            start.saturating_add(u64::from(superblock.chunk_bytes)),
            Provenance::Damaged,
            CompletenessCause::Incomplete,
            &context,
        )?;
    }
    has_damage |= !decoded.damaged_sequences.is_empty();
    normalize_completeness(&mut completeness, &context)?;
    add_discontinuity_events(
        &mut events,
        &completeness,
        &sequence_proofs,
        artifact,
        source_size,
        &mut context,
    )?;
    context.counters.events_emitted = events.len() as u64;
    context.counters.opaque_records = 0;
    for (index, event) in events.iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        if matches!(event.payload, EventPayload::OpaqueOptional(_)) {
            context.counters.opaque_records = context.counters.opaque_records.saturating_add(1);
        }
    }
    context.counters.damaged_records = context
        .counters
        .damaged_records
        .saturating_add(decoded.damaged_sequences.len() as u64);
    active_chunks = guarded_radix_sort(active_chunks, 4, u32_byte, &context)?;
    stale_directory_entries = guarded_radix_sort(stale_directory_entries, 4, u32_byte, &context)?;
    rotating_directory_entries =
        guarded_radix_sort(rotating_directory_entries, 4, u32_byte, &context)?;
    let complete = superblock.flags == 0
        && !has_damage
        && !has_coverage
        && stale_directory_entries.is_empty()
        && decoded.damaged_sequences.is_empty();
    Ok(RecoveredFlight {
        source_bytes: source_size,
        events,
        tids,
        completeness,
        counters: context.counters,
        final_registers: decoded.final_registers,
        termination: decoded.termination,
        recovery_summary: super::FlightRecoverySummary {
            format_version: 2,
            run_id: superblock.run_id,
            pid: superblock.pid,
            module_generation: superblock.module_generation,
            target_module: super::fallible_string(
                std::str::from_utf8(&superblock.target[..usize::from(superblock.target_len)])
                    .map_err(|_| {
                        super::wire::superblock_error("invalid validated Flight target")
                    })?,
                context.guard,
            )?,
            pointer_width: superblock.pointer_width,
            artifact_flags: superblock.flags,
            complete,
            active_chunks,
            stale_directory_entries,
            rotating_directory_entries,
            target_pcs: decoded.target_pcs,
        },
    })
}

fn add_discontinuity_events(
    events: &mut Vec<EventRecord>,
    completeness: &[CompletenessRange],
    sequence_proofs: &[SequenceProof],
    artifact: crate::ArtifactDigest,
    artifact_bytes: u64,
    context: &mut RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    let evidence_capacity = completeness
        .len()
        .checked_add(sequence_proofs.len())
        .ok_or_else(|| allocation_error("discontinuity evidence count overflow"))?;
    let evidence_delta = WorkDelta {
        events: evidence_capacity as u64,
        nodes: evidence_capacity as u64,
        ..WorkDelta::default()
    };
    context.guard.consume(evidence_delta)?;
    let mut proof_ranges = fallible_vec(sequence_proofs.len(), context)?;
    for (index, proof) in sequence_proofs.iter().copied().enumerate() {
        guard_checkpoint(context.guard, index)?;
        let evidence = CompletenessRange::captured_sequence_with_cause(
            proof.range.first,
            proof.range.last,
            proof.provenance,
            proof.cause,
        )
        .ok_or_else(|| allocation_error("invalid discontinuity proof range"))?;
        proof_ranges.push(evidence);
    }
    normalize_completeness(&mut proof_ranges, context)?;
    let mut proof_coverage = fallible_hash_map(proof_ranges.len(), context)?;
    for (index, range) in proof_ranges.into_iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        proof_coverage.insert(range, ());
    }
    for (index, evidence) in completeness.iter().copied().enumerate() {
        guard_checkpoint(context.guard, index)?;
        if evidence.cause() == CompletenessCause::Retained {
            continue;
        }
        if matches!(evidence.bounds(), RangeBounds::InclusiveSequence { .. })
            && proof_coverage.contains_key(&evidence)
        {
            continue;
        }
        let source_offset = match evidence.bounds() {
            RangeBounds::HalfOpen { start, .. } => start,
            RangeBounds::InclusiveSequence { .. } => {
                return Err(allocation_error(
                    "sequence discontinuity lacks a physical proof coordinate",
                ));
            }
        };
        push_discontinuity(events, evidence, source_offset, artifact, context)?;
    }
    for (index, proof) in sequence_proofs.iter().copied().enumerate() {
        guard_checkpoint(context.guard, index)?;
        let evidence = CompletenessRange::captured_sequence_with_cause(
            proof.range.first,
            proof.range.last,
            proof.provenance,
            proof.cause,
        )
        .ok_or_else(|| allocation_error("invalid discontinuity proof range"))?;
        let source_offset = match proof.coordinate {
            ProofCoordinate::Source(offset) => offset,
            ProofCoordinate::Eof => artifact_bytes,
        };
        push_discontinuity(events, evidence, source_offset, artifact, context)?;
    }
    Ok(())
}

fn push_discontinuity(
    events: &mut Vec<EventRecord>,
    evidence: CompletenessRange,
    source_offset: u64,
    artifact: crate::ArtifactDigest,
    context: &mut RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    let cause = match evidence.cause() {
        CompletenessCause::Lost => DiscontinuityCause::Loss,
        CompletenessCause::Overwritten => DiscontinuityCause::Overwrite,
        CompletenessCause::Checksum => DiscontinuityCause::Damage,
        CompletenessCause::Truncation => DiscontinuityCause::Truncation,
        _ => DiscontinuityCause::Unknown,
    };
    let key = EventKey::new(
        artifact,
        MERGED_TIMELINE_ID,
        context.next_ordinal,
        source_offset,
        None,
        None,
    );
    context.next_ordinal = context
        .next_ordinal
        .checked_add(1)
        .ok_or_else(|| allocation_error("discontinuity ordinal overflow"))?;
    guarded_push(
        events,
        EventRecord::new(
            key,
            evidence.provenance(),
            EventPayload::Discontinuity(Discontinuity { cause, evidence }),
        ),
        context,
    )
}

fn metadata_work(superblock: &Superblock) -> Result<WorkDelta, ProviderError> {
    let nodes = u64::from(superblock.directory_entries)
        .checked_add(u64::from(superblock.chunk_count))
        .and_then(|value| value.checked_add(u64::from(superblock.emergency_count)))
        .ok_or_else(|| allocation_error("Flight metadata node count overflow"))?;
    Ok(WorkDelta {
        nodes,
        ..WorkDelta::default()
    })
}

fn scan_records(
    context: &mut RecoveryContext<'_>,
    artifact: crate::ArtifactDigest,
    chunk_index: u32,
    header: &ChunkHeader,
    data_offset: u64,
    limit: u64,
    active: bool,
) -> Result<RecordScan, ProviderError> {
    let mut events = Vec::new();
    let mut lifecycle_balance = 0_i64;
    let mut lifecycle_first_begin = None;
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
        let event = EventRecord::new_scoped(
            key,
            Provenance::Captured,
            crate::EventScope::FlightChunk {
                chunk_index,
                generation: header.generation,
                tid: header.tid,
            },
            EventPayload::OpaqueOptional(OpaqueOptionalRecord {
                record_type: record.kind,
                flags: record.flags,
                bytes: payload,
            }),
        );
        guarded_push(&mut events, event, context)?;
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
            &mut lifecycle_balance,
            &mut lifecycle_first_begin,
            record.kind,
            record.sequence,
        );
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
        lifecycle_balance,
        lifecycle_first_begin,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_emergencies(
    context: &mut RecoveryContext<'_>,
    superblock: &Superblock,
    artifact: crate::ArtifactDigest,
    events: &mut Vec<EventRecord>,
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
            guarded_push(events, event, context)?;
            context.counters.records_seen = context.counters.records_seen.saturating_add(1);
        }
    }
    Ok(status)
}

fn index_regular_sequences(
    events: &[EventRecord],
    context: &RecoveryContext<'_>,
) -> Result<HashMap<u64, ()>, ProviderError> {
    let mut sequences = fallible_hash_map(events.len(), context)?;
    for (index, event) in events.iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        let sequence = event
            .key
            .sequence
            .ok_or_else(|| allocation_error("Flight event has no sequence"))?;
        if sequences.insert(sequence, ()).is_some() {
            return Err(ProviderError::new(
                "source.flight.sequence",
                "flight.recovery",
                Some(SourceCoordinate {
                    offset: event.key.source_offset,
                    record_ordinal: Some(event.key.record_ordinal),
                }),
                false,
                "duplicate Flight global sequence",
            ));
        }
    }
    Ok(sequences)
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
    hints: &[SequenceFact],
    damage_ranges: &[SequenceRange],
    status: RecoveryStatus,
    completeness: &mut Vec<CompletenessRange>,
    sequence_proofs: &mut Vec<SequenceProof>,
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
    for (index, hint) in hints.iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        first = first.min(hint.range.first);
        last = last.max(hint.range.last);
    }
    if first == u64::MAX && last == 0 {
        return Ok(());
    }

    let mut retained_start = None;
    let mut retained_last = 0;
    for (index, event) in events.iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
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
    let mut damage_index = 0_usize;
    let mut damage_steps = 0_usize;
    let mut missing_ranges = Vec::new();
    for (index, event) in events.iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
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
                &mut damage_index,
                &mut damage_steps,
                missing_cause,
                completeness,
                &mut missing_ranges,
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
                &mut damage_index,
                &mut damage_steps,
                missing_cause,
                completeness,
                &mut missing_ranges,
                context,
            )?;
        }
    }
    add_missing_proofs(&missing_ranges, hints, sequence_proofs, context)
}

#[allow(clippy::too_many_arguments)]
fn add_missing_without_damage(
    first: u64,
    last: u64,
    damage_ranges: &[SequenceRange],
    damage_index: &mut usize,
    damage_steps: &mut usize,
    cause: CompletenessCause,
    completeness: &mut Vec<CompletenessRange>,
    missing_ranges: &mut Vec<MissingRange>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    let mut cursor = Some(first);
    while let Some(damage) = damage_ranges.get(*damage_index) {
        let Some(current) = cursor else {
            break;
        };
        if damage.last < current {
            guard_checkpoint(context.guard, *damage_steps)?;
            *damage_steps = damage_steps
                .checked_add(1)
                .ok_or_else(|| allocation_error("damage sweep work overflow"))?;
            *damage_index = damage_index
                .checked_add(1)
                .ok_or_else(|| allocation_error("damage sweep index overflow"))?;
            continue;
        }
        if damage.first > last {
            break;
        }
        if damage.first > current {
            push_missing_range(
                completeness,
                current,
                damage.first - 1,
                cause,
                missing_ranges,
                context,
            )?;
        }
        cursor = damage.last.checked_add(1);
        if damage.last > last {
            break;
        }
        guard_checkpoint(context.guard, *damage_steps)?;
        *damage_steps = damage_steps
            .checked_add(1)
            .ok_or_else(|| allocation_error("damage sweep work overflow"))?;
        *damage_index = damage_index
            .checked_add(1)
            .ok_or_else(|| allocation_error("damage sweep index overflow"))?;
    }
    if let Some(current) = cursor {
        if current <= last {
            push_missing_range(completeness, current, last, cause, missing_ranges, context)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_missing_range(
    completeness: &mut Vec<CompletenessRange>,
    first: u64,
    last: u64,
    cause: CompletenessCause,
    missing_ranges: &mut Vec<MissingRange>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    push_sequence_range(
        completeness,
        first,
        last,
        Provenance::Unknown,
        cause,
        context,
    )?;
    guarded_push(
        missing_ranges,
        MissingRange {
            range: SequenceRange { first, last },
            cause,
        },
        context,
    )
}

fn add_missing_proofs(
    missing: &[MissingRange],
    facts: &[SequenceFact],
    output: &mut Vec<SequenceProof>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    context.guard.consume(WorkDelta {
        nodes: facts.len() as u64,
        ..WorkDelta::default()
    })?;
    let mut first_candidate = 0_usize;
    let mut steps = 0_usize;
    for fact in facts {
        guard_checkpoint(context.guard, steps)?;
        steps = steps
            .checked_add(1)
            .ok_or_else(|| allocation_error("sequence proof work overflow"))?;
        while missing
            .get(first_candidate)
            .is_some_and(|range| range.range.last < fact.range.first)
        {
            guard_checkpoint(context.guard, steps)?;
            steps = steps
                .checked_add(1)
                .ok_or_else(|| allocation_error("sequence proof work overflow"))?;
            first_candidate = first_candidate
                .checked_add(1)
                .ok_or_else(|| allocation_error("sequence proof index overflow"))?;
        }
        for range in &missing[first_candidate..] {
            guard_checkpoint(context.guard, steps)?;
            steps = steps
                .checked_add(1)
                .ok_or_else(|| allocation_error("sequence proof work overflow"))?;
            if range.range.first > fact.range.last {
                break;
            }
            let first = range.range.first.max(fact.range.first);
            let last = range.range.last.min(fact.range.last);
            guarded_push(
                output,
                SequenceProof {
                    range: SequenceRange { first, last },
                    cause: range.cause,
                    provenance: Provenance::Unknown,
                    coordinate: fact.coordinate,
                },
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
    sequence_proofs: &mut Vec<SequenceProof>,
    range: Option<SequenceRange>,
    offset: u64,
    chunk_bytes: u64,
    cause: CompletenessCause,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    if let Some(range) = range {
        guarded_push(
            sequence_proofs,
            SequenceProof {
                range,
                cause,
                provenance: Provenance::Damaged,
                coordinate: ProofCoordinate::Source(offset),
            },
            context,
        )?;
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

fn update_lifecycle(balance: &mut i64, first_begin: &mut Option<u64>, kind: u16, sequence: u64) {
    let delta = match kind {
        2 => 1,
        3 => -1,
        _ => return,
    };
    *balance = balance.saturating_add(delta);
    if delta > 0 && *balance == delta {
        *first_begin = Some(sequence);
    }
}

fn merge_lifecycle(
    target: &mut HashMap<u32, LifecycleBalance>,
    tid: u32,
    incoming_balance: i64,
    incoming_first_begin: Option<u64>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    if incoming_balance == 0 && incoming_first_begin.is_none() {
        return Ok(());
    }
    if !target.contains_key(&tid) {
        allocation::try_reserve_hash_map(
            target,
            1,
            context.guard,
            "Flight lifecycle allocation failed",
        )?;
    }
    match target.entry(tid) {
        std::collections::hash_map::Entry::Occupied(mut occupied) => {
            let item = occupied.get_mut();
            if item.balance <= 0 && incoming_balance > 0 {
                item.first_begin = incoming_first_begin.unwrap_or(0);
            }
            item.balance = item.balance.saturating_add(incoming_balance);
        }
        std::collections::hash_map::Entry::Vacant(vacant) => {
            vacant.insert(LifecycleBalance {
                balance: incoming_balance,
                first_begin: incoming_first_begin.unwrap_or(0),
            });
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
        guarded_push(target, event, context)?;
    }
    Ok(())
}

fn resolve_sequence_collisions(
    events: Vec<EventRecord>,
    emergency_start: u64,
    emergency_end: u64,
    completeness: &mut Vec<CompletenessRange>,
    context: &RecoveryContext<'_>,
) -> Result<Vec<EventRecord>, ProviderError> {
    let mut output = fallible_vec(events.len(), context)?;
    let mut sequence = None;
    let mut regular = None;
    let mut emergency = None;
    for (index, event) in events.into_iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        let current = event
            .key
            .sequence
            .ok_or_else(|| allocation_error("Flight event has no sequence"))?;
        if sequence.is_some_and(|value| value != current) {
            flush_sequence_group(&mut output, regular, emergency, completeness, context)?;
            regular = None;
            emergency = None;
        }
        sequence = Some(current);
        let from_emergency =
            event.key.source_offset >= emergency_start && event.key.source_offset < emergency_end;
        let slot = if from_emergency {
            &mut emergency
        } else {
            &mut regular
        };
        if slot.is_some() {
            return Err(ProviderError::new(
                "source.flight.sequence",
                "flight.recovery",
                Some(SourceCoordinate {
                    offset: event.key.source_offset,
                    record_ordinal: Some(event.key.record_ordinal),
                }),
                false,
                "duplicate Flight global sequence",
            ));
        }
        *slot = Some(event);
    }
    flush_sequence_group(&mut output, regular, emergency, completeness, context)?;
    Ok(output)
}

fn flush_sequence_group(
    output: &mut Vec<EventRecord>,
    regular: Option<EventRecord>,
    emergency: Option<EventRecord>,
    completeness: &mut Vec<CompletenessRange>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    match (regular, emergency) {
        (Some(regular), Some(emergency)) => {
            push_source_range(
                completeness,
                emergency.key.source_offset,
                emergency
                    .key
                    .source_offset
                    .saturating_add(FLIGHT_EMERGENCY_RECORD_BYTES as u64),
                Provenance::Unknown,
                CompletenessCause::Stale,
                context,
            )?;
            guarded_push(output, regular, context)
        }
        (Some(event), None) | (None, Some(event)) => guarded_push(output, event, context),
        (None, None) => Ok(()),
    }
}

fn normalize_completeness(
    ranges: &mut Vec<CompletenessRange>,
    context: &RecoveryContext<'_>,
) -> Result<(), ProviderError> {
    let sorted = guarded_radix_sort(std::mem::take(ranges), 19, completeness_byte, context)?;
    *ranges = sorted;
    let mut output = fallible_vec(ranges.len(), context)?;
    for (index, range) in ranges.drain(..).enumerate() {
        guard_checkpoint(context.guard, index)?;
        if let Some(previous) = output.last().copied() {
            if let Some(merged) = merge_canonical_completeness(previous, range) {
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

fn event_sequence_byte(event: &EventRecord, pass: usize) -> Result<u8, ProviderError> {
    let sequence = event
        .key
        .sequence
        .ok_or_else(|| allocation_error("Flight event has no sequence"))?;
    byte_at(&sequence.to_le_bytes(), pass)
}

fn u32_byte(value: &u32, pass: usize) -> Result<u8, ProviderError> {
    byte_at(&value.to_le_bytes(), pass)
}

fn u64_byte(value: &u64, pass: usize) -> Result<u8, ProviderError> {
    byte_at(&value.to_le_bytes(), pass)
}

fn sequence_range_byte(range: &SequenceRange, pass: usize) -> Result<u8, ProviderError> {
    if pass < 8 {
        byte_at(&range.last.to_le_bytes(), pass)
    } else {
        byte_at(&range.first.to_le_bytes(), pass - 8)
    }
}

fn sequence_fact_byte(fact: &SequenceFact, pass: usize) -> Result<u8, ProviderError> {
    byte_at(&fact.range.first.to_le_bytes(), pass)
}

fn completeness_byte(range: &CompletenessRange, pass: usize) -> Result<u8, ProviderError> {
    let (domain, cause, first, last, provenance) = completeness_canonical_key(range);
    match pass {
        0 => Ok(provenance),
        1..=8 => byte_at(&last.to_le_bytes(), pass - 1),
        9..=16 => byte_at(&first.to_le_bytes(), pass - 9),
        17 => Ok(cause),
        18 => Ok(domain),
        _ => Err(allocation_error("invalid completeness radix pass")),
    }
}

fn byte_at(bytes: &[u8], index: usize) -> Result<u8, ProviderError> {
    bytes
        .get(index)
        .copied()
        .ok_or_else(|| allocation_error("invalid radix byte index"))
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
    allocation::try_push_vec(output, value, context.guard, "Flight vector growth failed")
}

fn guarded_push_without_charge<T>(output: &mut Vec<T>, value: T) -> Result<(), ProviderError> {
    if output.len() == output.capacity() {
        return Err(allocation_error(
            "Flight fixed-capacity vector count mismatch",
        ));
    }
    output.push(value);
    Ok(())
}

fn fallible_vec<T>(
    capacity: usize,
    context: &RecoveryContext<'_>,
) -> Result<Vec<T>, ProviderError> {
    allocation::try_vec_with_capacity(capacity, context.guard, "Flight recovery allocation failed")
}

fn fallible_none_vec<T>(
    length: usize,
    context: &RecoveryContext<'_>,
) -> Result<Vec<Option<T>>, ProviderError> {
    let mut output = fallible_vec(length, context)?;
    for index in 0..length {
        guard_checkpoint(context.guard, index)?;
        output.push(None);
    }
    Ok(output)
}

fn fallible_hash_map<K, V>(
    capacity: usize,
    context: &RecoveryContext<'_>,
) -> Result<HashMap<K, V>, ProviderError>
where
    K: Eq + std::hash::Hash,
{
    allocation::try_hash_map_with_capacity(
        capacity,
        context.guard,
        "Flight recovery hash allocation failed",
    )
}

fn guarded_radix_sort<T, F>(
    values: Vec<T>,
    passes: usize,
    key_byte: F,
    context: &RecoveryContext<'_>,
) -> Result<Vec<T>, ProviderError>
where
    F: Fn(&T, usize) -> Result<u8, ProviderError>,
{
    if values.len() < 2 {
        return Ok(values);
    }
    let length = values.len();
    let mut input = fallible_vec(length, context)?;
    for (index, value) in values.into_iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        input.push(Some(value));
    }
    let mut scratch = fallible_none_vec(length, context)?;

    for pass in 0..passes {
        let mut counts = [0_usize; 256];
        for (index, item) in input.iter().enumerate() {
            guard_checkpoint(context.guard, index)?;
            let value = item
                .as_ref()
                .ok_or_else(|| allocation_error("radix input slot is empty"))?;
            let bucket = usize::from(key_byte(value, pass)?);
            let count = counts
                .get_mut(bucket)
                .ok_or_else(|| allocation_error("radix count bucket is invalid"))?;
            *count = count
                .checked_add(1)
                .ok_or_else(|| allocation_error("radix bucket count overflow"))?;
        }

        let mut positions = [0_usize; 256];
        let mut cursor = 0_usize;
        for (bucket, count) in counts.iter().copied().enumerate() {
            let position = positions
                .get_mut(bucket)
                .ok_or_else(|| allocation_error("radix position bucket is invalid"))?;
            *position = cursor;
            cursor = cursor
                .checked_add(count)
                .ok_or_else(|| allocation_error("radix position overflow"))?;
        }
        if cursor != length {
            return Err(allocation_error("radix item count mismatch"));
        }

        for (index, item) in input.iter_mut().enumerate() {
            guard_checkpoint(context.guard, index)?;
            let value = item
                .take()
                .ok_or_else(|| allocation_error("radix input slot is empty"))?;
            let bucket = usize::from(key_byte(&value, pass)?);
            let position = positions
                .get_mut(bucket)
                .ok_or_else(|| allocation_error("radix position bucket is invalid"))?;
            let destination = *position;
            *position = position
                .checked_add(1)
                .ok_or_else(|| allocation_error("radix destination overflow"))?;
            let slot = scratch
                .get_mut(destination)
                .ok_or_else(|| allocation_error("radix destination is invalid"))?;
            if slot.is_some() {
                return Err(allocation_error("radix destination is occupied"));
            }
            *slot = Some(value);
        }
        std::mem::swap(&mut input, &mut scratch);
    }

    let mut output = fallible_vec(length, context)?;
    for (index, item) in input.into_iter().enumerate() {
        guard_checkpoint(context.guard, index)?;
        output.push(item.ok_or_else(|| allocation_error("radix output slot is empty"))?);
    }
    Ok(output)
}

fn guard_checkpoint(guard: &dyn WorkGuard, index: usize) -> Result<(), ProviderError> {
    let interval = usize::try_from(MAX_UNGUARDED_RECORDS)
        .map_err(|_| allocation_error("Flight checkpoint interval does not fit host"))?;
    if index % interval == 0 {
        guard.consume(WorkDelta::default())?;
    }
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
            ..WorkDelta::default()
        })?;
        let mut output = Vec::new();
        allocation::try_reserve_vec_exact(
            &mut output,
            length,
            self.guard,
            "Flight payload allocation failed",
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactDigest, ByteSource, OperationAbort};

    struct AllowAll;

    impl WorkGuard for AllowAll {
        fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
            Ok(())
        }
    }

    #[test]
    fn proof_for_one_range_does_not_cover_an_unproved_range_in_the_same_domain() {
        let source = ByteSource::new(Vec::<u8>::new());
        let guard = AllowAll;
        let mut context = RecoveryContext {
            source: &source,
            guard: &guard,
            counters: ProviderCounters::default(),
            next_ordinal: 0,
        };
        let completeness = vec![
            CompletenessRange::captured_sequence_with_cause(
                10,
                11,
                Provenance::Unknown,
                CompletenessCause::Lost,
            )
            .expect("valid range"),
            CompletenessRange::captured_sequence_with_cause(
                20,
                21,
                Provenance::Unknown,
                CompletenessCause::Lost,
            )
            .expect("valid range"),
        ];
        let proofs = [SequenceProof {
            range: SequenceRange {
                first: 10,
                last: 11,
            },
            cause: CompletenessCause::Lost,
            provenance: Provenance::Unknown,
            coordinate: ProofCoordinate::Source(4096),
        }];

        let error = add_discontinuity_events(
            &mut Vec::new(),
            &completeness,
            &proofs,
            ArtifactDigest::new([0; 32]),
            8192,
            &mut context,
        )
        .expect_err("the unrelated range has no physical proof");

        assert_eq!(error.code(), "source.flight.resource");
    }
}
