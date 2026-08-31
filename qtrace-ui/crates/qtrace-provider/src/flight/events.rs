use std::{collections::HashMap, sync::Arc};

use crate::qtrb::events::{
    BeginMetadata, InstructionDefinition, TerminalMetrics, Termination, TerminationIntent,
    TerminationKind, TraceProfile, decode_instruction_definition_record, decode_instruction_record,
    decode_memory_record,
};
use crate::{
    AllocationScope, CoverageGap, EventKey, EventPayload, EventRecord, EventScope,
    OpaqueOptionalRecord, Provenance, ProviderError, RegisterCheckpoint, RegisterDelta,
    RegisterSlot, RegisterSnapshot, RegisterValue, SemanticEvent, Signal, SignalHandlerBoundary,
    SignalHandlerPhase, SourceCoordinate, StringDefinition, Syscall, ThreadLifecycle,
    ThreadLifecyclePhase, WorkDelta, WorkGuard,
};

use super::{
    fragments::{self, Fragment},
    recovery::ChunkIdentity,
    wire::Superblock,
};

pub(super) struct DecodedFlight {
    pub(super) events: Vec<EventRecord>,
    pub(super) final_registers: HashMap<u32, RegisterSnapshot>,
    pub(super) target_pcs: Vec<u64>,
    pub(super) termination: Option<Termination>,
    pub(super) damaged_sequences: Vec<u64>,
    pub(super) damaged_source_offsets: Vec<u64>,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum PrefixState {
    #[default]
    ExpectBegin,
    ExpectCheckpoint,
    Ready,
    Broken,
}

#[derive(Default)]
struct ChunkState {
    prefix: PrefixState,
    prefix_damage_recorded: bool,
    module_base: u64,
    strings: HashMap<u32, Arc<[u8]>>,
    definitions: HashMap<u32, InstructionDefinition>,
    registers: Option<RegisterSnapshot>,
}

pub(super) fn decode(
    physical: Vec<EventRecord>,
    superblock: &Superblock,
    chunks: &[Option<ChunkIdentity>],
    artifact: crate::ArtifactDigest,
    guard: &dyn WorkGuard,
) -> Result<DecodedFlight, ProviderError> {
    guard.consume(WorkDelta::default())?;
    let mut payload_bytes = 0_u64;
    let mut definition_entries = 0_u64;
    let mut string_entries = 0_u64;
    let mut fragment_entries = 0_u64;
    for (index, event) in physical.iter().enumerate() {
        if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let EventPayload::OpaqueOptional(raw) = &event.payload {
            payload_bytes = payload_bytes
                .checked_add(raw.bytes.len() as u64)
                .ok_or_else(|| allocation_error("Flight payload allocation bound overflow"))?;
            definition_entries = definition_entries
                .checked_add(u64::from(matches!((raw.record_type, raw.flags), (4, 1))))
                .ok_or_else(|| allocation_error("Flight definition count overflow"))?;
            string_entries = string_entries
                .checked_add(u64::from(matches!((raw.record_type, raw.flags), (6, 3))))
                .ok_or_else(|| allocation_error("Flight string count overflow"))?;
            fragment_entries = fragment_entries
                .checked_add(u64::from(matches!(
                    (raw.record_type, raw.flags),
                    (6..=8, 4)
                )))
                .ok_or_else(|| allocation_error("Flight fragment count overflow"))?;
        }
    }
    // HashMap's first bucket group includes control bytes and alignment; charging sixty-four
    // complete entries per inserted closed record bounds that group plus every full geometric
    // reallocation request without a fixed per-event tax.
    let state_map_bytes = definition_entries
        .checked_mul(std::mem::size_of::<(u32, InstructionDefinition)>() as u64)
        .and_then(|bytes| bytes.checked_mul(64))
        .and_then(|bytes| {
            string_entries
                .checked_mul(std::mem::size_of::<(u32, Arc<[u8]>)>() as u64)
                .and_then(|string_bytes| string_bytes.checked_mul(64))
                .and_then(|string_bytes| bytes.checked_add(string_bytes))
        })
        .ok_or_else(|| allocation_error("Flight state-map allocation bound overflow"))?;
    let fixed_item_bytes = std::mem::size_of::<EventRecord>()
        .checked_add(std::mem::size_of::<Fragment>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u64>().saturating_mul(3)))
        .ok_or_else(|| allocation_error("Flight decode item layout overflow"))?;
    let fixed_decode_bytes = physical
        .len()
        .checked_mul(fixed_item_bytes)
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| allocation_error("Flight fixed decode allocation bound overflow"))?;
    let state_bytes = chunks
        .len()
        .checked_mul(std::mem::size_of::<ChunkState>())
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| allocation_error("Flight state allocation bound overflow"))?;
    let register_state_bytes = chunks
        .len()
        .checked_mul(RegisterSlot::COUNT)
        .and_then(|count| count.checked_mul(std::mem::size_of::<u64>()))
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| allocation_error("Flight register-state allocation bound overflow"))?;
    let fragment_item_bytes = std::mem::size_of::<Fragment>()
        .checked_add(std::mem::size_of::<EventRecord>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<(Option<u64>, u64)>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| allocation_error("Flight fragment item layout overflow"))?;
    let fragment_bytes = fragment_entries
        .checked_mul(fragment_item_bytes)
        .and_then(|bytes| bytes.checked_mul(64))
        .ok_or_else(|| allocation_error("Flight fragment allocation bound overflow"))?;
    let decode_work = WorkDelta {
        nodes: physical.len().saturating_mul(8) as u64,
        resident_bytes: fixed_decode_bytes
            .checked_add(state_bytes)
            .and_then(|bytes| bytes.checked_add(register_state_bytes))
            .and_then(|bytes| bytes.checked_add(payload_bytes.saturating_mul(4)))
            .and_then(|bytes| bytes.checked_add(state_map_bytes))
            .and_then(|bytes| bytes.checked_add(fragment_bytes))
            .ok_or_else(|| allocation_error("Flight decode allocation bound overflow"))?,
        ..WorkDelta::default()
    };
    let _decode_scope =
        AllocationScope::begin_with_delta(guard, decode_work, decode_work.resident_bytes)?;
    let mut states = initialize_states(chunks.len(), guard)?;
    let mut output = reserved_vec(physical.len(), "Flight typed output allocation failed")?;
    let mut fragments = reserved_vec(physical.len(), "Flight fragment allocation failed")?;
    let mut final_state: HashMap<u32, (u64, RegisterSnapshot)> = HashMap::new();
    final_state
        .try_reserve(chunks.len())
        .map_err(|_| allocation_error("Flight final-state allocation failed"))?;
    let mut target_pcs = reserved_vec(physical.len(), "Flight PC allocation failed")?;
    let mut termination = None;
    let mut damaged_sequences = reserved_vec(physical.len(), "Flight damage allocation failed")?;
    let mut damaged_source_offsets =
        reserved_vec(physical.len(), "Flight damage-offset allocation failed")?;

    for (position, event) in physical.into_iter().enumerate() {
        if position as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
            guard.consume(WorkDelta::default())?;
        }
        let coordinate = coordinate(&event);
        let sequence = event.key.sequence.unwrap_or(0);
        let tid = event.key.tid.unwrap_or(0);
        let scope = event.scope();
        let EventPayload::OpaqueOptional(raw) = event.payload else {
            output.push(event);
            continue;
        };
        let chunk_index = chunk_index(superblock, event.key.source_offset);
        if let Some(index) = chunk_index {
            let Some(identity) = chunks.get(index as usize).and_then(Option::as_ref) else {
                output.push(rewrap(event.key, event.provenance, scope, raw));
                continue;
            };
            let state = &mut states[index as usize];
            if matches!((raw.record_type, raw.flags), (4, 1)) {
                state
                    .definitions
                    .try_reserve(1)
                    .map_err(|_| allocation_error("Flight definition-state allocation failed"))?;
            }
            if matches!((raw.record_type, raw.flags), (6, 3)) {
                state
                    .strings
                    .try_reserve(1)
                    .map_err(|_| allocation_error("Flight string-state allocation failed"))?;
            }
            if state.prefix == PrefixState::ExpectBegin {
                if raw.record_type != 1 || raw.flags != 0 {
                    state.prefix = PrefixState::Broken;
                    record_prefix_damage(
                        state,
                        sequence,
                        event.key.source_offset,
                        &mut damaged_sequences,
                        &mut damaged_source_offsets,
                    );
                    output.push(rewrap(event.key, Provenance::Damaged, scope, raw));
                    continue;
                }
                match decode_begin(&raw.bytes, superblock, identity, index, coordinate) {
                    Ok(begin) => {
                        state.prefix = PrefixState::ExpectCheckpoint;
                        state.module_base = begin.module_base;
                        output.push(EventRecord::new_scoped(
                            event.key,
                            event.provenance,
                            scope,
                            EventPayload::Begin(begin),
                        ));
                    }
                    Err(_) => {
                        state.prefix = PrefixState::Broken;
                        record_prefix_damage(
                            state,
                            sequence,
                            event.key.source_offset,
                            &mut damaged_sequences,
                            &mut damaged_source_offsets,
                        );
                        output.push(rewrap(event.key, Provenance::Damaged, scope, raw));
                    }
                }
                continue;
            }
            if state.prefix == PrefixState::ExpectCheckpoint
                && !matches!((raw.record_type, raw.flags), (9, 1))
            {
                state.prefix = PrefixState::Broken;
                record_prefix_damage(
                    state,
                    sequence,
                    event.key.source_offset,
                    &mut damaged_sequences,
                    &mut damaged_source_offsets,
                );
                output.push(rewrap(event.key, Provenance::Damaged, scope, raw));
                continue;
            }
            if state.prefix == PrefixState::Ready && matches!((raw.record_type, raw.flags), (9, 1))
            {
                state.prefix = PrefixState::Broken;
                state.registers = None;
                final_state.remove(&tid);
                record_prefix_damage(
                    state,
                    sequence,
                    event.key.source_offset,
                    &mut damaged_sequences,
                    &mut damaged_source_offsets,
                );
                output.push(rewrap(event.key, Provenance::Damaged, scope, raw));
                continue;
            }
            if state.prefix == PrefixState::Broken {
                let damage_was_recorded = state.prefix_damage_recorded;
                record_prefix_damage(
                    state,
                    sequence,
                    event.key.source_offset,
                    &mut damaged_sequences,
                    &mut damaged_source_offsets,
                );
                if damage_was_recorded {
                    damaged_sequences.push(sequence);
                    damaged_source_offsets.push(event.key.source_offset);
                }
                if matches!((raw.record_type, raw.flags), (9, 0))
                    && let Ok(delta) = decode_delta(&raw.bytes, superblock.pointer_width, None)
                {
                    output.push(EventRecord::new_scoped(
                        event.key,
                        Provenance::Damaged,
                        scope,
                        EventPayload::RegisterDelta(delta),
                    ));
                } else {
                    output.push(rewrap(event.key, Provenance::Damaged, scope, raw));
                }
                continue;
            }
            let decoded = decode_chunk_record(
                raw,
                &event.key,
                event.provenance,
                scope,
                identity,
                index,
                state,
                superblock,
                &mut fragments,
                &mut target_pcs,
            );
            match decoded {
                Ok(Some(typed)) => {
                    if let Some(snapshot) = &state.registers {
                        let item = final_state.entry(tid).or_insert((0, snapshot.clone()));
                        if sequence >= item.0 {
                            *item = (sequence, snapshot.clone());
                        }
                    }
                    if typed.provenance == Provenance::Damaged {
                        damaged_sequences.push(sequence);
                        damaged_source_offsets.push(event.key.source_offset);
                    }
                    output.push(typed);
                }
                Ok(None) => {}
                Err(original) => {
                    if original.record_type == 9 {
                        state.registers = None;
                        state.prefix = PrefixState::Broken;
                        final_state.remove(&tid);
                    }
                    damaged_sequences.push(sequence);
                    damaged_source_offsets.push(event.key.source_offset);
                    output.push(rewrap(event.key, Provenance::Damaged, scope, original));
                }
            }
        } else if event.key.source_offset >= superblock.emergencies.offset
            && event.key.source_offset < superblock.emergencies.end
        {
            let typed = decode_emergency(raw, event.key, coordinate)?;
            if let EventPayload::CoverageGap(value) = &typed.payload {
                push_pc(&mut target_pcs, value.pc);
            }
            if let EventPayload::Signal(value) = &typed.payload {
                push_pc(&mut target_pcs, value.pc);
            }
            if let EventPayload::SignalHandlerBoundary(value) = &typed.payload {
                push_pc(&mut target_pcs, value.pc);
            }
            if let EventPayload::Termination(value) = &typed.payload {
                push_pc(
                    &mut target_pcs,
                    value.intent.as_ref().map_or(0, |item| item.pc),
                );
                termination = Some(value.clone());
            }
            output.push(typed);
        } else {
            output.push(rewrap(event.key, event.provenance, scope, raw));
        }
    }

    fragments::finish(
        fragments,
        artifact,
        &mut output,
        &mut damaged_sequences,
        &mut damaged_source_offsets,
        superblock,
        chunks,
        guard,
    )?;
    output = guarded_sort_events(output, guard)?;
    target_pcs = guarded_sort_u64(target_pcs, guard)?;
    let final_registers = finalize_registers(final_state, guard)?;
    Ok(DecodedFlight {
        events: output,
        final_registers,
        target_pcs,
        termination,
        damaged_sequences,
        damaged_source_offsets,
    })
}

fn initialize_states(
    count: usize,
    guard: &dyn WorkGuard,
) -> Result<Vec<ChunkState>, ProviderError> {
    let mut states = reserved_vec(count, "Flight chunk-state allocation failed")?;
    for index in 0..count {
        if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
            guard.consume(WorkDelta::default())?;
        }
        states.push(ChunkState::default());
    }
    Ok(states)
}

fn finalize_registers(
    states: HashMap<u32, (u64, RegisterSnapshot)>,
    guard: &dyn WorkGuard,
) -> Result<HashMap<u32, RegisterSnapshot>, ProviderError> {
    let resident_bytes = states
        .len()
        .checked_mul(std::mem::size_of::<(u32, RegisterSnapshot)>())
        .and_then(|bytes| bytes.checked_mul(4))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| allocation_error("Flight final-register size overflow"))?;
    guard.consume(WorkDelta {
        nodes: states.len() as u64,
        resident_bytes,
        ..WorkDelta::default()
    })?;
    let mut output = HashMap::new();
    output
        .try_reserve(states.len())
        .map_err(|_| allocation_error("Flight final-register allocation failed"))?;
    for (index, (tid, (_, state))) in states.into_iter().enumerate() {
        if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
            guard.consume(WorkDelta::default())?;
        }
        output.insert(tid, state);
    }
    Ok(output)
}

fn reserved_vec<T>(capacity: usize, message: &'static str) -> Result<Vec<T>, ProviderError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| allocation_error(message))?;
    Ok(output)
}

fn allocation_error(message: &'static str) -> ProviderError {
    ProviderError::new(
        "source.flight.allocation",
        "flight.events",
        None,
        false,
        message,
    )
}

fn record_prefix_damage(
    state: &mut ChunkState,
    sequence: u64,
    source_offset: u64,
    damaged_sequences: &mut Vec<u64>,
    damaged_source_offsets: &mut Vec<u64>,
) {
    if !state.prefix_damage_recorded {
        damaged_sequences.push(sequence);
        damaged_source_offsets.push(source_offset);
        state.prefix_damage_recorded = true;
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_chunk_record(
    raw: OpaqueOptionalRecord,
    key: &EventKey,
    provenance: Provenance,
    scope: EventScope,
    identity: &ChunkIdentity,
    chunk_index: u32,
    state: &mut ChunkState,
    superblock: &Superblock,
    fragments: &mut Vec<Fragment>,
    target_pcs: &mut Vec<u64>,
) -> Result<Option<EventRecord>, OpaqueOptionalRecord> {
    let coordinate = SourceCoordinate {
        offset: key.source_offset,
        record_ordinal: Some(key.record_ordinal),
    };
    let tid = identity.tid;
    let result = match (raw.record_type, raw.flags) {
        (9, 1) => decode_checkpoint(&raw.bytes, superblock.pointer_width)
            .map(|(checkpoint, snapshot)| {
                push_pc(target_pcs, snapshot.value(RegisterSlot::Pc).unwrap_or(0));
                state.registers = Some(snapshot);
                state.prefix = PrefixState::Ready;
                EventPayload::RegisterCheckpoint(checkpoint)
            })
            .map_err(|_| payload_error(coordinate, "invalid register checkpoint")),
        (9, 0) => decode_delta(
            &raw.bytes,
            superblock.pointer_width,
            state.registers.as_mut(),
        )
        .map(|delta| {
            if let Some(snapshot) = &state.registers {
                push_pc(target_pcs, snapshot.value(RegisterSlot::Pc).unwrap_or(0));
            }
            EventPayload::RegisterDelta(delta)
        })
        .map_err(|_| payload_error(coordinate, "invalid register delta")),
        (4, 1) => {
            decode_instruction_definition_record(&raw.bytes, coordinate).and_then(|definition| {
                if state.definitions.contains_key(&definition.definition_id) {
                    return Err(payload_error(
                        coordinate,
                        "duplicate Flight instruction definition",
                    ));
                }
                state
                    .definitions
                    .insert(definition.definition_id, definition.clone());
                Ok(EventPayload::InstructionDefinition(definition))
            })
        }
        (4, 0) => definition_id(&raw.bytes).and_then(|id| {
            let definition = state.definitions.get(&id).ok_or_else(|| {
                payload_error(coordinate, "undefined Flight instruction definition")
            })?;
            decode_instruction_record(&raw.bytes, definition, coordinate).and_then(|decoded| {
                let _local_sequence = decoded.local_sequence;
                let pc = pointer_sum(
                    state.module_base,
                    decoded.instruction.relative_pc,
                    superblock.pointer_width,
                )
                .ok_or_else(|| payload_error(coordinate, "instruction PC exceeds pointer width"))?;
                for observation in decoded
                    .instruction
                    .read_before
                    .iter()
                    .chain(&decoded.instruction.write_after)
                {
                    require_pointer(observation.value, superblock.pointer_width).map_err(|_| {
                        payload_error(coordinate, "instruction observation exceeds pointer width")
                    })?;
                }
                push_pc(target_pcs, pc);
                Ok(EventPayload::Instruction(decoded.instruction))
            })
        }),
        (5, 0) => decode_memory_record(&raw.bytes, coordinate).and_then(|memory| {
            let pc = pointer_sum(
                state.module_base,
                memory.relative_pc,
                superblock.pointer_width,
            )
            .ok_or_else(|| payload_error(coordinate, "memory PC exceeds pointer width"))?;
            require_pointer(memory.address, superblock.pointer_width)
                .map_err(|_| payload_error(coordinate, "memory address exceeds pointer width"))?;
            push_pc(target_pcs, pc);
            Ok(EventPayload::Memory(memory))
        }),
        (6, 3) => decode_string(&raw.bytes, &mut state.strings).map(EventPayload::StringDefinition),
        (kind @ 6..=8, 0) => decode_semantic(kind, &raw.bytes, &state.strings, Vec::new()),
        (kind @ 6..=8, 4) => {
            let fragment = fragments::decode(
                kind,
                &raw.bytes,
                &state.strings,
                key.clone(),
                provenance,
                chunk_index,
                identity.generation,
            )
            .map_err(|_| raw.clone())?;
            fragments.push(fragment);
            return Ok(None);
        }
        (2, 0) => {
            let lifecycle = decode_thread_begin(&raw.bytes, tid);
            lifecycle
                .start_routine
                .map_or(Ok(()), |start| {
                    require_pointer(start, superblock.pointer_width).map_err(|_| {
                        payload_error(coordinate, "thread start routine exceeds pointer width")
                    })
                })
                .map(|()| EventPayload::ThreadLifecycle(lifecycle))
        }
        (3, 0) => exact_u32(&raw.bytes)
            .and_then(|encoded| {
                (encoded == tid)
                    .then_some(EventPayload::ThreadLifecycle(ThreadLifecycle {
                        tid,
                        phase: ThreadLifecyclePhase::End,
                        creator_tid: None,
                        start_routine: None,
                        module_generation: None,
                    }))
                    .ok_or(())
            })
            .map_err(|_| payload_error(coordinate, "invalid thread end")),
        (10, 0) => {
            decode_syscall(&raw.bytes, tid, superblock.pointer_width).map(EventPayload::Syscall)
        }
        (11, 0) => decode_signal(&raw.bytes, tid, superblock.pointer_width).map(|item| {
            push_pc(target_pcs, item.pc);
            EventPayload::Signal(item)
        }),
        _ => return Err(raw),
    };
    match result {
        Ok(payload) => {
            let damaged = matches!(&payload, EventPayload::ThreadLifecycle(value) if value.creator_tid.is_none() && value.phase == ThreadLifecyclePhase::Begin)
                || matches!(&payload, EventPayload::RegisterDelta(value) if !value.ancestry_reliable);
            Ok(Some(EventRecord::new_scoped(
                key.clone(),
                if damaged {
                    Provenance::Damaged
                } else {
                    provenance
                },
                scope,
                payload,
            )))
        }
        Err(_) => Err(raw),
    }
}

fn decode_begin(
    bytes: &[u8],
    superblock: &Superblock,
    identity: &ChunkIdentity,
    index: u32,
    coordinate: SourceCoordinate,
) -> Result<BeginMetadata, ProviderError> {
    let mut c = Cursor::new(bytes);
    let profile = c.u8()?;
    let width = c.u8()?;
    let target_len = c.u16()? as usize;
    let scene_len = c.u16()? as usize;
    let reserved = c.u16()?;
    let pid = c.u32()?;
    let tid = c.u32()?;
    let module_base = c.u64()?;
    let target_offset = c.u64()?;
    let target_address = c.u64()?;
    let target = c.text(target_len)?;
    let scene = c.text(scene_len)?;
    c.finish()?;
    let expected_target = std::str::from_utf8(&superblock.target[..superblock.target_len as usize])
        .map_err(|_| payload_error(coordinate, "invalid superblock target"))?;
    let expected_address = module_base
        .checked_add(target_offset)
        .ok_or_else(|| payload_error(coordinate, "target address overflow"))?;
    for value in [module_base, target_offset, target_address] {
        require_pointer(value, width)
            .map_err(|_| payload_error(coordinate, "chunk address exceeds pointer width"))?;
    }
    if profile > 2
        || width != superblock.pointer_width
        || reserved != 0
        || pid != superblock.pid
        || tid != identity.tid
        || target != expected_target
        || target_address != expected_address
    {
        return Err(payload_error(
            coordinate,
            "invalid Flight chunk begin identity",
        ));
    }
    Ok(BeginMetadata {
        module_base,
        target_offset,
        target_address,
        pid,
        tid: Some(tid),
        profile: match profile {
            0 => TraceProfile::Fast,
            1 => TraceProfile::Balanced,
            _ => TraceProfile::Full,
        },
        compression_enabled: false,
        effective_buffer_bytes: 0,
        run_id: superblock.run_id,
        scene,
        target,
        pointer_width: width,
        chunk_index: Some(index),
        chunk_generation: Some(identity.generation),
    })
}

fn decode_checkpoint(
    bytes: &[u8],
    width: u8,
) -> Result<(RegisterCheckpoint, RegisterSnapshot), ()> {
    if bytes.len() != RegisterSlot::COUNT * 8 {
        return Err(());
    }
    let mut values = Vec::with_capacity(RegisterSlot::COUNT);
    let mut snapshot = Vec::with_capacity(RegisterSlot::COUNT);
    for index in 0..RegisterSlot::COUNT {
        let value = u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().map_err(|_| ())?);
        require_pointer(value, width)?;
        values.push(RegisterValue {
            slot: RegisterSlot::from_index(index).ok_or(())?,
            value,
        });
        snapshot.push(value);
    }
    Ok((
        RegisterCheckpoint { values },
        RegisterSnapshot::new(snapshot).ok_or(())?,
    ))
}

fn decode_delta(
    bytes: &[u8],
    width: u8,
    ancestry: Option<&mut RegisterSnapshot>,
) -> Result<RegisterDelta, ()> {
    if bytes.len() < 8 {
        return Err(());
    }
    let mask = u64::from_le_bytes(bytes[..8].try_into().map_err(|_| ())?);
    if mask == 0
        || mask >> RegisterSlot::COUNT != 0
        || bytes.len() != 8 + mask.count_ones() as usize * 8
    {
        return Err(());
    }
    let reliable = ancestry.is_some();
    let mut changed = Vec::with_capacity(mask.count_ones() as usize);
    let mut cursor = 8;
    for index in 0..RegisterSlot::COUNT {
        if mask & (1 << index) != 0 {
            let value = u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().map_err(|_| ())?);
            require_pointer(value, width)?;
            changed.push(RegisterValue {
                slot: RegisterSlot::from_index(index).ok_or(())?,
                value,
            });
            cursor += 8;
        }
    }
    if let Some(snapshot) = ancestry {
        snapshot.apply(&changed);
    }
    Ok(RegisterDelta {
        mask,
        changed,
        ancestry_reliable: reliable,
    })
}

fn decode_string(
    bytes: &[u8],
    strings: &mut HashMap<u32, Arc<[u8]>>,
) -> Result<StringDefinition, ProviderError> {
    if bytes.len() < 8 {
        return Err(payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated string definition",
        ));
    }
    let id = raw_u32(bytes, 0).ok_or_else(|| {
        payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated string definition",
        )
    })?;
    let size = raw_u32(bytes, 4).ok_or_else(|| {
        payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated string definition",
        )
    })? as usize;
    if id == 0 || size > 4096 || size != bytes.len() - 8 || strings.contains_key(&id) {
        return Err(payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "invalid string definition",
        ));
    }
    let value: Arc<[u8]> = Arc::from(&bytes[8..]);
    strings.insert(id, Arc::clone(&value));
    Ok(StringDefinition {
        id,
        bytes: value.to_vec(),
    })
}

fn decode_semantic(
    kind: u16,
    bytes: &[u8],
    strings: &HashMap<u32, Arc<[u8]>>,
    fragment_sequences: Vec<u64>,
) -> Result<EventPayload, ProviderError> {
    let count = if kind == 6 { 3 } else { 2 };
    if bytes.len() != count * 4 {
        return Err(payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "invalid semantic string references",
        ));
    }
    let mut fields = Vec::with_capacity(count);
    for index in 0..count {
        let id = raw_u32(bytes, index * 4).ok_or_else(|| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "truncated semantic string reference",
            )
        })?;
        let raw = strings.get(&id).ok_or_else(|| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "undefined string reference",
            )
        })?;
        fields.push(
            std::str::from_utf8(raw)
                .map_err(|_| {
                    payload_error(
                        SourceCoordinate {
                            offset: 0,
                            record_ordinal: None,
                        },
                        "semantic string is not UTF-8",
                    )
                })?
                .to_owned(),
        );
    }
    if fields[0].len() > 255
        || (kind == 6 && fields[1].len() > 255)
        || fields[count - 1].len() > 3072
    {
        return Err(payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "semantic field exceeds Flight bound",
        ));
    }
    let value = if kind == 6 {
        SemanticEvent {
            category: Some(fields.remove(0)),
            name: fields.remove(0),
            detail: fields.remove(0),
            fragment_sequences,
        }
    } else {
        SemanticEvent {
            category: None,
            name: fields.remove(0),
            detail: fields.remove(0),
            fragment_sequences,
        }
    };
    Ok(match kind {
        6 => EventPayload::SemanticCall(value),
        7 => EventPayload::SemanticRule(value),
        _ => EventPayload::SemanticError(value),
    })
}

fn decode_thread_begin(bytes: &[u8], tid: u32) -> ThreadLifecycle {
    if bytes.len() == 24
        && let (Some(creator), Some(encoded_tid), Some(start), Some(generation)) = (
            raw_u32(bytes, 0),
            raw_u32(bytes, 4),
            raw_u64(bytes, 8),
            raw_u64(bytes, 16),
        )
        && encoded_tid == tid
    {
        return ThreadLifecycle {
            tid,
            phase: ThreadLifecyclePhase::Begin,
            creator_tid: Some(creator),
            start_routine: Some(start),
            module_generation: Some(generation),
        };
    }
    ThreadLifecycle {
        tid,
        phase: ThreadLifecyclePhase::Begin,
        creator_tid: None,
        start_routine: None,
        module_generation: None,
    }
}

fn decode_syscall(bytes: &[u8], tid: u32, width: u8) -> Result<Syscall, ProviderError> {
    if bytes.len() != 72 {
        return Err(payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "invalid syscall payload",
        ));
    }
    let mut c = Cursor::new(bytes);
    let pc = c.u64()?;
    let mut arguments = [0; 6];
    for value in &mut arguments {
        *value = c.u64()?;
    }
    let number = c.u64()? as i64;
    let result = c.u64()? as i64;
    c.finish()?;
    for value in std::iter::once(pc).chain(arguments) {
        require_pointer(value, width).map_err(|_| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "syscall value exceeds pointer width",
            )
        })?;
    }
    Ok(Syscall {
        tid,
        number,
        pc,
        arguments,
        result: Some(result),
    })
}

fn decode_signal(bytes: &[u8], tid: u32, width: u8) -> Result<Signal, ProviderError> {
    if bytes.len() != 24 {
        return Err(payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "invalid signal payload",
        ));
    }
    let number = raw_u32(bytes, 0).ok_or_else(|| {
        payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated signal",
        )
    })? as i32;
    let code = raw_u32(bytes, 4).ok_or_else(|| {
        payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated signal",
        )
    })? as i32;
    let fault_address = raw_u64(bytes, 8).ok_or_else(|| {
        payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated signal",
        )
    })?;
    let pc = raw_u64(bytes, 16).ok_or_else(|| {
        payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated signal",
        )
    })?;
    for value in [fault_address, pc] {
        require_pointer(value, width).map_err(|_| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "signal address exceeds pointer width",
            )
        })?;
    }
    Ok(Signal {
        tid,
        number,
        code,
        pc,
        sp: 0,
        fault_address,
        flags: 0,
    })
}

fn decode_emergency(
    raw: OpaqueOptionalRecord,
    key: EventKey,
    coordinate: SourceCoordinate,
) -> Result<EventRecord, ProviderError> {
    if raw.bytes.len() != 52 {
        return Err(payload_error(coordinate, "invalid emergency payload"));
    }
    let mut c = Cursor::new(&raw.bytes);
    let kind = c.u32()? as u16;
    let tid = c.u32()?;
    let _sequence = c.u64()?;
    let pc = c.u64()?;
    let sp = c.u64()?;
    let fault = c.u64()?;
    let number = c.u32()?;
    let code = c.u32()?;
    let flags = c.u32()? & !super::wire::EMERGENCY_COMMITTED;
    let payload = match kind {
        10 => EventPayload::Syscall(Syscall {
            tid,
            number: number as i64,
            pc,
            arguments: [sp, fault, code as u64, flags as u64, 0, 0],
            result: None,
        }),
        11 => EventPayload::Signal(Signal {
            tid,
            number: number as i32,
            code: code as i32,
            pc,
            sp,
            fault_address: fault,
            flags,
        }),
        12 | 13 => EventPayload::SignalHandlerBoundary(SignalHandlerBoundary {
            tid,
            phase: if kind == 12 {
                SignalHandlerPhase::Begin
            } else {
                SignalHandlerPhase::Return
            },
            number: number as i32,
            code: code as i32,
            pc,
            sp,
            fault_address: fault,
            flags,
            depth: (flags & 0xffff) as u16,
            nested_delivery_count: (flags >> 16) as u16,
            begin_sequence: (kind == 13).then_some(fault),
        }),
        14 => EventPayload::Termination(Termination {
            kind: TerminationKind::Intent,
            reason: None,
            return_value: None,
            elapsed_ms: 0,
            metrics: TerminalMetrics::default(),
            intent: Some(TerminationIntent {
                pc,
                syscall_number: number as i64,
                arguments: [sp, fault, code as u64, flags as u64],
            }),
        }),
        15 => EventPayload::CoverageGap(CoverageGap {
            tid,
            pc,
            sp,
            fault_address: fault,
            reason_flags: flags,
            dropped_count: code,
        }),
        _ => return Err(payload_error(coordinate, "unknown emergency kind")),
    };
    Ok(EventRecord::new(key, Provenance::Captured, payload))
}

fn definition_id(bytes: &[u8]) -> Result<u32, ProviderError> {
    if bytes.len() < 32 {
        return Err(payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated instruction record",
        ));
    }
    raw_u32(bytes, 28).ok_or_else(|| {
        payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "truncated instruction record",
        )
    })
}

fn chunk_index(superblock: &Superblock, offset: u64) -> Option<u32> {
    if offset < superblock.chunks.offset || offset >= superblock.chunks.end {
        return None;
    }
    u32::try_from((offset - superblock.chunks.offset) / u64::from(superblock.chunk_bytes)).ok()
}

fn rewrap(
    key: EventKey,
    provenance: Provenance,
    scope: EventScope,
    raw: OpaqueOptionalRecord,
) -> EventRecord {
    EventRecord::new_scoped(key, provenance, scope, EventPayload::OpaqueOptional(raw))
}
fn coordinate(event: &EventRecord) -> SourceCoordinate {
    SourceCoordinate {
        offset: event.key.source_offset,
        record_ordinal: Some(event.key.record_ordinal),
    }
}
fn require_pointer(value: u64, width: u8) -> Result<(), ()> {
    if width == 4 && value > u32::MAX as u64 {
        Err(())
    } else {
        Ok(())
    }
}
fn pointer_sum(base: u64, relative: u64, width: u8) -> Option<u64> {
    require_pointer(base, width).ok()?;
    require_pointer(relative, width).ok()?;
    let value = base.checked_add(relative)?;
    require_pointer(value, width).ok()?;
    Some(value)
}
fn exact_u32(bytes: &[u8]) -> Result<u32, ()> {
    if bytes.len() == 4 {
        raw_u32(bytes, 0).ok_or(())
    } else {
        Err(())
    }
}
fn raw_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let mut raw = [0_u8; 4];
    raw.copy_from_slice(bytes.get(offset..offset.checked_add(4)?)?);
    Some(u32::from_le_bytes(raw))
}
fn raw_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(bytes.get(offset..offset.checked_add(8)?)?);
    Some(u64::from_le_bytes(raw))
}
fn push_pc(values: &mut Vec<u64>, value: u64) {
    if value != 0 {
        values.push(value);
    }
}
fn payload_error(coordinate: SourceCoordinate, detail: &str) -> ProviderError {
    ProviderError::new(
        "source.flight.payload",
        "flight.event",
        Some(coordinate),
        false,
        detail,
    )
}

fn guarded_sort_events(
    mut values: Vec<EventRecord>,
    guard: &dyn WorkGuard,
) -> Result<Vec<EventRecord>, ProviderError> {
    for byte in 0..8 {
        let mut counts = [0_usize; 256];
        for (index, event) in values.iter().enumerate() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            let key = event.key.sequence.unwrap_or(0);
            counts[((key >> (byte * 8)) & 0xff) as usize] += 1;
        }
        let mut positions = [0_usize; 256];
        for index in 1..256 {
            positions[index] = positions[index - 1] + counts[index - 1];
        }
        let mut slots = Vec::new();
        slots.try_reserve_exact(values.len()).map_err(|_| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "Flight event sort allocation failed",
            )
        })?;
        for index in 0..values.len() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            slots.push(None);
        }
        for (index, event) in values.drain(..).enumerate() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            let bucket = ((event.key.sequence.unwrap_or(0) >> (byte * 8)) & 0xff) as usize;
            let position = positions[bucket];
            positions[bucket] += 1;
            slots[position] = Some(event);
        }
        for (index, event) in slots.into_iter().enumerate() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            let Some(event) = event else {
                return Err(payload_error(
                    SourceCoordinate {
                        offset: 0,
                        record_ordinal: None,
                    },
                    "Flight event sort invariant failed",
                ));
            };
            values.push(event);
        }
    }
    Ok(values)
}

pub(super) fn guarded_sort_u64(
    mut values: Vec<u64>,
    guard: &dyn WorkGuard,
) -> Result<Vec<u64>, ProviderError> {
    for byte in 0..8 {
        let mut counts = [0_usize; 256];
        for (index, value) in values.iter().enumerate() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            counts[((value >> (byte * 8)) & 0xff) as usize] += 1;
        }
        let mut positions = [0_usize; 256];
        for index in 1..256 {
            positions[index] = positions[index - 1] + counts[index - 1];
        }
        let mut output = Vec::new();
        output.try_reserve_exact(values.len()).map_err(|_| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "Flight u64 sort allocation failed",
            )
        })?;
        for index in 0..values.len() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            output.push(0);
        }
        for (index, value) in values.drain(..).enumerate() {
            if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
                guard.consume(WorkDelta::default())?;
            }
            let bucket = ((value >> (byte * 8)) & 0xff) as usize;
            let position = positions[bucket];
            positions[bucket] += 1;
            output[position] = value;
        }
        values = output;
    }
    let mut unique = Vec::new();
    unique.try_reserve_exact(values.len()).map_err(|_| {
        payload_error(
            SourceCoordinate {
                offset: 0,
                record_ordinal: None,
            },
            "Flight u64 deduplication allocation failed",
        )
    })?;
    for (index, value) in values.into_iter().enumerate() {
        if index as u64 % crate::MAX_UNGUARDED_RECORDS == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if unique.last() != Some(&value) {
            unique.push(value);
        }
    }
    Ok(unique)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], ProviderError> {
        let end = self.offset.checked_add(count).ok_or_else(|| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "payload overflow",
            )
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "truncated payload",
            )
        })?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, ProviderError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProviderError> {
        let mut raw = [0_u8; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }
    fn u32(&mut self) -> Result<u32, ProviderError> {
        let mut raw = [0_u8; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }
    fn u64(&mut self) -> Result<u64, ProviderError> {
        let mut raw = [0_u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }
    fn text(&mut self, count: usize) -> Result<String, ProviderError> {
        String::from_utf8(self.take(count)?.to_vec()).map_err(|_| {
            payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "invalid UTF-8",
            )
        })
    }
    fn finish(&self) -> Result<(), ProviderError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(payload_error(
                SourceCoordinate {
                    offset: 0,
                    record_ordinal: None,
                },
                "trailing payload bytes",
            ))
        }
    }
}
