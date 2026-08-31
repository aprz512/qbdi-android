use qtrace_provider::{
    CompletenessCause, EventKey, EventKind, EventScope, MemoryDirection, PcRelativeKind,
    Provenance, ProviderCapabilities, RangeBounds, RangeDomain, RegisterSlot, WorkDelta, WorkGuard,
};

use crate::cache::OwnedSection;

use super::{
    BuildOptions, ByteArena, ByteSpan, CompletenessRow, DefinitionRow, EventColumn, IndexCatalog,
    IndexError, InstructionRow, MemoryRow, ModuleRow, NormalizedCatalog, SemanticRow, SortedMap,
    SourceKeyRow,
    checkpoints::{RegisterAccess, RegisterObservationRow},
    intervals::{IntervalEntry, IntervalIndex},
    postings::PostingList,
};

pub(super) const CAPABILITIES: &str = "capabilities.v2";
pub(super) const EVENT_META: &str = "event_meta.v2";
pub(super) const PAYLOAD_SPANS: &str = "payload_spans.v2";
pub(super) const PAYLOAD_ARENA: &str = "payload_arena.v2";
pub(super) const STRING_SPANS: &str = "string_spans.v2";
pub(super) const STRING_ARENA: &str = "string_arena.v2";
pub(super) const BLOB_SPANS: &str = "blob_spans.v2";
pub(super) const BLOB_ARENA: &str = "blob_arena.v2";
pub(super) const MODULES: &str = "modules.v2";
pub(super) const DEFINITIONS: &str = "definitions.v2";
pub(super) const INSTRUCTIONS: &str = "instructions.v2";
pub(super) const MEMORIES: &str = "memories.v2";
pub(super) const SEMANTICS: &str = "semantics.v2";
pub(super) const SOURCE_COMPLETENESS: &str = "source_completeness.v2";
pub(super) const COMPLETENESS: &str = "completeness.v2";
pub(super) const REGISTER_OBSERVATIONS: &str = "register_observations.v2";
pub(super) const INDEX_META: &str = "index_meta.v2";
pub(super) const TIMELINE_POSTINGS: &str = "timeline_postings.v2";
pub(super) const TID_POSTINGS: &str = "tid_postings.v2";
pub(super) const KIND_POSTINGS: &str = "kind_postings.v2";
pub(super) const MODULE_POSTINGS: &str = "module_postings.v2";
pub(super) const DEFINITION_POSTINGS: &str = "definition_postings.v2";
pub(super) const REGISTER_POSTINGS: &str = "register_postings.v2";
pub(super) const SEMANTIC_CATEGORY_POSTINGS: &str = "semantic_category_postings.v2";
pub(super) const SEMANTIC_NAME_POSTINGS: &str = "semantic_name_postings.v2";
pub(super) const CALL_POSTINGS: &str = "call_postings.v2";
pub(super) const RETURN_POSTINGS: &str = "return_postings.v2";
pub(super) const CHECKPOINT_POSTINGS: &str = "checkpoint_postings.v2";
pub(super) const SEQUENCE_INDEX: &str = "sequence_index.v2";
pub(super) const MODULE_PC_INDEX: &str = "module_pc_index.v2";
pub(super) const MEMORY_INTERVALS: &str = "memory_intervals.v2";
pub(super) const MEMORY_BLOCK_MAX: &str = "memory_block_max.v2";
pub(super) const SOURCE_ROWS: &str = "source_rows.v2";

pub(super) const EVENT_META_BYTES: u32 = 24;
const SPAN_BYTES: u32 = 16;
const MODULE_BYTES: u32 = 32;
const DEFINITION_BYTES: u32 = 64;
const INSTRUCTION_BYTES: u32 = 32;
const MEMORY_BYTES: u32 = 72;
const SEMANTIC_BYTES: u32 = 32;
const COMPLETENESS_BYTES: u32 = 32;
const OBSERVATION_BYTES: u32 = 24;
const PAIR_BYTES: u32 = 16;
const MODULE_PC_BYTES: u32 = 24;
const INTERVAL_BYTES: u32 = 32;

pub(super) const EXACT_SECTIONS: &[(&str, u32, u32)] = &[
    (CAPABILITIES, 8, 16),
    (EVENT_META, 8, EVENT_META_BYTES),
    (PAYLOAD_SPANS, 8, SPAN_BYTES),
    (PAYLOAD_ARENA, 1, 1),
    (STRING_SPANS, 8, SPAN_BYTES),
    (STRING_ARENA, 1, 1),
    (BLOB_SPANS, 8, SPAN_BYTES),
    (BLOB_ARENA, 1, 1),
    (MODULES, 8, MODULE_BYTES),
    (DEFINITIONS, 8, DEFINITION_BYTES),
    (INSTRUCTIONS, 8, INSTRUCTION_BYTES),
    (MEMORIES, 8, MEMORY_BYTES),
    (SEMANTICS, 8, SEMANTIC_BYTES),
    (SOURCE_COMPLETENESS, 8, COMPLETENESS_BYTES),
    (COMPLETENESS, 8, COMPLETENESS_BYTES),
    (REGISTER_OBSERVATIONS, 8, OBSERVATION_BYTES),
    (INDEX_META, 8, 16),
    (TIMELINE_POSTINGS, 8, PAIR_BYTES),
    (TID_POSTINGS, 8, PAIR_BYTES),
    (KIND_POSTINGS, 8, PAIR_BYTES),
    (MODULE_POSTINGS, 8, PAIR_BYTES),
    (DEFINITION_POSTINGS, 8, PAIR_BYTES),
    (REGISTER_POSTINGS, 8, PAIR_BYTES),
    (SEMANTIC_CATEGORY_POSTINGS, 8, PAIR_BYTES),
    (SEMANTIC_NAME_POSTINGS, 8, PAIR_BYTES),
    (CALL_POSTINGS, 8, 8),
    (RETURN_POSTINGS, 8, 8),
    (CHECKPOINT_POSTINGS, 8, 8),
    (SEQUENCE_INDEX, 8, PAIR_BYTES),
    (MODULE_PC_INDEX, 8, MODULE_PC_BYTES),
    (MEMORY_INTERVALS, 8, INTERVAL_BYTES),
    (MEMORY_BLOCK_MAX, 8, PAIR_BYTES),
    (SOURCE_ROWS, 8, 8),
];

pub(super) fn contract(name: &str) -> Option<(u32, u32)> {
    EXACT_SECTIONS
        .iter()
        .find(|(known, _, _)| *known == name)
        .map(|(_, alignment, element)| (*alignment, *element))
}

pub(super) fn max_length(name: &str, event_count: usize) -> Result<u64, IndexError> {
    let events = u64::try_from(event_count)
        .map_err(|_| IndexError::corrupt("event count does not fit u64"))?;
    let rows = match name {
        CAPABILITIES | INDEX_META => return Ok(16),
        EVENT_META => {
            return events
                .checked_mul(u64::from(EVENT_META_BYTES))
                .ok_or_else(|| IndexError::corrupt("event metadata bound overflow"));
        }
        PAYLOAD_SPANS | SOURCE_ROWS => {
            return events
                .checked_mul(if name == PAYLOAD_SPANS {
                    u64::from(SPAN_BYTES)
                } else {
                    8
                })
                .ok_or_else(|| IndexError::corrupt("event-owned section bound overflow"));
        }
        PAYLOAD_ARENA => return Ok(BuildOptions::default().max_payload_bytes),
        STRING_ARENA => return Ok(BuildOptions::default().max_string_bytes),
        BLOB_ARENA => return Ok(BuildOptions::default().max_blob_bytes),
        STRING_SPANS | BLOB_SPANS => events.checked_mul(8).and_then(|value| value.checked_add(1)),
        SOURCE_COMPLETENESS | COMPLETENESS => {
            events.checked_mul(4).and_then(|value| value.checked_add(1))
        }
        REGISTER_OBSERVATIONS | REGISTER_POSTINGS => events.checked_mul(RegisterSlot::COUNT as u64),
        MODULE_PC_INDEX => events.checked_mul(2),
        MEMORY_BLOCK_MAX => events.checked_add(1),
        _ => Some(events),
    }
    .ok_or_else(|| IndexError::corrupt("binary section row bound overflow"))?;
    let element = u64::from(
        contract(name)
            .ok_or_else(|| IndexError::corrupt("unknown binary section"))?
            .1,
    );
    rows.checked_mul(element)
        .ok_or_else(|| IndexError::corrupt("binary section byte bound overflow"))
}

pub(super) fn encode(
    catalog: NormalizedCatalog,
    guard: &dyn WorkGuard,
) -> Result<Vec<OwnedSection>, IndexError> {
    let mut sections = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut sections,
        EXACT_SECTIONS.len(),
        guard,
        "binary section list allocation",
    )?;
    sections.push(section(
        CAPABILITIES,
        8,
        16,
        encode_capabilities(&catalog.capabilities, guard)?,
    ));
    sections.push(section(
        EVENT_META,
        8,
        EVENT_META_BYTES,
        encode_events(&catalog.events, guard)?,
    ));
    encode_arena(
        &mut sections,
        PAYLOAD_SPANS,
        PAYLOAD_ARENA,
        catalog.payloads,
        guard,
    )?;
    encode_arena(
        &mut sections,
        STRING_SPANS,
        STRING_ARENA,
        catalog.strings,
        guard,
    )?;
    encode_arena(&mut sections, BLOB_SPANS, BLOB_ARENA, catalog.blobs, guard)?;
    sections.push(section(
        MODULES,
        8,
        MODULE_BYTES,
        encode_modules(&catalog.modules, guard)?,
    ));
    sections.push(section(
        DEFINITIONS,
        8,
        DEFINITION_BYTES,
        encode_definitions(&catalog.definitions, guard)?,
    ));
    sections.push(section(
        INSTRUCTIONS,
        8,
        INSTRUCTION_BYTES,
        encode_instructions(&catalog.instructions, guard)?,
    ));
    sections.push(section(
        MEMORIES,
        8,
        MEMORY_BYTES,
        encode_memories(&catalog.memories, guard)?,
    ));
    sections.push(section(
        SEMANTICS,
        8,
        SEMANTIC_BYTES,
        encode_semantics(&catalog.semantics, guard)?,
    ));
    sections.push(section(
        SOURCE_COMPLETENESS,
        8,
        COMPLETENESS_BYTES,
        encode_completeness(&catalog.completeness, guard)?,
    ));
    sections.push(section(
        COMPLETENESS,
        8,
        COMPLETENESS_BYTES,
        encode_completeness(&catalog.completeness, guard)?,
    ));
    sections.push(section(
        REGISTER_OBSERVATIONS,
        8,
        OBSERVATION_BYTES,
        encode_observations(&catalog.observations, guard)?,
    ));
    let mut meta = Encoder::rows(1, 16, guard)?;
    meta.u64(catalog.indexes.memory.block_rows() as u64);
    meta.u64(catalog.events.len() as u64);
    sections.push(section(INDEX_META, 8, 16, meta.finish()?));
    for (name, bytes) in [
        (
            TIMELINE_POSTINGS,
            encode_map(&catalog.indexes.timeline, |key| *key, guard)?,
        ),
        (
            TID_POSTINGS,
            encode_map(&catalog.indexes.tid, |key| u64::from(*key), guard)?,
        ),
        (
            KIND_POSTINGS,
            encode_map(&catalog.indexes.kind, |key| u64::from(*key), guard)?,
        ),
        (
            MODULE_POSTINGS,
            encode_map(&catalog.indexes.module, |key| u64::from(*key), guard)?,
        ),
        (
            DEFINITION_POSTINGS,
            encode_map(&catalog.indexes.definition, |key| u64::from(*key), guard)?,
        ),
        (
            REGISTER_POSTINGS,
            encode_map(&catalog.indexes.register, |key| u64::from(*key), guard)?,
        ),
        (
            SEMANTIC_CATEGORY_POSTINGS,
            encode_map(
                &catalog.indexes.semantic_category,
                |key| u64::from(*key),
                guard,
            )?,
        ),
        (
            SEMANTIC_NAME_POSTINGS,
            encode_map(&catalog.indexes.semantic_name, |key| u64::from(*key), guard)?,
        ),
    ] {
        sections.push(section(name, 8, PAIR_BYTES, bytes));
    }
    sections.push(section(
        CALL_POSTINGS,
        8,
        8,
        encode_list(&catalog.indexes.call, guard)?,
    ));
    sections.push(section(
        RETURN_POSTINGS,
        8,
        8,
        encode_list(&catalog.indexes.return_rows, guard)?,
    ));
    sections.push(section(
        CHECKPOINT_POSTINGS,
        8,
        8,
        encode_list(&catalog.indexes.checkpoint, guard)?,
    ));
    sections.push(section(
        SEQUENCE_INDEX,
        8,
        PAIR_BYTES,
        encode_pairs(&catalog.indexes.sequence, guard)?,
    ));
    sections.push(section(
        MODULE_PC_INDEX,
        8,
        MODULE_PC_BYTES,
        encode_module_pc(&catalog.indexes.module_pc, guard)?,
    ));
    let (entries, prefix, blocks) = catalog.indexes.memory.encoded_parts();
    sections.push(section(
        MEMORY_INTERVALS,
        8,
        INTERVAL_BYTES,
        encode_intervals(entries, prefix, guard)?,
    ));
    sections.push(section(
        MEMORY_BLOCK_MAX,
        8,
        PAIR_BYTES,
        encode_block_max(blocks, guard)?,
    ));
    sections.push(section(
        SOURCE_ROWS,
        8,
        8,
        encode_source_rows(&catalog.indexes.source_keys, guard)?,
    ));
    Ok(sections)
}

fn section(name: &'static str, alignment: u32, element_size: u32, bytes: Vec<u8>) -> OwnedSection {
    OwnedSection {
        name,
        alignment,
        element_size,
        bytes,
    }
}

struct Encoder {
    bytes: Vec<u8>,
    expected: usize,
}

impl Encoder {
    fn rows(rows: usize, element: u32, guard: &dyn WorkGuard) -> Result<Self, IndexError> {
        let expected = rows
            .checked_mul(element as usize)
            .ok_or_else(|| IndexError::resource("binary section length overflow"))?;
        guard.consume(WorkDelta {
            rows: rows as u64,
            ..WorkDelta::default()
        })?;
        let mut bytes = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut bytes,
            expected,
            guard,
            "binary section allocation",
        )?;
        Ok(Self { bytes, expected })
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn zero(&mut self, count: usize) {
        self.bytes.resize(self.bytes.len() + count, 0);
    }
    fn finish(self) -> Result<Vec<u8>, IndexError> {
        if self.bytes.len() != self.expected {
            return Err(IndexError::invalid("binary encoder row-size mismatch"));
        }
        Ok(self.bytes)
    }
}

fn encode_capabilities(
    value: &ProviderCapabilities,
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(1, 16, guard)?;
    for bit in [
        value.global_ordering,
        value.per_thread_ordering,
        value.full_register_checkpoint,
        value.register_read_write_observation,
        value.memory_metadata,
        value.memory_before_after,
        value.lifecycle,
        value.signal_and_termination,
        value.loss_and_damage_ranges,
    ] {
        out.u8(u8::from(bit));
    }
    out.zero(7);
    out.finish()
}

fn encode_events(rows: &[EventColumn], guard: &dyn WorkGuard) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), EVENT_META_BYTES, guard)?;
    for (index, row) in rows.iter().enumerate() {
        checkpoint(guard, index)?;
        out.u8(provenance(row.provenance));
        match row.scope {
            EventScope::Artifact => {
                out.u8(0);
                out.u16(0);
                out.u32(0);
                out.u32(0);
                out.u32(0);
            }
            EventScope::FlightChunk {
                chunk_index,
                generation,
                tid,
            } => {
                out.u8(1);
                out.u16(0);
                out.u32(chunk_index);
                out.u32(generation);
                out.u32(tid);
            }
        }
        out.u32(row.payload_blob);
        out.zero(4);
    }
    out.finish()
}

fn encode_arena(
    sections: &mut Vec<OwnedSection>,
    spans_name: &'static str,
    bytes_name: &'static str,
    arena: ByteArena<'static>,
    guard: &dyn WorkGuard,
) -> Result<(), IndexError> {
    let mut spans = Encoder::rows(arena.spans().len(), SPAN_BYTES, guard)?;
    for (index, span) in arena.spans().iter().enumerate() {
        checkpoint(guard, index)?;
        spans.u64(span.offset);
        spans.u64(span.length);
    }
    sections.push(section(spans_name, 8, SPAN_BYTES, spans.finish()?));
    let (bytes, _, _) = arena.into_owned_parts()?;
    sections.push(section(bytes_name, 1, 1, bytes));
    Ok(())
}

fn encode_modules(rows: &[ModuleRow], guard: &dyn WorkGuard) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), MODULE_BYTES, guard)?;
    for (i, row) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(row.source_event_row as u64);
        out.u8(provenance(row.provenance));
        out.zero(3);
        out.u32(row.source_id);
        out.u64(row.base);
        out.u32(row.name);
        out.zero(4);
    }
    out.finish()
}

fn encode_definitions(
    rows: &[DefinitionRow],
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), DEFINITION_BYTES, guard)?;
    for (i, row) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(row.source_event_row as u64);
        out.u8(provenance(row.provenance));
        out.u8(pc_kind(row.pc_kind));
        out.u8(row.condition);
        out.u8(u8::from(row.slow_memory_path));
        out.u32(row.source_id);
        out.u32(row.opcode);
        out.u32(row.flags);
        out.u64(row.read_mask);
        out.u64(row.write_mask);
        out.i64(row.pc_displacement);
        out.u32(row.mnemonic);
        out.u32(row.operands);
        out.u32(row.disassembly);
        out.u32(row.exact_blob);
    }
    out.finish()
}

fn encode_instructions(
    rows: &[InstructionRow],
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), INSTRUCTION_BYTES, guard)?;
    for (i, row) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(row.owner_row as u64);
        out.u32(row.module.unwrap_or(0));
        out.u32(row.definition.unwrap_or(0));
        out.u64(row.relative_pc);
        out.u8(u8::from(row.module.is_some()) | (u8::from(row.definition.is_some()) << 1));
        out.zero(7);
    }
    out.finish()
}

fn encode_memories(rows: &[MemoryRow], guard: &dyn WorkGuard) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), MEMORY_BYTES, guard)?;
    for (i, row) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(row.owner_row as u64);
        out.u32(row.module.unwrap_or(0));
        out.u32(0);
        out.u64(row.relative_pc);
        out.u64(row.address);
        out.u64(row.end_exclusive);
        out.u64(row.value);
        out.u32(row.size);
        out.u16(row.flags);
        out.u8(memory_direction(row.direction));
        out.u8(u8::from(row.metadata_available));
        out.u8(u8::from(row.module.is_some()));
        out.zero(3);
        out.u32(row.before_blob);
        out.u32(row.after_blob);
        out.zero(4);
    }
    out.finish()
}

fn encode_semantics(rows: &[SemanticRow], guard: &dyn WorkGuard) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), SEMANTIC_BYTES, guard)?;
    for (i, row) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(row.owner_row as u64);
        out.u32(row.category.unwrap_or(0));
        out.u32(row.name);
        out.u32(row.detail_blob);
        out.u8(u8::from(row.category.is_some()));
        out.zero(11);
    }
    out.finish()
}

fn encode_completeness(
    rows: &[CompletenessRow],
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), COMPLETENESS_BYTES, guard)?;
    for (i, row) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u8(range_domain(row.domain));
        let (kind, start, end) = range_bounds(row.bounds);
        out.u8(kind);
        out.u8(provenance(row.provenance));
        out.u8(completeness_cause(row.cause));
        out.zero(4);
        out.u64(start);
        out.u64(end);
        out.zero(8);
    }
    out.finish()
}

fn encode_observations(
    rows: &[RegisterObservationRow],
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), OBSERVATION_BYTES, guard)?;
    for (i, row) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(row.owner_row as u64);
        out.u64(row.value);
        out.u8(row.slot);
        out.u8(row.captured_width);
        out.u8(register_access(row.access));
        out.u8(provenance(row.provenance));
        out.zero(4);
    }
    out.finish()
}

fn encode_map<K: Ord>(
    map: &SortedMap<K, PostingList>,
    key: impl Fn(&K) -> u64,
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    let rows = map.values().try_fold(0usize, |n, list| {
        n.checked_add(list.deltas().len())
            .ok_or_else(|| IndexError::resource("posting section length overflow"))
    })?;
    let mut out = Encoder::rows(rows, PAIR_BYTES, guard)?;
    let mut ordinal = 0;
    for (field, list) in map.iter() {
        for delta in list.deltas() {
            checkpoint(guard, ordinal)?;
            ordinal += 1;
            out.u64(key(field));
            out.u64(*delta);
        }
    }
    out.finish()
}

fn encode_list(list: &PostingList, guard: &dyn WorkGuard) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(list.deltas().len(), 8, guard)?;
    for (i, d) in list.deltas().iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(*d);
    }
    out.finish()
}
fn encode_pairs(rows: &[(u64, usize)], guard: &dyn WorkGuard) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), PAIR_BYTES, guard)?;
    for (i, (a, b)) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(*a);
        out.u64(*b as u64);
    }
    out.finish()
}
fn encode_module_pc(
    map: &SortedMap<u32, Vec<(u64, usize)>>,
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    let count = map.values().try_fold(0usize, |n, v| {
        n.checked_add(v.len())
            .ok_or_else(|| IndexError::resource("module PC length overflow"))
    })?;
    let mut out = Encoder::rows(count, MODULE_PC_BYTES, guard)?;
    let mut i = 0;
    for (module, rows) in map.iter() {
        for (pc, row) in rows {
            checkpoint(guard, i)?;
            i += 1;
            out.u32(*module);
            out.zero(4);
            out.u64(*pc);
            out.u64(*row as u64);
        }
    }
    out.finish()
}
fn encode_intervals(
    entries: &[IntervalEntry],
    prefix: &[u64],
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    if entries.len() != prefix.len() {
        return Err(IndexError::invalid("interval prefix shape"));
    }
    let mut out = Encoder::rows(entries.len(), INTERVAL_BYTES, guard)?;
    for (i, (e, p)) in entries.iter().zip(prefix).enumerate() {
        checkpoint(guard, i)?;
        out.u64(e.start);
        out.u64(e.end_exclusive);
        out.u64(e.row as u64);
        out.u64(*p);
    }
    out.finish()
}
fn encode_block_max(rows: &[u64], guard: &dyn WorkGuard) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), PAIR_BYTES, guard)?;
    for (i, v) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(i as u64);
        out.u64(*v);
    }
    out.finish()
}
fn encode_source_rows(rows: &[SourceKeyRow], guard: &dyn WorkGuard) -> Result<Vec<u8>, IndexError> {
    let mut out = Encoder::rows(rows.len(), 8, guard)?;
    for (i, v) in rows.iter().enumerate() {
        checkpoint(guard, i)?;
        out.u64(v.row as u64);
    }
    out.finish()
}

fn checkpoint(guard: &dyn WorkGuard, index: usize) -> Result<(), IndexError> {
    if index % 4096 == 0 {
        guard.consume(WorkDelta::default())?;
    }
    Ok(())
}
fn provenance(v: Provenance) -> u8 {
    match v {
        Provenance::Captured => 0,
        Provenance::Derived => 1,
        Provenance::Heuristic => 2,
        Provenance::Unknown => 3,
        Provenance::Damaged => 4,
    }
}
fn pc_kind(v: PcRelativeKind) -> u8 {
    match v {
        PcRelativeKind::None => 0,
        PcRelativeKind::Instruction => 1,
        PcRelativeKind::Page => 2,
    }
}
fn memory_direction(v: MemoryDirection) -> u8 {
    match v {
        MemoryDirection::Read => 0,
        MemoryDirection::Write => 1,
        MemoryDirection::ReadWrite => 2,
        MemoryDirection::Unknown => 3,
    }
}
fn register_access(v: RegisterAccess) -> u8 {
    match v {
        RegisterAccess::Read => 0,
        RegisterAccess::Write => 1,
        RegisterAccess::Checkpoint => 2,
        RegisterAccess::Delta => 3,
    }
}
fn range_domain(v: RangeDomain) -> u8 {
    match v {
        RangeDomain::CapturedSequence => 0,
        RangeDomain::SourceBytes => 1,
        RangeDomain::MemoryAddresses => 2,
    }
}
fn range_bounds(v: RangeBounds) -> (u8, u64, u64) {
    match v {
        RangeBounds::InclusiveSequence { first, last } => (0, first, last),
        RangeBounds::HalfOpen {
            start,
            end_exclusive,
        } => (1, start, end_exclusive),
    }
}
fn completeness_cause(v: CompletenessCause) -> u8 {
    match v {
        CompletenessCause::Retained => 0,
        CompletenessCause::MissingTerminal => 1,
        CompletenessCause::Active => 2,
        CompletenessCause::Stale => 3,
        CompletenessCause::Rotating => 4,
        CompletenessCause::Unreliable => 5,
        CompletenessCause::Incomplete => 6,
        CompletenessCause::Lost => 7,
        CompletenessCause::Overwritten => 8,
        CompletenessCause::CoverageGap => 9,
        CompletenessCause::Checksum => 10,
        CompletenessCause::UnterminatedThread => 11,
        CompletenessCause::Truncation => 12,
        CompletenessCause::Unknown => 13,
    }
}

pub(super) fn decode(
    mut sections: Vec<(&'static str, Vec<u8>)>,
    keys: &[EventKey],
    kinds: &[EventKind],
    source_format: &str,
    deep_validate: bool,
    guard: &dyn WorkGuard,
) -> Result<NormalizedCatalog, IndexError> {
    let capabilities = decode_capabilities(&take(&mut sections, CAPABILITIES)?)?;
    let events = decode_events(&take(&mut sections, EVENT_META)?, keys, guard)?;
    let payload_bytes = take(&mut sections, PAYLOAD_ARENA)?;
    let payload_spans = take(&mut sections, PAYLOAD_SPANS)?;
    let payloads = decode_arena(
        &payload_spans,
        payload_bytes,
        BuildOptions::default().max_payload_bytes,
        guard,
    )?;
    let string_bytes = take(&mut sections, STRING_ARENA)?;
    let string_spans = take(&mut sections, STRING_SPANS)?;
    let strings = decode_arena(
        &string_spans,
        string_bytes,
        BuildOptions::default().max_string_bytes,
        guard,
    )?;
    let blob_bytes = take(&mut sections, BLOB_ARENA)?;
    let blob_spans = take(&mut sections, BLOB_SPANS)?;
    let blobs = decode_arena(
        &blob_spans,
        blob_bytes,
        BuildOptions::default().max_blob_bytes,
        guard,
    )?;
    let modules = decode_modules(&take(&mut sections, MODULES)?, guard)?;
    let definitions = decode_definitions(&take(&mut sections, DEFINITIONS)?, guard)?;
    let instructions = decode_instructions(&take(&mut sections, INSTRUCTIONS)?, guard)?;
    let memories = decode_memories(&take(&mut sections, MEMORIES)?, guard)?;
    let semantics = decode_semantics(&take(&mut sections, SEMANTICS)?, guard)?;
    let source_completeness =
        decode_completeness(&take(&mut sections, SOURCE_COMPLETENESS)?, guard)?;
    let completeness = decode_completeness(&take(&mut sections, COMPLETENESS)?, guard)?;
    if completeness != source_completeness {
        return Err(IndexError::corrupt(
            "derived completeness differs from canonical provider summary",
        ));
    }
    let observations = decode_observations(&take(&mut sections, REGISTER_OBSERVATIONS)?, guard)?;
    let index_meta = take(&mut sections, INDEX_META)?;
    let meta = Cursor::new(&index_meta, 16)?;
    if meta.rows() != 1 {
        return Err(IndexError::corrupt("index metadata cardinality"));
    }
    let block_rows = usize::try_from(meta.u64(0, 0)?)
        .map_err(|_| IndexError::corrupt("interval block rows do not fit usize"))?;
    if meta.u64(0, 8)? != keys.len() as u64 {
        return Err(IndexError::corrupt("index metadata event count"));
    }
    let source_keys = decode_source_rows(&take(&mut sections, SOURCE_ROWS)?, keys, guard)?;
    let (interval_entries, prefix) =
        decode_intervals(&take(&mut sections, MEMORY_INTERVALS)?, guard)?;
    let block_prefix_max_end = decode_block_max(&take(&mut sections, MEMORY_BLOCK_MAX)?, guard)?;
    let indexes = IndexCatalog {
        timeline: decode_map(&take(&mut sections, TIMELINE_POSTINGS)?, Ok, guard)?,
        tid: decode_map(&take(&mut sections, TID_POSTINGS)?, checked_u32, guard)?,
        kind: decode_map(&take(&mut sections, KIND_POSTINGS)?, checked_u8, guard)?,
        module: decode_map(&take(&mut sections, MODULE_POSTINGS)?, checked_u32, guard)?,
        definition: decode_map(
            &take(&mut sections, DEFINITION_POSTINGS)?,
            checked_u32,
            guard,
        )?,
        register: decode_map(&take(&mut sections, REGISTER_POSTINGS)?, checked_u8, guard)?,
        semantic_category: decode_map(
            &take(&mut sections, SEMANTIC_CATEGORY_POSTINGS)?,
            checked_u32,
            guard,
        )?,
        semantic_name: decode_map(
            &take(&mut sections, SEMANTIC_NAME_POSTINGS)?,
            checked_u32,
            guard,
        )?,
        call: decode_list(&take(&mut sections, CALL_POSTINGS)?, guard)?,
        return_rows: decode_list(&take(&mut sections, RETURN_POSTINGS)?, guard)?,
        checkpoint: decode_list(&take(&mut sections, CHECKPOINT_POSTINGS)?, guard)?,
        sequence: decode_pairs(&take(&mut sections, SEQUENCE_INDEX)?, guard)?,
        module_pc: decode_module_pc(&take(&mut sections, MODULE_PC_INDEX)?, guard)?,
        memory: IntervalIndex::from_encoded_parts(
            interval_entries,
            prefix,
            block_prefix_max_end,
            block_rows,
        ),
        source_keys,
    };
    let catalog = NormalizedCatalog {
        schema: 2,
        capabilities,
        events,
        payloads,
        strings,
        blobs,
        modules,
        definitions,
        instructions,
        memories,
        semantics,
        observations,
        completeness,
        indexes,
    };
    if deep_validate {
        catalog.validate(keys, kinds, guard)?;
        super::builder::validate_cached_truth(
            &catalog,
            &source_completeness,
            keys,
            kinds,
            source_format,
            guard,
        )?;
    }
    Ok(catalog)
}

fn take(sections: &mut Vec<(&'static str, Vec<u8>)>, name: &str) -> Result<Vec<u8>, IndexError> {
    let index = sections
        .iter()
        .position(|(candidate, _)| *candidate == name)
        .ok_or_else(|| IndexError::corrupt(format!("missing binary section {name}")))?;
    Ok(sections.swap_remove(index).1)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    element: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], element: u32) -> Result<Self, IndexError> {
        let element = element as usize;
        if element == 0 || bytes.len() % element != 0 {
            return Err(IndexError::corrupt("binary section element remainder"));
        }
        Ok(Self { bytes, element })
    }
    fn rows(&self) -> usize {
        self.bytes.len() / self.element
    }
    fn slice(&self, row: usize, offset: usize, len: usize) -> Result<&'a [u8], IndexError> {
        let start = row
            .checked_mul(self.element)
            .and_then(|v| v.checked_add(offset))
            .ok_or_else(|| IndexError::corrupt("binary row offset overflow"))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| IndexError::corrupt("binary field end overflow"))?;
        if offset.checked_add(len).is_none_or(|v| v > self.element) {
            return Err(IndexError::corrupt("binary field outside row"));
        }
        self.bytes
            .get(start..end)
            .ok_or_else(|| IndexError::corrupt("binary row outside section"))
    }
    fn u8(&self, row: usize, offset: usize) -> Result<u8, IndexError> {
        Ok(self.slice(row, offset, 1)?[0])
    }
    fn u16(&self, row: usize, offset: usize) -> Result<u16, IndexError> {
        Ok(u16::from_le_bytes(
            self.slice(row, offset, 2)?
                .try_into()
                .map_err(|_| IndexError::corrupt("u16 field"))?,
        ))
    }
    fn u32(&self, row: usize, offset: usize) -> Result<u32, IndexError> {
        Ok(u32::from_le_bytes(
            self.slice(row, offset, 4)?
                .try_into()
                .map_err(|_| IndexError::corrupt("u32 field"))?,
        ))
    }
    fn u64(&self, row: usize, offset: usize) -> Result<u64, IndexError> {
        Ok(u64::from_le_bytes(
            self.slice(row, offset, 8)?
                .try_into()
                .map_err(|_| IndexError::corrupt("u64 field"))?,
        ))
    }
    fn i64(&self, row: usize, offset: usize) -> Result<i64, IndexError> {
        Ok(i64::from_le_bytes(
            self.slice(row, offset, 8)?
                .try_into()
                .map_err(|_| IndexError::corrupt("i64 field"))?,
        ))
    }
    fn zero(&self, row: usize, offset: usize, len: usize) -> Result<(), IndexError> {
        if self.slice(row, offset, len)?.iter().any(|v| *v != 0) {
            return Err(IndexError::corrupt("nonzero binary reserved bytes"));
        }
        Ok(())
    }
}

fn decode_capabilities(bytes: &[u8]) -> Result<ProviderCapabilities, IndexError> {
    let c = Cursor::new(bytes, 16)?;
    if c.rows() != 1 {
        return Err(IndexError::corrupt("capabilities cardinality"));
    }
    c.zero(0, 9, 7)?;
    let bit = |o| match c.u8(0, o)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(IndexError::corrupt("invalid capability boolean")),
    };
    Ok(ProviderCapabilities {
        global_ordering: bit(0)?,
        per_thread_ordering: bit(1)?,
        full_register_checkpoint: bit(2)?,
        register_read_write_observation: bit(3)?,
        memory_metadata: bit(4)?,
        memory_before_after: bit(5)?,
        lifecycle: bit(6)?,
        signal_and_termination: bit(7)?,
        loss_and_damage_ranges: bit(8)?,
    })
}

fn decode_events(
    bytes: &[u8],
    keys: &[EventKey],
    guard: &dyn WorkGuard,
) -> Result<Vec<EventColumn>, IndexError> {
    let c = Cursor::new(bytes, EVENT_META_BYTES)?;
    if c.rows() != keys.len() {
        return Err(IndexError::corrupt("event meta row count"));
    }
    let mut out = reserved(keys.len(), "event meta", guard)?;
    for (row, key) in keys.iter().enumerate() {
        checkpoint(guard, row)?;
        c.zero(row, 2, 2)?;
        c.zero(row, 20, 4)?;
        let scope = match c.u8(row, 1)? {
            0 => {
                if c.u32(row, 4)? != 0 || c.u32(row, 8)? != 0 || c.u32(row, 12)? != 0 {
                    return Err(IndexError::corrupt("artifact scope has values"));
                }
                EventScope::Artifact
            }
            1 => EventScope::FlightChunk {
                chunk_index: c.u32(row, 4)?,
                generation: c.u32(row, 8)?,
                tid: c.u32(row, 12)?,
            },
            _ => return Err(IndexError::corrupt("invalid event scope")),
        };
        out.push(EventColumn {
            timeline: key.timeline.0,
            tid: key.tid,
            sequence: key.sequence,
            scope,
            provenance: decode_provenance(c.u8(row, 0)?)?,
            payload_blob: c.u32(row, 16)?,
        });
    }
    Ok(out)
}

fn decode_arena(
    spans: &[u8],
    bytes: Vec<u8>,
    max_bytes: u64,
    guard: &dyn WorkGuard,
) -> Result<ByteArena<'static>, IndexError> {
    if bytes.len() as u64 > max_bytes {
        return Err(IndexError::corrupt("binary arena exceeds bound"));
    }
    let c = Cursor::new(spans, SPAN_BYTES)?;
    let mut decoded = reserved(c.rows(), "arena spans", guard)?;
    for row in 0..c.rows() {
        checkpoint(guard, row)?;
        decoded.push(ByteSpan {
            offset: c.u64(row, 0)?,
            length: c.u64(row, 8)?,
        });
    }
    guard.consume(WorkDelta {
        resident_bytes: u64::try_from(
            std::mem::size_of::<Vec<u8>>() + std::mem::size_of::<Vec<ByteSpan>>(),
        )
        .unwrap_or(u64::MAX),
        nodes: 2,
        ..WorkDelta::default()
    })?;
    let arena = ByteArena::from_owned_parts(bytes, decoded, max_bytes);
    arena.validate()?;
    Ok(arena)
}

fn decode_modules(bytes: &[u8], guard: &dyn WorkGuard) -> Result<Vec<ModuleRow>, IndexError> {
    let c = Cursor::new(bytes, MODULE_BYTES)?;
    let mut out = reserved(c.rows(), "modules", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        c.zero(r, 9, 3)?;
        c.zero(r, 28, 4)?;
        out.push(ModuleRow {
            source_event_row: usize_value(c.u64(r, 0)?)?,
            provenance: decode_provenance(c.u8(r, 8)?)?,
            source_id: c.u32(r, 12)?,
            base: c.u64(r, 16)?,
            name: c.u32(r, 24)?,
        });
    }
    Ok(out)
}
fn decode_definitions(
    bytes: &[u8],
    guard: &dyn WorkGuard,
) -> Result<Vec<DefinitionRow>, IndexError> {
    let c = Cursor::new(bytes, DEFINITION_BYTES)?;
    let mut out = reserved(c.rows(), "definitions", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        out.push(DefinitionRow {
            source_event_row: usize_value(c.u64(r, 0)?)?,
            provenance: decode_provenance(c.u8(r, 8)?)?,
            pc_kind: decode_pc_kind(c.u8(r, 9)?)?,
            condition: c.u8(r, 10)?,
            slow_memory_path: bool_value(c.u8(r, 11)?)?,
            source_id: c.u32(r, 12)?,
            opcode: c.u32(r, 16)?,
            flags: c.u32(r, 20)?,
            read_mask: c.u64(r, 24)?,
            write_mask: c.u64(r, 32)?,
            pc_displacement: c.i64(r, 40)?,
            mnemonic: c.u32(r, 48)?,
            operands: c.u32(r, 52)?,
            disassembly: c.u32(r, 56)?,
            exact_blob: c.u32(r, 60)?,
        });
    }
    Ok(out)
}
fn decode_instructions(
    bytes: &[u8],
    guard: &dyn WorkGuard,
) -> Result<Vec<InstructionRow>, IndexError> {
    let c = Cursor::new(bytes, INSTRUCTION_BYTES)?;
    let mut out = reserved(c.rows(), "instructions", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        let presence = c.u8(r, 24)?;
        if presence & !3 != 0 {
            return Err(IndexError::corrupt("instruction presence flags"));
        }
        c.zero(r, 25, 7)?;
        out.push(InstructionRow {
            owner_row: usize_value(c.u64(r, 0)?)?,
            module: (presence & 1 != 0).then(|| c.u32(r, 8)).transpose()?,
            definition: (presence & 2 != 0).then(|| c.u32(r, 12)).transpose()?,
            relative_pc: c.u64(r, 16)?,
        });
    }
    Ok(out)
}
fn decode_memories(bytes: &[u8], guard: &dyn WorkGuard) -> Result<Vec<MemoryRow>, IndexError> {
    let c = Cursor::new(bytes, MEMORY_BYTES)?;
    let mut out = reserved(c.rows(), "memories", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        c.zero(r, 12, 4)?;
        c.zero(r, 57, 3)?;
        c.zero(r, 68, 4)?;
        let present = bool_value(c.u8(r, 56)?)?;
        out.push(MemoryRow {
            owner_row: usize_value(c.u64(r, 0)?)?,
            module: present.then(|| c.u32(r, 8)).transpose()?,
            relative_pc: c.u64(r, 16)?,
            address: c.u64(r, 24)?,
            end_exclusive: c.u64(r, 32)?,
            value: c.u64(r, 40)?,
            size: c.u32(r, 48)?,
            flags: c.u16(r, 52)?,
            direction: decode_memory_direction(c.u8(r, 54)?)?,
            metadata_available: bool_value(c.u8(r, 55)?)?,
            before_blob: c.u32(r, 60)?,
            after_blob: c.u32(r, 64)?,
        });
    }
    Ok(out)
}
fn decode_semantics(bytes: &[u8], guard: &dyn WorkGuard) -> Result<Vec<SemanticRow>, IndexError> {
    let c = Cursor::new(bytes, SEMANTIC_BYTES)?;
    let mut out = reserved(c.rows(), "semantics", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        c.zero(r, 21, 11)?;
        let present = bool_value(c.u8(r, 20)?)?;
        out.push(SemanticRow {
            owner_row: usize_value(c.u64(r, 0)?)?,
            category: present.then(|| c.u32(r, 8)).transpose()?,
            name: c.u32(r, 12)?,
            detail_blob: c.u32(r, 16)?,
        });
    }
    Ok(out)
}
fn decode_completeness(
    bytes: &[u8],
    guard: &dyn WorkGuard,
) -> Result<Vec<CompletenessRow>, IndexError> {
    let c = Cursor::new(bytes, COMPLETENESS_BYTES)?;
    let mut out = reserved(c.rows(), "completeness", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        c.zero(r, 4, 4)?;
        c.zero(r, 24, 8)?;
        let domain = decode_range_domain(c.u8(r, 0)?)?;
        let start = c.u64(r, 8)?;
        let end = c.u64(r, 16)?;
        let bounds = match c.u8(r, 1)? {
            0 if domain == RangeDomain::CapturedSequence && start <= end => {
                RangeBounds::InclusiveSequence {
                    first: start,
                    last: end,
                }
            }
            1 if domain != RangeDomain::CapturedSequence && start <= end => RangeBounds::HalfOpen {
                start,
                end_exclusive: end,
            },
            _ => return Err(IndexError::corrupt("invalid completeness domain/bounds")),
        };
        out.push(CompletenessRow {
            domain,
            bounds,
            provenance: decode_provenance(c.u8(r, 2)?)?,
            cause: decode_completeness_cause(c.u8(r, 3)?)?,
        });
    }
    Ok(out)
}
fn decode_observations(
    bytes: &[u8],
    guard: &dyn WorkGuard,
) -> Result<Vec<RegisterObservationRow>, IndexError> {
    let c = Cursor::new(bytes, OBSERVATION_BYTES)?;
    let mut out = reserved(c.rows(), "register observations", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        c.zero(r, 20, 4)?;
        out.push(RegisterObservationRow {
            owner_row: usize_value(c.u64(r, 0)?)?,
            value: c.u64(r, 8)?,
            slot: c.u8(r, 16)?,
            captured_width: c.u8(r, 17)?,
            access: decode_register_access(c.u8(r, 18)?)?,
            provenance: decode_provenance(c.u8(r, 19)?)?,
        });
    }
    Ok(out)
}

fn decode_map<K: Ord>(
    bytes: &[u8],
    key: impl Fn(u64) -> Result<K, IndexError>,
    guard: &dyn WorkGuard,
) -> Result<SortedMap<K, PostingList>, IndexError> {
    let c = Cursor::new(bytes, PAIR_BYTES)?;
    let mut group_count = 0usize;
    for row in 0..c.rows() {
        checkpoint(guard, row)?;
        if row == 0 || c.u64(row - 1, 0)? != c.u64(row, 0)? {
            group_count = group_count
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("posting group count overflow"))?;
        }
    }
    let mut grouped = reserved(group_count, "posting map", guard)?;
    let mut first = 0;
    while first < c.rows() {
        checkpoint(guard, first)?;
        let raw = c.u64(first, 0)?;
        let k = key(raw)?;
        let mut last = first + 1;
        while last < c.rows() && c.u64(last, 0)? == raw {
            last += 1;
        }
        let mut deltas = reserved(last - first, "posting group", guard)?;
        for row in first..last {
            checkpoint(guard, row)?;
            let delta = c.u64(row, 8)?;
            if delta == 0 {
                return Err(IndexError::corrupt("zero posting delta"));
            }
            deltas.push(delta);
        }
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        grouped.push((k, PostingList::from_deltas(deltas)));
        first = last;
    }
    SortedMap::from_sorted(grouped)
}
fn decode_list(bytes: &[u8], guard: &dyn WorkGuard) -> Result<PostingList, IndexError> {
    let c = Cursor::new(bytes, 8)?;
    let mut out = reserved(c.rows(), "posting list", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        let d = c.u64(r, 0)?;
        if d == 0 {
            return Err(IndexError::corrupt("zero posting delta"));
        }
        out.push(d);
    }
    Ok(PostingList::from_deltas(out))
}
fn decode_pairs(bytes: &[u8], guard: &dyn WorkGuard) -> Result<Vec<(u64, usize)>, IndexError> {
    let c = Cursor::new(bytes, PAIR_BYTES)?;
    let mut out = reserved(c.rows(), "pair index", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        out.push((c.u64(r, 0)?, usize_value(c.u64(r, 8)?)?));
    }
    Ok(out)
}
fn decode_module_pc(
    bytes: &[u8],
    guard: &dyn WorkGuard,
) -> Result<SortedMap<u32, Vec<(u64, usize)>>, IndexError> {
    let c = Cursor::new(bytes, MODULE_PC_BYTES)?;
    let mut group_count = 0usize;
    for row in 0..c.rows() {
        checkpoint(guard, row)?;
        if row == 0 || c.u32(row - 1, 0)? != c.u32(row, 0)? {
            group_count = group_count
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("module PC group count overflow"))?;
        }
    }
    let mut out = reserved(group_count, "module PC map", guard)?;
    let mut first = 0;
    while first < c.rows() {
        checkpoint(guard, first)?;
        let k = c.u32(first, 0)?;
        let mut last = first + 1;
        while last < c.rows() && c.u32(last, 0)? == k {
            last += 1;
        }
        let mut rows = reserved(last - first, "module PC group", guard)?;
        for row in first..last {
            checkpoint(guard, row)?;
            c.zero(row, 4, 4)?;
            rows.push((c.u64(row, 8)?, usize_value(c.u64(row, 16)?)?));
        }
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        out.push((k, rows));
        first = last;
    }
    SortedMap::from_sorted(out)
}
fn decode_intervals(
    bytes: &[u8],
    guard: &dyn WorkGuard,
) -> Result<(Vec<IntervalEntry>, Vec<u64>), IndexError> {
    let c = Cursor::new(bytes, INTERVAL_BYTES)?;
    let mut entries = reserved(c.rows(), "interval entries", guard)?;
    let mut prefix = reserved(c.rows(), "interval prefix", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        entries.push(IntervalEntry {
            start: c.u64(r, 0)?,
            end_exclusive: c.u64(r, 8)?,
            row: usize_value(c.u64(r, 16)?)?,
        });
        prefix.push(c.u64(r, 24)?);
    }
    Ok((entries, prefix))
}
fn decode_block_max(bytes: &[u8], guard: &dyn WorkGuard) -> Result<Vec<u64>, IndexError> {
    let c = Cursor::new(bytes, PAIR_BYTES)?;
    let mut out = reserved(c.rows(), "block max", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        if c.u64(r, 0)? != r as u64 {
            return Err(IndexError::corrupt("block max ordinal"));
        }
        out.push(c.u64(r, 8)?);
    }
    Ok(out)
}
fn decode_source_rows(
    bytes: &[u8],
    keys: &[EventKey],
    guard: &dyn WorkGuard,
) -> Result<Vec<SourceKeyRow>, IndexError> {
    let c = Cursor::new(bytes, 8)?;
    if c.rows() != keys.len() {
        return Err(IndexError::corrupt("source row cardinality"));
    }
    let mut out = reserved(c.rows(), "source rows", guard)?;
    for r in 0..c.rows() {
        checkpoint(guard, r)?;
        let row = usize_value(c.u64(r, 0)?)?;
        let key = keys
            .get(row)
            .ok_or_else(|| IndexError::corrupt("source row outside keys"))?
            .clone();
        out.push(SourceKeyRow { key, row });
    }
    Ok(out)
}

fn reserved<T>(
    rows: usize,
    label: &'static str,
    guard: &dyn WorkGuard,
) -> Result<Vec<T>, IndexError> {
    let mut out = Vec::new();
    crate::allocation::try_reserve_vec(&mut out, rows, guard, label)?;
    Ok(out)
}
fn usize_value(v: u64) -> Result<usize, IndexError> {
    usize::try_from(v).map_err(|_| IndexError::corrupt("row does not fit usize"))
}
fn checked_u32(v: u64) -> Result<u32, IndexError> {
    u32::try_from(v).map_err(|_| IndexError::corrupt("index key does not fit u32"))
}
fn checked_u8(v: u64) -> Result<u8, IndexError> {
    u8::try_from(v).map_err(|_| IndexError::corrupt("index key does not fit u8"))
}
fn bool_value(v: u8) -> Result<bool, IndexError> {
    match v {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(IndexError::corrupt("invalid binary boolean")),
    }
}
fn decode_provenance(v: u8) -> Result<Provenance, IndexError> {
    match v {
        0 => Ok(Provenance::Captured),
        1 => Ok(Provenance::Derived),
        2 => Ok(Provenance::Heuristic),
        3 => Ok(Provenance::Unknown),
        4 => Ok(Provenance::Damaged),
        _ => Err(IndexError::corrupt("invalid provenance")),
    }
}
fn decode_pc_kind(v: u8) -> Result<PcRelativeKind, IndexError> {
    match v {
        0 => Ok(PcRelativeKind::None),
        1 => Ok(PcRelativeKind::Instruction),
        2 => Ok(PcRelativeKind::Page),
        _ => Err(IndexError::corrupt("invalid PC kind")),
    }
}
fn decode_memory_direction(v: u8) -> Result<MemoryDirection, IndexError> {
    match v {
        0 => Ok(MemoryDirection::Read),
        1 => Ok(MemoryDirection::Write),
        2 => Ok(MemoryDirection::ReadWrite),
        3 => Ok(MemoryDirection::Unknown),
        _ => Err(IndexError::corrupt("invalid memory direction")),
    }
}
fn decode_register_access(v: u8) -> Result<RegisterAccess, IndexError> {
    match v {
        0 => Ok(RegisterAccess::Read),
        1 => Ok(RegisterAccess::Write),
        2 => Ok(RegisterAccess::Checkpoint),
        3 => Ok(RegisterAccess::Delta),
        _ => Err(IndexError::corrupt("invalid register access")),
    }
}
fn decode_range_domain(v: u8) -> Result<RangeDomain, IndexError> {
    match v {
        0 => Ok(RangeDomain::CapturedSequence),
        1 => Ok(RangeDomain::SourceBytes),
        2 => Ok(RangeDomain::MemoryAddresses),
        _ => Err(IndexError::corrupt("invalid range domain")),
    }
}
fn decode_completeness_cause(v: u8) -> Result<CompletenessCause, IndexError> {
    match v {
        0 => Ok(CompletenessCause::Retained),
        1 => Ok(CompletenessCause::MissingTerminal),
        2 => Ok(CompletenessCause::Active),
        3 => Ok(CompletenessCause::Stale),
        4 => Ok(CompletenessCause::Rotating),
        5 => Ok(CompletenessCause::Unreliable),
        6 => Ok(CompletenessCause::Incomplete),
        7 => Ok(CompletenessCause::Lost),
        8 => Ok(CompletenessCause::Overwritten),
        9 => Ok(CompletenessCause::CoverageGap),
        10 => Ok(CompletenessCause::Checksum),
        11 => Ok(CompletenessCause::UnterminatedThread),
        12 => Ok(CompletenessCause::Truncation),
        13 => Ok(CompletenessCause::Unknown),
        _ => Err(IndexError::corrupt("invalid completeness cause")),
    }
}
