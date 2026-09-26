use std::{collections::HashMap, hash::Hash};

use qtrace_provider::{
    EventKind, EventPayload, EventRecord, EventScope, Provenance, ProviderCapabilities,
    RegisterSlot, TraceProvider, WorkDelta, WorkGuard,
};
use serde::Serialize;

use crate::ArtifactSource;

use super::{
    BuildOptions, ByteArena, CompletenessRow, DefinitionRow, EventColumn, IndexCatalog, IndexError,
    InstructionRow, MemoryRow, ModuleRow, NormalizedCatalog, NormalizedSourceFormat,
    OwnedTraceStore, SemanticRow, SortedMap, SourceKeyRow, checkpoints::RegisterAccess,
    checkpoints::RegisterObservationRow, intervals::IntervalEntry, intervals::IntervalIndex,
    postings::PostingList, validation::validate_external_payload_tag,
};

pub struct IndexBuilder;

impl IndexBuilder {
    pub fn build(
        source: &ArtifactSource,
        options: &BuildOptions,
        guard: &dyn WorkGuard,
    ) -> Result<OwnedTraceStore, IndexError> {
        options.validate()?;
        guard.consume(WorkDelta::default())?;
        let provider = source.open_provider(guard)?;
        Self::build_provider(provider, options, guard)
    }

    fn build_provider(
        provider: Box<dyn TraceProvider>,
        options: &BuildOptions,
        guard: &dyn WorkGuard,
    ) -> Result<OwnedTraceStore, IndexError> {
        let source_format = NormalizedSourceFormat::parse(&provider.identity().format)?;
        let mut capabilities = provider.capabilities().clone();
        let mut cursor = {
            let resident = provider.cursor_resident_bytes()?;
            let _scope = crate::allocation::scope(guard, resident, 0)?;
            provider.into_cursor()?
        };
        let mut state = BuildState::new(options)?;
        while let Some(event) = cursor.next_event(guard)? {
            guard.consume(WorkDelta {
                events: 1,
                rows: 1,
                ..WorkDelta::default()
            })?;
            state.append(event, guard)?;
        }
        guard.consume(WorkDelta::default())?;
        let summary = cursor.finish()?;
        guard.consume(WorkDelta::default())?;
        state.append_completeness(summary.completeness, guard)?;
        super::probe_index_memory("after_source_scan");
        capabilities.full_register_checkpoint &= state.saw_complete_checkpoint;
        state.finish(capabilities, options, source_format, guard)
    }
}

struct BuildState<'a> {
    next_row: usize,
    retain_source_columns: bool,
    keys: Vec<qtrace_provider::EventKey>,
    kinds: Vec<EventKind>,
    events: Vec<EventColumn>,
    payloads: ByteArena<'a>,
    strings: ByteArena<'a>,
    blobs: ByteArena<'a>,
    modules: Vec<ModuleRow>,
    definitions: Vec<DefinitionRow>,
    instructions: Vec<InstructionRow>,
    memories: Vec<MemoryRow>,
    semantics: Vec<SemanticRow>,
    observations: Vec<RegisterObservationRow>,
    completeness: Vec<CompletenessRow>,
    module_by_source: HashMap<(EventScope, u32), (u32, u64, u32)>,
    module_by_semantic: HashMap<(u64, u32), u32>,
    definition_by_source: HashMap<(EventScope, u32), (u32, u32)>,
    definition_by_blob: HashMap<u32, u32>,
    next_module_id: u32,
    next_definition_id: u32,
    saw_complete_checkpoint: bool,
    saw_register_observation: bool,
    saw_memory_metadata: bool,
    saw_memory_before_after: bool,
    saw_lifecycle: bool,
    saw_signal_or_termination: bool,
    current_module: HashMap<EventScope, (u64, Vec<u8>)>,
}

impl<'a> BuildState<'a> {
    fn new(options: &BuildOptions) -> Result<Self, IndexError> {
        Self::with_source_columns(options, true)
    }

    fn validation(
        options: &BuildOptions,
        catalog: &'a NormalizedCatalog,
    ) -> Result<Self, IndexError> {
        let mut state = Self::with_source_columns(options, false)?;
        state.strings = ByteArena::validation(&catalog.strings);
        state.blobs = ByteArena::validation(&catalog.blobs);
        Ok(state)
    }

    fn with_source_columns(
        options: &BuildOptions,
        retain_source_columns: bool,
    ) -> Result<Self, IndexError> {
        Ok(Self {
            next_row: 0,
            retain_source_columns,
            keys: Vec::new(),
            kinds: Vec::new(),
            events: Vec::new(),
            payloads: ByteArena::new(options.max_payload_bytes),
            strings: ByteArena::new(options.max_string_bytes),
            blobs: ByteArena::new(options.max_blob_bytes),
            modules: Vec::new(),
            definitions: Vec::new(),
            instructions: Vec::new(),
            memories: Vec::new(),
            semantics: Vec::new(),
            observations: Vec::new(),
            completeness: Vec::new(),
            module_by_source: HashMap::new(),
            module_by_semantic: HashMap::new(),
            definition_by_source: HashMap::new(),
            definition_by_blob: HashMap::new(),
            next_module_id: 0,
            next_definition_id: 0,
            saw_complete_checkpoint: false,
            saw_register_observation: false,
            saw_memory_metadata: false,
            saw_memory_before_after: false,
            saw_lifecycle: false,
            saw_signal_or_termination: false,
            current_module: HashMap::new(),
        })
    }

    fn append(&mut self, event: EventRecord, guard: &dyn WorkGuard) -> Result<(), IndexError> {
        let payload_bytes = canonical_bytes(&event.payload, guard)?;
        let payload_blob = self.payloads.intern(&payload_bytes, guard)?;
        self.append_with_payload_blob(event, payload_blob, guard)
    }

    fn append_with_payload_blob(
        &mut self,
        event: EventRecord,
        payload_blob: u32,
        guard: &dyn WorkGuard,
    ) -> Result<(), IndexError> {
        let row = self.next_row;
        self.next_row = self
            .next_row
            .checked_add(1)
            .ok_or_else(|| IndexError::resource("event row count overflow"))?;
        if self.retain_source_columns {
            crate::allocation::try_reserve_vec(&mut self.keys, 1, guard, "event key allocation")?;
            crate::allocation::try_reserve_vec(&mut self.kinds, 1, guard, "event kind allocation")?;
            crate::allocation::try_reserve_vec(
                &mut self.events,
                1,
                guard,
                "event column allocation",
            )?;
            self.keys.push(event.key.clone());
            self.kinds.push(event.kind());
            self.events.push(EventColumn {
                scope: event.scope(),
                provenance: event.provenance,
                payload_blob,
            });
        }

        match &event.payload {
            EventPayload::Begin(begin) => {
                crate::allocation::try_reserve_hash_map(
                    &mut self.current_module,
                    1,
                    guard,
                    "module scope allocation",
                )?;
                self.current_module.insert(
                    event.scope(),
                    (
                        begin.module_base,
                        try_copy_bytes(begin.target.as_bytes(), guard, "begin target")?,
                    ),
                );
            }
            EventPayload::ModuleDefinition(module) => {
                let name = self.strings.intern(module.name.as_bytes(), guard)?;
                let source_key = (event.scope(), module.module_id);
                match self.module_by_source.get(&source_key).copied() {
                    Some((_, base, existing_name))
                        if base == module.base && existing_name == name => {}
                    Some(_) => return Err(IndexError::invalid("conflicting module definition")),
                    None => {
                        let semantic_key = (module.base, name);
                        let id = if let Some(id) = self.module_by_semantic.get(&semantic_key) {
                            *id
                        } else {
                            let id = self.next_module_id;
                            self.next_module_id = id.checked_add(1).ok_or_else(|| {
                                IndexError::resource("module dictionary exceeds u32")
                            })?;
                            crate::allocation::try_reserve_vec(
                                &mut self.modules,
                                1,
                                guard,
                                "module dictionary allocation",
                            )?;
                            self.modules.push(ModuleRow {
                                source_event_row: row,
                                provenance: event.provenance,
                                source_id: module.module_id,
                                base: module.base,
                                name,
                            });
                            crate::allocation::try_reserve_hash_map(
                                &mut self.module_by_semantic,
                                1,
                                guard,
                                "module semantic map allocation",
                            )?;
                            self.module_by_semantic.insert(semantic_key, id);
                            id
                        };
                        crate::allocation::try_reserve_hash_map(
                            &mut self.module_by_source,
                            1,
                            guard,
                            "module source map allocation",
                        )?;
                        self.module_by_source
                            .insert(source_key, (id, module.base, name));
                    }
                }
            }
            EventPayload::InstructionDefinition(definition) => {
                let exact =
                    canonical_bytes(&qtrace_provider::SemanticDefinition(definition), guard)?;
                let exact_blob = self.blobs.intern(&exact, guard)?;
                let source_key = (event.scope(), definition.definition_id);
                if let Some((_, previous_blob)) = self.definition_by_source.get(&source_key) {
                    if *previous_blob != exact_blob {
                        return Err(IndexError::invalid("conflicting instruction definition"));
                    }
                } else {
                    let id = if let Some(id) = self.definition_by_blob.get(&exact_blob) {
                        *id
                    } else {
                        let id = self.next_definition_id;
                        self.next_definition_id = id.checked_add(1).ok_or_else(|| {
                            IndexError::resource("definition dictionary exceeds u32")
                        })?;
                        let mnemonic =
                            self.strings.intern(definition.mnemonic.as_bytes(), guard)?;
                        let operands =
                            self.strings.intern(definition.operands.as_bytes(), guard)?;
                        let disassembly = self
                            .strings
                            .intern(definition.disassembly.as_bytes(), guard)?;
                        crate::allocation::try_reserve_vec(
                            &mut self.definitions,
                            1,
                            guard,
                            "definition dictionary allocation",
                        )?;
                        self.definitions.push(DefinitionRow {
                            source_event_row: row,
                            provenance: event.provenance,
                            source_id: definition.definition_id,
                            opcode: definition.opcode,
                            read_mask: definition.read_mask,
                            write_mask: definition.write_mask,
                            pc_displacement: definition.pc_displacement,
                            flags: definition.flags,
                            pc_kind: definition.pc_kind,
                            condition: definition.condition,
                            slow_memory_path: definition.slow_memory_path,
                            mnemonic,
                            operands,
                            disassembly,
                            exact_blob,
                        });
                        crate::allocation::try_reserve_hash_map(
                            &mut self.definition_by_blob,
                            1,
                            guard,
                            "definition semantic map allocation",
                        )?;
                        self.definition_by_blob.insert(exact_blob, id);
                        id
                    };
                    crate::allocation::try_reserve_hash_map(
                        &mut self.definition_by_source,
                        1,
                        guard,
                        "definition source map allocation",
                    )?;
                    self.definition_by_source
                        .insert(source_key, (id, exact_blob));
                }
            }
            EventPayload::Instruction(instruction) => {
                let module_source_key = (event.scope(), instruction.module_id);
                if !self.module_by_source.contains_key(&module_source_key) {
                    if let Some((base, name)) = self.current_module.get(&event.scope()) {
                        let name = self.strings.intern(name, guard)?;
                        let semantic_key = (*base, name);
                        let id = if let Some(id) = self.module_by_semantic.get(&semantic_key) {
                            *id
                        } else {
                            let id = self.next_module_id;
                            self.next_module_id = id.checked_add(1).ok_or_else(|| {
                                IndexError::resource("module dictionary exceeds u32")
                            })?;
                            crate::allocation::try_reserve_vec(
                                &mut self.modules,
                                1,
                                guard,
                                "module dictionary allocation",
                            )?;
                            self.modules.push(ModuleRow {
                                source_event_row: row,
                                provenance: Provenance::Derived,
                                source_id: instruction.module_id,
                                base: *base,
                                name,
                            });
                            crate::allocation::try_reserve_hash_map(
                                &mut self.module_by_semantic,
                                1,
                                guard,
                                "module semantic map allocation",
                            )?;
                            self.module_by_semantic.insert(semantic_key, id);
                            id
                        };
                        crate::allocation::try_reserve_hash_map(
                            &mut self.module_by_source,
                            1,
                            guard,
                            "module source map allocation",
                        )?;
                        self.module_by_source
                            .insert(module_source_key, (id, *base, name));
                    }
                }
                let module = self
                    .module_by_source
                    .get(&module_source_key)
                    .map(|value| value.0);
                let definition = self
                    .definition_by_source
                    .get(&(event.scope(), instruction.definition_id))
                    .map(|item| item.0);
                crate::allocation::try_reserve_vec(
                    &mut self.instructions,
                    1,
                    guard,
                    "instruction column allocation",
                )?;
                self.instructions.push(InstructionRow {
                    owner_row: row,
                    module,
                    relative_pc: instruction.relative_pc,
                    definition,
                });
                let observation_count = instruction
                    .read_before
                    .len()
                    .checked_add(instruction.write_after.len())
                    .ok_or_else(|| {
                        IndexError::resource("instruction observation count overflow")
                    })?;
                crate::allocation::try_reserve_vec(
                    &mut self.observations,
                    observation_count,
                    guard,
                    "register observation allocation",
                )?;
                for value in &instruction.read_before {
                    self.saw_register_observation = true;
                    self.observations.push(RegisterObservationRow {
                        owner_row: row,
                        slot: value.slot,
                        captured_width: value.captured_width,
                        access: RegisterAccess::Read,
                        value: value.value,
                        provenance: event.provenance,
                    });
                }
                for value in &instruction.write_after {
                    self.saw_register_observation = true;
                    self.observations.push(RegisterObservationRow {
                        owner_row: row,
                        slot: value.slot,
                        captured_width: value.captured_width,
                        access: RegisterAccess::Write,
                        value: value.value,
                        provenance: event.provenance,
                    });
                }
            }
            EventPayload::Memory(memory) => {
                self.saw_memory_metadata |= memory.metadata_available;
                self.saw_memory_before_after |=
                    !matches!(&memory.before, qtrace_provider::CaptureBytes::NotCaptured)
                        || !matches!(&memory.after, qtrace_provider::CaptureBytes::NotCaptured);
                let end_exclusive = memory
                    .address
                    .checked_add(u64::from(memory.size))
                    .ok_or_else(|| IndexError::invalid("memory address plus size overflows"))?;
                crate::allocation::try_reserve_vec(
                    &mut self.memories,
                    1,
                    guard,
                    "memory column allocation",
                )?;
                self.memories.push(MemoryRow {
                    owner_row: row,
                    module: self
                        .module_by_source
                        .get(&(event.scope(), memory.module_id))
                        .map(|value| value.0),
                    relative_pc: memory.relative_pc,
                    address: memory.address,
                    end_exclusive,
                    size: memory.size,
                    direction: memory.direction,
                    metadata_available: memory.metadata_available,
                    flags: memory.flags,
                    value: memory.value,
                    before_blob: self
                        .blobs
                        .intern(&canonical_bytes(&memory.before, guard)?, guard)?,
                    after_blob: self
                        .blobs
                        .intern(&canonical_bytes(&memory.after, guard)?, guard)?,
                });
            }
            EventPayload::SemanticCall(value)
            | EventPayload::SemanticRule(value)
            | EventPayload::SemanticError(value) => {
                crate::allocation::try_reserve_vec(
                    &mut self.semantics,
                    1,
                    guard,
                    "semantic column allocation",
                )?;
                self.semantics.push(SemanticRow {
                    owner_row: row,
                    category: value
                        .category
                        .as_ref()
                        .map(|value| self.strings.intern(value.as_bytes(), guard))
                        .transpose()?,
                    name: self.strings.intern(value.name.as_bytes(), guard)?,
                    detail_blob: self.blobs.intern(value.detail.as_bytes(), guard)?,
                });
            }
            EventPayload::RegisterCheckpoint(checkpoint) => {
                self.saw_complete_checkpoint |=
                    matches!(event.provenance, Provenance::Captured | Provenance::Derived)
                        && checkpoint.values.len() == RegisterSlot::COUNT
                        && checkpoint
                            .values
                            .iter()
                            .enumerate()
                            .all(|(index, item)| item.slot.index() == index);
                crate::allocation::try_reserve_vec(
                    &mut self.observations,
                    checkpoint.values.len(),
                    guard,
                    "register checkpoint observation allocation",
                )?;
                for value in &checkpoint.values {
                    self.observations.push(RegisterObservationRow {
                        owner_row: row,
                        slot: value.slot.index() as u8,
                        captured_width: 8,
                        access: RegisterAccess::Checkpoint,
                        value: value.value,
                        provenance: event.provenance,
                    });
                }
            }
            EventPayload::RegisterDelta(delta) => {
                crate::allocation::try_reserve_vec(
                    &mut self.observations,
                    delta.changed.len(),
                    guard,
                    "register delta observation allocation",
                )?;
                for value in &delta.changed {
                    self.observations.push(RegisterObservationRow {
                        owner_row: row,
                        slot: value.slot.index() as u8,
                        captured_width: 8,
                        access: RegisterAccess::Delta,
                        value: value.value,
                        provenance: if delta.ancestry_reliable {
                            event.provenance
                        } else {
                            Provenance::Damaged
                        },
                    });
                }
            }
            EventPayload::StringDefinition(value) => {
                let _ = self.strings.intern(&value.bytes, guard)?;
            }
            EventPayload::ThreadLifecycle(_) => self.saw_lifecycle = true,
            EventPayload::Signal(_)
            | EventPayload::SignalHandlerBoundary(_)
            | EventPayload::Termination(_) => self.saw_signal_or_termination = true,
            _ => {}
        }
        Ok(())
    }

    fn append_completeness(
        &mut self,
        ranges: Vec<qtrace_provider::CompletenessRange>,
        guard: &dyn WorkGuard,
    ) -> Result<(), IndexError> {
        crate::allocation::try_reserve_vec(
            &mut self.completeness,
            ranges.len(),
            guard,
            "completeness allocation",
        )?;
        for range in ranges {
            guard.consume(WorkDelta {
                nodes: 1,
                ..WorkDelta::default()
            })?;
            self.completeness.push(CompletenessRow::from_range(range));
        }
        validate_completeness_rows(&self.completeness, guard).map_err(|error| {
            if error.code().starts_with("control.") || error.code() == "job.cancelled" {
                error
            } else {
                IndexError::invalid("provider completeness is not canonical")
            }
        })?;
        Ok(())
    }

    fn finish(
        self,
        mut capabilities: ProviderCapabilities,
        options: &BuildOptions,
        source_format: NormalizedSourceFormat,
        guard: &dyn WorkGuard,
    ) -> Result<OwnedTraceStore, IndexError> {
        capabilities.register_read_write_observation &= self.saw_register_observation;
        capabilities.memory_metadata &= self.saw_memory_metadata;
        capabilities.memory_before_after &= self.saw_memory_before_after;
        capabilities.lifecycle &= self.saw_lifecycle;
        capabilities.signal_and_termination &= self.saw_signal_or_termination;
        guard.consume(WorkDelta::default())?;
        let indexes = build_indexes(
            &self.keys,
            &self.kinds,
            &self.events,
            &self.definitions,
            &self.instructions,
            &self.memories,
            &self.semantics,
            &self.observations,
            options,
            guard,
        )?;
        super::probe_index_memory("after_postings");
        let (payload_bytes, payload_spans, payload_max) = self.payloads.into_owned_parts()?;
        let (string_bytes, string_spans, string_max) = self.strings.into_owned_parts()?;
        let (blob_bytes, blob_spans, blob_max) = self.blobs.into_owned_parts()?;
        let catalog = NormalizedCatalog {
            schema: 2,
            capabilities,
            events: self.events,
            payloads: ByteArena::from_owned_parts(payload_bytes, payload_spans, payload_max),
            strings: ByteArena::from_owned_parts(string_bytes, string_spans, string_max),
            blobs: ByteArena::from_owned_parts(blob_bytes, blob_spans, blob_max),
            modules: self.modules,
            definitions: self.definitions,
            instructions: self.instructions,
            memories: self.memories,
            semantics: self.semantics,
            observations: self.observations,
            completeness: self.completeness,
            indexes,
        };
        guard.consume(WorkDelta::default())?;
        OwnedTraceStore::new(self.keys, self.kinds, catalog, source_format, guard)
    }
}

pub(super) fn validate_cached_truth(
    catalog: &NormalizedCatalog,
    source_completeness: &[CompletenessRow],
    keys: &[qtrace_provider::EventKey],
    kinds: &[EventKind],
    source_format: &str,
    guard: &dyn WorkGuard,
) -> Result<(), IndexError> {
    if catalog.events.len() != keys.len() || kinds.len() != keys.len() {
        return Err(IndexError::corrupt(
            "cached source fact cardinality differs",
        ));
    }
    let options = BuildOptions {
        interval_block_rows: u32::try_from(catalog.indexes.memory.block_rows())
            .map_err(|_| IndexError::corrupt("interval block size does not fit u32"))?,
        max_payload_bytes: catalog.payloads.max_bytes,
        max_blob_bytes: catalog.blobs.max_bytes,
        max_string_bytes: catalog.strings.max_bytes,
    };
    let mut state = BuildState::validation(&options, catalog)?;
    let mut instruction_cursor = 0;
    let mut memory_cursor = 0;
    let mut semantic_cursor = 0;
    let mut observation_cursor = 0;
    let mut module_cursor = 0;
    let mut definition_cursor = 0;
    let mut discontinuity_count = 0_usize;
    for kind in kinds {
        discontinuity_count = discontinuity_count
            .checked_add(usize::from(*kind == EventKind::Discontinuity))
            .ok_or_else(|| IndexError::resource("discontinuity count overflow"))?;
    }
    let mut discontinuities = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut discontinuities,
        discontinuity_count,
        guard,
        "discontinuity evidence allocation",
    )?;
    let mut validated_opaque_payloads = HashMap::<u32, ()>::new();
    let mut last_validated_opaque = None;
    for (row, kind) in kinds.iter().copied().enumerate() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        let payload_blob = catalog.events[row].payload_blob;
        if kind == EventKind::OpaqueOptional && last_validated_opaque == Some(payload_blob) {
            state.next_row = state
                .next_row
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("event row count overflow"))?;
            continue;
        }
        let bytes = catalog.payloads.get(payload_blob)?;
        validate_external_payload_tag(bytes, kind)?;
        if kind == EventKind::OpaqueOptional {
            if !validated_opaque_payloads.contains_key(&payload_blob) {
                let decoded: EventPayload = {
                    let resident =
                        crate::allocation::payload_decode_upper_bound(kind, bytes.len())?;
                    let _scope = crate::allocation::scope(guard, resident, resident)?;
                    serde_json::from_slice(bytes).map_err(|_| {
                        IndexError::corrupt("canonical event payload cannot be decoded")
                    })?
                };
                if !matches!(decoded, EventPayload::OpaqueOptional(_))
                    || canonical_bytes(&decoded, guard)? != bytes
                {
                    return Err(IndexError::corrupt(
                        "opaque event payload bytes are not canonical",
                    ));
                }
                crate::allocation::try_reserve_hash_map(
                    &mut validated_opaque_payloads,
                    1,
                    guard,
                    "opaque payload validation cache",
                )?;
                validated_opaque_payloads.insert(payload_blob, ());
            }
            last_validated_opaque = Some(payload_blob);
            state.next_row = state
                .next_row
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("event row count overflow"))?;
            continue;
        }
        let payload: EventPayload = {
            let resident = crate::allocation::payload_decode_upper_bound(kind, bytes.len())?;
            let _scope = crate::allocation::scope(guard, resident, resident)?;
            serde_json::from_slice(bytes)
                .map_err(|_| IndexError::corrupt("canonical event payload cannot be decoded"))?
        };
        if canonical_bytes(&payload, guard)? != bytes {
            return Err(IndexError::corrupt("event payload bytes are not canonical"));
        }
        if let EventPayload::Discontinuity(discontinuity) = &payload {
            guard.consume(WorkDelta {
                nodes: 1,
                ..WorkDelta::default()
            })?;
            discontinuities.push(CompletenessRow::from_range(discontinuity.evidence));
        }
        let event = EventRecord::new_scoped(
            keys[row].clone(),
            catalog.events[row].provenance,
            catalog.events[row].scope,
            payload,
        );
        if event.kind() != kinds[row] {
            return Err(IndexError::corrupt(
                "base event kind disagrees with canonical payload",
            ));
        }
        let expected_event = EventColumn {
            scope: event.scope(),
            provenance: event.provenance,
            payload_blob: catalog.events[row].payload_blob,
        };
        if expected_event != catalog.events[row] {
            return Err(IndexError::corrupt(
                "event metadata disagrees with its source facts",
            ));
        }
        state
            .append_with_payload_blob(event, catalog.events[row].payload_blob, guard)
            .map_err(cached_rebuild_error)?;
        compare_streamed_rows(
            &state.instructions,
            &catalog.instructions,
            &mut instruction_cursor,
            "instruction",
        )?;
        compare_streamed_rows(
            &state.memories,
            &catalog.memories,
            &mut memory_cursor,
            "memory",
        )?;
        compare_streamed_rows(
            &state.semantics,
            &catalog.semantics,
            &mut semantic_cursor,
            "semantic",
        )?;
        compare_streamed_rows(
            &state.observations,
            &catalog.observations,
            &mut observation_cursor,
            "register observation",
        )?;
        compare_streamed_rows(
            &state.modules,
            &catalog.modules,
            &mut module_cursor,
            "module",
        )?;
        compare_streamed_rows(
            &state.definitions,
            &catalog.definitions,
            &mut definition_cursor,
            "definition",
        )?;
        state.instructions.clear();
        state.memories.clear();
        state.semantics.clear();
        state.observations.clear();
        state.modules.clear();
        state.definitions.clear();
    }
    if instruction_cursor != catalog.instructions.len()
        || memory_cursor != catalog.memories.len()
        || semantic_cursor != catalog.semantics.len()
        || observation_cursor != catalog.observations.len()
        || module_cursor != catalog.modules.len()
        || definition_cursor != catalog.definitions.len()
    {
        return Err(IndexError::corrupt(
            "stored typed child cardinality exceeds canonical payload facts",
        ));
    }
    validate_completeness_rows(source_completeness, guard).map_err(cached_rebuild_error)?;
    if source_format.eq_ignore_ascii_case("flight") {
        cancellable_sort_by(&mut discontinuities, guard, compare_completeness_rows)?;
        discontinuities.dedup();
        let mut evidence = discontinuities.iter();
        for (ordinal, source) in source_completeness
            .iter()
            .filter(|row| row.cause != qtrace_provider::CompletenessCause::Retained)
            .enumerate()
        {
            if ordinal % 4096 == 0 {
                guard.consume(WorkDelta::default())?;
            }
            if evidence.next() != Some(source) {
                return Err(IndexError::corrupt(
                    "Flight discontinuity payloads disagree with provider completeness",
                ));
            }
        }
        if evidence.next().is_some() {
            return Err(IndexError::corrupt(
                "Flight discontinuity payload has no provider completeness fact",
            ));
        }
    }
    for (ordinal, _) in catalog.completeness.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
    }
    let mut capabilities = if source_format.eq_ignore_ascii_case("flight") {
        ProviderCapabilities {
            global_ordering: true,
            per_thread_ordering: true,
            full_register_checkpoint: true,
            register_read_write_observation: true,
            memory_metadata: true,
            memory_before_after: true,
            lifecycle: true,
            signal_and_termination: true,
            loss_and_damage_ranges: true,
        }
    } else if source_format.eq_ignore_ascii_case("qtrb") {
        ProviderCapabilities::qtrb_register_observations()
    } else {
        return Err(IndexError::corrupt(
            "cache identity has an unsupported provider format",
        ));
    };
    capabilities.full_register_checkpoint &= state.saw_complete_checkpoint;
    capabilities.loss_and_damage_ranges &= !source_completeness.is_empty();
    capabilities.register_read_write_observation &= state.saw_register_observation;
    capabilities.memory_metadata &= state.saw_memory_metadata;
    capabilities.memory_before_after &= state.saw_memory_before_after;
    capabilities.lifecycle &= state.saw_lifecycle;
    capabilities.signal_and_termination &= state.saw_signal_or_termination;
    state.strings.validate_dictionary_complete()?;
    state.blobs.validate_dictionary_complete()?;
    if capabilities != catalog.capabilities {
        return Err(IndexError::corrupt(
            "binary columns, dictionaries, capabilities, or indexes disagree with source facts",
        ));
    }
    Ok(())
}

fn validate_completeness_rows(
    rows: &[CompletenessRow],
    guard: &dyn WorkGuard,
) -> Result<(), IndexError> {
    for (ordinal, row) in rows.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if row.to_range().is_none() {
            return Err(IndexError::invalid(
                "completeness bounds disagree with their domain",
            ));
        }
    }
    for (ordinal, pair) in rows.windows(2).enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if compare_completeness_rows(&pair[0], &pair[1]) != std::cmp::Ordering::Less {
            return Err(IndexError::invalid(
                "completeness rows are not strictly canonical",
            ));
        }
        if same_completeness_class(&pair[0], &pair[1])
            && completeness_ranges_touch_or_overlap(&pair[0], &pair[1])?
        {
            return Err(IndexError::invalid(
                "mergeable completeness rows remain adjacent",
            ));
        }
    }
    Ok(())
}

fn compare_completeness_rows(
    left: &CompletenessRow,
    right: &CompletenessRow,
) -> std::cmp::Ordering {
    let left = left
        .to_range()
        .map(|range| qtrace_provider::completeness_canonical_key(&range));
    let right = right
        .to_range()
        .map(|range| qtrace_provider::completeness_canonical_key(&range));
    left.cmp(&right)
}

fn same_completeness_class(left: &CompletenessRow, right: &CompletenessRow) -> bool {
    left.domain == right.domain && left.cause == right.cause && left.provenance == right.provenance
}

fn completeness_ranges_touch_or_overlap(
    left: &CompletenessRow,
    right: &CompletenessRow,
) -> Result<bool, IndexError> {
    match (left.bounds, right.bounds) {
        (
            qtrace_provider::RangeBounds::InclusiveSequence { last, .. },
            qtrace_provider::RangeBounds::InclusiveSequence { first, .. },
        ) => Ok(last == u64::MAX || first <= last + 1),
        (
            qtrace_provider::RangeBounds::HalfOpen { end_exclusive, .. },
            qtrace_provider::RangeBounds::HalfOpen { start, .. },
        ) => Ok(start <= end_exclusive),
        _ => Err(IndexError::invalid(
            "completeness bounds disagree with their domain",
        )),
    }
}

fn compare_streamed_rows<T: Eq>(
    actual: &[T],
    stored: &[T],
    cursor: &mut usize,
    label: &str,
) -> Result<(), IndexError> {
    let end = cursor
        .checked_add(actual.len())
        .ok_or_else(|| IndexError::corrupt(format!("{label} cursor overflow")))?;
    if stored.get(*cursor..end) != Some(actual) {
        return Err(IndexError::corrupt(format!(
            "stored {label} rows disagree with canonical payload facts"
        )));
    }
    *cursor = end;
    Ok(())
}

fn cached_rebuild_error(error: IndexError) -> IndexError {
    if error.code().starts_with("control.") || error.code() == "job.cancelled" {
        error
    } else {
        IndexError::corrupt(format!("cached source fact reconstruction failed: {error}"))
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_indexes(
    keys: &[qtrace_provider::EventKey],
    kinds: &[EventKind],
    events: &[EventColumn],
    definitions: &[DefinitionRow],
    instructions: &[InstructionRow],
    memories: &[MemoryRow],
    semantics: &[SemanticRow],
    observations: &[RegisterObservationRow],
    options: &BuildOptions,
    guard: &dyn WorkGuard,
) -> Result<IndexCatalog, IndexError> {
    let timeline = keyed_posting_partition(events.len(), guard, |row| Some(keys[row].timeline.0))?;
    let tid = keyed_posting_partition(events.len(), guard, |row| keys[row].tid)?;
    let kind = keyed_posting_partition(kinds.len(), guard, |row| {
        Some(crate::layout::encode_event_kind(kinds[row]))
    })?;

    let mut sequence = reserved_pairs(events.len(), "sequence index", guard)?;
    for (row, key) in keys.iter().enumerate() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(value) = key.sequence {
            sequence.push((value, row));
        }
    }
    cancellable_sort(&mut sequence, guard)?;

    let mut module_pairs = reserved_pairs(instructions.len(), "module index", guard)?;
    for (ordinal, instruction) in instructions.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(id) = instruction.module {
            module_pairs.push((id, instruction.owner_row));
        }
    }
    let module = keyed_postings(module_pairs, guard)?;

    let mut definition_pairs = reserved_pairs(instructions.len(), "definition index", guard)?;
    for (ordinal, instruction) in instructions.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(id) = instruction.definition {
            definition_pairs.push((id, instruction.owner_row));
        }
    }
    let definition = keyed_postings(definition_pairs, guard)?;

    let mut call = reserved_rows(instructions.len(), "call index", guard)?;
    let mut return_rows = reserved_rows(instructions.len(), "return index", guard)?;
    for (ordinal, instruction) in instructions.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(id) = instruction.definition {
            if let Some(value) = definitions.get(id as usize) {
                if value.flags & (1 << 2) != 0 {
                    call.push(instruction.owner_row);
                }
                if value.flags & (1 << 3) != 0 {
                    return_rows.push(instruction.owner_row);
                }
            }
        }
    }
    let call = PostingList::from_rows(&call, guard)?;
    let return_rows = PostingList::from_rows(&return_rows, guard)?;

    let mut pc_pairs = reserved_pairs(instructions.len(), "module PC index", guard)?;
    for (ordinal, instruction) in instructions.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(id) = instruction.module {
            pc_pairs.push((id, (instruction.relative_pc, instruction.owner_row)));
        }
    }
    let module_pc = keyed_values(pc_pairs, guard)?;

    let mut register_pairs = reserved_pairs(observations.len(), "register index", guard)?;
    for (ordinal, observation) in observations.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        register_pairs.push((observation.slot, observation.owner_row));
    }
    let register = keyed_postings(register_pairs, guard)?;

    let mut checkpoint = reserved_rows(observations.len(), "checkpoint index", guard)?;
    for (ordinal, observation) in observations.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if observation.access == RegisterAccess::Checkpoint {
            checkpoint.push(observation.owner_row);
        }
    }
    cancellable_sort(&mut checkpoint, guard)?;
    checkpoint.dedup();
    let checkpoint = PostingList::from_rows(&checkpoint, guard)?;

    let mut semantic_category_pairs =
        reserved_pairs(semantics.len(), "semantic category index", guard)?;
    for (ordinal, semantic) in semantics.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(category) = semantic.category {
            semantic_category_pairs.push((category, semantic.owner_row));
        }
    }
    let semantic_category = keyed_postings(semantic_category_pairs, guard)?;

    let mut semantic_name_pairs = reserved_pairs(semantics.len(), "semantic name index", guard)?;
    for (ordinal, semantic) in semantics.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        semantic_name_pairs.push((semantic.name, semantic.owner_row));
    }
    let semantic_name = keyed_postings(semantic_name_pairs, guard)?;

    let mut intervals = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut intervals,
        memories.len(),
        guard,
        "memory interval allocation",
    )?;
    for (ordinal, memory) in memories.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if memory.address < memory.end_exclusive {
            intervals.push(IntervalEntry {
                start: memory.address,
                end_exclusive: memory.end_exclusive,
                row: memory.owner_row,
            });
        }
    }
    let memory = IntervalIndex::build(intervals, options.interval_block_rows as usize, guard)?;

    let mut source_keys = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut source_keys,
        keys.len(),
        guard,
        "source-key index allocation",
    )?;
    for row in 0..keys.len() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        source_keys.push(SourceKeyRow { row });
    }
    if !keys
        .windows(2)
        .all(|pair| super::compare_event_keys(&pair[0], &pair[1]).is_lt())
    {
        cancellable_sort_by(&mut source_keys, guard, |left, right| {
            super::compare_event_keys(&keys[left.row], &keys[right.row])
        })?;
    }
    if source_keys
        .windows(2)
        .any(|pair| super::compare_event_keys(&keys[pair[0].row], &keys[pair[1].row]).is_eq())
    {
        return Err(IndexError::duplicate_key("duplicate source EventKey"));
    }
    Ok(IndexCatalog {
        timeline,
        tid,
        kind,
        module,
        definition,
        register,
        semantic_category,
        semantic_name,
        call,
        return_rows,
        checkpoint,
        sequence,
        module_pc,
        memory,
        source_keys,
    })
}

pub(super) fn validate_index_families(
    keys: &[qtrace_provider::EventKey],
    kinds: &[EventKind],
    catalog: &NormalizedCatalog,
    options: &BuildOptions,
    guard: &dyn WorkGuard,
) -> Result<(), IndexError> {
    let indexes = &catalog.indexes;
    validate_posting_partition(&indexes.timeline, catalog.events.len(), guard, |row| {
        Some(keys[row].timeline.0)
    })?;
    validate_posting_partition(&indexes.tid, catalog.events.len(), guard, |row| {
        keys[row].tid
    })?;
    validate_posting_partition(&indexes.kind, kinds.len(), guard, |row| {
        Some(crate::layout::encode_event_kind(kinds[row]))
    })?;

    let mut pairs = reserved_pairs(catalog.instructions.len(), "module validation", guard)?;
    pairs.extend(
        catalog
            .instructions
            .iter()
            .filter_map(|row| row.module.map(|module| (module, row.owner_row))),
    );
    require_equal(keyed_postings(pairs, guard)?, &indexes.module, "module")?;

    let mut pairs = reserved_pairs(catalog.instructions.len(), "definition validation", guard)?;
    pairs.extend(
        catalog
            .instructions
            .iter()
            .filter_map(|row| row.definition.map(|definition| (definition, row.owner_row))),
    );
    require_equal(
        keyed_postings(pairs, guard)?,
        &indexes.definition,
        "definition",
    )?;

    for slot in 0..RegisterSlot::COUNT as u8 {
        guard.consume(WorkDelta::default())?;
        let mut count = 0usize;
        for (ordinal, observation) in catalog.observations.iter().enumerate() {
            if ordinal % 4096 == 0 {
                guard.consume(WorkDelta::default())?;
            }
            count = count
                .checked_add(usize::from(observation.slot == slot))
                .ok_or_else(|| IndexError::resource("register validation count overflow"))?;
        }
        let mut rows = reserved_rows(count, "register validation", guard)?;
        for (ordinal, observation) in catalog.observations.iter().enumerate() {
            if ordinal % 4096 == 0 {
                guard.consume(WorkDelta::default())?;
            }
            if observation.slot == slot {
                rows.push(observation.owner_row);
            }
        }
        cancellable_sort(&mut rows, guard)?;
        rows.dedup();
        let expected = PostingList::from_rows(&rows, guard)?;
        let actual = indexes.register.get(&slot);
        if (!rows.is_empty() && actual != Some(&expected)) || (rows.is_empty() && actual.is_some())
        {
            return Err(IndexError::corrupt(
                "register index differs from typed rows",
            ));
        }
    }

    let mut pairs = reserved_pairs(
        catalog.semantics.len(),
        "semantic category validation",
        guard,
    )?;
    pairs.extend(
        catalog
            .semantics
            .iter()
            .filter_map(|row| row.category.map(|category| (category, row.owner_row))),
    );
    require_equal(
        keyed_postings(pairs, guard)?,
        &indexes.semantic_category,
        "semantic category",
    )?;
    let mut pairs = reserved_pairs(catalog.semantics.len(), "semantic name validation", guard)?;
    pairs.extend(
        catalog
            .semantics
            .iter()
            .map(|row| (row.name, row.owner_row)),
    );
    require_equal(
        keyed_postings(pairs, guard)?,
        &indexes.semantic_name,
        "semantic name",
    )?;

    let mut call = reserved_rows(catalog.instructions.len(), "call validation", guard)?;
    let mut returns = reserved_rows(catalog.instructions.len(), "return validation", guard)?;
    for instruction in &catalog.instructions {
        if let Some(definition) = instruction
            .definition
            .and_then(|id| catalog.definitions.get(id as usize))
        {
            if definition.flags & (1 << 2) != 0 {
                call.push(instruction.owner_row);
            }
            if definition.flags & (1 << 3) != 0 {
                returns.push(instruction.owner_row);
            }
        }
    }
    require_equal(PostingList::from_rows(&call, guard)?, &indexes.call, "call")?;
    require_equal(
        PostingList::from_rows(&returns, guard)?,
        &indexes.return_rows,
        "return",
    )?;

    let checkpoint_count = catalog
        .observations
        .iter()
        .filter(|row| row.access == RegisterAccess::Checkpoint)
        .count();
    guard.consume(WorkDelta::default())?;
    let mut checkpoint = reserved_rows(checkpoint_count, "checkpoint validation", guard)?;
    for (ordinal, observation) in catalog.observations.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if observation.access == RegisterAccess::Checkpoint {
            checkpoint.push(observation.owner_row);
        }
    }
    cancellable_sort(&mut checkpoint, guard)?;
    checkpoint.dedup();
    require_equal(
        PostingList::from_rows(&checkpoint, guard)?,
        &indexes.checkpoint,
        "checkpoint",
    )?;

    let mut sequence = reserved_pairs(keys.len(), "sequence validation", guard)?;
    sequence.extend(
        keys.iter()
            .enumerate()
            .filter_map(|(row, key)| key.sequence.map(|sequence| (sequence, row))),
    );
    cancellable_sort(&mut sequence, guard)?;
    require_equal(sequence, &indexes.sequence, "sequence")?;

    let mut module_pc = reserved_pairs(catalog.instructions.len(), "module PC validation", guard)?;
    module_pc.extend(catalog.instructions.iter().filter_map(|row| {
        row.module
            .map(|module| (module, (row.relative_pc, row.owner_row)))
    }));
    require_equal(
        keyed_values(module_pc, guard)?,
        &indexes.module_pc,
        "module PC",
    )?;

    let mut intervals = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut intervals,
        catalog.memories.len(),
        guard,
        "memory validation allocation",
    )?;
    intervals.extend(
        catalog
            .memories
            .iter()
            .filter(|row| row.address < row.end_exclusive)
            .map(|row| IntervalEntry {
                start: row.address,
                end_exclusive: row.end_exclusive,
                row: row.owner_row,
            }),
    );
    let memory = IntervalIndex::build(intervals, options.interval_block_rows as usize, guard)?;
    require_equal(memory, &indexes.memory, "memory interval")?;

    let mut source_keys = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut source_keys,
        keys.len(),
        guard,
        "source validation allocation",
    )?;
    source_keys.extend((0..keys.len()).map(|row| SourceKeyRow { row }));
    if !keys
        .windows(2)
        .all(|pair| super::compare_event_keys(&pair[0], &pair[1]).is_lt())
    {
        cancellable_sort_by(&mut source_keys, guard, |left, right| {
            super::compare_event_keys(&keys[left.row], &keys[right.row])
        })?;
    }
    require_equal(source_keys, &indexes.source_keys, "source key")?;
    Ok(())
}

fn require_equal<T: Eq>(actual: T, expected: &T, label: &str) -> Result<(), IndexError> {
    if &actual != expected {
        return Err(IndexError::corrupt(format!(
            "{label} index differs from normalized facts"
        )));
    }
    Ok(())
}

fn reserved_pairs<A, B>(
    rows: usize,
    label: &'static str,
    guard: &dyn WorkGuard,
) -> Result<Vec<(A, B)>, IndexError> {
    let mut values = Vec::new();
    crate::allocation::try_reserve_vec(&mut values, rows, guard, label)?;
    Ok(values)
}

fn reserved_rows(
    rows: usize,
    label: &'static str,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, IndexError> {
    let mut values = Vec::new();
    crate::allocation::try_reserve_vec(&mut values, rows, guard, label)?;
    Ok(values)
}

fn keyed_posting_partition<K: Ord + Copy + Eq + Hash>(
    row_count: usize,
    guard: &dyn WorkGuard,
    key_for_row: impl Fn(usize) -> Option<K>,
) -> Result<SortedMap<K, PostingList>, IndexError> {
    let mut groups = HashMap::<K, (PostingList, Option<u64>)>::new();
    for row in 0..row_count {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(key) = key_for_row(row) {
            if !groups.contains_key(&key) {
                crate::allocation::try_reserve_hash_map(&mut groups, 1, guard, "posting groups")?;
            }
            let (posting, previous) = groups.entry(key).or_default();
            posting.push_row(row, previous, guard)?;
        }
    }
    let mut entries = Vec::new();
    crate::allocation::try_reserve_vec(&mut entries, groups.len(), guard, "posting map")?;
    for (key, (posting, _)) in groups {
        entries.push((key, posting));
    }
    cancellable_sort_by(&mut entries, guard, |left, right| left.0.cmp(&right.0))?;
    SortedMap::from_sorted(entries)
}

fn validate_posting_partition<K: Ord + Copy + Eq>(
    postings: &SortedMap<K, PostingList>,
    row_count: usize,
    guard: &dyn WorkGuard,
    expected: impl Fn(usize) -> Option<K>,
) -> Result<(), IndexError> {
    let expected_count = (0..row_count)
        .filter(|row| expected(*row).is_some())
        .count();
    let mut actual_count = 0usize;
    for (key, posting) in postings.iter() {
        let mut previous: Option<u64> = None;
        let mut ordinal = 0usize;
        posting.visit_deltas(|delta| {
            if ordinal % 4096 == 0 {
                guard.consume(WorkDelta::default())?;
            }
            ordinal += 1;
            if delta == 0 {
                return Err(IndexError::corrupt("posting delta is zero"));
            }
            let encoded = match previous {
                None => delta.checked_sub(1),
                Some(value) => value.checked_add(delta),
            }
            .ok_or_else(|| IndexError::corrupt("posting row overflow"))?;
            let row = usize::try_from(encoded)
                .map_err(|_| IndexError::corrupt("posting row does not fit usize"))?;
            if row >= row_count || expected(row) != Some(*key) {
                return Err(IndexError::corrupt(
                    "posting index differs from normalized facts",
                ));
            }
            previous = Some(encoded);
            actual_count = actual_count
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("posting count overflow"))?;
            Ok(())
        })?;
    }
    if actual_count != expected_count {
        return Err(IndexError::corrupt("posting index cardinality differs"));
    }
    Ok(())
}

fn keyed_postings<K: Ord + Clone>(
    mut pairs: Vec<(K, usize)>,
    guard: &dyn WorkGuard,
) -> Result<SortedMap<K, PostingList>, IndexError> {
    cancellable_sort(&mut pairs, guard)?;
    let mut groups = 0usize;
    for index in 0..pairs.len() {
        if index % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if index == 0 || pairs[index - 1].0 != pairs[index].0 {
            groups = groups
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("posting group count overflow"))?;
        }
    }
    let mut result = Vec::new();
    crate::allocation::try_reserve_vec(&mut result, groups, guard, "posting map allocation")?;
    let mut first = 0;
    while first < pairs.len() {
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        let mut last = first + 1;
        while last < pairs.len() && pairs[last].0 == pairs[first].0 {
            last += 1;
        }
        let mut rows = reserved_rows(last - first, "posting rows", guard)?;
        rows.extend(pairs[first..last].iter().map(|(_, row)| *row));
        rows.dedup();
        result.push((
            pairs[first].0.clone(),
            PostingList::from_rows(&rows, guard)?,
        ));
        first = last;
    }
    SortedMap::from_sorted(result)
}

fn keyed_values<K: Ord + Clone, V: Ord + Clone>(
    mut pairs: Vec<(K, V)>,
    guard: &dyn WorkGuard,
) -> Result<SortedMap<K, Vec<V>>, IndexError> {
    cancellable_sort(&mut pairs, guard)?;
    let mut groups = 0usize;
    for index in 0..pairs.len() {
        if index % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if index == 0 || pairs[index - 1].0 != pairs[index].0 {
            groups = groups
                .checked_add(1)
                .ok_or_else(|| IndexError::resource("keyed value group count overflow"))?;
        }
    }
    let mut result = Vec::new();
    crate::allocation::try_reserve_vec(&mut result, groups, guard, "keyed value map allocation")?;
    let mut first = 0;
    while first < pairs.len() {
        guard.consume(WorkDelta {
            nodes: 1,
            ..WorkDelta::default()
        })?;
        let mut last = first + 1;
        while last < pairs.len() && pairs[last].0 == pairs[first].0 {
            last += 1;
        }
        let mut values = Vec::new();
        crate::allocation::try_reserve_vec(
            &mut values,
            last - first,
            guard,
            "keyed value allocation",
        )?;
        values.extend(pairs[first..last].iter().map(|(_, value)| value.clone()));
        result.push((pairs[first].0.clone(), values));
        first = last;
    }
    SortedMap::from_sorted(result)
}

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

pub(super) fn canonical_bytes<T: Serialize>(
    value: &T,
    guard: &dyn WorkGuard,
) -> Result<Vec<u8>, IndexError> {
    #[derive(Default)]
    struct Counter(usize);

    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("serialized payload length overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter::default();
    serde_json::to_writer(&mut counter, value)
        .map_err(|error| IndexError::invalid(format!("cannot size normalized payload: {error}")))?;
    let mut bytes = Vec::new();
    crate::allocation::try_reserve_vec(
        &mut bytes,
        counter.0,
        guard,
        "normalized payload allocation",
    )?;
    serde_json::to_writer(&mut bytes, value).map_err(|error| {
        IndexError::invalid(format!("cannot encode normalized payload: {error}"))
    })?;
    if bytes.len() != counter.0 {
        return Err(IndexError::invalid(
            "normalized payload serialization was not deterministic",
        ));
    }
    Ok(bytes)
}

fn try_copy_bytes(
    value: &[u8],
    guard: &dyn WorkGuard,
    label: &'static str,
) -> Result<Vec<u8>, IndexError> {
    let mut output = Vec::new();
    crate::allocation::try_reserve_vec(&mut output, value.len(), guard, label)?;
    output.extend_from_slice(value);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use qtrace_provider::{
        ArtifactDigest, BeginMetadata, EventCursor, EventKey, EventPayload, EventRecord,
        EventScope, Instruction, InstructionDefinition, Memory, MemoryDirection, Provenance,
        ProviderCapabilities, ProviderCounters, ProviderError, ProviderSummary, SourceIdentity,
        StringDefinition, TimelineDescriptor, TimelineId, TraceProvider, WorkDelta, WorkGuard,
    };

    use crate::{NormalizedBulkView, NormalizedPostingQuery, TraceStoreView};

    use super::super::validation::scan_external_payload_tag;
    use super::{
        BuildOptions, BuildState, IndexBuilder, cancellable_sort, cancellable_sort_by,
        validate_external_payload_tag,
    };

    struct AllowAll;

    impl WorkGuard for AllowAll {
        fn consume(&self, _delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
            Ok(())
        }
    }

    struct FakeProvider {
        identity: SourceIdentity,
        capabilities: ProviderCapabilities,
        timelines: Vec<TimelineDescriptor>,
        events: Vec<EventRecord>,
    }

    impl TraceProvider for FakeProvider {
        fn identity(&self) -> &SourceIdentity {
            &self.identity
        }

        fn capabilities(&self) -> &ProviderCapabilities {
            &self.capabilities
        }

        fn timelines(&self) -> &[TimelineDescriptor] {
            &self.timelines
        }

        fn into_cursor(self: Box<Self>) -> Result<Box<dyn EventCursor>, ProviderError> {
            Ok(Box::new(FakeCursor {
                events: self.events.into_iter(),
                drained: false,
            }))
        }
    }

    struct FakeCursor {
        events: std::vec::IntoIter<EventRecord>,
        drained: bool,
    }

    impl EventCursor for FakeCursor {
        fn next_event(
            &mut self,
            _guard: &dyn WorkGuard,
        ) -> Result<Option<EventRecord>, ProviderError> {
            let next = self.events.next();
            self.drained |= next.is_none();
            Ok(next)
        }

        fn finish(self: Box<Self>) -> Result<ProviderSummary, ProviderError> {
            if !self.drained {
                return Err(ProviderError::stream_not_drained());
            }
            Ok(ProviderSummary {
                timelines: vec![timeline()],
                termination: None,
                counters: ProviderCounters::default(),
                completeness: Vec::new(),
            })
        }
    }

    fn timeline() -> TimelineDescriptor {
        TimelineDescriptor {
            id: TimelineId(7),
            tid: Some(42),
            label: Some("fake".to_owned()),
        }
    }

    fn provider(events: Vec<EventRecord>) -> Box<dyn TraceProvider> {
        Box::new(FakeProvider {
            identity: SourceIdentity {
                artifact: ArtifactDigest::new([0x11; 32]),
                format: "fake".to_owned(),
                format_major: 1,
                format_minor: 0,
                source_bytes: 0,
            },
            capabilities: ProviderCapabilities {
                global_ordering: false,
                per_thread_ordering: true,
                full_register_checkpoint: false,
                register_read_write_observation: false,
                memory_metadata: true,
                memory_before_after: false,
                lifecycle: false,
                signal_and_termination: false,
                loss_and_damage_ranges: false,
            },
            timelines: vec![timeline()],
            events,
        })
    }

    fn memory_event(ordinal: u64, address: u64, size: u32) -> EventRecord {
        EventRecord::new(
            EventKey::new(
                ArtifactDigest::new([0x11; 32]),
                TimelineId(7),
                ordinal,
                ordinal * 8,
                Some(ordinal),
                Some(42),
            ),
            Provenance::Captured,
            EventPayload::Memory(Memory {
                address,
                size,
                direction: MemoryDirection::Read,
                metadata_available: true,
                ..Memory::default()
            }),
        )
    }

    #[test]
    fn duplicate_source_key_is_a_typed_global_build_failure() {
        let event = memory_event(1, 0x1000, 4);
        let error = IndexBuilder::build_provider(
            provider(vec![event.clone(), event]),
            &BuildOptions::default(),
            &AllowAll,
        )
        .expect_err("duplicate keys must never silently overwrite the reverse map");

        assert_eq!(error.code(), "index.duplicate_source_key");
    }

    #[test]
    fn memory_address_size_overflow_is_rejected() {
        let error = IndexBuilder::build_provider(
            provider(vec![memory_event(1, u64::MAX, 2)]),
            &BuildOptions::default(),
            &AllowAll,
        )
        .expect_err("wrapped intervals must never enter the index");

        assert_eq!(error.code(), "index.invalid");
    }

    #[test]
    fn large_synthetic_store_uses_fixed_binary_rows_without_a_json_catalog_wall() {
        let count = 20_000_u64;
        let mut events = Vec::new();
        events
            .try_reserve_exact(count as usize)
            .expect("synthetic events");
        for ordinal in 0..count {
            events.push(memory_event(ordinal, 0x10_0000 + ordinal * 8, 4));
        }
        let store =
            IndexBuilder::build_provider(provider(events), &BuildOptions::default(), &AllowAll)
                .expect("large synthetic build");
        assert_eq!(store.event_count(), count as usize);
        let catalog = *store.catalog;
        let sections =
            super::super::wire::encode(catalog, &AllowAll).expect("large binary sections");
        let event_meta = sections
            .iter()
            .find(|section| section.name == "event_meta.v2")
            .expect("event metadata");
        assert_eq!(event_meta.data.len(), count * 24);
        assert!(
            sections
                .iter()
                .all(|section| !section.name.contains("catalog"))
        );
    }

    struct CancelMerge {
        calls: AtomicUsize,
        cancel_at: usize,
    }

    impl WorkGuard for CancelMerge {
        fn consume(&self, _delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == self.cancel_at {
                Err(qtrace_provider::OperationAbort::Cancelled)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn chunk_merge_sort_can_cancel_after_chunk_sorting_and_during_merge() {
        for cancel_at in [2, 5] {
            let mut rows = (0..20_000_u64).rev().collect::<Vec<_>>();
            let error = cancellable_sort(
                &mut rows,
                &CancelMerge {
                    calls: AtomicUsize::new(0),
                    cancel_at,
                },
            )
            .expect_err("sort checkpoint cancellation");
            assert_eq!(error.code(), "job.cancelled");
        }
    }

    struct CancelInsideMerge {
        calls: AtomicUsize,
        armed: AtomicBool,
        comparisons: AtomicUsize,
    }

    impl WorkGuard for CancelInsideMerge {
        fn consume(&self, _delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call == 7 {
                self.comparisons.store(0, Ordering::SeqCst);
                self.armed.store(true, Ordering::SeqCst);
                return Ok(());
            }
            if self.armed.load(Ordering::SeqCst) && self.comparisons.load(Ordering::SeqCst) > 0 {
                return Err(qtrace_provider::OperationAbort::Cancelled);
            }
            Ok(())
        }
    }

    #[test]
    fn merge_sort_checks_cancel_within_each_4096_output_rows() {
        let mut rows = (0..4096_u64).map(|value| value * 2).collect::<Vec<_>>();
        rows.extend((0..4096_u64).map(|value| value * 2 + 1));
        rows.extend(8192..20_000_u64);
        let guard = CancelInsideMerge {
            calls: AtomicUsize::new(0),
            armed: AtomicBool::new(false),
            comparisons: AtomicUsize::new(0),
        };
        let error = cancellable_sort_by(&mut rows, &guard, |left, right| {
            if guard.armed.load(Ordering::SeqCst) {
                guard.comparisons.fetch_add(1, Ordering::SeqCst);
            }
            left.cmp(right)
        })
        .expect_err("merge cancellation");
        assert_eq!(error.code(), "job.cancelled");
        assert!(
            guard.comparisons.load(Ordering::SeqCst) > 0,
            "test must cancel after merge comparisons begin"
        );
        assert!(
            guard.comparisons.load(Ordering::SeqCst) <= 4096,
            "merge ran more than 4096 output comparisons without a checkpoint"
        );
    }

    #[test]
    fn zero_size_memory_is_retained_but_not_indexed_as_an_overlap() {
        let store = IndexBuilder::build_provider(
            provider(vec![memory_event(1, 0x1004, 0)]),
            &BuildOptions::default(),
            &AllowAll,
        )
        .expect("zero-sized observations have explicit empty-interval semantics");

        assert_eq!(store.event_count(), 1);
        assert_eq!(store.memory_overlaps(0x1004, 0x1005).unwrap().count(), 0);
    }

    #[test]
    fn normalized_builder_fixture_sorts_nonmonotonic_pair_postings_by_row() {
        let event = |ordinal, payload| {
            EventRecord::new(
                EventKey::new(
                    ArtifactDigest::new([0x11; 32]),
                    TimelineId(7),
                    ordinal,
                    ordinal * 8,
                    Some(ordinal),
                    Some(42),
                ),
                Provenance::Captured,
                payload,
            )
        };
        let events = vec![
            event(
                1,
                EventPayload::ModuleDefinition(qtrace_provider::ModuleDefinition {
                    module_id: 1,
                    base: 0x7100_0000,
                    name: "libtarget.so".to_owned(),
                }),
            ),
            event(
                2,
                EventPayload::InstructionDefinition(InstructionDefinition {
                    definition_id: 7,
                    mnemonic: "nop".to_owned(),
                    ..InstructionDefinition::default()
                }),
            ),
            event(
                3,
                EventPayload::Instruction(Instruction {
                    definition_id: 7,
                    module_id: 1,
                    relative_pc: 0x30,
                    ..Instruction::default()
                }),
            ),
            event(
                4,
                EventPayload::Instruction(Instruction {
                    definition_id: 7,
                    module_id: 1,
                    relative_pc: 0x10,
                    ..Instruction::default()
                }),
            ),
        ];
        let store =
            IndexBuilder::build_provider(provider(events), &BuildOptions::default(), &AllowAll)
                .expect("normalized builder fixture");
        let rows = store
            .bounded_rows(
                NormalizedPostingQuery::ModulePc {
                    module: 0,
                    start: 0,
                    end_exclusive: u64::MAX,
                },
                usize::MAX,
                &AllowAll,
            )
            .expect("bounded module-PC rows");
        assert_eq!(rows, vec![2, 3]);
    }

    #[test]
    fn exact_string_bytes_preserve_invalid_utf8() {
        let mut event = memory_event(1, 0, 0);
        event.payload = EventPayload::StringDefinition(StringDefinition {
            id: 7,
            bytes: vec![0xff, 0x00, 0x80],
        });
        let store = IndexBuilder::build_provider(
            provider(vec![event]),
            &BuildOptions::default(),
            &AllowAll,
        )
        .expect("invalid UTF-8 remains byte evidence");
        let bytes = TraceStoreView::string_bytes(&store, 0).expect("string bytes");
        assert_eq!(bytes, &[0xff, 0x00, 0x80]);
        assert!(std::str::from_utf8(bytes).is_err());
    }

    #[test]
    fn source_local_ids_and_current_modules_are_scoped_to_flight_chunk_generations() {
        let first = EventScope::FlightChunk {
            chunk_index: 1,
            generation: 4,
            tid: 41,
        };
        let second = EventScope::FlightChunk {
            chunk_index: 2,
            generation: 9,
            tid: 42,
        };
        let mut events = Vec::new();
        for (ordinal, scope, payload) in [
            (
                1,
                first,
                EventPayload::Begin(BeginMetadata {
                    module_base: 0x1000,
                    target: "first.so".to_owned(),
                    ..BeginMetadata::default()
                }),
            ),
            (
                2,
                second,
                EventPayload::Begin(BeginMetadata {
                    module_base: 0x9000,
                    target: "second.so".to_owned(),
                    ..BeginMetadata::default()
                }),
            ),
            (
                3,
                first,
                EventPayload::InstructionDefinition(InstructionDefinition {
                    definition_id: 7,
                    opcode: 0xaaaa,
                    mnemonic: "add".to_owned(),
                    ..InstructionDefinition::default()
                }),
            ),
            (
                4,
                second,
                EventPayload::InstructionDefinition(InstructionDefinition {
                    definition_id: 7,
                    opcode: 0xbbbb,
                    mnemonic: "sub".to_owned(),
                    ..InstructionDefinition::default()
                }),
            ),
            (
                5,
                first,
                EventPayload::InstructionDefinition(InstructionDefinition {
                    definition_id: 8,
                    opcode: 0xaaaa,
                    mnemonic: "add".to_owned(),
                    ..InstructionDefinition::default()
                }),
            ),
            (
                6,
                first,
                EventPayload::Instruction(Instruction {
                    definition_id: 8,
                    module_id: 1,
                    relative_pc: 4,
                    ..Instruction::default()
                }),
            ),
            (
                7,
                second,
                EventPayload::Instruction(Instruction {
                    definition_id: 7,
                    module_id: 1,
                    relative_pc: 8,
                    ..Instruction::default()
                }),
            ),
        ] {
            events.push(EventRecord::new_scoped(
                EventKey::new(
                    ArtifactDigest::new([0x11; 32]),
                    TimelineId(7),
                    ordinal,
                    ordinal * 8,
                    Some(ordinal),
                    Some(if scope == first { 41 } else { 42 }),
                ),
                Provenance::Captured,
                scope,
                payload,
            ));
        }

        let store =
            IndexBuilder::build_provider(provider(events), &BuildOptions::default(), &AllowAll)
                .expect("source-local IDs are independent across real Flight scopes");
        assert_eq!(store.catalog.definitions.len(), 2);
        assert_eq!(store.catalog.modules.len(), 2);
        assert_ne!(
            store.catalog.instructions[0].module,
            store.catalog.instructions[1].module
        );
    }

    #[test]
    fn many_source_ids_and_max_typed_children_use_only_authorized_growth() {
        let definitions = || {
            (0..qtrace_provider::RegisterSlot::COUNT)
                .map(|slot| qtrace_provider::RegisterDefinition {
                    slot: slot as u8,
                    captured_width: 8,
                    name: format!("r{slot}"),
                })
                .collect::<Vec<_>>()
        };
        let observations = || {
            (0..qtrace_provider::RegisterSlot::COUNT)
                .map(|slot| qtrace_provider::RegisterObservation {
                    slot: slot as u8,
                    captured_width: 8,
                    name: format!("r{slot}"),
                    value: slot as u64,
                })
                .collect::<Vec<_>>()
        };
        let mut events = Vec::new();
        for source_id in 0..64_u32 {
            let ordinal = u64::from(source_id) * 3;
            let key = |delta| {
                EventKey::new(
                    ArtifactDigest::new([0x91; 32]),
                    TimelineId(0),
                    ordinal + delta,
                    ordinal * 16 + delta,
                    Some(ordinal + delta + 1),
                    Some(7),
                )
            };
            events.push(EventRecord::new(
                key(0),
                Provenance::Captured,
                EventPayload::ModuleDefinition(qtrace_provider::ModuleDefinition {
                    module_id: source_id,
                    base: u64::from(source_id) << 20,
                    name: format!("module-{source_id}"),
                }),
            ));
            events.push(EventRecord::new(
                key(1),
                Provenance::Captured,
                EventPayload::InstructionDefinition(InstructionDefinition {
                    definition_id: source_id,
                    opcode: source_id,
                    mnemonic: format!("op-{source_id}"),
                    reads: definitions(),
                    writes: definitions(),
                    ..InstructionDefinition::default()
                }),
            ));
            let values = observations();
            events.push(EventRecord::new(
                key(2),
                Provenance::Captured,
                EventPayload::Instruction(Instruction {
                    definition_id: source_id,
                    module_id: source_id,
                    relative_pc: u64::from(source_id) * 4,
                    read_before: values.clone(),
                    write_after: values,
                }),
            ));
        }

        crate::allocation::tests::activate_allocation_oracle();
        let guard = crate::allocation::tests::DecodeGuard;
        let options = BuildOptions::default();
        let mut state = BuildState::new(&options).expect("state");
        for event in events {
            state.append(event, &guard).expect("append");
        }
        state
            .append_completeness(Vec::new(), &guard)
            .expect("empty completeness");
        let store = state
            .finish(
                ProviderCapabilities {
                    global_ordering: false,
                    per_thread_ordering: true,
                    full_register_checkpoint: false,
                    register_read_write_observation: true,
                    memory_metadata: false,
                    memory_before_after: false,
                    lifecycle: false,
                    signal_and_termination: false,
                    loss_and_damage_ranges: false,
                },
                &options,
                super::NormalizedSourceFormat::Other,
                &guard,
            )
            .expect("finish");
        let unauthorized = crate::allocation::tests::finish_allocation_oracle();
        let (sizes, ordinals, size_len) = crate::allocation::tests::allocation_oracle_sizes();
        assert_eq!(store.event_count(), 64 * 3);
        assert_eq!(
            unauthorized,
            0,
            "unauthorized sizes/ordinals: {:?}/{:?}",
            &sizes[..size_len],
            &ordinals[..size_len]
        );
    }

    #[test]
    fn external_payload_tag_is_verified_without_allocation_before_decode() {
        let tags = [
            ("begin", qtrace_provider::EventKind::Begin),
            (
                "module_definition",
                qtrace_provider::EventKind::ModuleDefinition,
            ),
            (
                "instruction_definition",
                qtrace_provider::EventKind::InstructionDefinition,
            ),
            ("instruction", qtrace_provider::EventKind::Instruction),
            ("memory", qtrace_provider::EventKind::Memory),
            ("semantic_call", qtrace_provider::EventKind::SemanticCall),
            ("semantic_rule", qtrace_provider::EventKind::SemanticRule),
            ("semantic_error", qtrace_provider::EventKind::SemanticError),
            (
                "thread_lifecycle",
                qtrace_provider::EventKind::ThreadLifecycle,
            ),
            ("syscall", qtrace_provider::EventKind::Syscall),
            ("signal", qtrace_provider::EventKind::Signal),
            (
                "signal_handler_boundary",
                qtrace_provider::EventKind::SignalHandlerBoundary,
            ),
            ("termination", qtrace_provider::EventKind::Termination),
            (
                "register_checkpoint",
                qtrace_provider::EventKind::RegisterCheckpoint,
            ),
            ("register_delta", qtrace_provider::EventKind::RegisterDelta),
            (
                "string_definition",
                qtrace_provider::EventKind::StringDefinition,
            ),
            ("coverage_gap", qtrace_provider::EventKind::CoverageGap),
            ("discontinuity", qtrace_provider::EventKind::Discontinuity),
            (
                "opaque_optional",
                qtrace_provider::EventKind::OpaqueOptional,
            ),
        ];
        assert_eq!(tags.len(), 19);
        for (tag, kind) in tags {
            let bytes = format!("{{\"{tag}\":{{}}}}").into_bytes();
            crate::allocation::tests::activate_allocation_oracle();
            validate_external_payload_tag(&bytes, kind).expect("matching external tag");
            assert_eq!(
                crate::allocation::tests::finish_allocation_oracle(),
                0,
                "tag scan for {tag} must not allocate"
            );
        }
    }

    #[test]
    fn external_payload_tag_rejects_ambiguity_and_kind_confusion_before_decode() {
        for (bytes, expected) in [
            (
                r#"{"semantic_rule":{}}"#,
                qtrace_provider::EventKind::Memory,
            ),
            (r#"{"memory":{}}"#, qtrace_provider::EventKind::SemanticRule),
            (
                r#"{"discontinuity":{}}"#,
                qtrace_provider::EventKind::CoverageGap,
            ),
            (
                r#"{"semantic_\u0072ule":{}}"#,
                qtrace_provider::EventKind::SemanticRule,
            ),
            (r#"{"unknown":{}}"#, qtrace_provider::EventKind::Memory),
            (
                r#"{"memory":{},"memory":{}}"#,
                qtrace_provider::EventKind::Memory,
            ),
            (
                r#"{"memory":{},"extra":0}"#,
                qtrace_provider::EventKind::Memory,
            ),
            (r#"{"memory":"#, qtrace_provider::EventKind::Memory),
            (r#"[]"#, qtrace_provider::EventKind::Memory),
        ] {
            crate::allocation::tests::activate_allocation_oracle();
            let error = validate_external_payload_tag(bytes.as_bytes(), expected)
                .expect_err("ambiguous, malformed, or mismatched tag");
            assert_eq!(error.code(), "cache.normalized_corrupt");
            // Error reporting may own its bounded diagnostic; the scanner itself is proven
            // allocation-free by the successful matrix above, before serde is reachable.
            crate::allocation::tests::finish_allocation_oracle();
        }
    }

    #[test]
    fn external_payload_validation_rejects_invalid_utf8_and_surrogates_before_decode() {
        let mut invalid_after_large_field =
            b"{\"semantic_rule\":{\"category\":null,\"name\":\"".to_vec();
        invalid_after_large_field.extend(std::iter::repeat_n(b'a', 16 * 1024));
        invalid_after_large_field.extend_from_slice(b"\",\"detail\":\"");
        invalid_after_large_field.push(0xff);
        invalid_after_large_field.extend_from_slice(b"\",\"fragment_sequences\":[]}}");
        let mut invalid_overlong = b"{\"semantic_rule\":{\"category\":null,\"name\":\"".to_vec();
        invalid_overlong.extend_from_slice(&[0xc0, 0xaf]);
        invalid_overlong.extend_from_slice(b"\",\"detail\":\"x\"}}");
        let mut invalid_control = b"{\"semantic_rule\":{\"category\":null,\"name\":\"".to_vec();
        invalid_control.push(0x01);
        invalid_control.extend_from_slice(b"\",\"detail\":\"x\"}}");
        let mut truncated_utf8 = b"{\"semantic_rule\":{\"category\":null,\"name\":\"".to_vec();
        truncated_utf8.extend_from_slice(&[0xe2, 0x82]);
        truncated_utf8.extend_from_slice(b"\",\"detail\":\"x\"}}");
        let invalid_cases: &[&[u8]] = &[
            &invalid_after_large_field,
            &invalid_overlong,
            &invalid_control,
            &truncated_utf8,
            br#"{"semantic_rule":{"category":null,"name":"\uD800","detail":"x"}}"#,
            br#"{"semantic_rule":{"category":null,"name":"\uDC00","detail":"x"}}"#,
            br#"{"semantic_rule":{"category":null,"name":"\uD800\u0041","detail":"x"}}"#,
            br#"{"semantic_rule":{"category":null,"name":"bad\xescape","detail":"x"}}"#,
        ];
        for bytes in invalid_cases {
            crate::allocation::tests::activate_allocation_oracle();
            let error = scan_external_payload_tag(bytes, qtrace_provider::EventKind::SemanticRule)
                .expect_err("invalid string content must fail before serde");
            assert!(error.contains("payload"));
            assert_eq!(
                crate::allocation::tests::finish_allocation_oracle(),
                0,
                "validation itself must remain allocation-free"
            );
        }

        let valid_utf8 = r#"{"semantic_rule":{"category":null,"name":"雪","detail":"x"}}"#;
        for bytes in [
            valid_utf8.as_bytes(),
            br#"{"semantic_rule":{"category":null,"name":"\uD83D\uDE00","detail":"x"}}"#,
        ] {
            validate_external_payload_tag(bytes, qtrace_provider::EventKind::SemanticRule)
                .expect("valid UTF-8 and surrogate pair");
        }
    }
}
