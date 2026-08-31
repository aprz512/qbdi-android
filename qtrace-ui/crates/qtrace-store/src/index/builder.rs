use std::collections::{HashMap, HashSet};

use qtrace_provider::{
    EventKind, EventPayload, EventRecord, EventScope, Provenance, ProviderCapabilities,
    RegisterSlot, TraceProvider, WorkDelta, WorkGuard,
};
use serde::Serialize;

use crate::ArtifactSource;

use super::{
    BuildOptions, ByteArena, CompletenessRow, DefinitionRow, EventColumn, IndexCatalog, IndexError,
    InstructionRow, MemoryRow, ModuleRow, NormalizedCatalog, OwnedTraceStore, SemanticRow,
    SortedMap, SourceKeyRow, checkpoints::RegisterAccess, checkpoints::RegisterObservationRow,
    intervals::IntervalEntry, intervals::IntervalIndex, postings::PostingList,
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
        let mut capabilities = provider.capabilities().clone();
        let mut cursor = provider.into_cursor()?;
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
        capabilities.full_register_checkpoint &= state.saw_complete_checkpoint;
        state.finish(capabilities, options, guard)
    }
}

struct BuildState {
    next_row: usize,
    retain_source_columns: bool,
    keys: Vec<qtrace_provider::EventKey>,
    kinds: Vec<EventKind>,
    events: Vec<EventColumn>,
    payloads: ByteArena,
    strings: ByteArena,
    blobs: ByteArena,
    modules: Vec<ModuleRow>,
    definitions: Vec<DefinitionRow>,
    instructions: Vec<InstructionRow>,
    memories: Vec<MemoryRow>,
    semantics: Vec<SemanticRow>,
    observations: Vec<RegisterObservationRow>,
    completeness: Vec<CompletenessRow>,
    source_keys: HashSet<qtrace_provider::EventKey>,
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

impl BuildState {
    fn new(options: &BuildOptions) -> Result<Self, IndexError> {
        Self::with_source_columns(options, true)
    }

    fn validation(options: &BuildOptions) -> Result<Self, IndexError> {
        Self::with_source_columns(options, false)
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
            source_keys: HashSet::new(),
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
        let payload_bytes = canonical_bytes(&event.payload)?;
        let payload_blob = self.payloads.intern(&payload_bytes, guard)?;
        self.append_with_payload_blob(event, payload_blob, guard)
    }

    fn append_with_payload_blob(
        &mut self,
        event: EventRecord,
        payload_blob: u32,
        guard: &dyn WorkGuard,
    ) -> Result<(), IndexError> {
        if self.retain_source_columns {
            self.source_keys
                .try_reserve(1)
                .map_err(|_| IndexError::resource("source-key set allocation failed"))?;
            if !self.source_keys.insert(event.key.clone()) {
                return Err(IndexError::duplicate_key("duplicate source EventKey"));
            }
        }
        let row = self.next_row;
        self.next_row = self
            .next_row
            .checked_add(1)
            .ok_or_else(|| IndexError::resource("event row count overflow"))?;
        if self.retain_source_columns {
            self.keys
                .try_reserve(1)
                .map_err(|_| IndexError::resource("event key allocation failed"))?;
            self.kinds
                .try_reserve(1)
                .map_err(|_| IndexError::resource("event kind allocation failed"))?;
            self.events
                .try_reserve(1)
                .map_err(|_| IndexError::resource("event column allocation failed"))?;
            self.keys.push(event.key.clone());
            self.kinds.push(event.kind());
            self.events.push(EventColumn {
                timeline: event.key.timeline.0,
                tid: event.key.tid,
                sequence: event.key.sequence,
                scope: event.scope(),
                provenance: event.provenance,
                payload_blob,
            });
        }

        match &event.payload {
            EventPayload::Begin(begin) => {
                self.current_module
                    .try_reserve(1)
                    .map_err(|_| IndexError::resource("module scope allocation failed"))?;
                self.current_module.insert(
                    event.scope(),
                    (
                        begin.module_base,
                        try_copy_bytes(begin.target.as_bytes(), "begin target")?,
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
                            self.modules.try_reserve(1).map_err(|_| {
                                IndexError::resource("module dictionary allocation failed")
                            })?;
                            self.modules.push(ModuleRow {
                                source_event_row: row,
                                provenance: event.provenance,
                                source_id: module.module_id,
                                base: module.base,
                                name,
                            });
                            self.module_by_semantic.try_reserve(1).map_err(|_| {
                                IndexError::resource("module semantic map allocation failed")
                            })?;
                            self.module_by_semantic.insert(semantic_key, id);
                            id
                        };
                        self.module_by_source.try_reserve(1).map_err(|_| {
                            IndexError::resource("module source map allocation failed")
                        })?;
                        self.module_by_source
                            .insert(source_key, (id, module.base, name));
                    }
                }
            }
            EventPayload::InstructionDefinition(definition) => {
                let mut semantic_definition = definition.clone();
                semantic_definition.definition_id = 0;
                let exact = canonical_bytes(&semantic_definition)?;
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
                        self.definitions.try_reserve(1).map_err(|_| {
                            IndexError::resource("definition dictionary allocation failed")
                        })?;
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
                        self.definition_by_blob.try_reserve(1).map_err(|_| {
                            IndexError::resource("definition semantic map allocation failed")
                        })?;
                        self.definition_by_blob.insert(exact_blob, id);
                        id
                    };
                    self.definition_by_source.try_reserve(1).map_err(|_| {
                        IndexError::resource("definition source map allocation failed")
                    })?;
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
                            self.modules.try_reserve(1).map_err(|_| {
                                IndexError::resource("module dictionary allocation failed")
                            })?;
                            self.modules.push(ModuleRow {
                                source_event_row: row,
                                provenance: Provenance::Derived,
                                source_id: instruction.module_id,
                                base: *base,
                                name,
                            });
                            self.module_by_semantic.try_reserve(1).map_err(|_| {
                                IndexError::resource("module semantic map allocation failed")
                            })?;
                            self.module_by_semantic.insert(semantic_key, id);
                            id
                        };
                        self.module_by_source.try_reserve(1).map_err(|_| {
                            IndexError::resource("module source map allocation failed")
                        })?;
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
                self.instructions
                    .try_reserve(1)
                    .map_err(|_| IndexError::resource("instruction column allocation failed"))?;
                self.instructions.push(InstructionRow {
                    owner_row: row,
                    module,
                    relative_pc: instruction.relative_pc,
                    definition,
                });
                for value in &instruction.read_before {
                    self.saw_register_observation = true;
                    self.observations.try_reserve(1).map_err(|_| {
                        IndexError::resource("register observation allocation failed")
                    })?;
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
                    self.observations.try_reserve(1).map_err(|_| {
                        IndexError::resource("register observation allocation failed")
                    })?;
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
                self.memories
                    .try_reserve(1)
                    .map_err(|_| IndexError::resource("memory column allocation failed"))?;
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
                        .intern(&canonical_bytes(&memory.before)?, guard)?,
                    after_blob: self.blobs.intern(&canonical_bytes(&memory.after)?, guard)?,
                });
            }
            EventPayload::SemanticCall(value)
            | EventPayload::SemanticRule(value)
            | EventPayload::SemanticError(value) => {
                self.semantics
                    .try_reserve(1)
                    .map_err(|_| IndexError::resource("semantic column allocation failed"))?;
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
                for value in &checkpoint.values {
                    self.observations.try_reserve(1).map_err(|_| {
                        IndexError::resource("register observation allocation failed")
                    })?;
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
                for value in &delta.changed {
                    self.observations.try_reserve(1).map_err(|_| {
                        IndexError::resource("register observation allocation failed")
                    })?;
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
        self.completeness
            .try_reserve_exact(ranges.len())
            .map_err(|_| IndexError::resource("completeness allocation failed"))?;
        for range in ranges {
            guard.consume(WorkDelta {
                nodes: 1,
                ..WorkDelta::default()
            })?;
            self.completeness.push(CompletenessRow::from_range(range));
        }
        Ok(())
    }

    fn finish(
        self,
        mut capabilities: ProviderCapabilities,
        options: &BuildOptions,
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
        let catalog = NormalizedCatalog {
            schema: 2,
            capabilities,
            events: self.events,
            payloads: self.payloads,
            strings: self.strings,
            blobs: self.blobs,
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
        OwnedTraceStore::new(self.keys, self.kinds, catalog, guard)
    }
}

pub(super) fn validate_cached_truth(
    catalog: &NormalizedCatalog,
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
    let mut state = BuildState::validation(&options)?;
    state.strings = ByteArena::validation(&catalog.strings);
    state.blobs = ByteArena::validation(&catalog.blobs);
    let mut instruction_cursor = 0;
    let mut memory_cursor = 0;
    let mut semantic_cursor = 0;
    let mut observation_cursor = 0;
    let mut module_cursor = 0;
    let mut definition_cursor = 0;
    for row in 0..keys.len() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        let bytes = catalog.payloads.get(catalog.events[row].payload_blob)?;
        let payload: EventPayload = serde_json::from_slice(bytes)
            .map_err(|_| IndexError::corrupt("canonical event payload cannot be decoded"))?;
        if canonical_bytes(&payload)? != bytes {
            return Err(IndexError::corrupt("event payload bytes are not canonical"));
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
            timeline: keys[row].timeline.0,
            tid: keys[row].tid,
            sequence: keys[row].sequence,
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
    capabilities.loss_and_damage_ranges &= !catalog.completeness.is_empty();
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
    let mut timeline_pairs = reserved_pairs(events.len(), "timeline index", guard)?;
    for (row, event) in events.iter().enumerate() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        timeline_pairs.push((event.timeline, row));
    }
    let timeline = keyed_postings(timeline_pairs, guard)?;

    let mut tid_pairs = reserved_pairs(events.len(), "TID index", guard)?;
    for (row, event) in events.iter().enumerate() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(value) = event.tid {
            tid_pairs.push((value, row));
        }
    }
    let tid = keyed_postings(tid_pairs, guard)?;

    let mut kind_pairs = reserved_pairs(events.len(), "kind index", guard)?;
    for (row, kind) in kinds.iter().copied().enumerate() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        kind_pairs.push((crate::layout::encode_event_kind(kind), row));
    }
    let kind = keyed_postings(kind_pairs, guard)?;

    let mut sequence = reserved_pairs(events.len(), "sequence index", guard)?;
    for (row, event) in events.iter().enumerate() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(value) = event.sequence {
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
    let call = PostingList::from_rows(&call)?;
    let return_rows = PostingList::from_rows(&return_rows)?;

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
    let checkpoint = PostingList::from_rows(&checkpoint)?;

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

    charge_allocation::<IntervalEntry>(memories.len(), guard)?;
    let mut intervals = Vec::new();
    intervals
        .try_reserve(memories.len())
        .map_err(|_| IndexError::resource("memory interval allocation failed"))?;
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

    charge_allocation::<SourceKeyRow>(keys.len(), guard)?;
    let mut source_keys = Vec::new();
    source_keys
        .try_reserve_exact(keys.len())
        .map_err(|_| IndexError::resource("source-key index allocation failed"))?;
    for (row, key) in keys.iter().cloned().enumerate() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        source_keys.push(SourceKeyRow { key, row });
    }
    cancellable_sort_by(&mut source_keys, guard, |left, right| {
        super::compare_event_keys(&left.key, &right.key)
    })?;
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
    let mut pairs = reserved_pairs(catalog.events.len(), "timeline validation", guard)?;
    pairs.extend(
        catalog
            .events
            .iter()
            .enumerate()
            .map(|(row, event)| (event.timeline, row)),
    );
    require_equal(keyed_postings(pairs, guard)?, &indexes.timeline, "timeline")?;

    let mut pairs = reserved_pairs(catalog.events.len(), "TID validation", guard)?;
    pairs.extend(
        catalog
            .events
            .iter()
            .enumerate()
            .filter_map(|(row, event)| event.tid.map(|tid| (tid, row))),
    );
    require_equal(keyed_postings(pairs, guard)?, &indexes.tid, "TID")?;

    let mut pairs = reserved_pairs(kinds.len(), "kind validation", guard)?;
    pairs.extend(
        kinds
            .iter()
            .enumerate()
            .map(|(row, kind)| (crate::layout::encode_event_kind(*kind), row)),
    );
    require_equal(keyed_postings(pairs, guard)?, &indexes.kind, "kind")?;

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
        let expected = PostingList::from_rows(&rows)?;
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
    require_equal(PostingList::from_rows(&call)?, &indexes.call, "call")?;
    require_equal(
        PostingList::from_rows(&returns)?,
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
        PostingList::from_rows(&checkpoint)?,
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
    intervals
        .try_reserve_exact(catalog.memories.len())
        .map_err(|_| IndexError::resource("memory validation allocation failed"))?;
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
    source_keys
        .try_reserve_exact(keys.len())
        .map_err(|_| IndexError::resource("source validation allocation failed"))?;
    source_keys.extend(
        keys.iter()
            .cloned()
            .enumerate()
            .map(|(row, key)| SourceKeyRow { key, row }),
    );
    cancellable_sort_by(&mut source_keys, guard, |left, right| {
        super::compare_event_keys(&left.key, &right.key)
    })?;
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
    label: &str,
    guard: &dyn WorkGuard,
) -> Result<Vec<(A, B)>, IndexError> {
    charge_allocation::<(A, B)>(rows, guard)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(rows)
        .map_err(|_| IndexError::resource(format!("{label} allocation failed")))?;
    Ok(values)
}

fn reserved_rows(
    rows: usize,
    label: &str,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, IndexError> {
    charge_allocation::<usize>(rows, guard)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(rows)
        .map_err(|_| IndexError::resource(format!("{label} allocation failed")))?;
    Ok(values)
}

fn charge_allocation<T>(rows: usize, guard: &dyn WorkGuard) -> Result<(), IndexError> {
    let bytes = rows
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| IndexError::resource("allocation budget size overflow"))?;
    guard.consume(WorkDelta {
        resident_bytes: bytes,
        ..WorkDelta::default()
    })?;
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
    charge_allocation::<(K, PostingList)>(groups, guard)?;
    result
        .try_reserve_exact(groups)
        .map_err(|_| IndexError::resource("posting map allocation failed"))?;
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
        result.push((pairs[first].0.clone(), PostingList::from_rows(&rows)?));
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
    charge_allocation::<(K, Vec<V>)>(groups, guard)?;
    result
        .try_reserve_exact(groups)
        .map_err(|_| IndexError::resource("keyed value map allocation failed"))?;
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
        values
            .try_reserve_exact(last - first)
            .map_err(|_| IndexError::resource("keyed value allocation failed"))?;
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
    guard.consume(WorkDelta {
        resident_bytes: u64::try_from(rows.len().saturating_mul(std::mem::size_of::<T>()))
            .unwrap_or(u64::MAX),
        ..WorkDelta::default()
    })?;
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(rows.len())
        .map_err(|_| IndexError::resource("merge-sort scratch allocation failed"))?;
    let mut width = CHUNK;
    while width < rows.len() {
        scratch.clear();
        for first in (0..rows.len()).step_by(width.saturating_mul(2)) {
            guard.consume(WorkDelta::default())?;
            let middle = first.saturating_add(width).min(rows.len());
            let end = middle.saturating_add(width).min(rows.len());
            let (mut left, mut right) = (first, middle);
            while left < middle && right < end {
                if compare(&rows[left], &rows[right]).is_le() {
                    scratch.push(rows[left].clone());
                    left += 1;
                } else {
                    scratch.push(rows[right].clone());
                    right += 1;
                }
            }
            scratch.extend_from_slice(&rows[left..middle]);
            scratch.extend_from_slice(&rows[right..end]);
        }
        std::mem::swap(rows, &mut scratch);
        width = width.saturating_mul(2);
    }
    Ok(())
}

pub(super) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, IndexError> {
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
    bytes
        .try_reserve_exact(counter.0)
        .map_err(|_| IndexError::resource("normalized payload allocation failed"))?;
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

fn try_copy_bytes(value: &[u8], label: &str) -> Result<Vec<u8>, IndexError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| IndexError::resource(format!("{label} allocation failed")))?;
    output.extend_from_slice(value);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use qtrace_provider::{
        ArtifactDigest, BeginMetadata, EventCursor, EventKey, EventPayload, EventRecord,
        EventScope, Instruction, InstructionDefinition, Memory, MemoryDirection, Provenance,
        ProviderCapabilities, ProviderCounters, ProviderError, ProviderSummary, SourceIdentity,
        TimelineDescriptor, TimelineId, TraceProvider, WorkDelta, WorkGuard,
    };

    use super::{BuildOptions, IndexBuilder, cancellable_sort};

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
        let sections =
            super::super::wire::encode(store.catalog, &AllowAll).expect("large binary sections");
        let event_meta = sections
            .iter()
            .find(|section| section.name == "event_meta.v2")
            .expect("event metadata");
        assert_eq!(event_meta.bytes.len(), count as usize * 24);
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
}
