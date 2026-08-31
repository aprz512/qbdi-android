use std::collections::{BTreeMap, HashMap, HashSet};

use qtrace_provider::{
    EventKind, EventPayload, EventRecord, Provenance, ProviderCapabilities, RegisterSlot,
    TraceProvider, WorkDelta, WorkGuard,
};
use serde::Serialize;

use crate::ArtifactSource;

use super::{
    BuildOptions, ByteArena, CompletenessRow, DefinitionRow, EventColumn, IndexCatalog, IndexError,
    InstructionRow, MemoryRow, ModuleRow, NormalizedCatalog, OwnedTraceStore, SemanticRow,
    SourceKeyRow, checkpoints::RegisterAccess, checkpoints::RegisterObservationRow,
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
    keys: Vec<qtrace_provider::EventKey>,
    kinds: Vec<EventKind>,
    events: Vec<EventColumn>,
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
    module_by_source: HashMap<u32, u32>,
    definition_by_source: HashMap<u32, (u32, Vec<u8>)>,
    saw_complete_checkpoint: bool,
    saw_register_observation: bool,
    saw_memory_metadata: bool,
    saw_memory_before_after: bool,
    saw_lifecycle: bool,
    saw_signal_or_termination: bool,
    current_module: Option<(u64, Vec<u8>)>,
}

impl BuildState {
    fn new(options: &BuildOptions) -> Result<Self, IndexError> {
        Ok(Self {
            keys: Vec::new(),
            kinds: Vec::new(),
            events: Vec::new(),
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
            definition_by_source: HashMap::new(),
            saw_complete_checkpoint: false,
            saw_register_observation: false,
            saw_memory_metadata: false,
            saw_memory_before_after: false,
            saw_lifecycle: false,
            saw_signal_or_termination: false,
            current_module: None,
        })
    }

    fn append(&mut self, event: EventRecord, guard: &dyn WorkGuard) -> Result<(), IndexError> {
        self.source_keys
            .try_reserve(1)
            .map_err(|_| IndexError::resource("source-key set allocation failed"))?;
        if !self.source_keys.insert(event.key.clone()) {
            return Err(IndexError::duplicate_key("duplicate source EventKey"));
        }
        let row = self.keys.len();
        let payload_bytes = canonical_bytes(&event.payload)?;
        let payload_blob = self.blobs.intern(&payload_bytes, guard)?;
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
            provenance: event.provenance,
            payload_blob,
        });

        match &event.payload {
            EventPayload::Begin(begin) => {
                self.current_module = Some((
                    begin.module_base,
                    try_copy_bytes(begin.target.as_bytes(), "begin target")?,
                ));
            }
            EventPayload::ModuleDefinition(module) => {
                let name = self.strings.intern(module.name.as_bytes(), guard)?;
                match self.module_by_source.get(&module.module_id).copied() {
                    Some(id)
                        if self.modules.get(id as usize).is_some_and(|existing| {
                            existing.base == module.base && existing.name == name
                        }) => {}
                    Some(_) => return Err(IndexError::invalid("conflicting module definition")),
                    None => {
                        let id = if let Some(id) = self.modules.iter().position(|existing| {
                            existing.base == module.base && existing.name == name
                        }) {
                            u32::try_from(id).map_err(|_| {
                                IndexError::resource("module dictionary id exceeds u32")
                            })?
                        } else {
                            let id = checked_id(self.modules.len(), "module")?;
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
                            id
                        };
                        self.module_by_source.try_reserve(1).map_err(|_| {
                            IndexError::resource("module source map allocation failed")
                        })?;
                        self.module_by_source.insert(module.module_id, id);
                    }
                }
            }
            EventPayload::InstructionDefinition(definition) => {
                let exact = canonical_bytes(definition)?;
                if let Some((_, previous)) =
                    self.definition_by_source.get(&definition.definition_id)
                {
                    if previous != &exact {
                        return Err(IndexError::invalid("conflicting instruction definition"));
                    }
                } else {
                    let exact_blob = self.blobs.intern(&exact, guard)?;
                    let id = if let Some(id) = self
                        .definitions
                        .iter()
                        .position(|existing| existing.exact_blob == exact_blob)
                    {
                        u32::try_from(id).map_err(|_| {
                            IndexError::resource("definition dictionary id exceeds u32")
                        })?
                    } else {
                        let id = checked_id(self.definitions.len(), "definition")?;
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
                        id
                    };
                    self.definition_by_source.try_reserve(1).map_err(|_| {
                        IndexError::resource("definition source map allocation failed")
                    })?;
                    self.definition_by_source
                        .insert(definition.definition_id, (id, exact));
                }
            }
            EventPayload::Instruction(instruction) => {
                if !self.module_by_source.contains_key(&instruction.module_id) {
                    if let Some((base, name)) = &self.current_module {
                        let name = self.strings.intern(name, guard)?;
                        let id =
                            if let Some(id) = self.modules.iter().position(|existing| {
                                existing.base == *base && existing.name == name
                            }) {
                                u32::try_from(id).map_err(|_| {
                                    IndexError::resource("module dictionary id exceeds u32")
                                })?
                            } else {
                                let id = checked_id(self.modules.len(), "module")?;
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
                                id
                            };
                        self.module_by_source.try_reserve(1).map_err(|_| {
                            IndexError::resource("module source map allocation failed")
                        })?;
                        self.module_by_source.insert(instruction.module_id, id);
                    }
                }
                let module = self.module_by_source.get(&instruction.module_id).copied();
                let definition = self
                    .definition_by_source
                    .get(&instruction.definition_id)
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
                    module: self.module_by_source.get(&memory.module_id).copied(),
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
                self.saw_complete_checkpoint |= checkpoint.values.len() == RegisterSlot::COUNT
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
            schema: 1,
            capabilities,
            events: self.events,
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
    let mut timeline = BTreeMap::<u64, Vec<usize>>::new();
    let mut tid = BTreeMap::<u32, Vec<usize>>::new();
    let mut kind = BTreeMap::<u8, Vec<usize>>::new();
    let mut sequence = Vec::new();
    sequence
        .try_reserve(events.len())
        .map_err(|_| IndexError::resource("sequence index allocation failed"))?;
    for (row, event) in events.iter().enumerate() {
        if row % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        timeline.entry(event.timeline).or_default().push(row);
        if let Some(value) = event.tid {
            tid.entry(value).or_default().push(row);
        }
        kind.entry(crate::layout::encode_event_kind(kinds[row]))
            .or_default()
            .push(row);
        if let Some(value) = event.sequence {
            sequence.push((value, row));
        }
    }
    guard.consume(WorkDelta::default())?;
    sequence.sort_unstable();
    let mut module = BTreeMap::<u32, Vec<usize>>::new();
    let mut definition = BTreeMap::<u32, Vec<usize>>::new();
    let mut pc = BTreeMap::<u32, Vec<(u64, usize)>>::new();
    let mut call = Vec::new();
    let mut return_rows = Vec::new();
    for (ordinal, instruction) in instructions.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(id) = instruction.module {
            module.entry(id).or_default().push(instruction.owner_row);
            pc.entry(id)
                .or_default()
                .push((instruction.relative_pc, instruction.owner_row));
        }
        if let Some(id) = instruction.definition {
            definition
                .entry(id)
                .or_default()
                .push(instruction.owner_row);
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
    guard.consume(WorkDelta::default())?;
    for values in pc.values_mut() {
        values.sort_unstable();
    }
    let mut register = BTreeMap::<u8, Vec<usize>>::new();
    let mut checkpoint = Vec::new();
    for (ordinal, observation) in observations.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        register
            .entry(observation.slot)
            .or_default()
            .push(observation.owner_row);
        if observation.access == RegisterAccess::Checkpoint {
            checkpoint.push(observation.owner_row);
        }
    }
    for values in register.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    checkpoint.sort_unstable();
    checkpoint.dedup();
    let mut semantic_category = BTreeMap::<u32, Vec<usize>>::new();
    let mut semantic_name = BTreeMap::<u32, Vec<usize>>::new();
    for (ordinal, semantic) in semantics.iter().enumerate() {
        if ordinal % 4096 == 0 {
            guard.consume(WorkDelta::default())?;
        }
        if let Some(category) = semantic.category {
            semantic_category
                .entry(category)
                .or_default()
                .push(semantic.owner_row);
        }
        semantic_name
            .entry(semantic.name)
            .or_default()
            .push(semantic.owner_row);
    }
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
    guard.consume(WorkDelta::default())?;
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
    source_keys.sort_by(|left, right| super::compare_event_keys(&left.key, &right.key));
    guard.consume(WorkDelta::default())?;
    let memory = IntervalIndex::build(intervals, options.interval_block_rows as usize)?;
    guard.consume(WorkDelta::default())?;
    Ok(IndexCatalog {
        timeline: encode_map(timeline)?,
        tid: encode_map(tid)?,
        kind: encode_map(kind)?,
        module: encode_map(module)?,
        definition: encode_map(definition)?,
        register: encode_map(register)?,
        semantic_category: encode_map(semantic_category)?,
        semantic_name: encode_map(semantic_name)?,
        call: PostingList::from_rows(&call)?,
        return_rows: PostingList::from_rows(&return_rows)?,
        checkpoint: PostingList::from_rows(&checkpoint)?,
        sequence,
        module_pc: pc,
        memory,
        source_keys,
    })
}

fn encode_map<K: Ord>(
    source: BTreeMap<K, Vec<usize>>,
) -> Result<BTreeMap<K, PostingList>, IndexError> {
    source
        .into_iter()
        .map(|(key, rows)| Ok((key, PostingList::from_rows(&rows)?)))
        .collect()
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

fn checked_id(length: usize, label: &str) -> Result<u32, IndexError> {
    u32::try_from(length)
        .map_err(|_| IndexError::resource(format!("{label} dictionary exceeds u32")))
}

#[cfg(test)]
mod tests {
    use qtrace_provider::{
        ArtifactDigest, EventCursor, EventKey, EventPayload, EventRecord, Memory, MemoryDirection,
        Provenance, ProviderCapabilities, ProviderCounters, ProviderError, ProviderSummary,
        SourceIdentity, TimelineDescriptor, TimelineId, TraceProvider, WorkDelta, WorkGuard,
    };

    use super::{BuildOptions, IndexBuilder};

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
}
