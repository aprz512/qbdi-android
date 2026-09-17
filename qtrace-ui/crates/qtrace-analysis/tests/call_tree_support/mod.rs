#![allow(dead_code)]

use qtrace_provider::{
    ArtifactDigest, EventKey, EventKind, EventPayload, PcRelativeKind, Provenance,
    ProviderCapabilities, RegisterSlot, SignalHandlerBoundary, SignalHandlerPhase, TimelineId,
};
use qtrace_store::{
    CompletenessRow, DefinitionRow, IndexError, InstructionRow, MemoryRow, ModuleRow,
    NormalizedBulkView, NormalizedContentIdentity, NormalizedLayoutIdentity,
    NormalizedPostingQuery, NormalizedSourceFormat, RegisterAccess, RegisterObservationRow,
    SemanticRow, TraceStoreView,
};

pub const CALL: u32 = 1 << 2;
pub const RETURN: u32 = 1 << 3;
pub const BRANCH: u32 = 1;

#[derive(Clone)]
pub struct Spec {
    pub tid: Option<u32>,
    pub timeline: u64,
    pub kind: EventKind,
    pub pc: u64,
    pub flags: u32,
    pub displacement: i64,
    pub pc_kind: PcRelativeKind,
    pub observations: Vec<(RegisterSlot, RegisterAccess, u64)>,
    pub payload: EventPayload,
    pub semantic: Option<(&'static str, &'static str, &'static str)>,
}

impl Spec {
    pub fn instruction(tid: u32, pc: u64, flags: u32) -> Self {
        Self {
            tid: Some(tid),
            timeline: 1,
            kind: EventKind::Instruction,
            pc,
            flags,
            displacement: 0,
            pc_kind: PcRelativeKind::None,
            observations: Vec::new(),
            payload: EventPayload::OpaqueOptional(qtrace_provider::OpaqueOptionalRecord {
                record_type: 0x8000,
                flags: 0,
                bytes: Vec::new(),
            }),
            semantic: None,
        }
    }

    pub fn immediate_call(tid: u32, pc: u64, displacement: i64) -> Self {
        Self {
            flags: BRANCH | CALL,
            displacement,
            pc_kind: PcRelativeKind::Instruction,
            ..Self::instruction(tid, pc, 0)
        }
    }

    pub fn boundary(tid: Option<u32>, kind: EventKind, payload: EventPayload) -> Self {
        Self {
            tid,
            timeline: 1,
            kind,
            pc: 0,
            flags: 0,
            displacement: 0,
            pc_kind: PcRelativeKind::None,
            observations: Vec::new(),
            payload,
            semantic: None,
        }
    }

    pub fn semantic(tid: u32, category: &'static str, name: &'static str) -> Self {
        let event = qtrace_provider::SemanticEvent {
            category: Some(category.into()),
            name: name.into(),
            detail: "detail".into(),
            fragment_sequences: Vec::new(),
        };
        Self {
            tid: Some(tid),
            timeline: 1,
            kind: EventKind::SemanticCall,
            pc: 0,
            flags: 0,
            displacement: 0,
            pc_kind: PcRelativeKind::None,
            observations: Vec::new(),
            payload: EventPayload::SemanticCall(event),
            semantic: Some((category, name, "detail")),
        }
    }

    pub fn signal(tid: u32, phase: SignalHandlerPhase) -> Self {
        Self::boundary(
            Some(tid),
            EventKind::SignalHandlerBoundary,
            EventPayload::SignalHandlerBoundary(SignalHandlerBoundary {
                tid,
                phase,
                number: 11,
                code: 0,
                pc: 0x5000,
                sp: 0,
                fault_address: 0,
                flags: 0,
                depth: 1,
                nested_delivery_count: 0,
                begin_sequence: None,
            }),
        )
    }
}

pub struct FixtureStore {
    keys: Vec<EventKey>,
    kinds: Vec<EventKind>,
    provenances: Vec<Provenance>,
    instructions: Vec<InstructionRow>,
    definitions: Vec<DefinitionRow>,
    semantics: Vec<SemanticRow>,
    observations: Vec<RegisterObservationRow>,
    payloads: Vec<Vec<u8>>,
    strings: Vec<Vec<u8>>,
    blobs: Vec<Vec<u8>>,
    capabilities: ProviderCapabilities,
}

impl FixtureStore {
    pub fn new(specs: Vec<Spec>) -> Self {
        let mut store = Self {
            keys: Vec::new(),
            kinds: Vec::new(),
            provenances: Vec::new(),
            instructions: Vec::new(),
            definitions: Vec::new(),
            semantics: Vec::new(),
            observations: Vec::new(),
            payloads: Vec::new(),
            strings: Vec::new(),
            blobs: Vec::new(),
            capabilities: ProviderCapabilities {
                global_ordering: true,
                per_thread_ordering: true,
                full_register_checkpoint: true,
                register_read_write_observation: true,
                memory_metadata: true,
                memory_before_after: true,
                lifecycle: true,
                signal_and_termination: true,
                loss_and_damage_ranges: true,
            },
        };
        for (row, spec) in specs.into_iter().enumerate() {
            store.keys.push(EventKey::new(
                ArtifactDigest::new([0x51; 32]),
                TimelineId(spec.timeline),
                row as u64,
                row as u64,
                Some(row as u64 + 1),
                spec.tid,
            ));
            store.kinds.push(spec.kind);
            store.provenances.push(Provenance::Captured);
            store
                .payloads
                .push(serde_json::to_vec(&spec.payload).unwrap());
            if spec.kind == EventKind::Instruction {
                let definition = store.definitions.len() as u32;
                let mnemonic = store.intern_string(if spec.flags & RETURN != 0 {
                    b"ret"
                } else if spec.flags & CALL != 0 {
                    b"bl"
                } else {
                    b"nop"
                });
                store.definitions.push(DefinitionRow {
                    source_event_row: row,
                    provenance: Provenance::Captured,
                    source_id: definition,
                    opcode: 0,
                    read_mask: 0,
                    write_mask: 0,
                    pc_displacement: spec.displacement,
                    flags: spec.flags,
                    pc_kind: spec.pc_kind,
                    condition: 0,
                    slow_memory_path: false,
                    mnemonic,
                    operands: mnemonic,
                    disassembly: mnemonic,
                    exact_blob: 0,
                });
                store.instructions.push(InstructionRow {
                    owner_row: row,
                    module: None,
                    relative_pc: spec.pc,
                    definition: Some(definition),
                });
            }
            for (slot, access, value) in spec.observations {
                store.observations.push(RegisterObservationRow {
                    owner_row: row,
                    slot: slot.index() as u8,
                    captured_width: 8,
                    access,
                    value,
                    provenance: Provenance::Captured,
                });
            }
            if let Some((category, name, detail)) = spec.semantic {
                let category = store.intern_string(category.as_bytes());
                let name = store.intern_string(name.as_bytes());
                let detail_blob = store.intern_blob(detail.as_bytes());
                store.semantics.push(SemanticRow {
                    owner_row: row,
                    category: Some(category),
                    name,
                    detail_blob,
                });
            }
        }
        if store.blobs.is_empty() {
            store.blobs.push(b"{}".to_vec());
        }
        store
    }

    fn intern_string(&mut self, bytes: &[u8]) -> u32 {
        if let Some(index) = self.strings.iter().position(|item| item == bytes) {
            return index as u32;
        }
        self.strings.push(bytes.to_vec());
        (self.strings.len() - 1) as u32
    }

    fn intern_blob(&mut self, bytes: &[u8]) -> u32 {
        self.blobs.push(bytes.to_vec());
        (self.blobs.len() - 1) as u32
    }

    fn matching_rows(&self, predicate: impl Fn(usize) -> bool) -> Vec<usize> {
        (0..self.keys.len()).filter(|row| predicate(*row)).collect()
    }
}

impl TraceStoreView for FixtureStore {
    fn event_count(&self) -> usize {
        self.keys.len()
    }
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        Ok(self.keys.get(row).cloned())
    }
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        Ok(self.kinds.get(row).copied())
    }
    fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        Ok(self.provenances.get(row).copied())
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn instruction(&self, row: usize) -> Option<InstructionRow> {
        self.instructions
            .iter()
            .find(|item| item.owner_row == row)
            .copied()
    }
    fn memory(&self, _: usize) -> Option<MemoryRow> {
        None
    }
    fn semantic(&self, row: usize) -> Option<SemanticRow> {
        self.semantics
            .iter()
            .find(|item| item.owner_row == row)
            .copied()
    }
    fn payload_bytes(&self, row: usize) -> Result<&[u8], IndexError> {
        Ok(self.payloads.get(row).map(Vec::as_slice).unwrap_or(&[]))
    }
    fn string_bytes(&self, id: u32) -> Result<&[u8], IndexError> {
        Ok(self
            .strings
            .get(id as usize)
            .map(Vec::as_slice)
            .unwrap_or(&[]))
    }
    fn blob_bytes(&self, id: u32) -> Result<&[u8], IndexError> {
        Ok(self
            .blobs
            .get(id as usize)
            .map(Vec::as_slice)
            .unwrap_or(&[]))
    }
    fn memory_before_bytes(&self, _: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(None)
    }
    fn memory_after_bytes(&self, _: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(None)
    }
    fn module(&self, _: u32) -> Option<&ModuleRow> {
        None
    }
    fn definition(&self, id: u32) -> Option<&DefinitionRow> {
        self.definitions.get(id as usize)
    }
    fn register_observations(&self, row: usize) -> Vec<RegisterObservationRow> {
        self.observations
            .iter()
            .filter(|item| item.owner_row == row)
            .copied()
            .collect()
    }
    fn completeness(&self) -> &[CompletenessRow] {
        &[]
    }
    fn rows_for_timeline(&self, timeline: u64) -> Result<Vec<usize>, IndexError> {
        Ok(self.matching_rows(|row| self.keys[row].timeline.0 == timeline))
    }
    fn rows_for_tids(&self, tids: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(self.matching_rows(|row| self.keys[row].tid.is_some_and(|tid| tids.contains(&tid))))
    }
    fn rows_for_sequence_range(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        Ok(self.matching_rows(|row| {
            self.keys[row]
                .sequence
                .is_some_and(|seq| (start..end).contains(&seq))
        }))
    }
    fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        Ok(self.matching_rows(|row| kinds.contains(&self.kinds[row])))
    }
    fn rows_for_modules(&self, _: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_module_pc_range(&self, _: u32, _: u64, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_definitions(&self, definitions: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(self.matching_rows(|row| {
            self.instruction(row)
                .and_then(|item| item.definition)
                .is_some_and(|id| definitions.contains(&id))
        }))
    }
    fn rows_observing_register(&self, slot: RegisterSlot) -> Result<Vec<usize>, IndexError> {
        Ok(self.matching_rows(|row| {
            self.observations
                .iter()
                .any(|item| item.owner_row == row && item.slot as usize == slot.index())
        }))
    }
    fn checkpoint_rows(&self) -> Result<Vec<usize>, IndexError> {
        self.rows_of_kinds(&[EventKind::RegisterCheckpoint])
    }
    fn call_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(self.matching_rows(|row| {
            self.instruction(row)
                .and_then(|item| item.definition)
                .and_then(|id| self.definition(id))
                .is_some_and(|definition| definition.flags & CALL != 0)
        }))
    }
    fn return_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(self.matching_rows(|row| {
            self.instruction(row)
                .and_then(|item| item.definition)
                .and_then(|id| self.definition(id))
                .is_some_and(|definition| definition.flags & RETURN != 0)
        }))
    }
    fn rows_for_semantic_categories(&self, _: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn rows_for_semantic_names(&self, _: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn memory_overlaps(&self, _: u64, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize> {
        self.keys.iter().position(|item| item == key)
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.event_key(row)
    }
}

impl NormalizedBulkView for FixtureStore {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity {
        NormalizedLayoutIdentity::new(1, [0x11; 32])
    }
    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        NormalizedContentIdentity::new([0x22; 32])
    }
    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        NormalizedSourceFormat::Flight
    }
    fn module_rows(&self) -> &[ModuleRow] {
        &[]
    }
    fn definition_rows(&self) -> &[DefinitionRow] {
        &self.definitions
    }
    fn instruction_rows(&self) -> &[InstructionRow] {
        &self.instructions
    }
    fn memory_rows(&self) -> &[MemoryRow] {
        &[]
    }
    fn semantic_rows(&self) -> &[SemanticRow] {
        &self.semantics
    }
    fn register_observation_rows(&self) -> &[RegisterObservationRow] {
        &self.observations
    }
    fn string_count(&self) -> usize {
        self.strings.len()
    }
    fn blob_count(&self) -> usize {
        self.blobs.len()
    }
    fn bounded_row_count(
        &self,
        _: NormalizedPostingQuery<'_>,
        _: usize,
        _: &dyn qtrace_provider::WorkGuard,
    ) -> Result<usize, IndexError> {
        Ok(0)
    }
    fn bounded_rows(
        &self,
        _: NormalizedPostingQuery<'_>,
        _: usize,
        _: &dyn qtrace_provider::WorkGuard,
    ) -> Result<Vec<usize>, IndexError> {
        Ok(Vec::new())
    }
}
