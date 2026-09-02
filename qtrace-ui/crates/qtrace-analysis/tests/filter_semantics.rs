use std::{sync::Arc, time::Duration};

use qtrace_analysis::{
    AddressRange, EventFilter, MemoryFilter, MnemonicFilter, QueryContext, RegisterFilter,
    SequenceRange, TimelineProjection, query_events,
};
use qtrace_provider::{
    ArtifactDigest, EventKey, EventKind, MemoryDirection, Provenance, ProviderCapabilities,
    RegisterSlot, TimelineId,
};
use qtrace_store::{
    CompletenessRow, DefinitionRow, IndexError, InstructionRow, MemoryRow, ModuleRow,
    NormalizedBulkView, NormalizedContentIdentity, NormalizedLayoutIdentity,
    NormalizedPostingQuery, NormalizedSourceFormat, RegisterAccess, RegisterObservationRow,
    SemanticRow, TraceStoreView,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct EventFact {
    key: EventKey,
    kind: EventKind,
    provenance: Provenance,
    instruction: Option<InstructionRow>,
    memory: Option<MemoryRow>,
    semantic: Option<SemanticRow>,
    observations: Vec<RegisterObservationRow>,
}

#[derive(Clone)]
struct FixtureStore {
    events: Vec<EventFact>,
    modules: Vec<ModuleRow>,
    definitions: Vec<DefinitionRow>,
    instructions: Vec<InstructionRow>,
    memories: Vec<MemoryRow>,
    semantics: Vec<SemanticRow>,
    observations: Vec<RegisterObservationRow>,
    strings: Vec<Vec<u8>>,
    blobs: Vec<Vec<u8>>,
    payloads: Vec<Vec<u8>>,
    layout: NormalizedLayoutIdentity,
    capabilities: ProviderCapabilities,
    completeness: Vec<CompletenessRow>,
}

impl FixtureStore {
    fn new() -> Self {
        let artifact = ArtifactDigest::new([7; 32]);
        let key = |ordinal, tid, sequence| {
            EventKey::new(
                artifact,
                TimelineId(1),
                ordinal,
                ordinal * 16,
                Some(sequence),
                Some(tid),
            )
        };
        let instruction = |owner_row, module, relative_pc, definition| InstructionRow {
            owner_row,
            module: Some(module),
            relative_pc,
            definition: Some(definition),
        };
        let memory = |owner_row, module, relative_pc, address, end_exclusive, direction| {
            serde_json::from_value(serde_json::json!({
                "owner_row": owner_row,
                "module": module,
                "relative_pc": relative_pc,
                "address": address,
                "end_exclusive": end_exclusive,
                "size": u32::try_from(end_exclusive - address).unwrap(),
                "direction": direction,
                "metadata_available": true,
                "flags": 0,
                "value": 0,
                "before_blob": 0,
                "after_blob": 0
            }))
            .unwrap()
        };
        let observation = |owner_row, slot: RegisterSlot, access| RegisterObservationRow {
            owner_row,
            slot: slot.index() as u8,
            captured_width: 8,
            access,
            value: 0,
            provenance: Provenance::Captured,
        };

        let events = vec![
            EventFact {
                key: key(0, 7, 10),
                kind: EventKind::Instruction,
                provenance: Provenance::Captured,
                instruction: Some(instruction(0, 0, 0x10, 0)),
                memory: None,
                semantic: None,
                observations: vec![
                    observation(0, RegisterSlot::X0, RegisterAccess::Read),
                    observation(0, RegisterSlot::X1, RegisterAccess::Write),
                ],
            },
            EventFact {
                key: key(1, 8, 11),
                kind: EventKind::Instruction,
                provenance: Provenance::Derived,
                instruction: Some(instruction(1, 0, 0x20, 1)),
                memory: None,
                semantic: None,
                observations: vec![
                    observation(1, RegisterSlot::X2, RegisterAccess::Read),
                    observation(1, RegisterSlot::X3, RegisterAccess::Write),
                ],
            },
            EventFact {
                key: key(2, 7, 12),
                kind: EventKind::Memory,
                provenance: Provenance::Captured,
                instruction: None,
                memory: Some(memory(2, 0, 0x14, 0x2000, 0x2004, MemoryDirection::Read)),
                semantic: None,
                observations: vec![],
            },
            EventFact {
                key: key(3, 8, 13),
                kind: EventKind::Memory,
                provenance: Provenance::Captured,
                instruction: None,
                memory: Some(memory(3, 1, 0x30, 0x2004, 0x200c, MemoryDirection::Write)),
                semantic: None,
                observations: vec![],
            },
            EventFact {
                key: key(4, 7, 14),
                kind: EventKind::SemanticCall,
                provenance: Provenance::Captured,
                instruction: None,
                memory: None,
                semantic: Some(SemanticRow {
                    owner_row: 4,
                    category: Some(4),
                    name: 6,
                    detail_blob: 0,
                }),
                observations: vec![],
            },
            EventFact {
                key: key(5, 8, 15),
                kind: EventKind::SemanticRule,
                provenance: Provenance::Heuristic,
                instruction: None,
                memory: None,
                semantic: Some(SemanticRow {
                    owner_row: 5,
                    category: Some(5),
                    name: 7,
                    detail_blob: 1,
                }),
                observations: vec![],
            },
        ];
        let instructions = events
            .iter()
            .filter_map(|event| event.instruction)
            .collect();
        let memories = events.iter().filter_map(|event| event.memory).collect();
        let semantics = events.iter().filter_map(|event| event.semantic).collect();
        let observations = events
            .iter()
            .flat_map(|event| event.observations.iter().copied())
            .collect();
        Self {
            events,
            modules: vec![
                ModuleRow {
                    source_event_row: 0,
                    provenance: Provenance::Captured,
                    source_id: 10,
                    base: 0x1000,
                    name: 2,
                },
                ModuleRow {
                    source_event_row: 0,
                    provenance: Provenance::Captured,
                    source_id: 20,
                    base: 0x3000,
                    name: 3,
                },
            ],
            definitions: vec![definition(0, 0), definition(1, 1)],
            instructions,
            memories,
            semantics,
            observations,
            strings: vec![
                b"ADD".to_vec(),
                b"SUB".to_vec(),
                b"liba.so".to_vec(),
                b"libb.so".to_vec(),
                b"jni".to_vec(),
                b"policy".to_vec(),
                b"FindClass".to_vec(),
                b"allow".to_vec(),
            ],
            blobs: vec![b"critical token".to_vec(), b"boring".to_vec()],
            payloads: vec![b"{}".to_vec(); 6],
            layout: layout_identity(2, 1),
            capabilities: ProviderCapabilities::qtrb_register_observations(),
            completeness: vec![],
        }
    }
}

fn layout_identity(schema_version: u32, fingerprint: u8) -> NormalizedLayoutIdentity {
    serde_json::from_value(serde_json::json!({
        "schema_version": schema_version,
        "layout_fingerprint": vec![fingerprint; 32],
    }))
    .unwrap()
}

fn definition(source_event_row: usize, mnemonic: u32) -> DefinitionRow {
    DefinitionRow {
        source_event_row,
        provenance: Provenance::Captured,
        source_id: source_event_row as u32,
        opcode: 0,
        read_mask: 0,
        write_mask: 0,
        pc_displacement: 0,
        flags: 0,
        pc_kind: qtrace_provider::PcRelativeKind::None,
        condition: 0,
        slow_memory_path: false,
        mnemonic,
        operands: mnemonic,
        disassembly: mnemonic,
        exact_blob: 0,
    }
}

impl TraceStoreView for FixtureStore {
    fn event_count(&self) -> usize {
        self.events.len()
    }
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        Ok(self.events.get(row).map(|event| event.key.clone()))
    }
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        Ok(self.events.get(row).map(|event| event.kind))
    }
    fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        Ok(self.events.get(row).map(|event| event.provenance))
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn instruction(&self, row: usize) -> Option<InstructionRow> {
        self.events.get(row)?.instruction
    }
    fn memory(&self, row: usize) -> Option<MemoryRow> {
        self.events.get(row)?.memory
    }
    fn semantic(&self, row: usize) -> Option<SemanticRow> {
        self.events.get(row)?.semantic
    }
    fn payload_bytes(&self, row: usize) -> Result<&[u8], IndexError> {
        Ok(&self.payloads[row])
    }
    fn string_bytes(&self, id: u32) -> Result<&[u8], IndexError> {
        Ok(&self.strings[id as usize])
    }
    fn blob_bytes(&self, id: u32) -> Result<&[u8], IndexError> {
        Ok(&self.blobs[id as usize])
    }
    fn memory_before_bytes(&self, _row: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(None)
    }
    fn memory_after_bytes(&self, _row: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(None)
    }
    fn module(&self, id: u32) -> Option<&ModuleRow> {
        self.modules.get(id as usize)
    }
    fn definition(&self, id: u32) -> Option<&DefinitionRow> {
        self.definitions.get(id as usize)
    }
    fn register_observations(&self, row: usize) -> Vec<RegisterObservationRow> {
        self.events
            .get(row)
            .map_or_else(Vec::new, |event| event.observations.clone())
    }
    fn completeness(&self) -> &[CompletenessRow] {
        &self.completeness
    }
    fn rows_for_timeline(&self, timeline: u64) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| event.key.timeline.0 == timeline))
    }
    fn rows_for_tids(&self, tids: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| event.key.tid.is_some_and(|tid| tids.contains(&tid))))
    }
    fn rows_for_sequence_range(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| {
            event
                .key
                .sequence
                .is_some_and(|seq| start <= seq && seq < end)
        }))
    }
    fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| kinds.contains(&event.kind)))
    }
    fn rows_for_modules(&self, modules: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| {
            event
                .instruction
                .and_then(|row| row.module)
                .or_else(|| event.memory.and_then(|row| row.module))
                .is_some_and(|module| modules.contains(&module))
        }))
    }
    fn rows_for_module_pc_range(
        &self,
        module: u32,
        start: u64,
        end: u64,
    ) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| {
            event
                .instruction
                .map(|row| (row.module, row.relative_pc))
                .or_else(|| event.memory.map(|row| (row.module, row.relative_pc)))
                .is_some_and(|(candidate, pc)| candidate == Some(module) && start <= pc && pc < end)
        }))
    }
    fn rows_for_definitions(&self, definitions: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| {
            event
                .instruction
                .and_then(|row| row.definition)
                .is_some_and(|id| definitions.contains(&id))
        }))
    }
    fn rows_observing_register(&self, slot: RegisterSlot) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| {
            event
                .observations
                .iter()
                .any(|row| row.slot as usize == slot.index())
        }))
    }
    fn checkpoint_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn call_rows(&self) -> Result<Vec<usize>, IndexError> {
        self.rows_of_kinds(&[EventKind::SemanticCall])
    }
    fn return_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_for_semantic_categories(&self, categories: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| {
            event
                .semantic
                .and_then(|row| row.category)
                .is_some_and(|id| categories.contains(&self.strings[id as usize].as_slice()))
        }))
    }
    fn rows_for_semantic_names(&self, names: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| {
            event
                .semantic
                .is_some_and(|row| names.contains(&self.strings[row.name as usize].as_slice()))
        }))
    }
    fn memory_overlaps(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|event| {
            event
                .memory
                .is_some_and(|row| row.address < end && start < row.end_exclusive)
        }))
    }
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize> {
        self.events.iter().position(|event| event.key == *key)
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.event_key(row)
    }
}

impl NormalizedBulkView for FixtureStore {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity {
        self.layout
    }

    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        let mut hash = Sha256::new();
        for event in &self.events {
            hash.update(serde_json::to_vec(&event.key).unwrap());
            hash.update(event.kind.external_tag());
            hash.update([event.provenance as u8]);
        }
        for value in [
            serde_json::to_vec(&self.modules).unwrap(),
            serde_json::to_vec(&self.definitions).unwrap(),
            serde_json::to_vec(&self.instructions).unwrap(),
            serde_json::to_vec(&self.memories).unwrap(),
            serde_json::to_vec(&self.semantics).unwrap(),
            serde_json::to_vec(&self.observations).unwrap(),
            serde_json::to_vec(&self.capabilities).unwrap(),
            serde_json::to_vec(&self.completeness).unwrap(),
            serde_json::to_vec(&self.payloads).unwrap(),
            serde_json::to_vec(&self.strings).unwrap(),
            serde_json::to_vec(&self.blobs).unwrap(),
        ] {
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value);
        }
        NormalizedContentIdentity::new(hash.finalize().into())
    }

    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        NormalizedSourceFormat::Other
    }

    fn module_rows(&self) -> &[ModuleRow] {
        &self.modules
    }
    fn definition_rows(&self) -> &[DefinitionRow] {
        &self.definitions
    }
    fn instruction_rows(&self) -> &[InstructionRow] {
        &self.instructions
    }
    fn memory_rows(&self) -> &[MemoryRow] {
        &self.memories
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

    fn bounded_row_estimate(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn qtrace_provider::WorkGuard,
    ) -> Result<qtrace_store::NormalizedPostingEstimate, IndexError> {
        let rows = self.bounded_row_count(query, max_rows, guard)?;
        Ok(qtrace_store::NormalizedPostingEstimate::new(rows, 0))
    }

    fn bounded_definition_decode_work(
        &self,
        _query_terms: usize,
        _max_rows: usize,
    ) -> Result<u64, IndexError> {
        Ok(0)
    }

    fn bounded_row_count(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn qtrace_provider::WorkGuard,
    ) -> Result<usize, IndexError> {
        self.bounded_rows(query, max_rows, guard)
            .map(|rows| rows.len())
    }

    fn bounded_rows(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        _guard: &dyn qtrace_provider::WorkGuard,
    ) -> Result<Vec<usize>, IndexError> {
        let mut rows = match query {
            NormalizedPostingQuery::Tids(values) => self.rows_for_tids(values)?,
            NormalizedPostingQuery::Kinds(values) => self.rows_of_kinds(values)?,
            NormalizedPostingQuery::Modules(values) => self.rows_for_modules(values)?,
            NormalizedPostingQuery::Sequence {
                start,
                end_exclusive,
            } => self.rows_for_sequence_range(start, end_exclusive)?,
            NormalizedPostingQuery::ModulePc {
                module,
                start,
                end_exclusive,
            } => self.rows_for_module_pc_range(module, start, end_exclusive)?,
            NormalizedPostingQuery::Definitions(values) => self.rows_for_definitions(values)?,
            NormalizedPostingQuery::Registers(values) => {
                let mut rows = Vec::new();
                for slot in values {
                    rows.extend(self.rows_observing_register(*slot)?);
                }
                rows
            }
            NormalizedPostingQuery::SemanticCategories(values) => {
                self.rows_for_semantic_categories(values)?
            }
            NormalizedPostingQuery::SemanticNames(values) => {
                self.rows_for_semantic_names(values)?
            }
            NormalizedPostingQuery::Memory {
                start,
                end_exclusive,
            } => self.memory_overlaps(start, end_exclusive)?,
        };
        rows.sort_unstable();
        rows.dedup();
        assert!(rows.len() <= max_rows, "mock posting exceeded test budget");
        Ok(rows)
    }
}

impl FixtureStore {
    fn rows(&self, predicate: impl Fn(&EventFact) -> bool) -> Vec<usize> {
        self.events
            .iter()
            .enumerate()
            .filter_map(|(row, event)| predicate(event).then_some(row))
            .collect()
    }
}

fn ordinals(filter: EventFilter) -> Vec<u64> {
    let context = Arc::new(QueryContext::new(Arc::new(FixtureStore::new())).unwrap());
    let projection = TimelineProjection::new(context, filter).unwrap();
    assert!(projection.wait_until_complete(Duration::from_secs(2)));
    query_events(&projection, None, 2_000)
        .unwrap()
        .rows
        .into_iter()
        .map(|row| row.key().record_ordinal)
        .collect()
}

#[test]
fn every_structured_field_uses_approved_range_and_match_semantics() {
    let cases = vec![
        (
            EventFilter {
                tids: vec![7],
                ..EventFilter::default()
            },
            vec![0, 2, 4],
        ),
        (
            EventFilter {
                kinds: vec![EventKind::Instruction, EventKind::Memory],
                ..EventFilter::default()
            },
            vec![0, 1, 2, 3],
        ),
        (
            EventFilter {
                modules: vec![0],
                ..EventFilter::default()
            },
            vec![0, 1, 2],
        ),
        (
            EventFilter {
                relative_pc: vec![AddressRange::new(0x13, 0x21).unwrap()],
                ..EventFilter::default()
            },
            vec![1, 2],
        ),
        (
            EventFilter {
                absolute_pc: vec![AddressRange::new(0x1010, 0x1015).unwrap()],
                ..EventFilter::default()
            },
            vec![0, 2],
        ),
        (
            EventFilter {
                sequence: vec![SequenceRange::new(11, 13).unwrap()],
                ..EventFilter::default()
            },
            vec![1, 2, 3],
        ),
        (
            EventFilter {
                mnemonic: vec![MnemonicFilter::Exact("add".into())],
                ..EventFilter::default()
            },
            vec![0],
        ),
        (
            EventFilter {
                mnemonic: vec![MnemonicFilter::Contains("u".into())],
                ..EventFilter::default()
            },
            vec![1],
        ),
        (
            EventFilter {
                register: RegisterFilter {
                    reads: vec![RegisterSlot::X0, RegisterSlot::X2],
                    writes: vec![],
                },
                ..EventFilter::default()
            },
            vec![0, 1],
        ),
        (
            EventFilter {
                register: RegisterFilter {
                    reads: vec![],
                    writes: vec![RegisterSlot::X1],
                },
                ..EventFilter::default()
            },
            vec![0],
        ),
        (
            EventFilter {
                memory: vec![MemoryFilter {
                    range: AddressRange::new(0x2003, 0x2005).unwrap(),
                    directions: vec![MemoryDirection::Read],
                }],
                ..EventFilter::default()
            },
            vec![2],
        ),
        (
            EventFilter {
                semantic_categories: vec!["jni".into()],
                ..EventFilter::default()
            },
            vec![4],
        ),
        (
            EventFilter {
                semantic_names: vec!["FindClass".into()],
                ..EventFilter::default()
            },
            vec![4],
        ),
        (
            EventFilter {
                semantic_detail_contains: vec!["token".into()],
                ..EventFilter::default()
            },
            vec![4],
        ),
    ];

    for (filter, expected) in cases {
        assert_eq!(ordinals(filter), expected);
    }
}

#[test]
fn noncontiguous_register_observation_owners_preserve_all_reads_and_writes() {
    let mut store = FixtureStore::new();
    store.observations = vec![
        store.observations[0],
        store.observations[2],
        store.observations[1],
        store.observations[3],
    ];
    let context = Arc::new(QueryContext::new(Arc::new(store)).unwrap());
    for (reads, writes, expected) in [
        (vec![RegisterSlot::X0], vec![], vec![0]),
        (vec![], vec![RegisterSlot::X1], vec![0]),
        (vec![RegisterSlot::X2], vec![], vec![1]),
        (vec![], vec![RegisterSlot::X3], vec![1]),
    ] {
        let projection = TimelineProjection::new(
            context.clone(),
            EventFilter {
                register: RegisterFilter { reads, writes },
                ..EventFilter::default()
            },
        )
        .unwrap();
        let actual = query_events(&projection, None, 10)
            .unwrap()
            .rows
            .into_iter()
            .map(|row| row.source_row())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
}

#[test]
fn values_within_a_field_are_ored_and_populated_fields_are_anded() {
    assert_eq!(
        ordinals(EventFilter {
            tids: vec![7, 8],
            kinds: vec![EventKind::Instruction],
            ..EventFilter::default()
        }),
        vec![0, 1]
    );
    assert_eq!(
        ordinals(EventFilter {
            tids: vec![7],
            kinds: vec![EventKind::Instruction],
            ..EventFilter::default()
        }),
        vec![0]
    );
}

#[test]
fn sequence_is_inclusive_while_pc_and_memory_ranges_are_half_open() {
    assert_eq!(
        ordinals(EventFilter {
            sequence: vec![SequenceRange::new(10, 10).unwrap()],
            ..EventFilter::default()
        }),
        vec![0]
    );
    assert!(AddressRange::new(0x10, 0x10).is_err());
    assert!(
        ordinals(EventFilter {
            memory: vec![MemoryFilter {
                range: AddressRange::new(0x1ffc, 0x2000).unwrap(),
                directions: vec![]
            }],
            ..EventFilter::default()
        })
        .is_empty()
    );
    assert!(
        ordinals(EventFilter {
            memory: vec![MemoryFilter {
                range: AddressRange::new(0x200c, 0x2010).unwrap(),
                directions: vec![]
            }],
            ..EventFilter::default()
        })
        .is_empty()
    );
}

fn store_identity(store: FixtureStore) -> qtrace_analysis::StoreIdentity {
    QueryContext::new(Arc::new(store)).unwrap().identity()
}

#[test]
fn store_identity_binds_every_public_normalized_fact_and_byte_domain() {
    let baseline = FixtureStore::new();
    let expected = store_identity(baseline.clone());
    let mut mutations = Vec::new();

    let mut changed = baseline.clone();
    changed.modules[0].base += 1;
    mutations.push(("module", changed));
    let mut changed = baseline.clone();
    changed.definitions[0].opcode += 1;
    mutations.push(("definition", changed));
    let mut changed = baseline.clone();
    changed.instructions[0].relative_pc += 1;
    mutations.push(("instruction", changed));
    let mut changed = baseline.clone();
    changed.memories[0].address += 1;
    mutations.push(("memory", changed));
    let mut changed = baseline.clone();
    changed.semantics[0].name = 7;
    mutations.push(("semantic", changed));
    let mut changed = baseline.clone();
    changed.observations[0].value += 1;
    mutations.push(("register observation", changed));
    let mut changed = baseline.clone();
    changed.payloads[0] = b"different payload".to_vec();
    mutations.push(("event payload", changed));
    let mut changed = baseline.clone();
    changed.strings[0] = b"ADC".to_vec();
    mutations.push(("string arena", changed));
    let mut changed = baseline.clone();
    changed.blobs[0] = b"different detail".to_vec();
    mutations.push(("blob arena", changed));
    let mut changed = baseline;
    changed.layout = layout_identity(3, 2);
    mutations.push(("schema/layout", changed));

    for (label, changed) in mutations {
        assert_ne!(store_identity(changed), expected, "unbound {label}");
    }
}

#[test]
fn cursor_accepts_equivalent_union_normal_forms_for_ranges_and_memory_directions() {
    let store = Arc::new(FixtureStore::new());
    let context = Arc::new(QueryContext::new(store).unwrap());
    let split = TimelineProjection::new(
        context.clone(),
        EventFilter {
            sequence: vec![
                SequenceRange::new(12, 12).unwrap(),
                SequenceRange::new(13, 13).unwrap(),
            ],
            memory: vec![
                MemoryFilter {
                    range: AddressRange::new(0x2000, 0x2005).unwrap(),
                    directions: vec![MemoryDirection::Read, MemoryDirection::ReadWrite],
                },
                MemoryFilter {
                    range: AddressRange::new(0x2000, 0x2005).unwrap(),
                    directions: vec![MemoryDirection::Write],
                },
                MemoryFilter {
                    range: AddressRange::new(0x2004, 0x200d).unwrap(),
                    directions: vec![MemoryDirection::Read],
                },
            ],
            ..EventFilter::default()
        },
    )
    .unwrap();
    let cursor = query_events(&split, None, 1)
        .unwrap()
        .next
        .expect("second matching row");
    let merged = TimelineProjection::new(
        context,
        EventFilter {
            sequence: vec![SequenceRange::new(12, 13).unwrap()],
            memory: vec![
                MemoryFilter {
                    range: AddressRange::new(0x2000, 0x200d).unwrap(),
                    directions: vec![MemoryDirection::Read],
                },
                MemoryFilter {
                    range: AddressRange::new(0x2000, 0x2005).unwrap(),
                    directions: vec![MemoryDirection::Write],
                },
            ],
            ..EventFilter::default()
        },
    )
    .unwrap();
    assert_eq!(
        query_events(&merged, Some(&cursor), 1).unwrap().rows.len(),
        1
    );
}
