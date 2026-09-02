use std::sync::Arc;

use qtrace_analysis::{RegisterReplay, RegisterSlot};
use qtrace_provider::{
    ArtifactDigest, BudgetDimension, EventKey, EventKind, InstructionDefinition, OperationAbort,
    Provenance, ProviderCapabilities, RegisterDefinition, TimelineId, WorkDelta, WorkGuard,
};
use qtrace_store::{
    AuthorizedPath, BuildOptions, DefinitionRow, IndexBuilder, IndexError, InstructionRow,
    MemoryRow, ModuleRow, NormalizedBulkView, NormalizedContentIdentity, NormalizedLayoutIdentity,
    NormalizedPostingEstimate, NormalizedPostingQuery, NormalizedSourceFormat, OpenPolicy,
    RegisterAccess, RegisterObservationRow, SemanticRow, SessionLoader, TraceStoreView,
};

struct RegisterStore {
    keys: Vec<EventKey>,
    kinds: Vec<EventKind>,
    instructions: Vec<InstructionRow>,
    observations: Vec<RegisterObservationRow>,
    capabilities: ProviderCapabilities,
    definitions: Vec<DefinitionRow>,
    blobs: Vec<Vec<u8>>,
    source: NormalizedSourceFormat,
}

impl RegisterStore {
    fn qtrb() -> Self {
        let key = |row, sequence| {
            EventKey::new(
                ArtifactDigest::new([0x14; 32]),
                TimelineId(1),
                row,
                row,
                Some(sequence),
                Some(7),
            )
        };
        Self {
            keys: vec![key(0, 10), key(1, 11)],
            kinds: vec![EventKind::Instruction, EventKind::Instruction],
            instructions: vec![
                InstructionRow {
                    owner_row: 0,
                    module: None,
                    relative_pc: 0x1000,
                    definition: None,
                },
                InstructionRow {
                    owner_row: 1,
                    module: None,
                    relative_pc: 0x1004,
                    definition: None,
                },
            ],
            observations: vec![
                RegisterObservationRow {
                    owner_row: 0,
                    slot: RegisterSlot::X0.index() as u8,
                    captured_width: 8,
                    access: RegisterAccess::Read,
                    value: u64::MAX,
                    provenance: Provenance::Captured,
                },
                RegisterObservationRow {
                    owner_row: 0,
                    slot: RegisterSlot::X1.index() as u8,
                    captured_width: 8,
                    access: RegisterAccess::Write,
                    value: 9,
                    provenance: Provenance::Captured,
                },
                RegisterObservationRow {
                    owner_row: 1,
                    slot: RegisterSlot::X1.index() as u8,
                    captured_width: 8,
                    access: RegisterAccess::Read,
                    value: 12,
                    provenance: Provenance::Captured,
                },
            ],
            capabilities: ProviderCapabilities::qtrb_register_observations(),
            definitions: vec![],
            blobs: vec![],
            source: NormalizedSourceFormat::Qtrb,
        }
    }
}

impl TraceStoreView for RegisterStore {
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
        Ok((row < self.keys.len()).then_some(Provenance::Captured))
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn instruction(&self, event_row: usize) -> Option<InstructionRow> {
        self.instructions
            .iter()
            .find(|row| row.owner_row == event_row)
            .copied()
    }
    fn memory(&self, _: usize) -> Option<MemoryRow> {
        None
    }
    fn semantic(&self, _: usize) -> Option<SemanticRow> {
        None
    }
    fn payload_bytes(&self, _: usize) -> Result<&[u8], IndexError> {
        Ok(&[])
    }
    fn string_bytes(&self, _: u32) -> Result<&[u8], IndexError> {
        Ok(&[])
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
    fn register_observations(&self, event_row: usize) -> Vec<RegisterObservationRow> {
        self.observations
            .iter()
            .filter(|row| row.owner_row == event_row)
            .copied()
            .collect()
    }
    fn completeness(&self) -> &[qtrace_store::CompletenessRow] {
        &[]
    }
    fn rows_for_timeline(&self, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok((0..self.keys.len()).collect())
    }
    fn rows_for_tids(&self, _: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok((0..self.keys.len()).collect())
    }
    fn rows_for_sequence_range(&self, _: u64, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok((0..self.keys.len()).collect())
    }
    fn rows_of_kinds(&self, _: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        Ok((0..self.keys.len()).collect())
    }
    fn rows_for_modules(&self, _: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_for_module_pc_range(&self, _: u32, _: u64, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_for_definitions(&self, _: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_observing_register(&self, _: RegisterSlot) -> Result<Vec<usize>, IndexError> {
        Ok((0..self.keys.len()).collect())
    }
    fn checkpoint_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn call_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn return_rows(&self) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_for_semantic_categories(&self, _: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_for_semantic_names(&self, _: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn memory_overlaps(&self, _: u64, _: u64) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize> {
        self.keys.iter().position(|candidate| candidate == key)
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.event_key(row)
    }
}

impl NormalizedBulkView for RegisterStore {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity {
        NormalizedLayoutIdentity::new(2, [0; 32])
    }
    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        NormalizedContentIdentity::new([1; 32])
    }
    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        self.source
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
        &[]
    }
    fn register_observation_rows(&self) -> &[RegisterObservationRow] {
        &self.observations
    }
    fn string_count(&self) -> usize {
        0
    }
    fn blob_count(&self) -> usize {
        self.blobs.len()
    }
    fn bounded_row_estimate(
        &self,
        _: NormalizedPostingQuery<'_>,
        _: usize,
        _: &dyn WorkGuard,
    ) -> Result<NormalizedPostingEstimate, IndexError> {
        Ok(NormalizedPostingEstimate::new(
            self.keys.len(),
            self.keys.len() as u64,
        ))
    }
    fn bounded_row_count(
        &self,
        _: NormalizedPostingQuery<'_>,
        _: usize,
        _: &dyn WorkGuard,
    ) -> Result<usize, IndexError> {
        Ok(self.keys.len())
    }
    fn bounded_rows(
        &self,
        _: NormalizedPostingQuery<'_>,
        _: usize,
        _: &dyn WorkGuard,
    ) -> Result<Vec<usize>, IndexError> {
        Ok((0..self.keys.len()).collect())
    }
}

#[test]
fn qtrb_reads_are_before_writes_are_after_and_max_is_known() {
    let store = Arc::new(RegisterStore::qtrb());
    let target = store.keys[0].clone();
    let replay = RegisterReplay::new(store).unwrap();
    let state = replay.state_at(&target).unwrap();

    assert_eq!(state.before.cell(RegisterSlot::X0).value, Some(u64::MAX));
    assert_eq!(
        state.before.cell(RegisterSlot::X0).provenance,
        Provenance::Captured
    );
    assert_eq!(state.before.cell(RegisterSlot::X1).value, None);
    assert_eq!(state.after.cell(RegisterSlot::X1).value, Some(9));
}

#[test]
fn captured_contradiction_replaces_prior_derived_state() {
    let store = Arc::new(RegisterStore::qtrb());
    let target = store.keys[1].clone();
    let replay = RegisterReplay::new(store).unwrap();
    let state = replay.state_at(&target).unwrap();

    assert_eq!(state.before.cell(RegisterSlot::X1).value, Some(12));
    assert_eq!(
        state.before.cell(RegisterSlot::X1).provenance,
        Provenance::Captured
    );
    assert_eq!(state.after.cell(RegisterSlot::X1).value, Some(12));
}

#[test]
fn partial_x_capture_keeps_high_bits_unknown_but_canonical_w_write_zero_extends() {
    let mut x_store = RegisterStore::qtrb();
    x_store.observations[1].captured_width = 4;
    x_store.observations[1].value = 0xffff_ffff_1234_5678;
    let x = RegisterReplay::new(Arc::new(x_store))
        .unwrap()
        .state_at(&RegisterStore::qtrb().keys[0])
        .unwrap();
    assert_eq!(x.after.cell(RegisterSlot::X1).value, Some(0x1234_5678));
    assert_eq!(x.after.cell(RegisterSlot::X1).known_mask, 0xffff_ffff);

    let mut w_store = RegisterStore::qtrb();
    w_store.observations[1].captured_width = 4;
    w_store.observations[1].value = 0xffff_ffff_1234_5678;
    w_store.instructions[0].definition = Some(0);
    let mut definition = InstructionDefinition::default();
    definition.writes.push(RegisterDefinition {
        slot: 1,
        captured_width: 4,
        name: "w1".into(),
    });
    w_store.blobs.push(serde_json::to_vec(&definition).unwrap());
    w_store.definitions.push(
        serde_json::from_value(serde_json::json!({
            "source_event_row": 0, "provenance": "captured", "source_id": 0,
            "opcode": 0, "read_mask": 0, "write_mask": 2, "pc_displacement": 0,
            "flags": 0, "pc_kind": "none", "condition": 0, "slow_memory_path": false,
            "mnemonic": 0, "operands": 0, "disassembly": 0, "exact_blob": 0
        }))
        .unwrap(),
    );
    let key = w_store.keys[0].clone();
    let w = RegisterReplay::new(Arc::new(w_store))
        .unwrap()
        .state_at(&key)
        .unwrap();
    assert_eq!(w.after.cell(RegisterSlot::X1).value, Some(0x1234_5678));
    assert_eq!(w.after.cell(RegisterSlot::X1).known_mask, u64::MAX);
}

#[test]
fn discontinuity_is_thread_scoped_and_later_capture_restores_one_cell() {
    let mut store = RegisterStore::qtrb();
    let make_key = |row, tid| {
        EventKey::new(
            ArtifactDigest::new([0x14; 32]),
            TimelineId(1),
            row,
            row,
            Some(row),
            Some(tid),
        )
    };
    store.keys = vec![
        make_key(0, 7),
        make_key(1, 8),
        make_key(2, 7),
        make_key(3, 7),
    ];
    store.kinds = vec![
        EventKind::Instruction,
        EventKind::Instruction,
        EventKind::Discontinuity,
        EventKind::Instruction,
    ];
    store.instructions = vec![
        InstructionRow {
            owner_row: 0,
            module: None,
            relative_pc: 0,
            definition: None,
        },
        InstructionRow {
            owner_row: 1,
            module: None,
            relative_pc: 0,
            definition: None,
        },
        InstructionRow {
            owner_row: 3,
            module: None,
            relative_pc: 0,
            definition: None,
        },
    ];
    store.observations = vec![
        RegisterObservationRow {
            owner_row: 0,
            slot: 0,
            captured_width: 8,
            access: RegisterAccess::Write,
            value: 5,
            provenance: Provenance::Captured,
        },
        RegisterObservationRow {
            owner_row: 1,
            slot: 0,
            captured_width: 8,
            access: RegisterAccess::Write,
            value: 99,
            provenance: Provenance::Captured,
        },
        RegisterObservationRow {
            owner_row: 3,
            slot: 0,
            captured_width: 8,
            access: RegisterAccess::Read,
            value: 7,
            provenance: Provenance::Captured,
        },
    ];
    let gap_key = store.keys[2].clone();
    let recapture_key = store.keys[3].clone();
    let other_key = store.keys[1].clone();
    let replay = RegisterReplay::new(Arc::new(store)).unwrap();
    assert_eq!(
        replay
            .state_at(&gap_key)
            .unwrap()
            .after
            .cell(RegisterSlot::X0)
            .provenance,
        Provenance::Damaged
    );
    assert_eq!(
        replay
            .state_at(&recapture_key)
            .unwrap()
            .before
            .cell(RegisterSlot::X0)
            .value,
        Some(7)
    );
    assert_eq!(
        replay
            .state_at(&other_key)
            .unwrap()
            .after
            .cell(RegisterSlot::X0)
            .value,
        Some(99)
    );
}

#[derive(Default)]
struct CountingGuard(std::sync::atomic::AtomicU64);
impl WorkGuard for CountingGuard {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        self.0.fetch_add(
            delta.rows + delta.nodes,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(())
    }
}

#[test]
fn derived_checkpoint_limits_state_at_replay_to_one_checkpoint_interval() {
    let mut store = RegisterStore::qtrb();
    let count: usize = 4_098;
    store.keys = (0..count)
        .map(|row| {
            EventKey::new(
                ArtifactDigest::new([0x14; 32]),
                TimelineId(1),
                row as u64,
                row as u64,
                Some(row as u64),
                Some(7),
            )
        })
        .collect();
    store.kinds = vec![EventKind::Instruction; count];
    store.instructions = (0..count)
        .map(|owner_row| InstructionRow {
            owner_row,
            module: None,
            relative_pc: owner_row as u64,
            definition: None,
        })
        .collect();
    store.observations = vec![RegisterObservationRow {
        owner_row: 0,
        slot: 0,
        captured_width: 8,
        access: RegisterAccess::Write,
        value: 41,
        provenance: Provenance::Captured,
    }];
    let target = store.keys[count - 1].clone();
    let replay = RegisterReplay::new(Arc::new(store)).unwrap();
    let guard = CountingGuard::default();
    let state = replay.state_at_with_guard(&target, &guard).unwrap();
    assert_eq!(state.after.cell(RegisterSlot::X0).value, Some(41));
    assert_eq!(
        state.after.cell(RegisterSlot::X0).provenance,
        Provenance::Derived
    );
    assert!(guard.0.load(std::sync::atomic::Ordering::Relaxed) < 1_000);
}

struct RejectGuard(OperationAbort);
impl WorkGuard for RejectGuard {
    fn consume(&self, _: WorkDelta) -> Result<(), OperationAbort> {
        Err(self.0.clone())
    }
}

#[test]
fn service_budget_and_cancellation_have_stable_codes() {
    let store = Arc::new(RegisterStore::qtrb());
    let key = store.keys[0].clone();
    let replay = RegisterReplay::new(store).unwrap();
    let budget = RejectGuard(OperationAbort::budget_exceeded(
        BudgetDimension::Nodes,
        0,
        1,
    ));
    assert_eq!(
        replay
            .state_at_with_guard(&key, &budget)
            .unwrap_err()
            .code(),
        "analysis.budget_exceeded"
    );
    let cancelled = RejectGuard(OperationAbort::Cancelled);
    assert_eq!(
        replay
            .state_at_with_guard(&key, &cancelled)
            .unwrap_err()
            .code(),
        "job.cancelled"
    );
}

#[test]
fn flight_full_checkpoint_delta_unreliable_gap_and_later_checkpoint_are_per_tid() {
    let mut store = RegisterStore::qtrb();
    store.source = NormalizedSourceFormat::Flight;
    store.capabilities = ProviderCapabilities {
        global_ordering: true,
        per_thread_ordering: true,
        full_register_checkpoint: true,
        register_read_write_observation: false,
        memory_metadata: true,
        memory_before_after: true,
        lifecycle: true,
        signal_and_termination: true,
        loss_and_damage_ranges: true,
    };
    let make_key = |row, tid| {
        EventKey::new(
            ArtifactDigest::new([0x44; 32]),
            TimelineId(4),
            row,
            row,
            Some(row + 1),
            Some(tid),
        )
    };
    store.keys = vec![
        make_key(0, 1),
        make_key(1, 2),
        make_key(2, 1),
        make_key(3, 1),
        make_key(4, 1),
    ];
    store.kinds = vec![
        EventKind::RegisterCheckpoint,
        EventKind::RegisterCheckpoint,
        EventKind::RegisterDelta,
        EventKind::RegisterDelta,
        EventKind::RegisterCheckpoint,
    ];
    store.instructions.clear();
    store.observations.clear();
    for row in [0_usize, 1, 4] {
        for slot in 0..RegisterSlot::COUNT {
            store.observations.push(RegisterObservationRow {
                owner_row: row,
                slot: slot as u8,
                captured_width: 8,
                access: RegisterAccess::Checkpoint,
                value: row as u64 * 100 + slot as u64,
                provenance: Provenance::Captured,
            });
        }
    }
    store.observations.push(RegisterObservationRow {
        owner_row: 2,
        slot: 0,
        captured_width: 8,
        access: RegisterAccess::Delta,
        value: 77,
        provenance: Provenance::Captured,
    });
    store.observations.push(RegisterObservationRow {
        owner_row: 3,
        slot: 1,
        captured_width: 8,
        access: RegisterAccess::Delta,
        value: 88,
        provenance: Provenance::Damaged,
    });
    store.observations.sort_by_key(|row| row.owner_row);
    let delta_key = store.keys[2].clone();
    let bad_key = store.keys[3].clone();
    let restored_key = store.keys[4].clone();
    let other_key = store.keys[1].clone();
    let replay = RegisterReplay::new(Arc::new(store)).unwrap();
    assert_eq!(
        replay
            .state_at(&delta_key)
            .unwrap()
            .after
            .cell(RegisterSlot::X0)
            .value,
        Some(77)
    );
    assert_eq!(
        replay
            .state_at(&other_key)
            .unwrap()
            .after
            .cell(RegisterSlot::X0)
            .value,
        Some(100)
    );
    assert_eq!(
        replay
            .state_at(&bad_key)
            .unwrap()
            .after
            .cell(RegisterSlot::X0)
            .provenance,
        Provenance::Damaged
    );
    assert_eq!(
        replay
            .state_at(&restored_key)
            .unwrap()
            .after
            .cell(RegisterSlot::X0)
            .value,
        Some(400)
    );
    assert_eq!(
        replay
            .state_at(&restored_key)
            .unwrap()
            .after
            .cell(RegisterSlot::X0)
            .provenance,
        Provenance::Captured
    );
}

#[test]
fn production_normalized_qtrb_store_replays_registers() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures/sessions/valid-mixed");
    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture),
        OpenPolicy::default(),
        &CountingGuard::default(),
    )
    .unwrap();
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .unwrap();
    let store = Arc::new(
        IndexBuilder::build(source, &BuildOptions::default(), &CountingGuard::default()).unwrap(),
    );
    let instruction_row = store.instruction_rows()[0].owner_row;
    let key = store.event_key(instruction_row).unwrap();
    let state = RegisterReplay::new(store).unwrap().state_at(&key).unwrap();
    assert_eq!(state.key, key);
    assert!(state.before.cell(RegisterSlot::X0).value.is_some());
}
