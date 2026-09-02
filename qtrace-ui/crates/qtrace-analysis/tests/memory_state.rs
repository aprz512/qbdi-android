use std::{ops::Range, sync::Arc};

use qtrace_analysis::MemoryAnalyzer;
use qtrace_provider::{
    ArtifactDigest, BudgetDimension, CaptureBytes, EventKey, EventKind, MemoryDirection,
    OperationAbort, Provenance, ProviderCapabilities, RegisterSlot, TimelineId, WorkDelta,
    WorkGuard,
};
use qtrace_store::{
    AuthorizedPath, BuildOptions, DefinitionRow, IndexBuilder, IndexError, InstructionRow,
    MemoryRow, ModuleRow, NormalizedBulkView, NormalizedContentIdentity, NormalizedLayoutIdentity,
    NormalizedPostingEstimate, NormalizedPostingQuery, NormalizedSourceFormat, OpenPolicy,
    RegisterObservationRow, SemanticRow, SessionLoader, TraceStoreView,
};

struct MemoryStore {
    keys: Vec<EventKey>,
    rows: Vec<MemoryRow>,
    before: Vec<Vec<u8>>,
    after: Vec<Vec<u8>>,
    capabilities: ProviderCapabilities,
    completeness: Vec<qtrace_store::CompletenessRow>,
}

fn memory_row(
    owner_row: usize,
    address: u64,
    size: u32,
    direction: MemoryDirection,
    value: u64,
) -> MemoryRow {
    serde_json::from_value(serde_json::json!({
        "owner_row": owner_row, "module": null, "relative_pc": 0,
        "address": address, "end_exclusive": address + u64::from(size), "size": size,
        "direction": direction, "metadata_available": true, "flags": 0, "value": value,
        "before_blob": owner_row, "after_blob": owner_row
    }))
    .unwrap()
}

impl MemoryStore {
    fn overlapping_write_then_read() -> Self {
        let key = |row| {
            EventKey::new(
                ArtifactDigest::new([0x24; 32]),
                TimelineId(2),
                row,
                row,
                Some(row + 1),
                Some(9),
            )
        };
        Self {
            keys: vec![key(0), key(1)],
            rows: vec![
                memory_row(0, 0x2000, 8, MemoryDirection::Write, 0x0807_0605_0403_0201),
                memory_row(1, 0x2002, 4, MemoryDirection::Read, 0x0605_0403),
            ],
            before: vec![
                serde_json::to_vec(&CaptureBytes::NotCaptured).unwrap(),
                serde_json::to_vec(&CaptureBytes::Captured(vec![3, 4, 5, 6])).unwrap(),
            ],
            after: vec![
                serde_json::to_vec(&CaptureBytes::Captured(vec![1, 2, 3, 4, 5, 6, 7, 8])).unwrap(),
                serde_json::to_vec(&CaptureBytes::NotCaptured).unwrap(),
            ],
            capabilities: ProviderCapabilities {
                global_ordering: true,
                per_thread_ordering: true,
                full_register_checkpoint: false,
                register_read_write_observation: false,
                memory_metadata: true,
                memory_before_after: true,
                lifecycle: false,
                signal_and_termination: false,
                loss_and_damage_ranges: true,
            },
            completeness: vec![],
        }
    }

    fn repeated_writes(count: usize) -> Self {
        let mut store = Self::overlapping_write_then_read();
        store.keys = (0..count)
            .map(|row| {
                EventKey::new(
                    ArtifactDigest::new([0x25; 32]),
                    TimelineId(2),
                    row as u64,
                    row as u64,
                    Some(row as u64),
                    Some(9),
                )
            })
            .collect();
        store.rows = (0..count)
            .map(|owner_row| {
                memory_row(
                    owner_row,
                    0x3000,
                    1,
                    MemoryDirection::Write,
                    owner_row as u64,
                )
            })
            .collect();
        let not_captured = serde_json::to_vec(&CaptureBytes::NotCaptured).unwrap();
        store.before = vec![not_captured; count];
        store.after = (0..count)
            .map(|row| serde_json::to_vec(&CaptureBytes::Captured(vec![row as u8])).unwrap())
            .collect();
        store
    }
}

impl TraceStoreView for MemoryStore {
    fn event_count(&self) -> usize {
        self.keys.len()
    }
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        Ok(self.keys.get(row).cloned())
    }
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        Ok((row < self.keys.len()).then_some(EventKind::Memory))
    }
    fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        Ok((row < self.keys.len()).then_some(Provenance::Captured))
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn instruction(&self, _: usize) -> Option<InstructionRow> {
        None
    }
    fn memory(&self, event_row: usize) -> Option<MemoryRow> {
        self.rows
            .iter()
            .find(|row| row.owner_row == event_row)
            .copied()
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
    fn blob_bytes(&self, _: u32) -> Result<&[u8], IndexError> {
        Ok(&[])
    }
    fn memory_before_bytes(&self, row: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(self.before.get(row).map(Vec::as_slice))
    }
    fn memory_after_bytes(&self, row: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(self.after.get(row).map(Vec::as_slice))
    }
    fn module(&self, _: u32) -> Option<&ModuleRow> {
        None
    }
    fn definition(&self, _: u32) -> Option<&DefinitionRow> {
        None
    }
    fn register_observations(&self, _: usize) -> Vec<RegisterObservationRow> {
        vec![]
    }
    fn completeness(&self) -> &[qtrace_store::CompletenessRow] {
        &self.completeness
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
        Ok(vec![])
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
    fn memory_overlaps(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        Ok(self
            .rows
            .iter()
            .filter(|row| row.address < end && start < row.end_exclusive)
            .map(|row| row.owner_row)
            .collect())
    }
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize> {
        self.keys.iter().position(|candidate| candidate == key)
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.event_key(row)
    }
}

impl NormalizedBulkView for MemoryStore {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity {
        NormalizedLayoutIdentity::new(2, [0; 32])
    }
    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        NormalizedContentIdentity::new([2; 32])
    }
    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        NormalizedSourceFormat::Qtrb
    }
    fn module_rows(&self) -> &[ModuleRow] {
        &[]
    }
    fn definition_rows(&self) -> &[DefinitionRow] {
        &[]
    }
    fn instruction_rows(&self) -> &[InstructionRow] {
        &[]
    }
    fn memory_rows(&self) -> &[MemoryRow] {
        &self.rows
    }
    fn semantic_rows(&self) -> &[SemanticRow] {
        &[]
    }
    fn register_observation_rows(&self) -> &[RegisterObservationRow] {
        &[]
    }
    fn string_count(&self) -> usize {
        0
    }
    fn blob_count(&self) -> usize {
        self.before.len() + self.after.len()
    }
    fn bounded_row_estimate(
        &self,
        query: NormalizedPostingQuery<'_>,
        max: usize,
        _: &dyn WorkGuard,
    ) -> Result<NormalizedPostingEstimate, IndexError> {
        let rows = match query {
            NormalizedPostingQuery::Memory {
                start,
                end_exclusive,
            } => self.memory_overlaps(start, end_exclusive)?,
            _ => vec![],
        };
        if rows.len() > max {
            return Err(OperationAbort::budget_exceeded(
                BudgetDimension::Rows,
                max as u64,
                rows.len() as u64,
            )
            .into());
        }
        Ok(NormalizedPostingEstimate::new(
            rows.len(),
            rows.len() as u64,
        ))
    }
    fn bounded_row_count(
        &self,
        query: NormalizedPostingQuery<'_>,
        max: usize,
        guard: &dyn WorkGuard,
    ) -> Result<usize, IndexError> {
        Ok(self.bounded_row_estimate(query, max, guard)?.rows)
    }
    fn bounded_rows(
        &self,
        query: NormalizedPostingQuery<'_>,
        _: usize,
        _: &dyn WorkGuard,
    ) -> Result<Vec<usize>, IndexError> {
        match query {
            NormalizedPostingQuery::Memory {
                start,
                end_exclusive,
            } => self.memory_overlaps(start, end_exclusive),
            _ => Ok(vec![]),
        }
    }
}

#[test]
fn overlap_before_range_start_contributes_last_written_but_read_does_not_write() {
    let store = Arc::new(MemoryStore::overlapping_write_then_read());
    let target = store.keys[1].clone();
    let analyzer = MemoryAnalyzer::new(store).unwrap();
    let state = analyzer
        .state_at(
            &target,
            Range {
                start: 0x2002,
                end: 0x2006,
            },
        )
        .unwrap();

    assert_eq!(
        state
            .observed
            .iter()
            .map(|byte| byte.value)
            .collect::<Vec<_>>(),
        vec![Some(3), Some(4), Some(5), Some(6)]
    );
    assert_eq!(
        state
            .before
            .iter()
            .map(|byte| byte.value)
            .collect::<Vec<_>>(),
        vec![Some(3), Some(4), Some(5), Some(6)]
    );
    assert_eq!(
        state
            .last_written
            .iter()
            .map(|byte| byte.value)
            .collect::<Vec<_>>(),
        vec![Some(3), Some(4), Some(5), Some(6)]
    );
    assert!(
        state
            .last_written
            .iter()
            .all(|byte| byte.evidence.as_ref().unwrap().direction == MemoryDirection::Write)
    );
}

#[test]
fn read_only_target_is_never_promoted_to_last_written() {
    let mut store = MemoryStore::overlapping_write_then_read();
    store.rows.remove(0);
    let store = Arc::new(store);
    let target = store.keys[1].clone();
    let analyzer = MemoryAnalyzer::new(store).unwrap();
    let state = analyzer.state_at(&target, 0x2002..0x2006).unwrap();

    assert!(state.observed.iter().all(|byte| byte.value.is_some()));
    assert!(state.last_written.iter().all(|byte| byte.value.is_none()));
}

#[test]
fn partial_capture_keeps_uncovered_bytes_unknown_and_after_is_separate() {
    let mut store = MemoryStore::overlapping_write_then_read();
    store.before[1] = serde_json::to_vec(&CaptureBytes::Captured(vec![30, 40])).unwrap();
    store.rows[1] = memory_row(1, 0x2002, 4, MemoryDirection::Write, 0x0605_0403);
    store.after[1] = serde_json::to_vec(&CaptureBytes::Captured(vec![31, 41])).unwrap();
    let key = store.keys[1].clone();
    let state = MemoryAnalyzer::new(Arc::new(store))
        .unwrap()
        .state_at(&key, 0x2002..0x2008)
        .unwrap();
    assert_eq!(
        state.before.iter().map(|b| b.value).collect::<Vec<_>>(),
        vec![Some(30), Some(40), Some(5), Some(6), Some(7), Some(8)]
    );
    assert_eq!(
        state.after.iter().map(|b| b.value).collect::<Vec<_>>(),
        vec![Some(31), Some(41), Some(5), Some(6), Some(7), Some(8)]
    );
}

#[test]
fn unavailable_capture_marks_only_covered_bytes_damaged() {
    let mut store = MemoryStore::overlapping_write_then_read();
    store.before[1] = serde_json::to_vec(&CaptureBytes::Unavailable).unwrap();
    let key = store.keys[1].clone();
    let state = MemoryAnalyzer::new(Arc::new(store))
        .unwrap()
        .state_at(&key, 0x2000..0x2008)
        .unwrap();
    assert!(
        state.before[2..6]
            .iter()
            .all(|byte| byte.provenance == Provenance::Damaged)
    );
    assert_eq!(state.before[0].value, Some(1));
    assert_eq!(state.before[7].value, Some(8));
}

#[test]
fn history_uses_overlap_index_and_preserves_cross_thread_evidence_when_globally_ordered() {
    let mut store = MemoryStore::overlapping_write_then_read();
    store.keys[0].tid = Some(77);
    let target = store.keys[1].clone();
    let analyzer = MemoryAnalyzer::new(Arc::new(store)).unwrap();
    let history = analyzer.history(&target, 0x2002..0x2006).unwrap();
    assert_eq!(history[0].address, 0x2000);
    assert_eq!(history[0].tid, Some(77));
    let state = analyzer.state_at(&target, 0x2002..0x2006).unwrap();
    assert_eq!(state.last_written[0].value, Some(3));
    assert_eq!(
        state.last_written[0].evidence.as_ref().unwrap().tid,
        Some(77)
    );
}

#[test]
fn unordered_cross_thread_write_makes_competing_bytes_damaged_regardless_of_row_order() {
    let mut store = MemoryStore::overlapping_write_then_read();
    store.capabilities.global_ordering = false;
    store.keys[0].tid = Some(77);
    let target = store.keys[1].clone();
    let state = MemoryAnalyzer::new(Arc::new(store))
        .unwrap()
        .state_at(&target, 0x2002..0x2006)
        .unwrap();
    assert!(
        state
            .last_written
            .iter()
            .all(|byte| byte.provenance == Provenance::Damaged)
    );
    assert!(
        state
            .last_written
            .iter()
            .all(|byte| byte.evidence.as_ref().unwrap().tid == Some(77))
    );
}

#[test]
fn address_damage_is_per_byte_and_a_later_captured_write_recovers_it() {
    let mut store = MemoryStore::overlapping_write_then_read();
    store.completeness.push(qtrace_store::CompletenessRow {
        domain: qtrace_provider::RangeDomain::MemoryAddresses,
        bounds: qtrace_provider::RangeBounds::HalfOpen {
            start: 0x2002,
            end_exclusive: 0x2004,
        },
        provenance: Provenance::Damaged,
        cause: qtrace_provider::CompletenessCause::Lost,
    });
    let target = store.keys[1].clone();
    let state = MemoryAnalyzer::new(Arc::new(store))
        .unwrap()
        .state_at(&target, 0x2002..0x2006)
        .unwrap();
    assert_eq!(state.last_written[0].value, Some(3));
    assert_eq!(state.last_written[0].provenance, Provenance::Derived);
}

struct RejectGuard(OperationAbort);
impl WorkGuard for RejectGuard {
    fn consume(&self, _: WorkDelta) -> Result<(), OperationAbort> {
        Err(self.0.clone())
    }
}

#[derive(Default)]
struct CheckpointCancelGuard {
    nodes: std::sync::atomic::AtomicU64,
    max_delta: std::sync::atomic::AtomicU64,
}
impl WorkGuard for CheckpointCancelGuard {
    fn consume(&self, delta: WorkDelta) -> Result<(), OperationAbort> {
        self.max_delta
            .fetch_max(delta.nodes, std::sync::atomic::Ordering::Relaxed);
        let total = self
            .nodes
            .fetch_add(delta.nodes, std::sync::atomic::Ordering::Relaxed)
            + delta.nodes;
        if total > 4_096 {
            Err(OperationAbort::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[test]
fn hard_range_history_and_service_work_budgets_are_stable() {
    let store = Arc::new(MemoryStore::overlapping_write_then_read());
    let key = store.keys[1].clone();
    let analyzer = MemoryAnalyzer::new(store).unwrap();
    assert_eq!(
        analyzer
            .state_at(&key, 0..(1024 * 1024 + 1))
            .unwrap_err()
            .code(),
        "analysis.budget_exceeded"
    );
    assert!(
        analyzer
            .state_at(&key, u64::MAX..u64::MAX)
            .unwrap()
            .observed
            .is_empty()
    );
    let budget = RejectGuard(OperationAbort::budget_exceeded(
        BudgetDimension::Nodes,
        0,
        1,
    ));
    assert_eq!(
        analyzer
            .state_at_with_guard(&key, 0x2002..0x2006, &budget)
            .unwrap_err()
            .code(),
        "analysis.budget_exceeded"
    );
    let cancelled = RejectGuard(OperationAbort::Cancelled);
    assert_eq!(
        analyzer
            .state_at_with_guard(&key, 0x2002..0x2006, &cancelled)
            .unwrap_err()
            .code(),
        "job.cancelled"
    );
}

#[test]
fn large_result_checks_cancellation_at_four_kibibyte_work_boundaries() {
    let store = Arc::new(MemoryStore::overlapping_write_then_read());
    let key = store.keys[1].clone();
    let analyzer = MemoryAnalyzer::new(store).unwrap();
    let guard = CheckpointCancelGuard::default();
    assert_eq!(
        analyzer
            .state_at_with_guard(&key, 0x4000..0x6001, &guard)
            .unwrap_err()
            .code(),
        "job.cancelled"
    );
    assert!(guard.max_delta.load(std::sync::atomic::Ordering::Relaxed) <= 4_096);
}

#[test]
fn history_accepts_exactly_ten_thousand_rows_and_rejects_one_more() {
    let exact = Arc::new(MemoryStore::repeated_writes(10_000));
    let exact_key = exact.keys[9_999].clone();
    assert_eq!(
        MemoryAnalyzer::new(exact)
            .unwrap()
            .history(&exact_key, 0x3000..0x3001)
            .unwrap()
            .len(),
        10_000
    );

    let over = Arc::new(MemoryStore::repeated_writes(10_001));
    let over_key = over.keys[10_000].clone();
    assert_eq!(
        MemoryAnalyzer::new(over)
            .unwrap()
            .history(&over_key, 0x3000..0x3001)
            .unwrap_err()
            .code(),
        "analysis.budget_exceeded"
    );
}

struct AllowAll;
impl WorkGuard for AllowAll {
    fn consume(&self, _: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

#[test]
fn production_normalized_qtrb_store_uses_real_overlap_posting() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures/sessions/valid-mixed");
    let session = SessionLoader::open_report(
        AuthorizedPath::new(fixture),
        OpenPolicy::default(),
        &AllowAll,
    )
    .unwrap();
    let source = session
        .artifacts()
        .iter()
        .find(|artifact| artifact.local_path().ends_with("main.trace.bin"))
        .unwrap();
    let store = Arc::new(IndexBuilder::build(source, &BuildOptions::default(), &AllowAll).unwrap());
    let row = store.memory_rows()[0];
    let key = store.event_key(row.owner_row).unwrap();
    let analyzer = MemoryAnalyzer::new(store).unwrap();
    let history = analyzer
        .history(&key, row.address + 1..row.end_exclusive)
        .unwrap();
    assert!(
        history
            .iter()
            .any(|item| item.address == row.address && item.size == row.size)
    );
}
