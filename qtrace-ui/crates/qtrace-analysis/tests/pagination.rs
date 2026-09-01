use std::{
    sync::{
        Arc, Barrier, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use qtrace_analysis::{
    AddressRange, CompletenessStatus, EventFilter, MAX_DISCONTINUITY_PAYLOAD_BYTES,
    MAX_DISCONTINUITY_TOTAL_BYTES, PageCursor, QueryContext, TimelineProjection, TimelineRow,
    query_events,
};
use qtrace_provider::{
    ArtifactDigest, CompletenessCause, CompletenessRange, Discontinuity, DiscontinuityCause,
    EventKey, EventKind, EventPayload, Provenance, ProviderCapabilities, RangeBounds, RangeDomain,
    TimelineId,
};
use qtrace_store::{
    CompletenessRow, DefinitionRow, IndexError, InstructionRow, MemoryRow, ModuleRow,
    NormalizedBulkView, NormalizedContentIdentity, NormalizedLayoutIdentity,
    NormalizedPostingQuery, NormalizedSourceFormat, RegisterObservationRow, SemanticRow,
    TraceStoreView,
};
use sha2::Digest;

struct CountingStore {
    keys: Vec<EventKey>,
    semantic: bool,
    release: (Mutex<bool>, Condvar),
    scan_progress: (Mutex<usize>, Condvar),
    event_key_calls: AtomicUsize,
    payload_calls: AtomicUsize,
    blob_calls: AtomicUsize,
    typed_lookup_calls: AtomicUsize,
    capabilities: ProviderCapabilities,
    completeness: Vec<CompletenessRow>,
    discontinuity_payload: Vec<u8>,
    semantics: Vec<SemanticRow>,
    oversized_blob: Option<Vec<u8>>,
    oversized_blob_after: Option<u32>,
    unblocked_scan_calls: usize,
    event_count_override: Option<usize>,
    discontinuity_rows: usize,
    cancel_discontinuity_posting: bool,
    posting_count_calls: AtomicUsize,
    posting_count_override: Option<usize>,
    posting_decode_calls: AtomicUsize,
    posting_decoded_rows: AtomicUsize,
    posting_decode_order: Mutex<Vec<&'static str>>,
    posting_count_abort: Option<qtrace_provider::BudgetDimension>,
    posting_decode_abort: Option<qtrace_provider::BudgetDimension>,
}

impl CountingStore {
    fn new(count: usize, middle_digest: u8, semantic: bool) -> Self {
        let mut keys = (0..count)
            .map(|ordinal| {
                EventKey::new(
                    ArtifactDigest::new([9; 32]),
                    TimelineId(1),
                    ordinal as u64,
                    ordinal as u64 * 8,
                    Some(ordinal as u64 + 1),
                    Some(if ordinal % 2 == 0 { 7 } else { 8 }),
                )
            })
            .collect::<Vec<_>>();
        if count > 2 {
            keys[count / 2].artifact = ArtifactDigest::new([middle_digest; 32]);
        }
        let evidence = CompletenessRange::captured_sequence_with_cause(
            3,
            4,
            Provenance::Damaged,
            CompletenessCause::Lost,
        )
        .unwrap();
        Self {
            keys,
            semantic,
            release: (Mutex::new(!semantic), Condvar::new()),
            scan_progress: (Mutex::new(0), Condvar::new()),
            event_key_calls: AtomicUsize::new(0),
            payload_calls: AtomicUsize::new(0),
            blob_calls: AtomicUsize::new(0),
            typed_lookup_calls: AtomicUsize::new(0),
            capabilities: ProviderCapabilities::qtrb_register_observations(),
            completeness: vec![
                CompletenessRow {
                    domain: RangeDomain::CapturedSequence,
                    bounds: RangeBounds::InclusiveSequence {
                        first: 1,
                        last: count.max(1) as u64,
                    },
                    provenance: Provenance::Captured,
                    cause: CompletenessCause::Retained,
                },
                CompletenessRow {
                    domain: RangeDomain::CapturedSequence,
                    bounds: RangeBounds::InclusiveSequence { first: 3, last: 4 },
                    provenance: Provenance::Damaged,
                    cause: CompletenessCause::Lost,
                },
            ],
            discontinuity_payload: serde_json::to_vec(&EventPayload::Discontinuity(
                Discontinuity {
                    cause: DiscontinuityCause::Truncation,
                    evidence,
                },
            ))
            .unwrap(),
            semantics: if semantic {
                (0..count)
                    .map(|owner_row| SemanticRow {
                        owner_row,
                        category: None,
                        name: 0,
                        detail_blob: owner_row as u32,
                    })
                    .collect()
            } else {
                Vec::new()
            },
            oversized_blob: None,
            oversized_blob_after: None,
            unblocked_scan_calls: 1,
            event_count_override: None,
            discontinuity_rows: usize::from(!semantic),
            cancel_discontinuity_posting: false,
            posting_count_calls: AtomicUsize::new(0),
            posting_count_override: None,
            posting_decode_calls: AtomicUsize::new(0),
            posting_decoded_rows: AtomicUsize::new(0),
            posting_decode_order: Mutex::new(Vec::new()),
            posting_count_abort: None,
            posting_decode_abort: None,
        }
    }

    fn release_semantic_scan(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }

    fn wait_for_semantic_calls(&self, calls: usize) {
        let progress = self.scan_progress.0.lock().unwrap();
        let (progress, result) = self
            .scan_progress
            .1
            .wait_timeout_while(progress, Duration::from_secs(2), |progress| {
                *progress < calls
            })
            .unwrap();
        assert!(
            !result.timed_out(),
            "semantic scan reached only {} calls",
            *progress
        );
    }

    fn rows(&self, predicate: impl Fn(usize, &EventKey) -> bool) -> Vec<usize> {
        self.keys
            .iter()
            .enumerate()
            .filter_map(|(row, key)| predicate(row, key).then_some(row))
            .collect()
    }

    fn posting_rows(&self, query: NormalizedPostingQuery<'_>) -> Result<Vec<usize>, IndexError> {
        match query {
            NormalizedPostingQuery::Tids(values) => self.rows_for_tids(values),
            NormalizedPostingQuery::Kinds(values) => self.rows_of_kinds(values),
            NormalizedPostingQuery::Modules(values) => self.rows_for_modules(values),
            NormalizedPostingQuery::Sequence {
                start,
                end_exclusive,
            } => self.rows_for_sequence_range(start, end_exclusive),
            NormalizedPostingQuery::ModulePc {
                module,
                start,
                end_exclusive,
            } => self.rows_for_module_pc_range(module, start, end_exclusive),
            NormalizedPostingQuery::Definitions(values) => self.rows_for_definitions(values),
            NormalizedPostingQuery::Registers(values) => {
                let mut rows = Vec::new();
                for slot in values {
                    rows.extend(self.rows_observing_register(*slot)?);
                }
                Ok(rows)
            }
            NormalizedPostingQuery::SemanticCategories(values) => {
                self.rows_for_semantic_categories(values)
            }
            NormalizedPostingQuery::SemanticNames(values) => self.rows_for_semantic_names(values),
            NormalizedPostingQuery::Memory {
                start,
                end_exclusive,
            } => self.memory_overlaps(start, end_exclusive),
        }
    }

    fn posting_count(&self, query: NormalizedPostingQuery<'_>) -> usize {
        match query {
            NormalizedPostingQuery::Tids(values) => self
                .keys
                .iter()
                .filter(|key| key.tid.is_some_and(|tid| values.contains(&tid)))
                .count(),
            NormalizedPostingQuery::Kinds(values) => (0..self.keys.len())
                .filter(|row| {
                    let kind = if self.semantic {
                        EventKind::SemanticCall
                    } else if row + self.discontinuity_rows >= self.keys.len() {
                        EventKind::Discontinuity
                    } else {
                        EventKind::OpaqueOptional
                    };
                    values.contains(&kind)
                })
                .count(),
            NormalizedPostingQuery::Sequence {
                start,
                end_exclusive,
            } => self
                .keys
                .iter()
                .filter(|key| {
                    key.sequence
                        .is_some_and(|sequence| start <= sequence && sequence < end_exclusive)
                })
                .count(),
            NormalizedPostingQuery::Modules(_)
            | NormalizedPostingQuery::ModulePc { .. }
            | NormalizedPostingQuery::Definitions(_)
            | NormalizedPostingQuery::Registers(_)
            | NormalizedPostingQuery::SemanticCategories(_)
            | NormalizedPostingQuery::SemanticNames(_)
            | NormalizedPostingQuery::Memory { .. } => 0,
        }
    }

    fn posting_label(query: NormalizedPostingQuery<'_>) -> &'static str {
        match query {
            NormalizedPostingQuery::Tids(_) => "tids",
            NormalizedPostingQuery::Kinds(_) => "kinds",
            NormalizedPostingQuery::Modules(_) => "modules",
            NormalizedPostingQuery::Sequence { .. } => "sequence",
            NormalizedPostingQuery::ModulePc { .. } => "module_pc",
            NormalizedPostingQuery::Definitions(_) => "definitions",
            NormalizedPostingQuery::Registers(_) => "registers",
            NormalizedPostingQuery::SemanticCategories(_) => "semantic_categories",
            NormalizedPostingQuery::SemanticNames(_) => "semantic_names",
            NormalizedPostingQuery::Memory { .. } => "memory",
        }
    }
}

impl TraceStoreView for CountingStore {
    fn event_count(&self) -> usize {
        self.event_count_override.unwrap_or(self.keys.len())
    }
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.event_key_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.keys.get(row).cloned())
    }
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        Ok((row < self.keys.len()).then_some(if self.semantic {
            EventKind::SemanticCall
        } else if row + self.discontinuity_rows >= self.keys.len() {
            EventKind::Discontinuity
        } else {
            EventKind::OpaqueOptional
        }))
    }
    fn provenance(&self, row: usize) -> Result<Option<Provenance>, IndexError> {
        Ok((row < self.keys.len()).then_some(Provenance::Captured))
    }
    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }
    fn instruction(&self, _row: usize) -> Option<InstructionRow> {
        self.typed_lookup_calls.fetch_add(1, Ordering::Relaxed);
        None
    }
    fn memory(&self, _row: usize) -> Option<MemoryRow> {
        self.typed_lookup_calls.fetch_add(1, Ordering::Relaxed);
        None
    }
    fn semantic(&self, row: usize) -> Option<SemanticRow> {
        self.typed_lookup_calls.fetch_add(1, Ordering::Relaxed);
        (self.semantic && row < self.keys.len()).then_some(SemanticRow {
            owner_row: row,
            category: None,
            name: 0,
            detail_blob: row as u32,
        })
    }
    fn payload_bytes(&self, row: usize) -> Result<&[u8], IndexError> {
        self.payload_calls.fetch_add(1, Ordering::Relaxed);
        Ok(
            if !self.semantic && row + self.discontinuity_rows >= self.keys.len() {
                &self.discontinuity_payload
            } else {
                b"{}"
            },
        )
    }
    fn string_bytes(&self, _id: u32) -> Result<&[u8], IndexError> {
        Ok(b"event")
    }
    fn blob_bytes(&self, id: u32) -> Result<&[u8], IndexError> {
        let detail: &[u8] = if id == 0 {
            b"detail matches needle"
        } else {
            b"detail matches needle future"
        };
        self.blob_calls.fetch_add(1, Ordering::Relaxed);
        let call = {
            let mut progress = self.scan_progress.0.lock().unwrap();
            *progress += 1;
            self.scan_progress.1.notify_all();
            *progress
        };
        if call > self.unblocked_scan_calls {
            let mut released = self.release.0.lock().unwrap();
            while !*released {
                released = self.release.1.wait(released).unwrap();
            }
        }
        if let Some(blob) = &self.oversized_blob
            && self.oversized_blob_after.is_none_or(|first| id >= first)
        {
            return Ok(blob);
        }
        Ok(detail)
    }
    fn memory_before_bytes(&self, _row: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(None)
    }
    fn memory_after_bytes(&self, _row: usize) -> Result<Option<&[u8]>, IndexError> {
        Ok(None)
    }
    fn module(&self, _id: u32) -> Option<&ModuleRow> {
        None
    }
    fn definition(&self, _id: u32) -> Option<&DefinitionRow> {
        None
    }
    fn register_observations(&self, _row: usize) -> Vec<RegisterObservationRow> {
        self.typed_lookup_calls.fetch_add(1, Ordering::Relaxed);
        vec![]
    }
    fn completeness(&self) -> &[CompletenessRow] {
        &self.completeness
    }
    fn rows_for_timeline(&self, timeline: u64) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|_, key| key.timeline.0 == timeline))
    }
    fn rows_for_tids(&self, tids: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|_, key| key.tid.is_some_and(|tid| tids.contains(&tid))))
    }
    fn rows_for_sequence_range(&self, start: u64, end: u64) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|_, key| {
            key.sequence
                .is_some_and(|sequence| start <= sequence && sequence < end)
        }))
    }
    fn rows_of_kinds(&self, kinds: &[EventKind]) -> Result<Vec<usize>, IndexError> {
        Ok(self.rows(|row, _| kinds.contains(&self.event_kind(row).unwrap().unwrap())))
    }
    fn rows_for_modules(&self, _modules: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_for_module_pc_range(
        &self,
        _module: u32,
        _start: u64,
        _end: u64,
    ) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_for_definitions(&self, _definitions: &[u32]) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_observing_register(
        &self,
        _slot: qtrace_provider::RegisterSlot,
    ) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
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
    fn rows_for_semantic_categories(
        &self,
        _categories: &[&[u8]],
    ) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn rows_for_semantic_names(&self, _names: &[&[u8]]) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn memory_overlaps(&self, _start: u64, _end: u64) -> Result<Vec<usize>, IndexError> {
        Ok(vec![])
    }
    fn row_for_source_key(&self, key: &EventKey) -> Option<usize> {
        self.keys.iter().position(|candidate| candidate == key)
    }
    fn source_key_for_row(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.event_key(row)
    }
}

struct CancelContext;

impl qtrace_provider::WorkGuard for CancelContext {
    fn consume(
        &self,
        _delta: qtrace_provider::WorkDelta,
    ) -> Result<(), qtrace_provider::OperationAbort> {
        Err(qtrace_provider::OperationAbort::Cancelled)
    }
}

struct CancelDuringContext {
    armed: AtomicBool,
    checkpoints: AtomicUsize,
}

struct ScopeOnlyGuard {
    scopes: AtomicUsize,
    active: AtomicBool,
}

impl qtrace_provider::WorkGuard for ScopeOnlyGuard {
    fn consume(
        &self,
        delta: qtrace_provider::WorkDelta,
    ) -> Result<(), qtrace_provider::OperationAbort> {
        if delta.resident_bytes != 0 {
            return Err(qtrace_provider::OperationAbort::budget_exceeded(
                qtrace_provider::BudgetDimension::ResidentBytes,
                0,
                delta.resident_bytes,
            ));
        }
        Ok(())
    }

    fn begin_allocation_scope(
        &self,
        _delta: qtrace_provider::WorkDelta,
        _allowed_slack: u64,
    ) -> Result<(), qtrace_provider::OperationAbort> {
        assert!(!self.active.swap(true, Ordering::SeqCst));
        self.scopes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn end_allocation_scope(&self) {
        assert!(self.active.swap(false, Ordering::SeqCst));
    }
}

struct AllocationCountGuard {
    allocations: AtomicUsize,
    checkpoints: AtomicUsize,
}

struct ResidentBudgetGuard {
    limit: usize,
    consumed: AtomicUsize,
    scopes: AtomicUsize,
    rejected_scope: AtomicUsize,
    requests: Mutex<Vec<usize>>,
}

impl ResidentBudgetGuard {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            consumed: AtomicUsize::new(0),
            scopes: AtomicUsize::new(0),
            rejected_scope: AtomicUsize::new(usize::MAX),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl qtrace_provider::WorkGuard for ResidentBudgetGuard {
    fn consume(
        &self,
        _delta: qtrace_provider::WorkDelta,
    ) -> Result<(), qtrace_provider::OperationAbort> {
        Ok(())
    }

    fn begin_allocation_scope(
        &self,
        delta: qtrace_provider::WorkDelta,
        _allowed_slack: u64,
    ) -> Result<(), qtrace_provider::OperationAbort> {
        let ordinal = self.scopes.fetch_add(1, Ordering::SeqCst);
        let bytes = usize::try_from(delta.resident_bytes).unwrap_or(usize::MAX);
        self.requests.lock().unwrap().push(bytes);
        let previous = self.consumed.fetch_add(bytes, Ordering::SeqCst);
        let consumed = previous.saturating_add(bytes);
        if consumed > self.limit {
            self.consumed.fetch_sub(bytes, Ordering::SeqCst);
            self.rejected_scope.store(ordinal, Ordering::SeqCst);
            return Err(qtrace_provider::OperationAbort::budget_exceeded(
                qtrace_provider::BudgetDimension::ResidentBytes,
                self.limit as u64,
                consumed as u64,
            ));
        }
        Ok(())
    }
}

impl qtrace_provider::WorkGuard for AllocationCountGuard {
    fn consume(
        &self,
        delta: qtrace_provider::WorkDelta,
    ) -> Result<(), qtrace_provider::OperationAbort> {
        if delta == qtrace_provider::WorkDelta::default() {
            self.checkpoints.fetch_add(1, Ordering::Relaxed);
        }
        if delta.resident_bytes != 0 {
            self.allocations.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn begin_allocation_scope(
        &self,
        delta: qtrace_provider::WorkDelta,
        _allowed_slack: u64,
    ) -> Result<(), qtrace_provider::OperationAbort> {
        if delta.resident_bytes != 0 {
            self.allocations.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl qtrace_provider::WorkGuard for CancelDuringContext {
    fn consume(
        &self,
        delta: qtrace_provider::WorkDelta,
    ) -> Result<(), qtrace_provider::OperationAbort> {
        if delta.rows != 0 {
            self.armed.store(true, Ordering::Release);
            if self.checkpoints.fetch_add(1, Ordering::Relaxed) == 1 {
                return Err(qtrace_provider::OperationAbort::Cancelled);
            }
        }
        Ok(())
    }
}

impl NormalizedBulkView for CountingStore {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity {
        NormalizedLayoutIdentity::new(2, [1; 32])
    }

    fn normalized_content_identity(&self) -> NormalizedContentIdentity {
        let mut digest = sha2::Sha256::new();
        for key in &self.keys {
            sha2::Digest::update(&mut digest, key.artifact.as_bytes());
        }
        NormalizedContentIdentity::new(sha2::Digest::finalize(digest).into())
    }

    fn normalized_source_format(&self) -> NormalizedSourceFormat {
        NormalizedSourceFormat::Flight
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
        &[]
    }
    fn semantic_rows(&self) -> &[SemanticRow] {
        &self.semantics
    }
    fn register_observation_rows(&self) -> &[RegisterObservationRow] {
        &[]
    }
    fn string_count(&self) -> usize {
        1
    }
    fn blob_count(&self) -> usize {
        self.keys.len().max(1)
    }

    fn bounded_row_count(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn qtrace_provider::WorkGuard,
    ) -> Result<usize, IndexError> {
        self.posting_count_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(dimension) = self.posting_count_abort
            && matches!(query, NormalizedPostingQuery::Tids(_))
        {
            return Err(IndexError::from(
                qtrace_provider::OperationAbort::budget_exceeded(dimension, 7, 8),
            ));
        }
        guard.consume(qtrace_provider::WorkDelta::default())?;
        let count = match self.posting_count_override {
            Some(count) => count,
            None => self.posting_count(query),
        };
        if count > max_rows {
            return Err(IndexError::from(
                qtrace_provider::OperationAbort::budget_exceeded(
                    qtrace_provider::BudgetDimension::Rows,
                    max_rows as u64,
                    count as u64,
                ),
            ));
        }
        Ok(count)
    }

    fn bounded_rows(
        &self,
        query: NormalizedPostingQuery<'_>,
        max_rows: usize,
        guard: &dyn qtrace_provider::WorkGuard,
    ) -> Result<Vec<usize>, IndexError> {
        if let Some(dimension) = self.posting_decode_abort
            && matches!(query, NormalizedPostingQuery::Tids(_))
        {
            return Err(IndexError::from(
                qtrace_provider::OperationAbort::budget_exceeded(dimension, 7, 8),
            ));
        }
        if self.cancel_discontinuity_posting
            && matches!(
                query,
                NormalizedPostingQuery::Kinds(kinds)
                    if kinds.contains(&EventKind::Discontinuity)
            )
        {
            return Err(IndexError::from(qtrace_provider::OperationAbort::Cancelled));
        }
        let label = Self::posting_label(query);
        let count = self.posting_count(query);
        guard.consume(qtrace_provider::WorkDelta {
            rows: count as u64,
            ..qtrace_provider::WorkDelta::default()
        })?;
        let rows = self.posting_rows(query)?;
        assert!(rows.len() <= max_rows, "mock posting exceeded test budget");
        self.posting_decode_calls.fetch_add(1, Ordering::Relaxed);
        self.posting_decoded_rows
            .fetch_add(rows.len(), Ordering::Relaxed);
        self.posting_decode_order.lock().unwrap().push(label);
        Ok(rows)
    }
}

fn projection(store: Arc<CountingStore>, filter: EventFilter) -> TimelineProjection {
    TimelineProjection::new(Arc::new(QueryContext::new(store).unwrap()), filter).unwrap()
}

fn context_error(store: CountingStore, message: &str) -> qtrace_analysis::AnalysisError {
    match QueryContext::new(Arc::new(store)) {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

fn context_error_with_guard(
    store: CountingStore,
    guard: &dyn qtrace_provider::WorkGuard,
    message: &str,
) -> qtrace_analysis::AnalysisError {
    match QueryContext::new_with_guard(Arc::new(store), guard) {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

#[test]
fn cursor_rejects_tampering_other_filters_and_same_shape_other_store_content() {
    let store_a = Arc::new(CountingStore::new(8, 1, false));
    let first_projection = projection(
        store_a.clone(),
        EventFilter {
            tids: vec![7],
            ..EventFilter::default()
        },
    );
    let first = query_events(&first_projection, None, 2).unwrap();
    let cursor = first.next.as_ref().unwrap();

    let normalized_equivalent = projection(
        store_a.clone(),
        EventFilter {
            tids: vec![7, 7],
            ..EventFilter::default()
        },
    );
    assert!(query_events(&normalized_equivalent, Some(cursor), 2).is_ok());

    let other_filter = projection(
        store_a,
        EventFilter {
            tids: vec![8],
            ..EventFilter::default()
        },
    );
    assert_eq!(
        query_events(&other_filter, Some(cursor), 2)
            .unwrap_err()
            .code(),
        "analysis.cursor_mismatch"
    );

    let other_store = projection(
        Arc::new(CountingStore::new(8, 2, false)),
        EventFilter {
            tids: vec![7],
            ..EventFilter::default()
        },
    );
    assert_eq!(
        query_events(&other_store, Some(cursor), 2)
            .unwrap_err()
            .code(),
        "analysis.cursor_mismatch"
    );

    let mut tampered = cursor.as_str().as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered = PageCursor::from_encoded(String::from_utf8(tampered).unwrap());
    assert_eq!(
        query_events(&first_projection, Some(&tampered), 2)
            .unwrap_err()
            .code(),
        "analysis.cursor_mismatch"
    );
}

#[test]
fn stable_cursor_traversal_has_no_duplicates_or_omissions_and_second_page_is_bounded() {
    let store = Arc::new(CountingStore::new(8_192, 9, false));
    let projection = projection(store.clone(), EventFilter::default());
    let planned_calls = store.event_key_calls.load(Ordering::Relaxed);

    let first = query_events(&projection, None, 37).unwrap();
    let before_second = store.event_key_calls.load(Ordering::Relaxed);
    let second = query_events(&projection, first.next.as_ref(), 37).unwrap();
    let second_page_calls = store.event_key_calls.load(Ordering::Relaxed) - before_second;
    assert!(
        second_page_calls <= 64,
        "second page performed {second_page_calls} key lookups after {planned_calls} planning lookups"
    );
    assert_eq!(second.rows.first().unwrap().key().record_ordinal, 37);

    let mut ordinals = first
        .rows
        .into_iter()
        .map(|row| row.key().record_ordinal)
        .collect::<Vec<_>>();
    ordinals.extend(second.rows.into_iter().map(|row| row.key().record_ordinal));
    let mut next = second.next;
    while let Some(cursor) = next {
        let page = query_events(&projection, Some(&cursor), 37).unwrap();
        ordinals.extend(page.rows.into_iter().map(|row| row.key().record_ordinal));
        next = page.next;
    }
    assert_eq!(ordinals, (0..8_192).collect::<Vec<_>>());
    assert_eq!(store.typed_lookup_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn context_builds_owner_maps_once_and_pages_share_store_wide_artifacts() {
    let store = Arc::new(CountingStore::new(512, 9, false));
    let context = Arc::new(QueryContext::new(store.clone()).unwrap());
    let context_key_calls = store.event_key_calls.load(Ordering::Relaxed);
    assert!(context_key_calls <= 513);
    assert_eq!(store.typed_lookup_calls.load(Ordering::Relaxed), 0);
    let projection = TimelineProjection::new(context, EventFilter::default()).unwrap();
    let first = query_events(&projection, None, 1).unwrap();
    let second = query_events(&projection, first.next.as_ref(), 1).unwrap();
    assert!(Arc::ptr_eq(&first.completeness, &second.completeness));
    assert_eq!(
        store.event_key_calls.load(Ordering::Relaxed),
        context_key_calls
    );
    assert_eq!(store.typed_lookup_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn planner_counts_fields_then_decodes_the_smallest_posting_first() {
    let store = Arc::new(CountingStore::new(512, 9, false));
    let context = Arc::new(QueryContext::new(store.clone()).unwrap());
    store.posting_count_calls.store(0, Ordering::Relaxed);
    store.posting_decode_calls.store(0, Ordering::Relaxed);
    store.posting_decoded_rows.store(0, Ordering::Relaxed);
    store.posting_decode_order.lock().unwrap().clear();

    let projection = TimelineProjection::new(
        context,
        EventFilter {
            tids: vec![7, 8],
            kinds: vec![EventKind::Discontinuity],
            ..EventFilter::default()
        },
    )
    .unwrap();
    assert_eq!(projection.plan().candidate_rows, 1);
    assert!(store.posting_count_calls.load(Ordering::Relaxed) >= 2);
    assert_eq!(
        store.posting_decode_order.lock().unwrap().first().copied(),
        Some("kinds")
    );
    assert!(store.posting_decoded_rows.load(Ordering::Relaxed) <= 513);
}

#[test]
fn planner_shared_budget_rejects_before_any_posting_decode() {
    let mut store = CountingStore::new(8, 9, false);
    store.posting_count_override = Some(7_000_000);
    let store = Arc::new(store);
    let context = Arc::new(QueryContext::new(store.clone()).unwrap());
    store.posting_count_calls.store(0, Ordering::Relaxed);
    store.posting_decode_calls.store(0, Ordering::Relaxed);
    let error = match TimelineProjection::new(
        context,
        EventFilter {
            tids: vec![7],
            kinds: vec![EventKind::Instruction],
            sequence: vec![qtrace_analysis::SequenceRange::new(1, 8).unwrap()],
            ..EventFilter::default()
        },
    ) {
        Ok(_) => panic!("candidate work above the shared budget was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "analysis.resource_exhausted");
    assert_eq!(store.posting_count_calls.load(Ordering::Relaxed), 3);
    assert_eq!(store.posting_decode_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn typed_store_aborts_have_stable_codes_during_estimate_and_decode() {
    for (dimension, expected_code) in [
        (
            qtrace_provider::BudgetDimension::Nodes,
            "analysis.cpu_budget_exceeded",
        ),
        (
            qtrace_provider::BudgetDimension::ResidentBytes,
            "analysis.resource_exhausted",
        ),
    ] {
        for during_estimate in [true, false] {
            let mut store = CountingStore::new(8, 9, false);
            if during_estimate {
                store.posting_count_abort = Some(dimension);
            } else {
                store.posting_decode_abort = Some(dimension);
            }
            let context = Arc::new(QueryContext::new(Arc::new(store)).unwrap());
            let error = match TimelineProjection::new(
                context,
                EventFilter {
                    tids: vec![7],
                    ..EventFilter::default()
                },
            ) {
                Ok(_) => panic!("typed store abort was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.code(), expected_code);
        }
    }
}

#[test]
fn context_hard_preflight_and_cancel_stop_before_event_or_payload_reads() {
    let mut oversized = CountingStore::new(1, 9, false);
    oversized.event_count_override = Some(qtrace_analysis::MAX_CONTEXT_EVENTS + 1);
    let oversized = Arc::new(oversized);
    let error = match QueryContext::new(oversized.clone()) {
        Ok(_) => panic!("oversized context was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "analysis.resource_exhausted");
    assert_eq!(oversized.event_key_calls.load(Ordering::Relaxed), 0);
    assert_eq!(oversized.payload_calls.load(Ordering::Relaxed), 0);
    assert_eq!(oversized.blob_calls.load(Ordering::Relaxed), 0);

    let cancelled = Arc::new(CountingStore::new(32, 9, false));
    let error = match QueryContext::new_with_guard(cancelled.clone(), &CancelContext) {
        Ok(_) => panic!("cancelled context was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "job.cancelled");
    assert_eq!(cancelled.event_key_calls.load(Ordering::Relaxed), 0);
    assert_eq!(cancelled.payload_calls.load(Ordering::Relaxed), 0);
    assert_eq!(cancelled.blob_calls.load(Ordering::Relaxed), 0);

    let interrupted = Arc::new(CountingStore::new(8_192, 9, false));
    let guard = CancelDuringContext {
        armed: AtomicBool::new(false),
        checkpoints: AtomicUsize::new(0),
    };
    let error = match QueryContext::new_with_guard(interrupted.clone(), &guard) {
        Ok(_) => panic!("mid-context cancellation was ignored"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "job.cancelled");
    assert_eq!(interrupted.event_key_calls.load(Ordering::Relaxed), 4_096);
    assert_eq!(interrupted.payload_calls.load(Ordering::Relaxed), 0);
    assert_eq!(interrupted.blob_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn context_heap_growth_uses_raii_allocation_scopes() {
    let guard = ScopeOnlyGuard {
        scopes: AtomicUsize::new(0),
        active: AtomicBool::new(false),
    };
    QueryContext::new_with_guard(Arc::new(CountingStore::new(32, 9, true)), &guard)
        .expect("scoped context allocation");
    assert!(guard.scopes.load(Ordering::SeqCst) > 0);
    assert!(!guard.active.load(Ordering::SeqCst));
}

#[test]
fn context_allocation_budget_accepts_exact_and_rejects_minus_one_before_growth() {
    let measure = ResidentBudgetGuard::new(usize::MAX);
    QueryContext::new_with_guard(Arc::new(CountingStore::new(64, 9, true)), &measure)
        .expect("measure context allocation");
    let exact = measure.consumed.load(Ordering::SeqCst);
    let expected_scopes = measure.scopes.load(Ordering::SeqCst);
    let requests = measure.requests.lock().unwrap().clone();
    assert!(exact > 0 && expected_scopes > 1);

    let exact_guard = ResidentBudgetGuard::new(exact);
    QueryContext::new_with_guard(Arc::new(CountingStore::new(64, 9, true)), &exact_guard)
        .expect("exact resident budget");
    assert_eq!(exact_guard.consumed.load(Ordering::SeqCst), exact);
    assert_eq!(exact_guard.scopes.load(Ordering::SeqCst), expected_scopes);
    assert_eq!(
        exact_guard.rejected_scope.load(Ordering::SeqCst),
        usize::MAX
    );

    let minus_one = ResidentBudgetGuard::new(exact - 1);
    let error = context_error_with_guard(
        CountingStore::new(64, 9, true),
        &minus_one,
        "minus-one resident budget was accepted",
    );
    assert_eq!(error.code(), "analysis.resource_exhausted");
    assert_eq!(
        minus_one.rejected_scope.load(Ordering::SeqCst) + 1,
        expected_scopes
    );
    assert!(minus_one.consumed.load(Ordering::SeqCst) < exact);

    for reject_at in [0, expected_scopes / 2, expected_scopes - 1] {
        let prefix = requests[..reject_at].iter().sum();
        let guard = ResidentBudgetGuard::new(prefix);
        let error = context_error_with_guard(
            CountingStore::new(64, 9, true),
            &guard,
            "representative allocation rejection was ignored",
        );
        assert_eq!(error.code(), "analysis.resource_exhausted");
        assert_eq!(guard.rejected_scope.load(Ordering::SeqCst), reject_at);
        assert_eq!(guard.consumed.load(Ordering::SeqCst), prefix);
        assert_eq!(guard.scopes.load(Ordering::SeqCst), reject_at + 1);
    }
}

fn maximum_sequence_complexity(events: usize) -> (usize, usize) {
    let mut store = CountingStore::new(events, 9, true);
    for key in &mut store.keys {
        key.sequence = Some(u64::MAX);
    }
    let guard = AllocationCountGuard {
        allocations: AtomicUsize::new(0),
        checkpoints: AtomicUsize::new(0),
    };
    QueryContext::new_with_guard(Arc::new(store), &guard).expect("maximum-sequence context");
    (
        guard.allocations.load(Ordering::Relaxed),
        guard.checkpoints.load(Ordering::Relaxed),
    )
}

#[test]
fn maximum_sequence_rows_reserve_once_instead_of_once_per_event() {
    let (n, n_work) = maximum_sequence_complexity(128);
    let (two_n, two_n_work) = maximum_sequence_complexity(256);
    let (four_n, four_n_work) = maximum_sequence_complexity(512);
    assert!(two_n <= n + 4, "allocation calls grew from {n} to {two_n}");
    assert!(
        four_n <= two_n + 4,
        "allocation calls grew from {two_n} to {four_n}"
    );
    assert!(
        two_n_work <= n_work.saturating_mul(2).saturating_add(16),
        "context checkpoints grew superlinearly: {n_work} -> {two_n_work}"
    );
    assert!(
        four_n_work <= two_n_work.saturating_mul(2).saturating_add(16),
        "context checkpoints grew superlinearly: {two_n_work} -> {four_n_work}"
    );
}

#[test]
fn discontinuity_payload_and_context_byte_limits_fail_before_decode() {
    let mut single = CountingStore::new(1, 9, false);
    let encoded = single.discontinuity_payload.clone();
    single.discontinuity_payload = vec![b' '; MAX_DISCONTINUITY_PAYLOAD_BYTES + 1];
    single.discontinuity_payload.extend_from_slice(&encoded);
    let error = context_error(single, "oversized discontinuity payload was accepted");
    assert_eq!(error.code(), "analysis.resource_exhausted");

    let mut cumulative = CountingStore::new(17, 9, false);
    cumulative.discontinuity_rows = 17;
    let encoded = cumulative.discontinuity_payload.clone();
    cumulative.discontinuity_payload = encoded[..encoded.len() - 1].to_vec();
    cumulative.discontinuity_payload.extend(std::iter::repeat_n(
        b' ',
        MAX_DISCONTINUITY_PAYLOAD_BYTES
            .checked_sub(encoded.len())
            .expect("payload bound exceeds encoded evidence"),
    ));
    cumulative.discontinuity_payload.push(b'}');
    assert!(
        cumulative.discontinuity_payload.len() * cumulative.discontinuity_rows
            > MAX_DISCONTINUITY_TOTAL_BYTES
    );
    let error = context_error(
        cumulative,
        "cumulative discontinuity bytes exceed context bound",
    );
    assert_eq!(error.code(), "analysis.resource_exhausted");
}

#[test]
fn discontinuity_posting_preserves_cancel_code() {
    let mut store = CountingStore::new(1, 9, false);
    store.cancel_discontinuity_posting = true;
    let error = context_error(store, "posting cancellation was accepted");
    assert_eq!(error.code(), "job.cancelled");
}

#[test]
fn validates_limits_reports_exact_total_and_projects_completeness_and_discontinuity() {
    let projection = projection(
        Arc::new(CountingStore::new(7, 4, false)),
        EventFilter::default(),
    );
    assert_eq!(
        query_events(&projection, None, 0).unwrap_err().code(),
        "analysis.invalid_limit"
    );
    assert_eq!(
        query_events(&projection, None, 2_001).unwrap_err().code(),
        "analysis.invalid_limit"
    );
    assert_eq!(query_events(&projection, None, 1).unwrap().rows.len(), 1);

    let page = query_events(&projection, None, 2_000).unwrap();
    assert_eq!(page.total, 7);
    assert!(page.exact_total);
    assert_eq!(page.completeness.retained_ranges, 1);
    assert_eq!(page.completeness.incomplete_ranges, 1);
    assert!(
        matches!(page.rows.last(), Some(TimelineRow::Discontinuity(row)) if row.cause == DiscontinuityCause::Truncation && row.evidence.cause == CompletenessCause::Lost)
    );
    projection.cancel();
    assert!(!projection.is_cancelled());
    assert_eq!(query_events(&projection, None, 2_000).unwrap(), page);
    assert_eq!(projection.total_visible_rows().unwrap(), (7, true));
}

#[test]
fn semantic_detail_scan_publishes_inexact_pages_then_an_immutable_exact_result() {
    let store = Arc::new(CountingStore::new(32, 9, true));
    let projection = projection(
        store.clone(),
        EventFilter {
            semantic_detail_contains: vec!["needle".into()],
            ..EventFilter::default()
        },
    );

    store.wait_for_semantic_calls(2);
    let pending = query_events(&projection, None, 10).unwrap();
    assert!(!pending.exact_total);
    assert_eq!(pending.total, 1);
    assert_eq!(pending.rows.len(), 1);
    let resume = pending
        .next
        .clone()
        .expect("incomplete result resume cursor");

    store.release_semantic_scan();
    assert!(projection.wait_until_complete(Duration::from_secs(2)));
    let resumed = query_events(&projection, Some(&resume), 10).unwrap();
    assert_eq!(resumed.rows.first().unwrap().key().record_ordinal, 1);
    let complete = query_events(&projection, None, 10).unwrap();
    assert!(complete.exact_total);
    assert_eq!(complete.total, 32);
    assert_eq!(complete.rows.len(), 10);
    assert_eq!(query_events(&projection, None, 10).unwrap(), complete);
    projection.cancel();
    assert!(!projection.is_cancelled());
    assert_eq!(query_events(&projection, None, 10).unwrap(), complete);
    assert_eq!(projection.total_visible_rows().unwrap(), (32, true));
}

#[test]
fn semantic_completion_racing_cancel_has_one_idempotent_terminal_outcome() {
    for _ in 0..8 {
        let store = Arc::new(CountingStore::new(32, 9, true));
        let projection = Arc::new(projection(
            store.clone(),
            EventFilter {
                semantic_detail_contains: vec!["needle".into()],
                ..EventFilter::default()
            },
        ));
        store.wait_for_semantic_calls(2);
        let barrier = Arc::new(Barrier::new(3));
        let cancelling = {
            let projection = projection.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                projection.cancel();
            })
        };
        let completing = {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.release_semantic_scan();
            })
        };
        barrier.wait();
        cancelling.join().unwrap();
        completing.join().unwrap();
        assert!(projection.wait_until_complete(Duration::from_secs(2)));

        let first = query_events(&projection, None, 10);
        projection.cancel();
        let second = query_events(&projection, None, 10);
        match (first, second) {
            (Ok(first), Ok(second)) => {
                assert_eq!(first, second);
                assert!(first.exact_total);
                assert!(!projection.is_cancelled());
            }
            (Err(first), Err(second)) => {
                assert_eq!(first.code(), "job.cancelled");
                assert_eq!(second.code(), "job.cancelled");
                assert!(projection.is_cancelled());
            }
            outcome => panic!("terminal outcome changed after repeated cancel: {outcome:?}"),
        }
    }
}

#[test]
fn semantic_detail_background_scan_is_cancellable() {
    let store = Arc::new(CountingStore::new(32, 9, true));
    let projection = projection(
        store.clone(),
        EventFilter {
            semantic_detail_contains: vec!["needle".into()],
            ..EventFilter::default()
        },
    );
    store.wait_for_semantic_calls(2);
    let pending = query_events(&projection, None, 10).unwrap();
    assert_eq!(pending.total, 1);
    assert!(!pending.exact_total);
    projection.cancel();
    assert!(projection.wait_until_complete(Duration::ZERO));
    store.release_semantic_scan();
    assert!(projection.wait_until_complete(Duration::from_secs(2)));
    assert!(projection.is_cancelled());
    assert_eq!(
        query_events(&projection, None, 10).unwrap_err().code(),
        "job.cancelled"
    );
    assert_eq!(
        projection.total_visible_rows().unwrap_err().code(),
        "job.cancelled"
    );
    let terminal_blob_calls = store.blob_calls.load(Ordering::Relaxed);
    assert_eq!(terminal_blob_calls, 2);
    assert_eq!(
        store.blob_calls.load(Ordering::Relaxed),
        terminal_blob_calls
    );
}

#[test]
fn semantic_resource_failure_hides_partial_rows_and_stops_terminal_growth() {
    let mut store = CountingStore::new(4, 9, true);
    store.oversized_blob = Some(vec![b'x'; 8 * 1024 * 1024 + 1]);
    store.oversized_blob_after = Some(1);
    let store = Arc::new(store);
    let projection = projection(
        store.clone(),
        EventFilter {
            semantic_detail_contains: vec!["needle".into()],
            ..EventFilter::default()
        },
    );
    store.wait_for_semantic_calls(2);
    let pending = query_events(&projection, None, 10).unwrap();
    assert_eq!(pending.total, 1);
    assert!(!pending.exact_total);

    store.release_semantic_scan();
    assert!(projection.wait_until_complete(Duration::from_secs(2)));
    assert_eq!(
        query_events(&projection, None, 10).unwrap_err().code(),
        "analysis.resource_exhausted"
    );
    assert_eq!(
        projection.total_visible_rows().unwrap_err().code(),
        "analysis.resource_exhausted"
    );
    let terminal_blob_calls = store.blob_calls.load(Ordering::Relaxed);
    assert_eq!(terminal_blob_calls, 2);
    assert_eq!(
        store.blob_calls.load(Ordering::Relaxed),
        terminal_blob_calls
    );
}

#[test]
fn pending_empty_page_returns_a_stable_watermark_cursor_and_resumes_after_progress() {
    let store = Arc::new(CountingStore::new(8, 9, true));
    let projection = projection(
        store.clone(),
        EventFilter {
            semantic_detail_contains: vec!["future".into()],
            ..EventFilter::default()
        },
    );
    store.wait_for_semantic_calls(2);
    let first_poll = query_events(&projection, None, 2).unwrap();
    assert!(first_poll.rows.is_empty());
    assert!(!first_poll.exact_total);
    let watermark = first_poll.next.expect("pending watermark cursor");
    let repeated = query_events(&projection, Some(&watermark), 2).unwrap();
    assert!(repeated.rows.is_empty());
    assert_eq!(repeated.next.as_ref(), Some(&watermark));

    store.release_semantic_scan();
    assert!(projection.wait_until_complete(Duration::from_secs(2)));
    let resumed = query_events(&projection, Some(&watermark), 20).unwrap();
    assert!(resumed.exact_total);
    assert_eq!(
        resumed
            .rows
            .iter()
            .map(|row| row.key().record_ordinal)
            .collect::<Vec<_>>(),
        (1..8).collect::<Vec<_>>()
    );
    assert!(resumed.next.is_none());
}

#[test]
fn pending_cursor_prefers_the_last_returned_row_when_more_visible_rows_exist() {
    let mut store = CountingStore::new(8, 9, true);
    store.unblocked_scan_calls = 5;
    let store = Arc::new(store);
    let projection = projection(
        store.clone(),
        EventFilter {
            semantic_detail_contains: vec!["needle".into()],
            ..EventFilter::default()
        },
    );
    store.wait_for_semantic_calls(6);
    let first = query_events(&projection, None, 2).unwrap();
    assert_eq!(
        first
            .rows
            .iter()
            .map(|row| row.key().record_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    let second = query_events(&projection, first.next.as_ref(), 2).unwrap();
    assert_eq!(
        second
            .rows
            .iter()
            .map(|row| row.key().record_ordinal)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    store.release_semantic_scan();
}

#[test]
fn excessive_filter_terms_fail_with_a_stable_error_code() {
    let filter = EventFilter {
        semantic_names: (0..513).map(|term| format!("name-{term}")).collect(),
        ..EventFilter::default()
    };
    let error = match TimelineProjection::new(
        Arc::new(QueryContext::new(Arc::new(CountingStore::new(1, 9, false))).unwrap()),
        filter,
    ) {
        Ok(_) => panic!("over-limit filter was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "analysis.filter_too_complex");
}

#[test]
fn excessive_module_range_expansion_fails_with_a_stable_error_code() {
    let filter = EventFilter {
        modules: (0..65).collect(),
        relative_pc: (0..65)
            .map(|term| AddressRange::new(term * 2, term * 2 + 1).unwrap())
            .collect(),
        ..EventFilter::default()
    };
    let error = match TimelineProjection::new(
        Arc::new(QueryContext::new(Arc::new(CountingStore::new(1, 9, false))).unwrap()),
        filter,
    ) {
        Ok(_) => panic!("over-limit module/range expansion was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "analysis.filter_too_complex");
}

#[test]
fn oversized_semantic_detail_fails_with_a_stable_resource_error() {
    let mut store = CountingStore::new(1, 9, true);
    store.oversized_blob = Some(vec![b'x'; 8 * 1024 * 1024 + 1]);
    let projection = projection(
        Arc::new(store),
        EventFilter {
            semantic_detail_contains: vec!["needle".into()],
            ..EventFilter::default()
        },
    );
    assert!(projection.wait_until_complete(Duration::from_secs(2)));
    assert_eq!(
        query_events(&projection, None, 1).unwrap_err().code(),
        "analysis.resource_exhausted"
    );
}

fn completeness_page(store: CountingStore) -> qtrace_analysis::EventPage {
    let projection = projection(Arc::new(store), EventFilter::default());
    query_events(&projection, None, 10).unwrap()
}

#[test]
fn completeness_is_unknown_without_capability_or_full_domain_coverage() {
    let mut empty = CountingStore::new(7, 9, true);
    empty.release_semantic_scan();
    empty.completeness.clear();
    let page = completeness_page(empty);
    assert_eq!(page.completeness.status, CompletenessStatus::Unknown);
    assert!(!page.completeness.is_complete());

    let mut partial = CountingStore::new(7, 9, true);
    partial.release_semantic_scan();
    partial.completeness = vec![CompletenessRow {
        domain: RangeDomain::CapturedSequence,
        bounds: RangeBounds::InclusiveSequence { first: 1, last: 2 },
        provenance: Provenance::Captured,
        cause: CompletenessCause::Retained,
    }];
    let page = completeness_page(partial);
    assert_eq!(page.completeness.status, CompletenessStatus::Unknown);

    let mut no_capability = CountingStore::new(7, 9, true);
    no_capability.release_semantic_scan();
    no_capability.completeness.truncate(1);
    no_capability.capabilities.loss_and_damage_ranges = false;
    let page = completeness_page(no_capability);
    assert_eq!(page.completeness.status, CompletenessStatus::Unknown);
}

#[test]
fn completeness_requires_full_retained_coverage_and_marks_damage_incomplete() {
    let mut complete = CountingStore::new(7, 9, true);
    complete.release_semantic_scan();
    complete.completeness.truncate(1);
    let page = completeness_page(complete);
    assert_eq!(page.completeness.status, CompletenessStatus::Complete);
    assert!(page.completeness.is_complete());

    let damaged = CountingStore::new(7, 9, true);
    damaged.release_semantic_scan();
    let page = completeness_page(damaged);
    assert_eq!(page.completeness.status, CompletenessStatus::Incomplete);
    assert!(!page.completeness.is_complete());
}
