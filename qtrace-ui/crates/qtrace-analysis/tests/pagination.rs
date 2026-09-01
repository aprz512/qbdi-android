use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use qtrace_analysis::{
    AddressRange, CompletenessStatus, EventFilter, PageCursor, QueryContext, TimelineProjection,
    TimelineRow, query_events,
};
use qtrace_provider::{
    ArtifactDigest, CompletenessCause, CompletenessRange, Discontinuity, DiscontinuityCause,
    EventKey, EventKind, EventPayload, Provenance, ProviderCapabilities, RangeBounds, RangeDomain,
    TimelineId,
};
use qtrace_store::{
    CompletenessRow, DefinitionRow, IndexError, InstructionRow, MemoryRow, ModuleRow,
    NormalizedLayoutIdentity, RegisterObservationRow, SemanticRow, TraceStoreView,
};

struct CountingStore {
    keys: Vec<EventKey>,
    semantic: bool,
    release: (Mutex<bool>, Condvar),
    scan_progress: (Mutex<usize>, Condvar),
    event_key_calls: AtomicUsize,
    blob_calls: AtomicUsize,
    typed_lookup_calls: AtomicUsize,
    capabilities: ProviderCapabilities,
    completeness: Vec<CompletenessRow>,
    discontinuity_payload: Vec<u8>,
    semantics: Vec<SemanticRow>,
    oversized_blob: Option<Vec<u8>>,
    unblocked_scan_calls: usize,
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
            unblocked_scan_calls: 1,
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
}

impl TraceStoreView for CountingStore {
    fn normalized_layout_identity(&self) -> NormalizedLayoutIdentity {
        serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "layout_fingerprint": vec![1_u8; 32],
        }))
        .unwrap()
    }
    fn event_count(&self) -> usize {
        self.keys.len()
    }
    fn event_key(&self, row: usize) -> Result<Option<EventKey>, IndexError> {
        self.event_key_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.keys.get(row).cloned())
    }
    fn event_kind(&self, row: usize) -> Result<Option<EventKind>, IndexError> {
        Ok((row < self.keys.len()).then_some(if self.semantic {
            EventKind::SemanticCall
        } else if row + 1 == self.keys.len() {
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
        Ok(if !self.semantic && row + 1 == self.keys.len() {
            &self.discontinuity_payload
        } else {
            b"{}"
        })
    }
    fn string_bytes(&self, _id: u32) -> Result<&[u8], IndexError> {
        Ok(b"event")
    }
    fn blob_bytes(&self, id: u32) -> Result<&[u8], IndexError> {
        if let Some(blob) = &self.oversized_blob {
            return Ok(blob);
        }
        let detail: &[u8] = if id == 0 {
            b"detail matches needle"
        } else {
            b"detail matches needle future"
        };
        let blob_call = self.blob_calls.fetch_add(1, Ordering::Relaxed);
        if blob_call < self.blob_count() {
            return Ok(detail);
        }
        let call = {
            let mut progress = self.scan_progress.0.lock().unwrap();
            *progress += 1;
            self.scan_progress.1.notify_all();
            *progress
        };
        if call <= self.unblocked_scan_calls {
            return Ok(detail);
        }
        let mut released = self.release.0.lock().unwrap();
        while !*released {
            released = self.release.1.wait(released).unwrap();
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

fn projection(store: Arc<CountingStore>, filter: EventFilter) -> TimelineProjection {
    TimelineProjection::new(Arc::new(QueryContext::new(store).unwrap()), filter).unwrap()
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
    let store = Arc::new(CountingStore::new(512, 9, false));
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
    assert_eq!(ordinals, (0..512).collect::<Vec<_>>());
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
    projection.cancel();
    store.release_semantic_scan();
    assert!(projection.wait_until_complete(Duration::from_secs(2)));
    assert!(projection.is_cancelled());
    assert!(!query_events(&projection, None, 10).unwrap().exact_total);
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
    assert!(!page.completeness.complete);

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
    assert!(page.completeness.complete);

    let damaged = CountingStore::new(7, 9, true);
    damaged.release_semantic_scan();
    let page = completeness_page(damaged);
    assert_eq!(page.completeness.status, CompletenessStatus::Incomplete);
    assert!(!page.completeness.complete);
}
