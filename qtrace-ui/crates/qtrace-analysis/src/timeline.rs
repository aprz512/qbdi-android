use std::{
    error::Error,
    fmt,
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use qtrace_provider::{
    AllocationScope, ArtifactDigest, EventKey, EventKind, MemoryDirection, Provenance,
    RegisterSlot, TimelineId, WorkDelta, WorkGuard,
};
use qtrace_store::{
    CompletenessRow, DefinitionRow, InstructionRow, MemoryRow, ModuleRow, NormalizedBulkView,
    NormalizedPostingQuery, RegisterAccess, RegisterObservationRow, SemanticRow, TraceStoreView,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{CompletenessSummary, DiscontinuityRow, EventFilter, MemoryFilter, MnemonicFilter};

const CURSOR_VERSION: u8 = 2;
const CURSOR_PAYLOAD_BYTES: usize = 136;
const CURSOR_BYTES: usize = CURSOR_PAYLOAD_BYTES + 32;
const MAX_CANDIDATE_ROWS: usize = 10_000_000;
const MAX_CANDIDATE_WORK: usize = 20_000_000;
const MAX_CANDIDATE_RESIDENT_BYTES: usize = 256 * 1024 * 1024;
const MAX_SEMANTIC_DETAIL_BYTES: usize = 8 * 1024 * 1024;
const MAX_SEMANTIC_SCAN_BYTES: usize = 64 * 1024 * 1024;
const SEMANTIC_WORKERS: usize = 4;
const MAX_PENDING_SEMANTIC_JOBS: usize = 32;
const MAX_MATCHER_BUILD_WORK: usize = 16 * 1024 * 1024;
pub const MAX_CONTEXT_EVENTS: usize = 10_000_000;
pub const MAX_CONTEXT_TYPED_ROWS: usize = 20_000_000;
pub const MAX_CONTEXT_DICTIONARY_ENTRIES: usize = 20_000_000;
pub const MAX_DISCONTINUITY_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_DISCONTINUITY_TOTAL_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisError {
    code: &'static str,
    detail: String,
}

impl AnalysisError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub(crate) fn invalid_filter(detail: impl Into<String>) -> Self {
        Self {
            code: "analysis.invalid_filter",
            detail: detail.into(),
        }
    }

    pub(crate) fn filter_too_complex(detail: impl Into<String>) -> Self {
        Self {
            code: "analysis.filter_too_complex",
            detail: detail.into(),
        }
    }

    fn resource_exhausted(detail: impl Into<String>) -> Self {
        Self {
            code: "analysis.resource_exhausted",
            detail: detail.into(),
        }
    }

    fn worker_panicked() -> Self {
        Self {
            code: "analysis.worker_panicked",
            detail: "semantic analysis worker panicked".to_owned(),
        }
    }

    fn cancelled(detail: impl Into<String>) -> Self {
        Self {
            code: "job.cancelled",
            detail: detail.into(),
        }
    }

    fn invalid_limit() -> Self {
        Self {
            code: "analysis.invalid_limit",
            detail: "page limit must be in 1..=2000".to_owned(),
        }
    }

    fn cursor_mismatch(detail: impl Into<String>) -> Self {
        Self {
            code: "analysis.cursor_mismatch",
            detail: detail.into(),
        }
    }

    fn store(error: qtrace_store::IndexError) -> Self {
        Self {
            code: "analysis.store",
            detail: format!("{}: {error}", error.code()),
        }
    }

    fn control(error: qtrace_provider::OperationAbort) -> Self {
        match error {
            qtrace_provider::OperationAbort::Cancelled => Self {
                code: "job.cancelled",
                detail: "query context construction cancelled".to_owned(),
            },
            error @ qtrace_provider::OperationAbort::BudgetExceeded { .. } => {
                Self::resource_exhausted(error.to_string())
            }
        }
    }
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl Error for AnalysisError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StoreIdentity([u8; 32]);

impl StoreIdentity {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProjectionIdentity([u8; 32]);

impl ProjectionIdentity {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct QueryContext {
    store: Arc<dyn NormalizedBulkView + Send + Sync>,
    identity: StoreIdentity,
    keys: Vec<EventKey>,
    kinds: Vec<EventKind>,
    provenances: Vec<Provenance>,
    modules: Vec<ModuleRow>,
    definitions: Vec<DefinitionRow>,
    instructions: Vec<Option<InstructionRow>>,
    memories: Vec<Option<MemoryRow>>,
    semantics: Vec<Option<SemanticRow>>,
    observations: Vec<RegisterObservationRow>,
    observation_ranges: Vec<(usize, usize)>,
    memory_pc: Vec<MemoryPcEntry>,
    max_sequence_rows: Vec<usize>,
    completeness: Arc<CompletenessSummary>,
    discontinuities: Arc<Vec<Option<(qtrace_provider::DiscontinuityCause, CompletenessRow)>>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct MemoryPcEntry {
    module: u32,
    pc: u64,
    row: usize,
}

type ObservationBuckets = (Vec<RegisterObservationRow>, Vec<(usize, usize)>);

impl QueryContext {
    pub fn new<T>(store: Arc<T>) -> Result<Self, AnalysisError>
    where
        T: NormalizedBulkView + Send + Sync + 'static,
    {
        Self::new_with_guard(store, &AllowContextWork)
    }

    pub fn new_with_guard<T>(store: Arc<T>, guard: &dyn WorkGuard) -> Result<Self, AnalysisError>
    where
        T: NormalizedBulkView + Send + Sync + 'static,
    {
        let store: Arc<dyn NormalizedBulkView + Send + Sync> = store;
        Self::from_arc_with_guard(store, guard)
    }

    pub fn from_arc(
        store: Arc<dyn NormalizedBulkView + Send + Sync>,
    ) -> Result<Self, AnalysisError> {
        Self::from_arc_with_guard(store, &AllowContextWork)
    }

    pub fn from_arc_with_guard(
        store: Arc<dyn NormalizedBulkView + Send + Sync>,
        guard: &dyn WorkGuard,
    ) -> Result<Self, AnalysisError> {
        build_query_context(store, guard)
    }

    pub fn identity(&self) -> StoreIdentity {
        self.identity
    }
}

struct AllowContextWork;

impl WorkGuard for AllowContextWork {
    fn consume(&self, _delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPlan {
    pub projection_identity: ProjectionIdentity,
    pub candidate_rows: usize,
    pub indexed_fields: usize,
    pub has_residual_scan: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRow {
    pub source_row: usize,
    pub key: EventKey,
    pub kind: EventKind,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimelineRow {
    Event(EventRow),
    Discontinuity(DiscontinuityRow),
}

impl TimelineRow {
    pub fn key(&self) -> &EventKey {
        match self {
            Self::Event(row) => &row.key,
            Self::Discontinuity(row) => &row.key,
        }
    }

    pub fn source_row(&self) -> usize {
        match self {
            Self::Event(row) => row.source_row,
            Self::Discontinuity(row) => row.source_row,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCursor(String);

impl PageCursor {
    pub fn from_encoded(encoded: String) -> Self {
        Self(encoded)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    pub rows: Vec<TimelineRow>,
    pub next: Option<PageCursor>,
    pub total: usize,
    pub exact_total: bool,
    pub completeness: Arc<CompletenessSummary>,
}

#[derive(Default)]
struct ProjectionState {
    visible: Vec<usize>,
    watermark: Option<EventKey>,
    exact_total: bool,
    completed: bool,
    error: Option<AnalysisError>,
}

pub struct TimelineProjection {
    context: Arc<QueryContext>,
    filter: EventFilter,
    plan: QueryPlan,
    state: Arc<(Mutex<ProjectionState>, Condvar)>,
    cancelled: Arc<AtomicBool>,
    guard: CandidateGuard,
}

impl TimelineProjection {
    pub fn new(context: Arc<QueryContext>, filter: EventFilter) -> Result<Self, AnalysisError> {
        let filter = filter.normalized()?;
        let projection_identity = derive_projection_identity(context.identity, &filter);
        let cancelled = Arc::new(AtomicBool::new(false));
        let guard = CandidateGuard::new(cancelled.clone());
        let (candidates, indexed_fields) = plan_candidates(&context, &filter, &guard)?;
        let residual = synchronous_residual_filter(&filter);
        let candidates = apply_synchronous_residuals(&context, &residual, candidates, &guard)?;
        let candidates = sort_rows_by_stable_key(&context, candidates, &guard)?;
        let has_residual_scan = filter.has_semantic_detail_residual();
        let state = Arc::new((Mutex::new(ProjectionState::default()), Condvar::new()));
        let plan = QueryPlan {
            projection_identity,
            candidate_rows: candidates.len(),
            indexed_fields,
            has_residual_scan,
        };

        if has_residual_scan {
            submit_semantic_scan(
                context.clone(),
                filter.semantic_detail_contains.clone(),
                candidates,
                state.clone(),
                cancelled.clone(),
                guard.clone(),
            )?;
        } else {
            let mut projection_state = state.0.lock().expect("projection state poisoned");
            projection_state.visible = candidates;
            projection_state.exact_total = true;
            projection_state.completed = true;
        }

        Ok(Self {
            context,
            filter,
            plan,
            state,
            cancelled,
            guard,
        })
    }

    pub fn plan(&self) -> &QueryPlan {
        &self.plan
    }

    pub fn filter(&self) -> &EventFilter {
        &self.filter
    }

    pub fn total_visible_rows(&self) -> Result<(usize, bool), AnalysisError> {
        let state = self.state.0.lock().expect("projection state poisoned");
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        Ok((state.visible.len(), state.exact_total))
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        terminalize_projection(
            &self.state,
            false,
            Some(AnalysisError::cancelled("semantic analysis cancelled")),
        );
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn wait_until_complete(&self, timeout: Duration) -> bool {
        let state = self.state.0.lock().expect("projection state poisoned");
        let (state, _) = self
            .state
            .1
            .wait_timeout_while(state, timeout, |state| !state.completed)
            .expect("projection state poisoned");
        state.completed
    }

    fn page(&self, cursor: Option<&PageCursor>, limit: usize) -> Result<EventPage, AnalysisError> {
        if !(1..=2_000).contains(&limit) {
            return Err(AnalysisError::invalid_limit());
        }
        let (page_rows, total, exact_total, has_more, analysis_pending, watermark) = {
            let state = self.state.0.lock().expect("projection state poisoned");
            if let Some(error) = &state.error {
                return Err(error.clone());
            }
            let start = match cursor {
                None => 0,
                Some(cursor) => {
                    let decoded = decode_cursor(cursor)?;
                    if decoded.store != self.context.identity
                        || decoded.projection != self.plan.projection_identity
                    {
                        return Err(AnalysisError::cursor_mismatch(
                            "cursor belongs to another store or normalized filter",
                        ));
                    }
                    decoded.last_key.as_ref().map_or(Ok(0), |key| {
                        locate_after_key(&self.context, &state.visible, key)
                    })?
                }
            };
            let end = start.saturating_add(limit).min(state.visible.len());
            (
                try_clone_slice(
                    &state.visible[start..end],
                    &self.guard,
                    "page source-row allocation failed",
                )?,
                state.visible.len(),
                state.exact_total,
                end < state.visible.len(),
                !state.completed,
                state.watermark.clone(),
            )
        };
        let mut rows = Vec::new();
        try_reserve_analysis(
            &mut rows,
            page_rows.len(),
            &self.guard,
            "page row allocation failed",
        )?;
        for chunk in page_rows.chunks(4096) {
            consume_analysis_work(&self.guard, chunk.len())?;
            for source_row in chunk {
                rows.push(self.project_row(*source_row)?);
            }
        }
        let next = if has_more || analysis_pending {
            let last_returned = rows.last().map(|row| row.key().clone());
            let anchor = if has_more {
                last_returned
            } else {
                match (last_returned, watermark) {
                    (Some(left), Some(right)) => {
                        Some(if compare_event_keys(&left, &right).is_lt() {
                            right
                        } else {
                            left
                        })
                    }
                    (left @ Some(_), None) => left,
                    (None, right) => right,
                }
            };
            Some(encode_cursor(
                self.context.identity,
                self.plan.projection_identity,
                anchor.as_ref(),
            ))
        } else {
            None
        };
        Ok(EventPage {
            rows,
            next,
            total,
            exact_total,
            completeness: self.context.completeness.clone(),
        })
    }

    fn project_row(&self, source_row: usize) -> Result<TimelineRow, AnalysisError> {
        let key = self.context.key(source_row)?.clone();
        let kind = *self
            .context
            .kinds
            .get(source_row)
            .ok_or_else(|| AnalysisError::store_shape("event kind is absent"))?;
        let provenance = *self
            .context
            .provenances
            .get(source_row)
            .ok_or_else(|| AnalysisError::store_shape("event provenance is absent"))?;
        if kind == EventKind::Discontinuity {
            let (cause, evidence) = self
                .context
                .discontinuities
                .get(source_row)
                .copied()
                .flatten()
                .ok_or_else(|| AnalysisError::store_shape("discontinuity evidence is absent"))?;
            return Ok(TimelineRow::Discontinuity(DiscontinuityRow {
                source_row,
                key,
                provenance,
                cause,
                evidence,
            }));
        }
        Ok(TimelineRow::Event(EventRow {
            source_row,
            key,
            kind,
            provenance,
        }))
    }
}

impl Drop for TimelineProjection {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl AnalysisError {
    fn store_shape(detail: impl Into<String>) -> Self {
        Self {
            code: "analysis.store",
            detail: detail.into(),
        }
    }
}

pub fn query_events(
    projection: &TimelineProjection,
    cursor: Option<&PageCursor>,
    limit: usize,
) -> Result<EventPage, AnalysisError> {
    projection.page(cursor, limit)
}

fn build_query_context(
    store: Arc<dyn NormalizedBulkView + Send + Sync>,
    guard: &dyn WorkGuard,
) -> Result<QueryContext, AnalysisError> {
    let event_count = store.event_count();
    if event_count > MAX_CONTEXT_EVENTS {
        return Err(AnalysisError::resource_exhausted(
            "store event count exceeds context hard limit",
        ));
    }
    let typed_rows = store
        .module_rows()
        .len()
        .checked_add(store.definition_rows().len())
        .and_then(|count| count.checked_add(store.instruction_rows().len()))
        .and_then(|count| count.checked_add(store.memory_rows().len()))
        .and_then(|count| count.checked_add(store.semantic_rows().len()))
        .and_then(|count| count.checked_add(store.register_observation_rows().len()))
        .and_then(|count| count.checked_add(store.completeness().len()))
        .ok_or_else(|| AnalysisError::resource_exhausted("typed row count overflow"))?;
    if typed_rows > MAX_CONTEXT_TYPED_ROWS
        || store.string_count() > MAX_CONTEXT_DICTIONARY_ENTRIES
        || store.blob_count() > MAX_CONTEXT_DICTIONARY_ENTRIES
    {
        return Err(AnalysisError::resource_exhausted(
            "normalized store exceeds context hard limits",
        ));
    }
    let mut hash = Sha256::new();
    hash.update(b"qtrace-analysis/store-identity/v3\0sha256\0normalized-content-identity");
    let layout = store.normalized_layout_identity();
    hash.update(layout.schema_version().to_le_bytes());
    hash.update(layout.layout_fingerprint());
    hash.update(store.normalized_content_identity().as_bytes());
    hash.update([match store.normalized_source_format() {
        qtrace_store::NormalizedSourceFormat::Qtrb => 0,
        qtrace_store::NormalizedSourceFormat::Flight => 1,
        qtrace_store::NormalizedSourceFormat::Other => 2,
    }]);
    let mut keys = Vec::new();
    let mut kinds = Vec::new();
    let mut provenances = Vec::new();
    try_reserve_context(
        &mut keys,
        event_count,
        guard,
        "event-key map allocation failed",
    )?;
    try_reserve_context(
        &mut kinds,
        event_count,
        guard,
        "event-kind map allocation failed",
    )?;
    try_reserve_context(
        &mut provenances,
        event_count,
        guard,
        "provenance map allocation failed",
    )?;
    let mut observed_first = None::<u64>;
    let mut observed_last = None::<u64>;
    let mut max_sequence_count = 0_usize;
    for row in 0..event_count {
        if row % 4096 == 0 {
            consume_analysis_work(guard, (event_count - row).min(4096))?;
        }
        let key = required_event_key(store.as_ref(), row)?;
        if let Some(sequence) = key.sequence {
            observed_first = Some(observed_first.map_or(sequence, |first| first.min(sequence)));
            observed_last = Some(observed_last.map_or(sequence, |last| last.max(sequence)));
            if sequence == u64::MAX {
                max_sequence_count = max_sequence_count.checked_add(1).ok_or_else(|| {
                    AnalysisError::resource_exhausted("maximum-sequence row count overflow")
                })?;
            }
        }
        let kind = store
            .event_kind(row)
            .map_err(AnalysisError::store)?
            .ok_or_else(|| AnalysisError::store_shape("event kind is absent"))?;
        let provenance = store
            .provenance(row)
            .map_err(AnalysisError::store)?
            .ok_or_else(|| AnalysisError::store_shape("event provenance is absent"))?;
        keys.push(key);
        kinds.push(kind);
        provenances.push(provenance);
    }
    let mut max_sequence_rows = Vec::new();
    try_reserve_context(
        &mut max_sequence_rows,
        max_sequence_count,
        guard,
        "maximum-sequence row allocation failed",
    )?;
    for (row, key) in keys.iter().enumerate() {
        if row % 4096 == 0 {
            consume_analysis_work(guard, (keys.len() - row).min(4096))?;
        }
        if key.sequence == Some(u64::MAX) {
            max_sequence_rows.push(row);
        }
    }
    let identity = StoreIdentity(hash.finalize().into());

    let instructions = dense_owner_map(
        event_count,
        store.instruction_rows(),
        |row| row.owner_row,
        guard,
    )?;
    let memories = dense_owner_map(event_count, store.memory_rows(), |row| row.owner_row, guard)?;
    let semantics = dense_owner_map(
        event_count,
        store.semantic_rows(),
        |row| row.owner_row,
        guard,
    )?;
    let (observations, observation_ranges) =
        bucket_observations(event_count, store.register_observation_rows(), guard)?;
    let mut memory_pc = Vec::new();
    try_reserve_context(
        &mut memory_pc,
        store.memory_rows().len(),
        guard,
        "memory PC index allocation failed",
    )?;
    for (index, memory) in store.memory_rows().iter().enumerate() {
        if index % 4096 == 0 {
            consume_analysis_work(guard, (store.memory_rows().len() - index).min(4096))?;
        }
        if let Some(module) = memory.module {
            memory_pc.push(MemoryPcEntry {
                module,
                pc: memory.relative_pc,
                row: memory.owner_row,
            });
        }
    }
    radix_sort_memory_pc(&mut memory_pc, guard)?;
    let mut completeness_rows = try_clone_slice(
        store.completeness(),
        guard,
        "completeness summary allocation failed",
    )?;
    radix_sort_completeness(&mut completeness_rows, guard)?;
    let completeness = Arc::new(CompletenessSummary::new(
        completeness_rows,
        store.capabilities(),
        store.normalized_source_format(),
        observed_first.zip(observed_last),
    ));
    let discontinuities = Arc::new(map_discontinuities(store.as_ref(), event_count, guard)?);
    Ok(QueryContext {
        modules: try_clone_slice(store.module_rows(), guard, "module map allocation failed")?,
        definitions: try_clone_slice(
            store.definition_rows(),
            guard,
            "definition map allocation failed",
        )?,
        store,
        identity,
        keys,
        kinds,
        provenances,
        instructions,
        memories,
        semantics,
        observations,
        observation_ranges,
        memory_pc,
        max_sequence_rows,
        completeness,
        discontinuities,
    })
}

fn dense_owner_map<T: Copy>(
    event_count: usize,
    rows: &[T],
    owner: impl Fn(T) -> usize,
    guard: &dyn WorkGuard,
) -> Result<Vec<Option<T>>, AnalysisError> {
    let mut result = Vec::new();
    try_reserve_context(
        &mut result,
        event_count,
        guard,
        "typed owner map allocation failed",
    )?;
    result.resize(event_count, None);
    for (index, item) in rows.iter().copied().enumerate() {
        if index % 4096 == 0 {
            consume_analysis_work(guard, (rows.len() - index).min(4096))?;
        }
        let owner = owner(item);
        let slot = result
            .get_mut(owner)
            .ok_or_else(|| AnalysisError::store_shape("typed fact owner is out of bounds"))?;
        if slot.replace(item).is_some() {
            return Err(AnalysisError::store_shape(
                "typed fact owner appears more than once",
            ));
        }
    }
    Ok(result)
}

fn try_clone_slice<T: Clone>(
    rows: &[T],
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<Vec<T>, AnalysisError> {
    let mut result = Vec::new();
    try_reserve_context(&mut result, rows.len(), guard, detail)?;
    for chunk in rows.chunks(4096) {
        consume_analysis_work(guard, chunk.len())?;
        result.extend_from_slice(chunk);
    }
    Ok(result)
}

fn try_reserve_context<T>(
    values: &mut Vec<T>,
    additional: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<(), AnalysisError> {
    let required = values
        .len()
        .checked_add(additional)
        .ok_or_else(|| AnalysisError::resource_exhausted(detail))?;
    if required <= values.capacity() {
        return Ok(());
    }
    let bytes = required
        .checked_mul(std::mem::size_of::<T>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| AnalysisError::resource_exhausted(detail))?;
    let _scope = AllocationScope::begin(guard, bytes, 0).map_err(AnalysisError::control)?;
    values
        .try_reserve_exact(additional)
        .map_err(|_| AnalysisError::resource_exhausted(detail))
}

fn bucket_observations(
    event_count: usize,
    source: &[RegisterObservationRow],
    guard: &dyn WorkGuard,
) -> Result<ObservationBuckets, AnalysisError> {
    let mut counts = Vec::new();
    try_reserve_context(
        &mut counts,
        event_count,
        guard,
        "observation count allocation failed",
    )?;
    counts.resize(event_count, 0_usize);
    for (index, row) in source.iter().enumerate() {
        if index % 4096 == 0 {
            consume_analysis_work(guard, (source.len() - index).min(4096))?;
        }
        let count = counts.get_mut(row.owner_row).ok_or_else(|| {
            AnalysisError::store_shape("register observation owner is out of bounds")
        })?;
        *count = count
            .checked_add(1)
            .ok_or_else(|| AnalysisError::resource_exhausted("observation count overflow"))?;
    }
    let mut ranges = Vec::new();
    try_reserve_context(
        &mut ranges,
        event_count,
        guard,
        "observation range allocation failed",
    )?;
    let mut next = 0_usize;
    for (index, count) in counts.iter().enumerate() {
        if index % 4096 == 0 {
            consume_analysis_work(guard, (counts.len() - index).min(4096))?;
        }
        let end = next
            .checked_add(*count)
            .ok_or_else(|| AnalysisError::resource_exhausted("observation range overflow"))?;
        ranges.push((next, end));
        next = end;
    }
    let mut observations = Vec::new();
    try_reserve_context(
        &mut observations,
        source.len(),
        guard,
        "observation bucket allocation failed",
    )?;
    observations.resize(
        source.len(),
        RegisterObservationRow {
            owner_row: 0,
            slot: 0,
            captured_width: 0,
            access: RegisterAccess::Read,
            value: 0,
            provenance: Provenance::Unknown,
        },
    );
    let mut cursors = Vec::new();
    try_reserve_context(
        &mut cursors,
        event_count,
        guard,
        "observation cursor allocation failed",
    )?;
    for (index, (start, _)) in ranges.iter().copied().enumerate() {
        if index % 4096 == 0 {
            consume_analysis_work(guard, (ranges.len() - index).min(4096))?;
        }
        cursors.push(start);
    }
    for (index, row) in source.iter().copied().enumerate() {
        if index % 4096 == 0 {
            consume_analysis_work(guard, (source.len() - index).min(4096))?;
        }
        let cursor = &mut cursors[row.owner_row];
        observations[*cursor] = row;
        *cursor += 1;
    }
    Ok((observations, ranges))
}

fn radix_sort_memory_pc(
    rows: &mut Vec<MemoryPcEntry>,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    if rows.len() < 2 {
        return Ok(());
    }
    let mut scratch = Vec::new();
    try_reserve_context(
        &mut scratch,
        rows.len(),
        guard,
        "memory PC radix allocation failed",
    )?;
    scratch.resize(rows.len(), MemoryPcEntry::default());
    for pass in 0..12 {
        let mut counts = [0_usize; 256];
        for chunk in rows.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            for row in chunk {
                counts[memory_pc_byte(*row, pass) as usize] += 1;
            }
        }
        consume_analysis_work(guard, counts.len())?;
        let mut position = 0_usize;
        for count in &mut counts {
            let current = *count;
            *count = position;
            position += current;
        }
        for chunk in rows.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                let slot = &mut counts[memory_pc_byte(row, pass) as usize];
                scratch[*slot] = row;
                *slot += 1;
            }
        }
        std::mem::swap(rows, &mut scratch);
    }
    Ok(())
}

fn memory_pc_byte(row: MemoryPcEntry, pass: usize) -> u8 {
    if pass < 8 {
        row.pc.to_le_bytes()[pass]
    } else {
        row.module.to_le_bytes()[pass - 8]
    }
}

fn radix_sort_completeness(
    rows: &mut Vec<CompletenessRow>,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    if rows.len() < 2 {
        return Ok(());
    }
    let mut scratch = Vec::new();
    try_reserve_context(
        &mut scratch,
        rows.len(),
        guard,
        "completeness radix allocation failed",
    )?;
    scratch.resize(rows.len(), rows[0]);
    for pass in 0..19 {
        let mut counts = [0_usize; 256];
        for chunk in rows.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                counts[completeness_byte(row, pass) as usize] += 1;
            }
        }
        consume_analysis_work(guard, counts.len())?;
        let mut position = 0_usize;
        for count in &mut counts {
            let current = *count;
            *count = position;
            position += current;
        }
        for chunk in rows.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                let slot = &mut counts[completeness_byte(row, pass) as usize];
                scratch[*slot] = row;
                *slot += 1;
            }
        }
        std::mem::swap(rows, &mut scratch);
    }
    Ok(())
}

fn completeness_byte(row: CompletenessRow, pass: usize) -> u8 {
    let (domain, start, end, provenance, cause) = crate::provenance::completeness_key(&row);
    match pass {
        0 => cause,
        1 => provenance,
        2..=9 => end.to_le_bytes()[pass - 2],
        10..=17 => start.to_le_bytes()[pass - 10],
        18 => domain,
        _ => unreachable!("completeness radix has exactly 19 passes"),
    }
}

impl QueryContext {
    fn key(&self, row: usize) -> Result<&EventKey, AnalysisError> {
        self.keys
            .get(row)
            .ok_or_else(|| AnalysisError::store_shape("event key is absent"))
    }

    fn observations(&self, row: usize) -> &[RegisterObservationRow] {
        let (start, end) = self.observation_ranges.get(row).copied().unwrap_or((0, 0));
        &self.observations[start..end]
    }
}

fn derive_projection_identity(store: StoreIdentity, filter: &EventFilter) -> ProjectionIdentity {
    let mut hash = Sha256::new();
    hash.update(b"qtrace-analysis/projection-identity/v2\0sha256\0canonical-filter");
    hash.update(store.0);
    hash.update(filter.digest());
    ProjectionIdentity(hash.finalize().into())
}

#[derive(Debug)]
enum CandidateField {
    Tids,
    Kinds,
    Modules,
    Sequence,
    RelativePc,
    AbsolutePc,
    Definitions(Vec<u32>),
    RegisterReads,
    RegisterWrites,
    Memory,
    SemanticCategories,
    SemanticNames,
    SemanticDetailKinds,
}

struct CandidateLedger {
    work: AtomicU64,
    resident: AtomicU64,
    cancelled: Arc<AtomicBool>,
}

#[derive(Clone)]
struct CandidateGuard {
    ledger: Arc<CandidateLedger>,
}

impl CandidateGuard {
    fn new(cancelled: Arc<AtomicBool>) -> Self {
        Self {
            ledger: Arc::new(CandidateLedger {
                work: AtomicU64::new(0),
                resident: AtomicU64::new(0),
                cancelled,
            }),
        }
    }

    fn consume_rows(&self, rows: usize) -> Result<(), AnalysisError> {
        self.consume(WorkDelta {
            rows: u64::try_from(rows).unwrap_or(u64::MAX),
            ..WorkDelta::default()
        })
        .map_err(AnalysisError::control)
    }
}

impl WorkGuard for CandidateGuard {
    fn consume(&self, delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
        if self.ledger.cancelled.load(Ordering::Acquire) {
            return Err(qtrace_provider::OperationAbort::Cancelled);
        }
        let work_delta = delta
            .rows
            .saturating_add(delta.events)
            .saturating_add(delta.nodes)
            .saturating_add(delta.input_bytes)
            .saturating_add(delta.decompressed_bytes);
        let work = self
            .ledger
            .work
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |work| {
                Some(work.saturating_add(work_delta))
            })
            .unwrap_or_else(|work| work)
            .saturating_add(work_delta);
        if work > MAX_CANDIDATE_WORK as u64 {
            return Err(qtrace_provider::OperationAbort::budget_exceeded(
                qtrace_provider::BudgetDimension::Rows,
                MAX_CANDIDATE_WORK as u64,
                work,
            ));
        }
        if delta.resident_bytes != 0 {
            let resident = self
                .ledger
                .resident
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |resident| {
                    Some(resident.saturating_add(delta.resident_bytes))
                })
                .unwrap_or_else(|resident| resident)
                .saturating_add(delta.resident_bytes);
            if resident > MAX_CANDIDATE_RESIDENT_BYTES as u64 {
                return Err(qtrace_provider::OperationAbort::budget_exceeded(
                    qtrace_provider::BudgetDimension::ResidentBytes,
                    MAX_CANDIDATE_RESIDENT_BYTES as u64,
                    resident,
                ));
            }
        }
        Ok(())
    }
}

fn plan_candidates(
    context: &QueryContext,
    filter: &EventFilter,
    guard: &CandidateGuard,
) -> Result<(Vec<usize>, usize), AnalysisError> {
    let mut fields = Vec::new();
    try_reserve_analysis(&mut fields, 13, guard, "posting plan allocation failed")?;
    if !filter.tids.is_empty() {
        fields.push(CandidateField::Tids);
    }
    if !filter.kinds.is_empty() {
        fields.push(CandidateField::Kinds);
    }
    if !filter.modules.is_empty() {
        fields.push(CandidateField::Modules);
    }
    if !filter.sequence.is_empty() {
        fields.push(CandidateField::Sequence);
    }
    if !filter.relative_pc.is_empty() && !filter.modules.is_empty() {
        fields.push(CandidateField::RelativePc);
    }
    if !filter.absolute_pc.is_empty() {
        let modules = if filter.modules.is_empty() {
            context.modules.len()
        } else {
            filter.modules.len()
        };
        if modules.saturating_mul(filter.absolute_pc.len()) > 4_096 {
            return Err(AnalysisError::filter_too_complex(
                "absolute-PC module/range expansion exceeds 4096 pairs",
            ));
        }
        fields.push(CandidateField::AbsolutePc);
    }
    if !filter.mnemonic.is_empty() {
        let work = context
            .definitions
            .len()
            .checked_mul(filter.mnemonic.len())
            .filter(|work| *work <= MAX_CANDIDATE_WORK)
            .ok_or_else(|| {
                AnalysisError::resource_exhausted("mnemonic definition scan exceeds work budget")
            })?;
        guard.consume_rows(work)?;
        let mut definitions = Vec::new();
        try_reserve_analysis(
            &mut definitions,
            context.definitions.len(),
            guard,
            "definition match allocation failed",
        )?;
        for (definition_id, definition) in context.definitions.iter().enumerate() {
            if definition_id % 4096 == 0 {
                consume_analysis_work(
                    guard,
                    (context.definitions.len() - definition_id).min(4096),
                )?;
            }
            let mnemonic = context
                .store
                .string_bytes(definition.mnemonic)
                .map_err(AnalysisError::store)?;
            if mnemonic_matches(&filter.mnemonic, mnemonic) {
                definitions.push(
                    u32::try_from(definition_id)
                        .map_err(|_| AnalysisError::store_shape("definition ID exceeds u32"))?,
                );
            }
        }
        fields.push(CandidateField::Definitions(definitions));
    }
    if !filter.register.reads.is_empty() {
        fields.push(CandidateField::RegisterReads);
    }
    if !filter.register.writes.is_empty() {
        fields.push(CandidateField::RegisterWrites);
    }
    if !filter.memory.is_empty() {
        fields.push(CandidateField::Memory);
    }
    if !filter.semantic_categories.is_empty() {
        preflight_semantic_lookup(context, filter.semantic_categories.len())?;
        fields.push(CandidateField::SemanticCategories);
    }
    if !filter.semantic_names.is_empty() {
        preflight_semantic_lookup(context, filter.semantic_names.len())?;
        fields.push(CandidateField::SemanticNames);
    }
    if filter.has_semantic_detail_residual() {
        fields.push(CandidateField::SemanticDetailKinds);
    }

    let mut planned = Vec::new();
    try_reserve_analysis(
        &mut planned,
        fields.len(),
        guard,
        "posting estimate allocation failed",
    )?;
    let mut estimated_decode_rows = 0_usize;
    for field in fields {
        let count = estimate_candidate_field(context, filter, &field, guard)?;
        checked_estimate_add(&mut estimated_decode_rows, count)?;
        planned.push((count, field));
    }
    for index in 1..planned.len() {
        let mut cursor = index;
        while cursor > 0 {
            consume_analysis_work(guard, 1)?;
            if planned[cursor - 1].0 <= planned[cursor].0 {
                break;
            }
            planned.swap(cursor - 1, cursor);
            cursor -= 1;
        }
    }
    let indexed_fields = planned.len();

    let mut candidates = if let Some((_, field)) = planned.first() {
        decode_candidate_field(context, filter, field, guard)?
    } else {
        let count = context.store.event_count();
        if count > MAX_CANDIDATE_ROWS {
            return Err(AnalysisError::resource_exhausted(
                "unindexed candidate set exceeds 10000000 rows",
            ));
        }
        guard.consume_rows(count)?;
        let mut rows = Vec::new();
        try_reserve_analysis(&mut rows, count, guard, "candidate row allocation failed")?;
        rows.extend(0..count);
        rows
    };
    for (_, field) in planned.iter().skip(1) {
        if candidates.is_empty() {
            break;
        }
        let group = decode_candidate_field(context, filter, field, guard)?;
        candidates = intersect_rows_fallible_guarded(&candidates, &group, guard)?;
    }
    Ok((candidates, indexed_fields))
}

fn try_reserve_analysis<T>(
    values: &mut Vec<T>,
    additional: usize,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<(), AnalysisError> {
    try_reserve_context(values, additional, guard, detail)
}

fn consume_analysis_work(guard: &dyn WorkGuard, work: usize) -> Result<(), AnalysisError> {
    guard
        .consume(WorkDelta {
            rows: u64::try_from(work).unwrap_or(u64::MAX),
            ..WorkDelta::default()
        })
        .map_err(AnalysisError::control)
}

fn dedup_sorted_rows_guarded(
    rows: &mut Vec<usize>,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    if rows.len() < 2 {
        return Ok(());
    }
    let mut output = 1_usize;
    let mut input = 1_usize;
    while input < rows.len() {
        let end = (input + 4096).min(rows.len());
        consume_analysis_work(guard, end - input)?;
        while input < end {
            if rows[input] != rows[output - 1] {
                rows[output] = rows[input];
                output += 1;
            }
            input += 1;
        }
    }
    rows.truncate(output);
    Ok(())
}

fn try_reserve_posting_lists(
    lists: &mut Vec<Vec<usize>>,
    capacity: usize,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    try_reserve_analysis(lists, capacity, guard, "posting list allocation failed")
}

fn borrowed_filter_bytes<'a>(
    values: &'a [String],
    guard: &dyn WorkGuard,
) -> Result<Vec<&'a [u8]>, AnalysisError> {
    let mut bytes = Vec::new();
    try_reserve_analysis(
        &mut bytes,
        values.len(),
        guard,
        "semantic filter reference allocation failed",
    )?;
    bytes.extend(values.iter().map(String::as_bytes));
    Ok(bytes)
}

fn estimate_posting(
    store: &dyn NormalizedBulkView,
    query: NormalizedPostingQuery<'_>,
    guard: &CandidateGuard,
) -> Result<usize, AnalysisError> {
    store
        .bounded_row_count(query, MAX_CANDIDATE_ROWS, guard)
        .map_err(map_store_query_error)
}

fn checked_estimate_add(total: &mut usize, value: usize) -> Result<(), AnalysisError> {
    *total = total
        .checked_add(value)
        .filter(|total| *total <= MAX_CANDIDATE_WORK)
        .ok_or_else(|| {
            AnalysisError::resource_exhausted("posting estimate exceeds candidate work budget")
        })?;
    Ok(())
}

fn estimate_candidate_field(
    context: &QueryContext,
    filter: &EventFilter,
    field: &CandidateField,
    guard: &CandidateGuard,
) -> Result<usize, AnalysisError> {
    let store = context.store.as_ref();
    let mut total = 0;
    match field {
        CandidateField::Tids => {
            total = estimate_posting(store, NormalizedPostingQuery::Tids(&filter.tids), guard)?;
        }
        CandidateField::Kinds => {
            total = estimate_posting(store, NormalizedPostingQuery::Kinds(&filter.kinds), guard)?;
        }
        CandidateField::Modules => {
            checked_estimate_add(
                &mut total,
                estimate_posting(
                    store,
                    NormalizedPostingQuery::Modules(&filter.modules),
                    guard,
                )?,
            )?;
            for module in &filter.modules {
                checked_estimate_add(&mut total, memory_module_count(context, *module))?;
            }
        }
        CandidateField::Sequence => {
            for range in &filter.sequence {
                checked_estimate_add(
                    &mut total,
                    estimate_posting(
                        store,
                        NormalizedPostingQuery::Sequence {
                            start: range.first,
                            end_exclusive: range.last.saturating_add(1),
                        },
                        guard,
                    )?,
                )?;
                if range.last == u64::MAX {
                    checked_estimate_add(&mut total, context.max_sequence_rows.len())?;
                }
            }
        }
        CandidateField::RelativePc => {
            for module in &filter.modules {
                for range in &filter.relative_pc {
                    checked_estimate_add(
                        &mut total,
                        estimate_posting(
                            store,
                            NormalizedPostingQuery::ModulePc {
                                module: *module,
                                start: range.start,
                                end_exclusive: range.end_exclusive,
                            },
                            guard,
                        )?,
                    )?;
                    checked_estimate_add(
                        &mut total,
                        memory_pc_count(context, *module, range.start, range.end_exclusive),
                    )?;
                }
            }
        }
        CandidateField::AbsolutePc => {
            visit_absolute_pairs(context, filter, |module, start, end| {
                checked_estimate_add(
                    &mut total,
                    estimate_posting(
                        store,
                        NormalizedPostingQuery::ModulePc {
                            module,
                            start,
                            end_exclusive: end,
                        },
                        guard,
                    )?,
                )?;
                checked_estimate_add(&mut total, memory_pc_count(context, module, start, end))
            })?;
        }
        CandidateField::Definitions(definitions) => {
            total = estimate_posting(
                store,
                NormalizedPostingQuery::Definitions(definitions),
                guard,
            )?;
        }
        CandidateField::RegisterReads => {
            total = estimate_posting(
                store,
                NormalizedPostingQuery::Registers(&filter.register.reads),
                guard,
            )?;
        }
        CandidateField::RegisterWrites => {
            total = estimate_posting(
                store,
                NormalizedPostingQuery::Registers(&filter.register.writes),
                guard,
            )?;
        }
        CandidateField::Memory => {
            for memory in &filter.memory {
                checked_estimate_add(
                    &mut total,
                    estimate_posting(
                        store,
                        NormalizedPostingQuery::Memory {
                            start: memory.range.start,
                            end_exclusive: memory.range.end_exclusive,
                        },
                        guard,
                    )?,
                )?;
            }
        }
        CandidateField::SemanticCategories => {
            let values = borrowed_filter_bytes(&filter.semantic_categories, guard)?;
            total = estimate_posting(
                store,
                NormalizedPostingQuery::SemanticCategories(&values),
                guard,
            )?;
        }
        CandidateField::SemanticNames => {
            let values = borrowed_filter_bytes(&filter.semantic_names, guard)?;
            total = estimate_posting(store, NormalizedPostingQuery::SemanticNames(&values), guard)?;
        }
        CandidateField::SemanticDetailKinds => {
            total = estimate_posting(
                store,
                NormalizedPostingQuery::Kinds(&[
                    EventKind::SemanticCall,
                    EventKind::SemanticRule,
                    EventKind::SemanticError,
                ]),
                guard,
            )?;
        }
    }
    Ok(total)
}

fn decode_candidate_field(
    context: &QueryContext,
    filter: &EventFilter,
    field: &CandidateField,
    guard: &CandidateGuard,
) -> Result<Vec<usize>, AnalysisError> {
    let store = context.store.as_ref();
    let direct = |query| bounded_rows_guarded(store, query, guard);
    let mut lists = Vec::new();
    let list_capacity = match field {
        CandidateField::Modules => filter.modules.len().checked_add(1),
        CandidateField::Sequence => Some(filter.sequence.len()),
        CandidateField::RelativePc => filter
            .modules
            .len()
            .checked_mul(filter.relative_pc.len())
            .and_then(|pairs| pairs.checked_mul(2)),
        CandidateField::AbsolutePc => {
            let modules = if filter.modules.is_empty() {
                context.modules.len()
            } else {
                filter.modules.len()
            };
            modules
                .checked_mul(filter.absolute_pc.len())
                .and_then(|pairs| pairs.checked_mul(2))
        }
        CandidateField::Memory => Some(filter.memory.len()),
        _ => Some(0),
    }
    .ok_or_else(|| AnalysisError::resource_exhausted("posting list count overflow"))?;
    try_reserve_posting_lists(&mut lists, list_capacity, guard)?;
    match field {
        CandidateField::Tids => return direct(NormalizedPostingQuery::Tids(&filter.tids)),
        CandidateField::Kinds => return direct(NormalizedPostingQuery::Kinds(&filter.kinds)),
        CandidateField::Modules => {
            lists.push(direct(NormalizedPostingQuery::Modules(&filter.modules))?);
            for module in &filter.modules {
                lists.push(memory_module_rows_guarded(context, *module, guard)?);
            }
        }
        CandidateField::Sequence => {
            for range in &filter.sequence {
                let mut rows = direct(NormalizedPostingQuery::Sequence {
                    start: range.first,
                    end_exclusive: range.last.saturating_add(1),
                })?;
                if range.last == u64::MAX {
                    try_reserve_analysis(
                        &mut rows,
                        context.max_sequence_rows.len(),
                        guard,
                        "maximum-sequence union allocation failed",
                    )?;
                    rows.extend_from_slice(&context.max_sequence_rows);
                    radix_sort_usize_guarded(&mut rows, guard)?;
                    dedup_sorted_rows_guarded(&mut rows, guard)?;
                }
                lists.push(rows);
            }
        }
        CandidateField::RelativePc => {
            for module in &filter.modules {
                for range in &filter.relative_pc {
                    lists.push(direct(NormalizedPostingQuery::ModulePc {
                        module: *module,
                        start: range.start,
                        end_exclusive: range.end_exclusive,
                    })?);
                    lists.push(memory_pc_rows_guarded(
                        context,
                        *module,
                        range.start,
                        range.end_exclusive,
                        guard,
                    )?);
                }
            }
        }
        CandidateField::AbsolutePc => {
            visit_absolute_pairs(context, filter, |module, start, end| {
                lists.push(direct(NormalizedPostingQuery::ModulePc {
                    module,
                    start,
                    end_exclusive: end,
                })?);
                lists.push(memory_pc_rows_guarded(context, module, start, end, guard)?);
                Ok(())
            })?;
        }
        CandidateField::Definitions(definitions) => {
            return direct(NormalizedPostingQuery::Definitions(definitions));
        }
        CandidateField::RegisterReads => {
            return direct(NormalizedPostingQuery::Registers(&filter.register.reads));
        }
        CandidateField::RegisterWrites => {
            return direct(NormalizedPostingQuery::Registers(&filter.register.writes));
        }
        CandidateField::Memory => {
            for memory in &filter.memory {
                lists.push(direct(NormalizedPostingQuery::Memory {
                    start: memory.range.start,
                    end_exclusive: memory.range.end_exclusive,
                })?);
            }
        }
        CandidateField::SemanticCategories => {
            let values = borrowed_filter_bytes(&filter.semantic_categories, guard)?;
            return direct(NormalizedPostingQuery::SemanticCategories(&values));
        }
        CandidateField::SemanticNames => {
            let values = borrowed_filter_bytes(&filter.semantic_names, guard)?;
            return direct(NormalizedPostingQuery::SemanticNames(&values));
        }
        CandidateField::SemanticDetailKinds => {
            return direct(NormalizedPostingQuery::Kinds(&[
                EventKind::SemanticCall,
                EventKind::SemanticRule,
                EventKind::SemanticError,
            ]));
        }
    }
    union_rows_guarded(lists, guard)
}

fn visit_absolute_pairs(
    context: &QueryContext,
    filter: &EventFilter,
    mut visit: impl FnMut(u32, u64, u64) -> Result<(), AnalysisError>,
) -> Result<(), AnalysisError> {
    let mut visit_module = |module_id: u32| -> Result<(), AnalysisError> {
        let Some(module) = context.modules.get(module_id as usize) else {
            return Ok(());
        };
        for absolute in &filter.absolute_pc {
            if absolute.end_exclusive <= module.base {
                continue;
            }
            visit(
                module_id,
                absolute.start.saturating_sub(module.base),
                absolute.end_exclusive - module.base,
            )?;
        }
        Ok(())
    };
    if filter.modules.is_empty() {
        for module in 0..context.modules.len() {
            visit_module(
                u32::try_from(module)
                    .map_err(|_| AnalysisError::store_shape("module ID exceeds u32"))?,
            )?;
        }
    } else {
        for module in &filter.modules {
            visit_module(*module)?;
        }
    }
    Ok(())
}

fn memory_pc_count(context: &QueryContext, module: u32, start: u64, end: u64) -> usize {
    let first = context.memory_pc.partition_point(|entry| {
        entry.module < module || entry.module == module && entry.pc < start
    });
    let last = context
        .memory_pc
        .partition_point(|entry| entry.module < module || entry.module == module && entry.pc < end);
    last - first
}

fn memory_module_count(context: &QueryContext, module: u32) -> usize {
    let first = context
        .memory_pc
        .partition_point(|entry| entry.module < module);
    let last = context
        .memory_pc
        .partition_point(|entry| entry.module <= module);
    last - first
}

fn bounded_rows_guarded(
    store: &dyn NormalizedBulkView,
    query: NormalizedPostingQuery<'_>,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, AnalysisError> {
    let rows = store
        .bounded_rows(query, MAX_CANDIDATE_ROWS, guard)
        .map_err(map_store_query_error)?;
    if rows.len() > MAX_CANDIDATE_ROWS {
        return Err(AnalysisError::resource_exhausted(
            "posting result exceeds row limit",
        ));
    }
    Ok(rows)
}

fn intersect_rows_fallible_guarded(
    left: &[usize],
    right: &[usize],
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, AnalysisError> {
    let mut result = Vec::new();
    try_reserve_analysis(
        &mut result,
        left.len().min(right.len()),
        guard,
        "posting intersection allocation failed",
    )?;
    let (mut left_index, mut right_index) = (0, 0);
    let mut pending_work = 0_usize;
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => {
                result.push(left[left_index]);
                left_index += 1;
                right_index += 1;
            }
        }
        pending_work += 1;
        if pending_work == 4096 {
            consume_analysis_work(guard, pending_work)?;
            pending_work = 0;
        }
    }
    consume_analysis_work(guard, pending_work)?;
    Ok(result)
}

fn preflight_semantic_lookup(context: &QueryContext, terms: usize) -> Result<(), AnalysisError> {
    if context
        .store
        .string_count()
        .checked_mul(terms)
        .is_none_or(|work| work > MAX_CANDIDATE_WORK)
    {
        return Err(AnalysisError::resource_exhausted(
            "semantic dictionary lookup exceeds work budget",
        ));
    }
    Ok(())
}

fn map_store_query_error(error: qtrace_store::IndexError) -> AnalysisError {
    match error.code() {
        "job.cancelled" => AnalysisError {
            code: "job.cancelled",
            detail: error.to_string(),
        },
        "control.resource_exhausted" | "control.budget_exceeded" => {
            AnalysisError::resource_exhausted(error.to_string())
        }
        _ => AnalysisError::store(error),
    }
}

fn memory_pc_rows_guarded(
    context: &QueryContext,
    module: u32,
    start: u64,
    end: u64,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, AnalysisError> {
    let first = context.memory_pc.partition_point(|entry| {
        entry.module < module || entry.module == module && entry.pc < start
    });
    let last = context
        .memory_pc
        .partition_point(|entry| entry.module < module || entry.module == module && entry.pc < end);
    let mut result = Vec::new();
    try_reserve_analysis(
        &mut result,
        last - first,
        guard,
        "memory PC posting allocation failed",
    )?;
    for chunk in context.memory_pc[first..last].chunks(4096) {
        consume_analysis_work(guard, chunk.len())?;
        result.extend(chunk.iter().map(|entry| entry.row));
    }
    radix_sort_usize_guarded(&mut result, guard)?;
    dedup_sorted_rows_guarded(&mut result, guard)?;
    Ok(result)
}

fn memory_module_rows_guarded(
    context: &QueryContext,
    module: u32,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, AnalysisError> {
    let first = context
        .memory_pc
        .partition_point(|entry| entry.module < module);
    let last = context
        .memory_pc
        .partition_point(|entry| entry.module <= module);
    if last - first > MAX_CANDIDATE_ROWS {
        return Err(AnalysisError::resource_exhausted(
            "memory module posting exceeds row limit",
        ));
    }
    let mut rows = Vec::new();
    try_reserve_analysis(
        &mut rows,
        last - first,
        guard,
        "memory module posting allocation failed",
    )?;
    for chunk in context.memory_pc[first..last].chunks(4096) {
        consume_analysis_work(guard, chunk.len())?;
        rows.extend(chunk.iter().map(|entry| entry.row));
    }
    radix_sort_usize_guarded(&mut rows, guard)?;
    dedup_sorted_rows_guarded(&mut rows, guard)?;
    Ok(rows)
}

fn union_rows_guarded(
    lists: Vec<Vec<usize>>,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, AnalysisError> {
    let work = lists
        .iter()
        .try_fold(0_usize, |total, rows| total.checked_add(rows.len()));
    let Some(work) = work.filter(|work| *work <= MAX_CANDIDATE_WORK) else {
        return Err(AnalysisError::resource_exhausted(
            "posting union exceeds candidate work budget",
        ));
    };
    let mut rows = Vec::new();
    try_reserve_analysis(&mut rows, work, guard, "posting union allocation failed")?;
    for list in lists {
        for chunk in list.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            rows.extend_from_slice(chunk);
        }
    }
    radix_sort_usize_guarded(&mut rows, guard)?;
    dedup_sorted_rows_guarded(&mut rows, guard)?;
    Ok(rows)
}

fn radix_sort_usize_guarded(
    rows: &mut Vec<usize>,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    if rows.len() < 2 {
        return Ok(());
    }
    let mut scratch = Vec::new();
    try_reserve_analysis(
        &mut scratch,
        rows.len(),
        guard,
        "row radix allocation failed",
    )?;
    scratch.resize(rows.len(), 0);
    for pass in 0..std::mem::size_of::<usize>() {
        let mut counts = [0_usize; 256];
        for chunk in rows.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                counts[row.to_le_bytes()[pass] as usize] += 1;
            }
        }
        consume_analysis_work(guard, counts.len())?;
        let mut position = 0;
        for count in &mut counts {
            let current = *count;
            *count = position;
            position += current;
        }
        for chunk in rows.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                let slot = &mut counts[row.to_le_bytes()[pass] as usize];
                scratch[*slot] = row;
                *slot += 1;
            }
        }
        std::mem::swap(rows, &mut scratch);
    }
    Ok(())
}

fn apply_synchronous_residuals(
    context: &QueryContext,
    filter: &EventFilter,
    candidates: Vec<usize>,
    guard: &CandidateGuard,
) -> Result<Vec<usize>, AnalysisError> {
    if filter.relative_pc.is_empty()
        && filter.register.reads.is_empty()
        && filter.register.writes.is_empty()
        && filter.memory.is_empty()
    {
        return Ok(candidates);
    }
    retain_rows_guarded(candidates, guard, |row| {
        matches_non_detail(context, filter, row)
    })
}

fn retain_rows_guarded(
    candidates: Vec<usize>,
    guard: &dyn WorkGuard,
    mut predicate: impl FnMut(usize) -> Result<bool, AnalysisError>,
) -> Result<Vec<usize>, AnalysisError> {
    let mut matched = Vec::new();
    try_reserve_analysis(
        &mut matched,
        candidates.len(),
        guard,
        "residual result allocation failed",
    )?;
    let mut candidates = candidates.into_iter();
    while !candidates.as_slice().is_empty() {
        let chunk = candidates.as_slice().len().min(4096);
        consume_analysis_work(guard, chunk)?;
        for row in candidates.by_ref().take(chunk) {
            if predicate(row)? {
                matched.push(row);
            }
        }
    }
    Ok(matched)
}

fn synchronous_residual_filter(filter: &EventFilter) -> EventFilter {
    EventFilter {
        relative_pc: if filter.modules.is_empty() {
            filter.relative_pc.clone()
        } else {
            Vec::new()
        },
        register: filter.register.clone(),
        memory: filter.memory.clone(),
        ..EventFilter::default()
    }
}

fn matches_non_detail(
    context: &QueryContext,
    filter: &EventFilter,
    row: usize,
) -> Result<bool, AnalysisError> {
    let store = context.store.as_ref();
    let key = context.key(row)?;
    if !filter.tids.is_empty() && !key.tid.is_some_and(|tid| filter.tids.contains(&tid)) {
        return Ok(false);
    }
    let kind = *context
        .kinds
        .get(row)
        .ok_or_else(|| AnalysisError::store_shape("event kind is absent"))?;
    if !filter.kinds.is_empty() && !filter.kinds.contains(&kind) {
        return Ok(false);
    }
    let position = context
        .instructions
        .get(row)
        .copied()
        .flatten()
        .map(|fact| (fact.module, fact.relative_pc))
        .or_else(|| {
            context
                .memories
                .get(row)
                .copied()
                .flatten()
                .map(|fact| (fact.module, fact.relative_pc))
        });
    if !filter.modules.is_empty()
        && !position
            .and_then(|(module, _)| module)
            .is_some_and(|module| filter.modules.contains(&module))
    {
        return Ok(false);
    }
    if !filter.relative_pc.is_empty()
        && !position.is_some_and(|(_, pc)| address_matches(&filter.relative_pc, pc))
    {
        return Ok(false);
    }
    if !filter.absolute_pc.is_empty()
        && !position.is_some_and(|(module, relative)| {
            module
                .and_then(|module| store.module(module))
                .and_then(|module| module.base.checked_add(relative))
                .is_some_and(|pc| address_matches(&filter.absolute_pc, pc))
        })
    {
        return Ok(false);
    }
    if !filter.sequence.is_empty()
        && !key.sequence.is_some_and(|sequence| {
            filter
                .sequence
                .iter()
                .any(|range| range.first <= sequence && sequence <= range.last)
        })
    {
        return Ok(false);
    }
    if !filter.mnemonic.is_empty() {
        let matches = context
            .instructions
            .get(row)
            .copied()
            .flatten()
            .and_then(|fact| fact.definition)
            .and_then(|definition| store.definition(definition))
            .map(|definition| {
                store
                    .string_bytes(definition.mnemonic)
                    .map(|bytes| mnemonic_matches(&filter.mnemonic, bytes))
                    .map_err(AnalysisError::store)
            })
            .transpose()?
            .unwrap_or(false);
        if !matches {
            return Ok(false);
        }
    }
    if !register_access_matches(context, row, &filter.register.reads, RegisterAccess::Read)
        || !register_access_matches(context, row, &filter.register.writes, RegisterAccess::Write)
    {
        return Ok(false);
    }
    if !filter.memory.is_empty()
        && !context
            .memories
            .get(row)
            .copied()
            .flatten()
            .is_some_and(|memory| {
                filter
                    .memory
                    .iter()
                    .any(|query| memory_matches(query, memory))
            })
    {
        return Ok(false);
    }
    if !filter.semantic_categories.is_empty()
        && !context
            .semantics
            .get(row)
            .copied()
            .flatten()
            .and_then(|semantic| semantic.category)
            .is_some_and(|id| {
                store.string_bytes(id).is_ok_and(|value| {
                    filter
                        .semantic_categories
                        .iter()
                        .any(|candidate| candidate.as_bytes() == value)
                })
            })
    {
        return Ok(false);
    }
    if !filter.semantic_names.is_empty()
        && !context
            .semantics
            .get(row)
            .copied()
            .flatten()
            .is_some_and(|semantic| {
                store.string_bytes(semantic.name).is_ok_and(|value| {
                    filter
                        .semantic_names
                        .iter()
                        .any(|candidate| candidate.as_bytes() == value)
                })
            })
    {
        return Ok(false);
    }
    Ok(true)
}

fn address_matches(ranges: &[crate::AddressRange], value: u64) -> bool {
    ranges
        .iter()
        .any(|range| range.start <= value && value < range.end_exclusive)
}

fn register_access_matches(
    context: &QueryContext,
    row: usize,
    slots: &[RegisterSlot],
    access: RegisterAccess,
) -> bool {
    slots.is_empty()
        || context.observations(row).iter().any(|observation| {
            observation.access == access
                && slots
                    .iter()
                    .any(|slot| slot.index() == observation.slot as usize)
        })
}

fn memory_matches(query: &MemoryFilter, memory: qtrace_store::MemoryRow) -> bool {
    memory.address < query.range.end_exclusive
        && query.range.start < memory.end_exclusive
        && (query.directions.is_empty()
            || query
                .directions
                .iter()
                .any(|direction| direction_matches(*direction, memory.direction)))
}

fn direction_matches(query: MemoryDirection, actual: MemoryDirection) -> bool {
    query == actual
        || actual == MemoryDirection::ReadWrite
            && matches!(query, MemoryDirection::Read | MemoryDirection::Write)
}

fn mnemonic_matches(filters: &[MnemonicFilter], mnemonic: &[u8]) -> bool {
    filters.iter().any(|filter| match filter {
        MnemonicFilter::Exact(value) => mnemonic.eq_ignore_ascii_case(value.as_bytes()),
        MnemonicFilter::Contains(value) => mnemonic
            .windows(value.len())
            .any(|window| window.eq_ignore_ascii_case(value.as_bytes())),
    })
}

fn sort_rows_by_stable_key(
    context: &QueryContext,
    rows: Vec<usize>,
    guard: &CandidateGuard,
) -> Result<Vec<usize>, AnalysisError> {
    radix_sort_rows_by_keys_guarded(&context.keys, rows, guard)
}

#[cfg(test)]
fn radix_sort_rows_by_keys(
    keys: &[EventKey],
    rows: Vec<usize>,
) -> Result<Vec<usize>, AnalysisError> {
    radix_sort_rows_by_keys_guarded(keys, rows, &AllowContextWork)
}

fn radix_sort_rows_by_keys_guarded(
    keys: &[EventKey],
    mut rows: Vec<usize>,
    guard: &dyn WorkGuard,
) -> Result<Vec<usize>, AnalysisError> {
    if rows.len() < 2 {
        return Ok(rows);
    }
    if rows.iter().any(|row| *row >= keys.len()) {
        return Err(AnalysisError::store_shape(
            "candidate row is outside the event-key map",
        ));
    }
    let mut scratch = Vec::new();
    try_reserve_analysis(
        &mut scratch,
        rows.len(),
        guard,
        "stable-key sort allocation failed",
    )?;
    scratch.resize(rows.len(), 0);
    for pass in 0..70 {
        let mut counts = [0_usize; 256];
        for chunk in rows.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                counts[stable_key_byte(&keys[row], pass) as usize] += 1;
            }
        }
        consume_analysis_work(guard, counts.len())?;
        let mut position = 0;
        for count in &mut counts {
            let current = *count;
            *count = position;
            position += current;
        }
        for chunk in rows.chunks(4096) {
            consume_analysis_work(guard, chunk.len())?;
            for row in chunk.iter().copied() {
                let slot = &mut counts[stable_key_byte(&keys[row], pass) as usize];
                scratch[*slot] = row;
                *slot += 1;
            }
        }
        std::mem::swap(&mut rows, &mut scratch);
    }
    Ok(rows)
}

fn stable_key_byte(key: &EventKey, pass: usize) -> u8 {
    match pass {
        0..=3 => key.tid.unwrap_or_default().to_le_bytes()[pass],
        4 => u8::from(key.tid.is_some()),
        5..=12 => key.sequence.unwrap_or_default().to_le_bytes()[pass - 5],
        13 => u8::from(key.sequence.is_some()),
        14..=21 => key.source_offset.to_le_bytes()[pass - 14],
        22..=29 => key.record_ordinal.to_le_bytes()[pass - 22],
        30..=37 => key.timeline.0.to_le_bytes()[pass - 30],
        38..=69 => key.artifact.as_bytes()[69 - pass],
        _ => unreachable!("stable key radix has exactly 70 passes"),
    }
}

fn map_discontinuities(
    store: &dyn NormalizedBulkView,
    event_count: usize,
    guard: &dyn WorkGuard,
) -> Result<Vec<Option<(qtrace_provider::DiscontinuityCause, CompletenessRow)>>, AnalysisError> {
    let rows = store
        .bounded_rows(
            NormalizedPostingQuery::Kinds(&[EventKind::Discontinuity]),
            event_count.min(MAX_CANDIDATE_ROWS),
            guard,
        )
        .map_err(map_store_query_error)?;
    let mut result = Vec::new();
    try_reserve_context(
        &mut result,
        event_count,
        guard,
        "discontinuity map allocation failed",
    )?;
    result.resize(event_count, None);
    let mut payload_bytes = 0_usize;
    let row_count = rows.len();
    for (index, row) in rows.into_iter().enumerate() {
        if index % 4096 == 0 {
            consume_analysis_work(guard, (row_count - index).min(4096))?;
        }
        let payload = store.payload_bytes(row).map_err(AnalysisError::store)?;
        if payload.len() > MAX_DISCONTINUITY_PAYLOAD_BYTES {
            return Err(AnalysisError::resource_exhausted(
                "discontinuity payload exceeds 1 MiB",
            ));
        }
        payload_bytes = payload_bytes
            .checked_add(payload.len())
            .filter(|bytes| *bytes <= MAX_DISCONTINUITY_TOTAL_BYTES)
            .ok_or_else(|| {
                AnalysisError::resource_exhausted(
                    "discontinuity payloads exceed 16 MiB context limit",
                )
            })?;
        for chunk in payload.chunks(4096) {
            guard
                .consume(WorkDelta {
                    input_bytes: chunk.len() as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::control)?;
        }
        validate_discontinuity_payload_tag(payload)?;
        for chunk in payload.chunks(4096) {
            guard
                .consume(WorkDelta {
                    input_bytes: chunk.len() as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::control)?;
        }
        let discontinuity = decode_discontinuity_payload_body(payload)?;
        let evidence = CompletenessRow {
            domain: discontinuity.evidence.domain(),
            bounds: discontinuity.evidence.bounds(),
            provenance: discontinuity.evidence.provenance(),
            cause: discontinuity.evidence.cause(),
        };
        let slot = result
            .get_mut(row)
            .ok_or_else(|| AnalysisError::store_shape("discontinuity row is out of bounds"))?;
        *slot = Some((discontinuity.cause, evidence));
    }
    Ok(result)
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClosedPayloadTag {
    Begin(serde::de::IgnoredAny),
    ModuleDefinition(serde::de::IgnoredAny),
    InstructionDefinition(serde::de::IgnoredAny),
    Instruction(serde::de::IgnoredAny),
    Memory(serde::de::IgnoredAny),
    SemanticCall(serde::de::IgnoredAny),
    SemanticRule(serde::de::IgnoredAny),
    SemanticError(serde::de::IgnoredAny),
    ThreadLifecycle(serde::de::IgnoredAny),
    Syscall(serde::de::IgnoredAny),
    Signal(serde::de::IgnoredAny),
    SignalHandlerBoundary(serde::de::IgnoredAny),
    Termination(serde::de::IgnoredAny),
    RegisterCheckpoint(serde::de::IgnoredAny),
    RegisterDelta(serde::de::IgnoredAny),
    StringDefinition(serde::de::IgnoredAny),
    CoverageGap(serde::de::IgnoredAny),
    Discontinuity(serde::de::IgnoredAny),
    OpaqueOptional(serde::de::IgnoredAny),
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum BorrowedDiscontinuityPayload {
    Discontinuity(BorrowedDiscontinuity),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BorrowedDiscontinuity {
    cause: qtrace_provider::DiscontinuityCause,
    evidence: qtrace_provider::CompletenessRange,
}

#[cfg(test)]
fn decode_discontinuity_payload(payload: &[u8]) -> Result<BorrowedDiscontinuity, AnalysisError> {
    validate_discontinuity_payload_tag(payload)?;
    decode_discontinuity_payload_body(payload)
}

fn validate_discontinuity_payload_tag(payload: &[u8]) -> Result<(), AnalysisError> {
    let tag: ClosedPayloadTag = serde_json::from_slice(payload).map_err(|error| {
        AnalysisError::store_shape(format!("invalid discontinuity payload tag: {error}"))
    })?;
    if !matches!(tag, ClosedPayloadTag::Discontinuity(_)) {
        return Err(AnalysisError::store_shape(
            "discontinuity row payload has the wrong event kind",
        ));
    }
    Ok(())
}

fn decode_discontinuity_payload_body(
    payload: &[u8],
) -> Result<BorrowedDiscontinuity, AnalysisError> {
    let BorrowedDiscontinuityPayload::Discontinuity(discontinuity) =
        serde_json::from_slice(payload).map_err(|error| {
            AnalysisError::store_shape(format!("invalid discontinuity payload: {error}"))
        })?;
    Ok(discontinuity)
}

struct SemanticJob {
    run: Option<Box<dyn FnOnce() + Send + 'static>>,
    on_failure: Option<Box<dyn FnOnce(AnalysisError) + Send + 'static>>,
}

impl SemanticJob {
    fn new(
        run: impl FnOnce() + Send + 'static,
        on_failure: impl FnOnce(AnalysisError) + Send + 'static,
    ) -> Self {
        Self {
            run: Some(Box::new(run)),
            on_failure: Some(Box::new(on_failure)),
        }
    }

    #[cfg(test)]
    fn plain(run: impl FnOnce() + Send + 'static) -> Self {
        Self::new(run, |_| {})
    }

    fn execute(mut self) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run.take().expect("semantic job is run once")();
        }));
        if result.is_err()
            && let Some(on_failure) = self.on_failure.take()
        {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                on_failure(AnalysisError::worker_panicked());
            }));
        }
    }

    fn fail(mut self, error: AnalysisError) {
        if let Some(on_failure) = self.on_failure.take() {
            on_failure(error);
        }
    }
}

struct SemanticExecutor {
    sender: Option<SyncSender<SemanticJob>>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl SemanticExecutor {
    fn new(workers: usize, queue_capacity: usize) -> Result<Self, AnalysisError> {
        let (sender, receiver) = mpsc::sync_channel::<SemanticJob>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut handles = Vec::new();
        handles.try_reserve_exact(workers).map_err(|_| {
            AnalysisError::resource_exhausted("semantic worker handle allocation failed")
        })?;
        for worker in 0..workers {
            let receiver = receiver.clone();
            match thread::Builder::new()
                .name(format!("qtrace-semantic-{worker}"))
                .spawn(move || {
                    loop {
                        let job = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        match job {
                            Ok(job) => job.execute(),
                            Err(_) => break,
                        }
                    }
                }) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    drop(sender);
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(AnalysisError::resource_exhausted(format!(
                        "semantic executor thread creation failed: {error}"
                    )));
                }
            }
        }
        Ok(Self {
            sender: Some(sender),
            workers: handles,
        })
    }

    fn global() -> Result<&'static Self, AnalysisError> {
        static EXECUTOR: OnceLock<Result<SemanticExecutor, AnalysisError>> = OnceLock::new();
        match EXECUTOR.get_or_init(|| Self::new(SEMANTIC_WORKERS, MAX_PENDING_SEMANTIC_JOBS)) {
            Ok(executor) => Ok(executor),
            Err(error) => Err(error.clone()),
        }
    }

    fn submit(&self, job: SemanticJob) -> Result<(), AnalysisError> {
        let Some(sender) = &self.sender else {
            let error = AnalysisError::resource_exhausted("semantic executor is shut down");
            job.fail(error.clone());
            return Err(error);
        };
        sender.try_send(job).map_err(|error| match error {
            TrySendError::Full(_) => {
                AnalysisError::resource_exhausted("semantic executor queue is full")
            }
            TrySendError::Disconnected(job) => {
                let analysis_error =
                    AnalysisError::resource_exhausted("semantic executor is unavailable");
                job.fail(analysis_error.clone());
                analysis_error
            }
        })
    }

    #[cfg(test)]
    fn shutdown(mut self) -> Result<(), AnalysisError> {
        self.join_workers()
    }

    fn join_workers(&mut self) -> Result<(), AnalysisError> {
        self.sender.take();
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                return Err(AnalysisError::worker_panicked());
            }
        }
        Ok(())
    }
}

impl Drop for SemanticExecutor {
    fn drop(&mut self) {
        let _ = self.join_workers();
    }
}

fn submit_semantic_scan(
    context: Arc<QueryContext>,
    needles: Vec<String>,
    candidates: Vec<usize>,
    state: Arc<(Mutex<ProjectionState>, Condvar)>,
    cancelled: Arc<AtomicBool>,
    guard: CandidateGuard,
) -> Result<(), AnalysisError> {
    let failure_state = state.clone();
    SemanticExecutor::global()?.submit(SemanticJob::new(
        move || {
            let mut terminal = ProjectionTerminalizer::new(state.clone());
            let mut charged_matcher_work = 0_usize;
            let mut matcher_ledger_error = None;
            let matcher_result = DetailMatcher::new_guarded_with_probe(
                &needles,
                MAX_MATCHER_BUILD_WORK,
                &guard,
                |work| {
                    let additional = work.saturating_sub(charged_matcher_work);
                    charged_matcher_work = work;
                    if let Err(error) = consume_analysis_work(&guard, additional) {
                        matcher_ledger_error = Some(error);
                        return true;
                    }
                    cancelled.load(Ordering::Acquire)
                },
            );
            if let Some(error) = matcher_ledger_error {
                terminal.fail(error);
                return;
            }
            let matcher = match matcher_result {
                Ok(matcher) => matcher,
                Err(error) if error.code() == "job.cancelled" => {
                    terminal.fail(error);
                    return;
                }
                Err(error) => {
                    terminal.fail(error);
                    return;
                }
            };
            let mut remaining_scan = MAX_SEMANTIC_SCAN_BYTES;
            for row in candidates {
                if cancelled.load(Ordering::Acquire) {
                    terminal.fail(AnalysisError::cancelled("semantic analysis cancelled"));
                    return;
                }
                if let Err(error) = guard.consume_rows(1) {
                    terminal.fail(error);
                    return;
                }
                let result = context
                    .semantics
                    .get(row)
                    .copied()
                    .flatten()
                    .ok_or_else(|| {
                        AnalysisError::store_shape("semantic posting row has no semantic fact")
                    })
                    .and_then(|semantic| {
                        context
                            .store
                            .blob_bytes(semantic.detail_blob)
                            .map_err(AnalysisError::store)
                    });
                match result {
                    Ok(detail) => {
                        if detail.len() > MAX_SEMANTIC_DETAIL_BYTES {
                            terminal.fail(AnalysisError::resource_exhausted(
                                "semantic detail blob exceeds 8 MiB",
                            ));
                            return;
                        }
                        let (matched, scanned) = match matcher.contains_guarded_with_probe(
                            detail,
                            remaining_scan,
                            &guard,
                            |_| cancelled.load(Ordering::Acquire),
                        ) {
                            Ok(matched) => matched,
                            Err(error) if error.code() == "job.cancelled" => {
                                terminal.fail(error);
                                return;
                            }
                            Err(error) => {
                                terminal.fail(error);
                                return;
                            }
                        };
                        remaining_scan = remaining_scan.saturating_sub(scanned);
                        if cancelled.load(Ordering::Acquire) {
                            terminal.fail(AnalysisError::cancelled("semantic analysis cancelled"));
                            return;
                        }
                        let key = match context.key(row) {
                            Ok(key) => key.clone(),
                            Err(error) => {
                                terminal.fail(error);
                                return;
                            }
                        };
                        let mut projection = state
                            .0
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if !projection.completed {
                            if matched {
                                if projection.visible.len() == MAX_CANDIDATE_ROWS {
                                    drop(projection);
                                    terminal.fail(AnalysisError::resource_exhausted(
                                        "semantic result exceeds row limit",
                                    ));
                                    return;
                                }
                                if projection.visible.len() == projection.visible.capacity() {
                                    let required = projection
                                        .visible
                                        .len()
                                        .checked_add(1)
                                        .and_then(|required| {
                                            projection
                                                .visible
                                                .capacity()
                                                .checked_mul(2)
                                                .map(|doubled| required.max(doubled.max(4)))
                                        })
                                        .and_then(|capacity| {
                                            capacity.checked_mul(std::mem::size_of::<usize>())
                                        })
                                        .and_then(|bytes| u64::try_from(bytes).ok());
                                    let Some(bytes) = required else {
                                        drop(projection);
                                        terminal.fail(AnalysisError::resource_exhausted(
                                            "semantic result allocation size overflow",
                                        ));
                                        return;
                                    };
                                    let scope = match AllocationScope::begin(&guard, bytes, 0) {
                                        Ok(scope) => scope,
                                        Err(error) => {
                                            drop(projection);
                                            terminal.fail(AnalysisError::control(error));
                                            return;
                                        }
                                    };
                                    if projection.visible.try_reserve(1).is_err() {
                                        drop(scope);
                                        drop(projection);
                                        terminal.fail(AnalysisError::resource_exhausted(
                                            "semantic result allocation failed",
                                        ));
                                        return;
                                    }
                                    drop(scope);
                                }
                                projection.visible.push(row);
                            }
                            projection.watermark = Some(key);
                        }
                        state.1.notify_all();
                    }
                    Err(error) => {
                        terminal.fail(error);
                        return;
                    }
                }
            }
            if cancelled.load(Ordering::Acquire) {
                terminal.fail(AnalysisError::cancelled("semantic analysis cancelled"));
            } else {
                terminal.finish(true);
            }
        },
        move |error| terminalize_projection(&failure_state, false, Some(error)),
    ))
}

struct ProjectionTerminalizer {
    state: Arc<(Mutex<ProjectionState>, Condvar)>,
    finished: bool,
}

impl ProjectionTerminalizer {
    fn new(state: Arc<(Mutex<ProjectionState>, Condvar)>) -> Self {
        Self {
            state,
            finished: false,
        }
    }

    fn finish(&mut self, exact: bool) {
        terminalize_projection(&self.state, exact, None);
        self.finished = true;
    }

    fn fail(&mut self, error: AnalysisError) {
        terminalize_projection(&self.state, false, Some(error));
        self.finished = true;
    }
}

impl Drop for ProjectionTerminalizer {
    fn drop(&mut self) {
        if !self.finished {
            terminalize_projection(&self.state, false, Some(AnalysisError::worker_panicked()));
        }
    }
}

fn terminalize_projection(
    state: &(Mutex<ProjectionState>, Condvar),
    exact: bool,
    error: Option<AnalysisError>,
) {
    let mut projection = state
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if projection.completed {
        return;
    }
    if error.is_some() {
        projection.visible.clear();
        projection.watermark = None;
    }
    projection.exact_total = exact;
    projection.completed = true;
    projection.error = error;
    state.1.notify_all();
}

const NO_EDGE: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct DetailNode {
    first_edge: u32,
    failure: u32,
    terminal: bool,
}

impl Default for DetailNode {
    fn default() -> Self {
        Self {
            first_edge: NO_EDGE,
            failure: 0,
            terminal: false,
        }
    }
}

#[derive(Clone, Copy)]
struct DetailEdge {
    byte: u8,
    target: u32,
    next: u32,
}

struct DetailMatcher {
    nodes: Vec<DetailNode>,
    edges: Vec<DetailEdge>,
}

impl DetailMatcher {
    #[cfg(test)]
    fn new<T: AsRef<[u8]>>(patterns: &[T]) -> Result<Self, AnalysisError> {
        Self::new_with_probe(patterns, MAX_MATCHER_BUILD_WORK, |_| false)
    }

    #[cfg(test)]
    fn new_with_probe<T: AsRef<[u8]>>(
        patterns: &[T],
        max_work: usize,
        cancelled: impl FnMut(usize) -> bool,
    ) -> Result<Self, AnalysisError> {
        Self::new_guarded_with_probe(patterns, max_work, &AllowContextWork, cancelled)
    }

    fn new_guarded_with_probe<T: AsRef<[u8]>>(
        patterns: &[T],
        max_work: usize,
        guard: &dyn WorkGuard,
        mut cancelled: impl FnMut(usize) -> bool,
    ) -> Result<Self, AnalysisError> {
        if cancelled(0) {
            return Err(AnalysisError {
                code: "job.cancelled",
                detail: "semantic matcher build cancelled".to_owned(),
            });
        }
        if patterns.iter().any(|pattern| pattern.as_ref().is_empty()) {
            return Err(AnalysisError::invalid_filter(
                "semantic detail needles must not be empty",
            ));
        }
        let mut work = 0_usize;
        let mut total_bytes = 0_usize;
        for pattern in patterns {
            for chunk in pattern.as_ref().chunks(4096) {
                matcher_build_work(&mut work, chunk.len(), max_work, &mut cancelled)?;
                total_bytes = total_bytes.checked_add(chunk.len()).ok_or_else(|| {
                    AnalysisError::filter_too_complex("semantic pattern byte count overflow")
                })?;
            }
        }
        if total_bytes > crate::filter::MAX_FILTER_TEXT_BYTES {
            return Err(AnalysisError::filter_too_complex(
                "semantic patterns exceed 1 MiB",
            ));
        }
        let mut nodes = Vec::new();
        try_reserve_analysis(
            &mut nodes,
            total_bytes.saturating_add(1),
            guard,
            "semantic automaton node allocation failed",
        )?;
        nodes.push(DetailNode::default());
        let mut edges = Vec::new();
        try_reserve_analysis(
            &mut edges,
            total_bytes,
            guard,
            "semantic automaton edge allocation failed",
        )?;
        let mut matcher = Self { nodes, edges };
        for pattern in patterns {
            let mut state = 0_usize;
            for byte in pattern.as_ref() {
                matcher_build_work(&mut work, 1, max_work, &mut cancelled)?;
                state = if let Some(target) = matcher.transition_for_build(
                    state,
                    *byte,
                    &mut work,
                    max_work,
                    &mut cancelled,
                )? {
                    target
                } else {
                    matcher_build_work(&mut work, 2, max_work, &mut cancelled)?;
                    let target = matcher.nodes.len();
                    let target_u32 = u32::try_from(target).map_err(|_| {
                        AnalysisError::resource_exhausted("semantic automaton exceeds u32")
                    })?;
                    let edge = u32::try_from(matcher.edges.len()).map_err(|_| {
                        AnalysisError::resource_exhausted("semantic automaton exceeds u32")
                    })?;
                    matcher.nodes.push(DetailNode::default());
                    matcher.edges.push(DetailEdge {
                        byte: *byte,
                        target: target_u32,
                        next: matcher.nodes[state].first_edge,
                    });
                    matcher.nodes[state].first_edge = edge;
                    target
                };
            }
            matcher.nodes[state].terminal = true;
        }
        matcher.build_failures(&mut work, max_work, guard, &mut cancelled)?;
        if cancelled(work) {
            return Err(AnalysisError {
                code: "job.cancelled",
                detail: "semantic matcher build cancelled".to_owned(),
            });
        }
        Ok(matcher)
    }

    fn transition_for_build(
        &self,
        state: usize,
        byte: u8,
        work: &mut usize,
        max_work: usize,
        cancelled: &mut impl FnMut(usize) -> bool,
    ) -> Result<Option<usize>, AnalysisError> {
        let mut edge = self.nodes[state].first_edge;
        while edge != NO_EDGE {
            matcher_build_work(work, 1, max_work, cancelled)?;
            let candidate = self.edges[edge as usize];
            if candidate.byte == byte {
                return Ok(Some(candidate.target as usize));
            }
            edge = candidate.next;
        }
        Ok(None)
    }

    fn transition(&self, state: usize, byte: u8) -> Option<usize> {
        let mut edge = self.nodes[state].first_edge;
        while edge != NO_EDGE {
            let candidate = self.edges[edge as usize];
            if candidate.byte == byte {
                return Some(candidate.target as usize);
            }
            edge = candidate.next;
        }
        None
    }

    fn build_failures(
        &mut self,
        work: &mut usize,
        max_work: usize,
        guard: &dyn WorkGuard,
        cancelled: &mut impl FnMut(usize) -> bool,
    ) -> Result<(), AnalysisError> {
        let mut queue = std::collections::VecDeque::new();
        let queue_bytes = self
            .nodes
            .len()
            .checked_mul(std::mem::size_of::<u32>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| {
                AnalysisError::resource_exhausted("semantic automaton queue size overflow")
            })?;
        let scope =
            AllocationScope::begin(guard, queue_bytes, 0).map_err(AnalysisError::control)?;
        queue.try_reserve(self.nodes.len()).map_err(|_| {
            AnalysisError::resource_exhausted("semantic automaton queue allocation failed")
        })?;
        drop(scope);
        let mut edge = self.nodes[0].first_edge;
        while edge != NO_EDGE {
            matcher_build_work(work, 1, max_work, cancelled)?;
            let target = self.edges[edge as usize].target;
            queue.push_back(target);
            edge = self.edges[edge as usize].next;
        }
        while let Some(state) = queue.pop_front() {
            matcher_build_work(work, 1, max_work, cancelled)?;
            let mut edge = self.nodes[state as usize].first_edge;
            while edge != NO_EDGE {
                matcher_build_work(work, 1, max_work, cancelled)?;
                let candidate = self.edges[edge as usize];
                queue.push_back(candidate.target);
                let mut failure = self.nodes[state as usize].failure as usize;
                while failure != 0
                    && self
                        .transition_for_build(failure, candidate.byte, work, max_work, cancelled)?
                        .is_none()
                {
                    matcher_build_work(work, 1, max_work, cancelled)?;
                    failure = self.nodes[failure].failure as usize;
                }
                let target_failure = self
                    .transition_for_build(failure, candidate.byte, work, max_work, cancelled)?
                    .unwrap_or(0);
                let target = candidate.target as usize;
                self.nodes[target].failure = target_failure as u32;
                self.nodes[target].terminal |= self.nodes[target_failure].terminal;
                edge = candidate.next;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn contains_with_probe(
        &self,
        haystack: &[u8],
        max_bytes: usize,
        cancelled: impl FnMut(usize) -> bool,
    ) -> Result<bool, AnalysisError> {
        self.contains_guarded_with_probe(haystack, max_bytes, &AllowContextWork, cancelled)
            .map(|(matched, _)| matched)
    }

    fn contains_guarded_with_probe(
        &self,
        haystack: &[u8],
        max_bytes: usize,
        guard: &dyn WorkGuard,
        mut cancelled: impl FnMut(usize) -> bool,
    ) -> Result<(bool, usize), AnalysisError> {
        if cancelled(0) {
            return Err(AnalysisError {
                code: "job.cancelled",
                detail: "semantic detail scan cancelled".to_owned(),
            });
        }
        let mut state = 0_usize;
        let mut processed = 0_usize;
        for chunk in haystack.chunks(4096) {
            processed = processed
                .checked_add(chunk.len())
                .ok_or_else(|| AnalysisError::resource_exhausted("semantic scan work overflow"))?;
            if processed > max_bytes {
                return Err(AnalysisError::resource_exhausted(
                    "semantic scan exceeds 64 MiB work budget",
                ));
            }
            let mut transitions = 0_usize;
            let mut matched = false;
            for byte in chunk {
                while state != 0 {
                    transitions += 1;
                    if self.transition(state, *byte).is_some() {
                        break;
                    }
                    state = self.nodes[state].failure as usize;
                }
                transitions += 1;
                state = self.transition(state, *byte).unwrap_or(0);
                if self.nodes[state].terminal {
                    matched = true;
                    break;
                }
            }
            consume_analysis_work(guard, transitions)?;
            if matched {
                return Ok((true, processed));
            }
            if cancelled(processed) {
                return Err(AnalysisError {
                    code: "job.cancelled",
                    detail: "semantic detail scan cancelled".to_owned(),
                });
            }
        }
        Ok((false, processed))
    }
}

fn matcher_build_work(
    work: &mut usize,
    additional: usize,
    max_work: usize,
    cancelled: &mut impl FnMut(usize) -> bool,
) -> Result<(), AnalysisError> {
    let prior_checkpoint = *work / 4096;
    *work = work
        .checked_add(additional)
        .filter(|work| *work <= max_work)
        .ok_or_else(|| AnalysisError::resource_exhausted("semantic matcher build work exceeded"))?;
    if *work / 4096 != prior_checkpoint && cancelled(*work) {
        return Err(AnalysisError {
            code: "job.cancelled",
            detail: "semantic matcher build cancelled".to_owned(),
        });
    }
    Ok(())
}

fn locate_after_key(
    context: &QueryContext,
    rows: &[usize],
    key: &EventKey,
) -> Result<usize, AnalysisError> {
    locate_after_key_with_probe(&context.keys, rows, key, || {})
}

fn locate_after_key_with_probe(
    keys: &[EventKey],
    rows: &[usize],
    key: &EventKey,
    mut comparison: impl FnMut(),
) -> Result<usize, AnalysisError> {
    let mut left = 0;
    let mut right = rows.len();
    while left < right {
        let middle = left + (right - left) / 2;
        comparison();
        let candidate = keys
            .get(rows[middle])
            .ok_or_else(|| AnalysisError::store_shape("cursor row is outside event-key map"))?;
        match compare_event_keys(candidate, key) {
            std::cmp::Ordering::Less => left = middle + 1,
            std::cmp::Ordering::Greater => right = middle,
            std::cmp::Ordering::Equal => return Ok(middle + 1),
        }
    }
    Ok(left)
}

fn required_event_key(
    store: &(impl TraceStoreView + ?Sized),
    row: usize,
) -> Result<EventKey, AnalysisError> {
    store
        .event_key(row)
        .map_err(AnalysisError::store)?
        .ok_or_else(|| AnalysisError::store_shape("event key is absent"))
}

fn compare_event_keys(left: &EventKey, right: &EventKey) -> std::cmp::Ordering {
    left.artifact
        .as_bytes()
        .cmp(right.artifact.as_bytes())
        .then_with(|| left.timeline.0.cmp(&right.timeline.0))
        .then_with(|| left.record_ordinal.cmp(&right.record_ordinal))
        .then_with(|| left.source_offset.cmp(&right.source_offset))
        .then_with(|| left.sequence.cmp(&right.sequence))
        .then_with(|| left.tid.cmp(&right.tid))
}

struct DecodedCursor {
    store: StoreIdentity,
    projection: ProjectionIdentity,
    last_key: Option<EventKey>,
}

fn encode_cursor(
    store: StoreIdentity,
    projection: ProjectionIdentity,
    key: Option<&EventKey>,
) -> PageCursor {
    let mut bytes = Vec::with_capacity(CURSOR_BYTES);
    bytes.push(CURSOR_VERSION);
    bytes.extend_from_slice(&store.0);
    bytes.extend_from_slice(&projection.0);
    bytes.push(u8::from(key.is_some()));
    let empty = EventKey::new(
        ArtifactDigest::new([0; 32]),
        TimelineId(0),
        0,
        0,
        None,
        None,
    );
    let key = key.unwrap_or(&empty);
    bytes.extend_from_slice(key.artifact.as_bytes());
    bytes.extend_from_slice(&key.timeline.0.to_le_bytes());
    bytes.extend_from_slice(&key.record_ordinal.to_le_bytes());
    bytes.extend_from_slice(&key.source_offset.to_le_bytes());
    bytes.push(u8::from(key.sequence.is_some()));
    bytes.extend_from_slice(&key.sequence.unwrap_or_default().to_le_bytes());
    bytes.push(u8::from(key.tid.is_some()));
    bytes.extend_from_slice(&key.tid.unwrap_or_default().to_le_bytes());
    debug_assert_eq!(bytes.len(), CURSOR_PAYLOAD_BYTES);
    let checksum = Sha256::digest(&bytes);
    bytes.extend_from_slice(&checksum);
    PageCursor(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(cursor: &PageCursor) -> Result<DecodedCursor, AnalysisError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| AnalysisError::cursor_mismatch("cursor is not URL-safe base64"))?;
    if bytes.len() != CURSOR_BYTES || bytes[0] != CURSOR_VERSION {
        return Err(AnalysisError::cursor_mismatch(
            "cursor version or length is invalid",
        ));
    }
    let expected = Sha256::digest(&bytes[..CURSOR_PAYLOAD_BYTES]);
    if expected.as_slice() != &bytes[CURSOR_PAYLOAD_BYTES..] {
        return Err(AnalysisError::cursor_mismatch("cursor checksum is invalid"));
    }
    let mut offset = 1;
    let store = StoreIdentity(read_array::<32>(&bytes, &mut offset)?);
    let projection = ProjectionIdentity(read_array::<32>(&bytes, &mut offset)?);
    let anchor_present = read_flag(&bytes, &mut offset)?;
    let artifact = ArtifactDigest::new(read_array::<32>(&bytes, &mut offset)?);
    let timeline = u64::from_le_bytes(read_array::<8>(&bytes, &mut offset)?);
    let record_ordinal = u64::from_le_bytes(read_array::<8>(&bytes, &mut offset)?);
    let source_offset = u64::from_le_bytes(read_array::<8>(&bytes, &mut offset)?);
    let sequence_present = read_flag(&bytes, &mut offset)?;
    let sequence_value = u64::from_le_bytes(read_array::<8>(&bytes, &mut offset)?);
    let tid_present = read_flag(&bytes, &mut offset)?;
    let tid_value = u32::from_le_bytes(read_array::<4>(&bytes, &mut offset)?);
    if offset != CURSOR_PAYLOAD_BYTES {
        return Err(AnalysisError::cursor_mismatch("cursor payload is invalid"));
    }
    Ok(DecodedCursor {
        store,
        projection,
        last_key: anchor_present.then(|| {
            EventKey::new(
                artifact,
                TimelineId(timeline),
                record_ordinal,
                source_offset,
                sequence_present.then_some(sequence_value),
                tid_present.then_some(tid_value),
            )
        }),
    })
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], AnalysisError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| AnalysisError::cursor_mismatch("cursor offset overflow"))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| AnalysisError::cursor_mismatch("cursor is truncated"))?
        .try_into()
        .map_err(|_| AnalysisError::cursor_mismatch("cursor field has invalid length"))?;
    *offset = end;
    Ok(value)
}

fn read_flag(bytes: &[u8], offset: &mut usize) -> Result<bool, AnalysisError> {
    let value = read_array::<1>(bytes, offset)?[0];
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AnalysisError::cursor_mismatch("cursor flag is invalid")),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };

    use super::*;

    #[derive(Clone, Copy, Default)]
    struct AllocationOracleState {
        active: bool,
        scope_active: bool,
        unauthorized: u64,
        requested: u64,
    }

    thread_local! {
        static ALLOCATION_ORACLE: Cell<AllocationOracleState> = const {
            Cell::new(AllocationOracleState {
                active: false,
                scope_active: false,
                unauthorized: 0,
                requested: 0,
            })
        };
    }

    struct TrackingAllocator;

    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record_test_allocation(layout.size());
            // SAFETY: forwards the allocator request unchanged.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record_test_allocation(layout.size());
            // SAFETY: forwards the allocator request unchanged.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            // SAFETY: forwards the matching deallocation unchanged.
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            record_test_allocation(size);
            // SAFETY: forwards the allocator request unchanged.
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    #[global_allocator]
    static TEST_ALLOCATOR: TrackingAllocator = TrackingAllocator;

    fn record_test_allocation(bytes: usize) {
        ALLOCATION_ORACLE.with(|oracle| {
            let mut state = oracle.get();
            if state.active {
                state.requested = state.requested.saturating_add(bytes as u64);
                state.unauthorized += u64::from(!state.scope_active);
                oracle.set(state);
            }
        });
    }

    fn activate_allocation_oracle() {
        ALLOCATION_ORACLE.with(|oracle| {
            oracle.set(AllocationOracleState {
                active: true,
                ..AllocationOracleState::default()
            });
        });
    }

    fn finish_allocation_oracle() -> AllocationOracleState {
        ALLOCATION_ORACLE.with(|oracle| {
            let mut state = oracle.get();
            state.active = false;
            oracle.set(state);
            state
        })
    }

    #[derive(Default)]
    struct ProductionPassProbe {
        work: AtomicU64,
        resident: AtomicU64,
        allocations: AtomicU64,
    }

    impl WorkGuard for ProductionPassProbe {
        fn consume(&self, delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
            self.work.fetch_add(
                delta
                    .rows
                    .saturating_add(delta.nodes)
                    .saturating_add(delta.events)
                    .saturating_add(delta.input_bytes)
                    .saturating_add(delta.decompressed_bytes),
                Ordering::SeqCst,
            );
            self.resident
                .fetch_add(delta.resident_bytes, Ordering::SeqCst);
            Ok(())
        }

        fn begin_allocation_scope(
            &self,
            delta: WorkDelta,
            _allowed_slack: u64,
        ) -> Result<(), qtrace_provider::OperationAbort> {
            self.allocations.fetch_add(1, Ordering::SeqCst);
            ALLOCATION_ORACLE.with(|oracle| {
                let mut state = oracle.get();
                assert!(!state.scope_active, "allocation scopes must not nest");
                state.scope_active = true;
                oracle.set(state);
            });
            self.consume(delta)
        }

        fn end_allocation_scope(&self) {
            ALLOCATION_ORACLE.with(|oracle| {
                let mut state = oracle.get();
                assert!(state.scope_active, "allocation scope must be active");
                state.scope_active = false;
                oracle.set(state);
            });
        }
    }

    #[derive(Clone, Copy)]
    struct PassCounts {
        radix: u64,
        intersection: u64,
        union: u64,
        residual: u64,
        stable: u64,
    }

    fn production_pass_counts(size: usize) -> PassCounts {
        let radix_probe = ProductionPassProbe::default();
        let mut radix_rows = (0..size).rev().collect::<Vec<_>>();
        activate_allocation_oracle();
        radix_sort_usize_guarded(&mut radix_rows, &radix_probe).unwrap();
        let allocation = finish_allocation_oracle();
        assert_eq!(radix_rows, (0..size).collect::<Vec<_>>());
        assert_eq!(allocation.unauthorized, 0);
        assert!(
            allocation.requested >= std::alloc::Layout::array::<usize>(size).unwrap().size() as u64
        );
        assert_eq!(radix_probe.allocations.load(Ordering::SeqCst), 1);
        assert_eq!(
            radix_probe.resident.load(Ordering::SeqCst),
            std::alloc::Layout::array::<usize>(size).unwrap().size() as u64,
            "allocation authorization must use the independent Layout size"
        );

        let intersection_probe = ProductionPassProbe::default();
        let left = (0..size).collect::<Vec<_>>();
        let right = (0..size).step_by(2).collect::<Vec<_>>();
        let intersection =
            intersect_rows_fallible_guarded(&left, &right, &intersection_probe).unwrap();
        assert_eq!(intersection, right);
        assert_eq!(intersection_probe.allocations.load(Ordering::SeqCst), 1);

        let union_probe = ProductionPassProbe::default();
        let union = union_rows_guarded(
            vec![
                (0..size).step_by(2).collect(),
                (1..size).step_by(2).collect(),
            ],
            &union_probe,
        )
        .unwrap();
        assert_eq!(union, (0..size).collect::<Vec<_>>());
        assert_eq!(union_probe.allocations.load(Ordering::SeqCst), 2);

        let residual_probe = ProductionPassProbe::default();
        let residual = retain_rows_guarded(left, &residual_probe, |row| Ok(row % 2 == 0)).unwrap();
        assert_eq!(residual.len(), size.div_ceil(2));
        assert_eq!(residual_probe.allocations.load(Ordering::SeqCst), 1);

        let stable_probe = ProductionPassProbe::default();
        let keys = (0..size)
            .map(|ordinal| {
                EventKey::new(
                    ArtifactDigest::new([ordinal as u8; 32]),
                    TimelineId(1),
                    ordinal as u64,
                    ordinal as u64,
                    Some(ordinal as u64),
                    Some(7),
                )
            })
            .collect::<Vec<_>>();
        let sorted =
            radix_sort_rows_by_keys_guarded(&keys, (0..size).rev().collect(), &stable_probe)
                .unwrap();
        assert_eq!(sorted.len(), size);
        assert_eq!(stable_probe.allocations.load(Ordering::SeqCst), 1);

        PassCounts {
            radix: radix_probe.work.load(Ordering::SeqCst),
            intersection: intersection_probe.work.load(Ordering::SeqCst),
            union: union_probe.work.load(Ordering::SeqCst),
            residual: residual_probe.work.load(Ordering::SeqCst),
            stable: stable_probe.work.load(Ordering::SeqCst),
        }
    }

    #[test]
    fn production_pass_counters_are_linear_across_real_chunk_boundaries() {
        let probes = [8_192, 16_384, 32_768].map(production_pass_counts);
        for field in [
            |counts: PassCounts| counts.radix,
            |counts: PassCounts| counts.intersection,
            |counts: PassCounts| counts.union,
            |counts: PassCounts| counts.residual,
            |counts: PassCounts| counts.stable,
        ] {
            let [n, two_n, four_n] = probes.map(field);
            assert!(n > 0);
            assert!(two_n <= n * 2 + 65_536, "{n} -> {two_n}");
            assert!(four_n <= two_n * 2 + 65_536, "{two_n} -> {four_n}");
        }
    }

    #[test]
    fn discontinuity_decoder_uses_the_closed_tag_before_specialized_decode() {
        let evidence = qtrace_provider::CompletenessRange::captured_sequence_with_cause(
            7,
            9,
            qtrace_provider::Provenance::Damaged,
            qtrace_provider::CompletenessCause::Lost,
        )
        .unwrap();
        let payload = serde_json::to_vec(&qtrace_provider::EventPayload::Discontinuity(
            qtrace_provider::Discontinuity {
                cause: qtrace_provider::DiscontinuityCause::Damage,
                evidence,
            },
        ))
        .unwrap();
        let decoded = decode_discontinuity_payload(&payload).unwrap();
        assert_eq!(decoded.cause, qtrace_provider::DiscontinuityCause::Damage);
        assert_eq!(decoded.evidence, evidence);

        let mut wrong = b"{\"semantic_call\":\"".to_vec();
        wrong.resize(MAX_DISCONTINUITY_PAYLOAD_BYTES - 2, b'x');
        wrong.extend_from_slice(b"\"}");
        let error = decode_discontinuity_payload(&wrong).unwrap_err();
        assert_eq!(error.code(), "analysis.store");
        assert!(error.detail().contains("wrong event kind"));

        let malformed = br#"{"discontinuity":{"cause":"loss"}}"#;
        let error = decode_discontinuity_payload(malformed).unwrap_err();
        assert_eq!(error.code(), "analysis.store");
        assert!(error.detail().contains("invalid discontinuity payload"));
    }

    struct PlannerScopeProbe {
        scopes: AtomicU64,
        active: AtomicBool,
    }

    impl WorkGuard for PlannerScopeProbe {
        fn consume(&self, delta: WorkDelta) -> Result<(), qtrace_provider::OperationAbort> {
            if delta.resident_bytes == 0 {
                Ok(())
            } else {
                Err(qtrace_provider::OperationAbort::budget_exceeded(
                    qtrace_provider::BudgetDimension::ResidentBytes,
                    0,
                    delta.resident_bytes,
                ))
            }
        }

        fn begin_allocation_scope(
            &self,
            _delta: WorkDelta,
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

    #[derive(Default)]
    struct WorkerState {
        active: usize,
        max_active: usize,
        completed: usize,
        released: bool,
    }

    #[test]
    fn posting_list_container_growth_uses_one_allocation_scope() {
        let guard = PlannerScopeProbe {
            scopes: AtomicU64::new(0),
            active: AtomicBool::new(false),
        };
        let mut lists = Vec::<Vec<usize>>::new();
        try_reserve_posting_lists(&mut lists, 4_096, &guard).unwrap();
        assert!(lists.capacity() >= 4_096);
        assert_eq!(guard.scopes.load(Ordering::SeqCst), 1);
        assert!(!guard.active.load(Ordering::SeqCst));
    }

    #[test]
    fn semantic_executor_caps_workers_and_queue_without_timing_assumptions() {
        let executor = SemanticExecutor::new(2, 4).unwrap();
        let state = Arc::new((Mutex::new(WorkerState::default()), Condvar::new()));
        let job = || {
            let state = state.clone();
            SemanticJob::plain(move || {
                let mut guard = state.0.lock().unwrap();
                guard.active += 1;
                guard.max_active = guard.max_active.max(guard.active);
                state.1.notify_all();
                while !guard.released {
                    guard = state.1.wait(guard).unwrap();
                }
                guard.active -= 1;
                guard.completed += 1;
                state.1.notify_all();
            })
        };

        executor.submit(job()).unwrap();
        executor.submit(job()).unwrap();
        let guard = state.0.lock().unwrap();
        let (guard, result) = state
            .1
            .wait_timeout_while(guard, Duration::from_secs(2), |state| state.active < 2)
            .unwrap();
        assert!(!result.timed_out());
        drop(guard);
        for _ in 0..4 {
            executor.submit(job()).unwrap();
        }
        assert_eq!(
            executor.submit(job()).unwrap_err().code(),
            "analysis.resource_exhausted"
        );
        let mut guard = state.0.lock().unwrap();
        guard.released = true;
        state.1.notify_all();
        let (guard, result) = state
            .1
            .wait_timeout_while(guard, Duration::from_secs(2), |state| state.completed < 6)
            .unwrap();
        assert!(!result.timed_out());
        assert_eq!(guard.max_active, 2);
    }

    #[test]
    fn semantic_executor_survives_a_panicking_job_and_joins_on_shutdown() {
        let executor = SemanticExecutor::new(1, 2).unwrap();
        let projection = Arc::new((Mutex::new(ProjectionState::default()), Condvar::new()));
        let failed = projection.clone();
        let running = projection.clone();
        executor
            .submit(SemanticJob::new(
                move || {
                    let _terminal = ProjectionTerminalizer::new(running);
                    panic!("deterministic worker panic");
                },
                move |error| terminalize_projection(&failed, false, Some(error)),
            ))
            .unwrap();
        let state = projection.0.lock().unwrap();
        let (state, timeout) = projection
            .1
            .wait_timeout_while(state, Duration::from_millis(100), |state| !state.completed)
            .unwrap();
        assert!(!timeout.timed_out());
        assert_eq!(
            state.error.as_ref().unwrap().code(),
            "analysis.worker_panicked"
        );
        drop(state);
        let completed = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = completed.clone();
        executor
            .submit(SemanticJob::plain(move || {
                *signal.0.lock().unwrap() = true;
                signal.1.notify_all();
            }))
            .unwrap();
        let done = completed.0.lock().unwrap();
        let (done, timeout) = completed
            .1
            .wait_timeout_while(done, Duration::from_millis(100), |done| !*done)
            .unwrap();
        assert!(!timeout.timed_out() && *done, "worker retired after panic");
        drop(done);
        executor.shutdown().unwrap();
    }

    #[test]
    fn disconnected_executor_terminalizes_the_rejected_job() {
        let executor = SemanticExecutor {
            sender: None,
            workers: Vec::new(),
        };
        let failure = Arc::new(Mutex::new(None));
        let observed = failure.clone();
        let error = executor
            .submit(SemanticJob::new(
                || panic!("disconnected jobs must not run"),
                move |error| *observed.lock().unwrap() = Some(error),
            ))
            .unwrap_err();
        assert_eq!(error.code(), "analysis.resource_exhausted");
        assert_eq!(
            failure.lock().unwrap().as_ref().unwrap().code(),
            "analysis.resource_exhausted"
        );
    }

    #[test]
    fn long_needle_scan_cancels_after_at_most_one_actual_input_chunk() {
        let haystack = vec![b'x'; 8 * 1024 * 1024];
        let mut needle = vec![b'x'; 1024 * 1024];
        *needle.last_mut().unwrap() = b'y';
        let matcher = DetailMatcher::new(&[needle]).unwrap();
        let mut last_processed = 0;
        let result = matcher.contains_with_probe(&haystack, usize::MAX, |processed| {
            last_processed = processed;
            processed >= 4096
        });
        assert_eq!(result.unwrap_err().code(), "job.cancelled");
        assert_eq!(last_processed, 4096);
    }

    #[test]
    fn multi_pattern_scan_matches_across_input_chunk_boundaries() {
        let mut haystack = vec![b'x'; 8192];
        haystack[4094..4102].copy_from_slice(b"boundary");
        let matcher = DetailMatcher::new(&[b"missing".to_vec(), b"boundary".to_vec()]).unwrap();
        assert!(
            matcher
                .contains_with_probe(&haystack, haystack.len(), |_| false)
                .unwrap()
        );
    }

    #[test]
    fn matcher_handles_overlap_prefix_utf8_bytes_and_rejects_empty_needles() {
        let matcher = DetailMatcher::new(&[
            b"aba".to_vec(),
            b"ababa".to_vec(),
            "界限".as_bytes().to_vec(),
        ])
        .unwrap();
        assert!(
            matcher
                .contains_with_probe(b"xxababa", 7, |_| false)
                .unwrap()
        );
        assert!(
            matcher
                .contains_with_probe("xx界限yy".as_bytes(), 12, |_| false)
                .unwrap()
        );
        let error = match DetailMatcher::new(&[Vec::<u8>::new()]) {
            Ok(_) => panic!("empty semantic needle was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "analysis.invalid_filter");
    }

    #[test]
    fn matcher_build_cancels_before_allocating_the_first_node() {
        let mut observed = None;
        let error = match DetailMatcher::new_with_probe(
            &[vec![b'a'; 1024 * 1024]],
            8 * 1024 * 1024,
            |work| {
                observed = Some(work);
                work == 0
            },
        ) {
            Ok(_) => panic!("pre-cancelled matcher build was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "job.cancelled");
        assert_eq!(observed, Some(0));
    }

    #[test]
    fn adversarial_prefix_matcher_build_work_scales_linearly() {
        fn work(depth: usize) -> (usize, usize) {
            let patterns = (1..=depth)
                .map(|length| vec![b'a'; length])
                .collect::<Vec<_>>();
            let input = patterns.iter().map(Vec::len).sum::<usize>();
            let mut observed = 0_usize;
            DetailMatcher::new_with_probe(&patterns, input * 8 + 4096, |work| {
                observed = work;
                false
            })
            .unwrap();
            (input, observed)
        }
        let probes = [work(64), work(90), work(128)];
        for (input, observed) in probes {
            assert!(
                observed <= input * 8 + 4096,
                "matcher used {observed} work for {input} input bytes"
            );
        }
    }

    #[test]
    fn stable_key_radix_matches_the_public_total_order_at_numeric_extremes() {
        let keys = vec![
            EventKey::new(
                ArtifactDigest::new([1; 32]),
                TimelineId(u64::MAX),
                0,
                u64::MAX,
                Some(u64::MAX),
                Some(u32::MAX),
            ),
            EventKey::new(
                ArtifactDigest::new([0xff; 32]),
                TimelineId(0),
                u64::MAX,
                0,
                None,
                None,
            ),
            EventKey::new(
                ArtifactDigest::new([1; 32]),
                TimelineId(u64::MAX),
                0,
                u64::MAX,
                None,
                Some(0),
            ),
            EventKey::new(
                ArtifactDigest::new([1; 32]),
                TimelineId(u64::MAX),
                0,
                u64::MAX,
                Some(0),
                None,
            ),
        ];
        let mut expected = (0..keys.len()).collect::<Vec<_>>();
        expected.sort_by(|left, right| compare_event_keys(&keys[*left], &keys[*right]));
        assert_eq!(
            radix_sort_rows_by_keys(&keys, (0..keys.len()).rev().collect()).unwrap(),
            expected
        );
    }

    #[test]
    fn cursor_lookup_and_page_projection_work_is_log_n_plus_limit() {
        for size in [8_192_usize, 16_384, 32_768] {
            let keys = (0..size)
                .map(|ordinal| {
                    EventKey::new(
                        ArtifactDigest::new([1; 32]),
                        TimelineId(1),
                        ordinal as u64,
                        ordinal as u64,
                        Some(ordinal as u64),
                        Some(7),
                    )
                })
                .collect::<Vec<_>>();
            let rows = (0..size).collect::<Vec<_>>();
            for limit in [1_usize, 32, 2_000] {
                let mut comparisons = 0;
                let index =
                    locate_after_key_with_probe(&keys, &rows, &keys[size / 2], || comparisons += 1)
                        .unwrap();
                assert_eq!(index, size / 2 + 1);
                let projected = limit.min(size - index);
                let logarithmic_bound = usize::BITS as usize - (size - 1).leading_zeros() as usize;
                assert!(comparisons <= logarithmic_bound + 1);
                assert!(comparisons + projected <= logarithmic_bound + 1 + limit);
            }
        }
    }
}
