use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use qtrace_provider::{
    ArtifactDigest, EventKey, EventKind, EventPayload, MemoryDirection, Provenance, RegisterSlot,
    TimelineId,
};
use qtrace_store::{CompletenessRow, RegisterAccess, TraceStoreView, intersect_rows};
use sha2::{Digest, Sha256};

use crate::{CompletenessSummary, DiscontinuityRow, EventFilter, MemoryFilter, MnemonicFilter};

const CURSOR_VERSION: u8 = 1;
const CURSOR_PAYLOAD_BYTES: usize = 135;
const CURSOR_BYTES: usize = CURSOR_PAYLOAD_BYTES + 32;

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
    store: Arc<dyn TraceStoreView + Send + Sync>,
    identity: StoreIdentity,
}

impl QueryContext {
    pub fn new<T>(store: Arc<T>) -> Result<Self, AnalysisError>
    where
        T: TraceStoreView + Send + Sync + 'static,
    {
        let store: Arc<dyn TraceStoreView + Send + Sync> = store;
        Self::from_arc(store)
    }

    pub fn from_arc(store: Arc<dyn TraceStoreView + Send + Sync>) -> Result<Self, AnalysisError> {
        let identity = derive_store_identity(store.as_ref())?;
        Ok(Self { store, identity })
    }

    pub fn identity(&self) -> StoreIdentity {
        self.identity
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
    pub completeness: CompletenessSummary,
}

#[derive(Default)]
struct ProjectionState {
    visible: Vec<usize>,
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
    completeness: CompletenessSummary,
    discontinuities: BTreeMap<usize, (qtrace_provider::DiscontinuityCause, CompletenessRow)>,
}

impl TimelineProjection {
    pub fn new(context: Arc<QueryContext>, filter: EventFilter) -> Result<Self, AnalysisError> {
        let filter = filter.normalized()?;
        let projection_identity = derive_projection_identity(context.identity, &filter);
        let (candidates, indexed_fields) = plan_candidates(context.store.as_ref(), &filter)?;
        let candidates = apply_synchronous_residuals(context.store.as_ref(), &filter, candidates)?;
        let candidates = sort_rows_by_stable_key(context.store.as_ref(), candidates)?;
        let completeness = CompletenessSummary::new(context.store.completeness());
        let discontinuities = map_discontinuities(context.store.as_ref())?;
        let has_residual_scan = filter.has_semantic_detail_residual();
        let state = Arc::new((Mutex::new(ProjectionState::default()), Condvar::new()));
        let cancelled = Arc::new(AtomicBool::new(false));
        let plan = QueryPlan {
            projection_identity,
            candidate_rows: candidates.len(),
            indexed_fields,
            has_residual_scan,
        };

        if has_residual_scan {
            start_semantic_scan(
                context.clone(),
                filter.semantic_detail_contains.clone(),
                candidates,
                state.clone(),
                cancelled.clone(),
            );
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
            completeness,
            discontinuities,
        })
    }

    pub fn plan(&self) -> &QueryPlan {
        &self.plan
    }

    pub fn filter(&self) -> &EventFilter {
        &self.filter
    }

    pub fn total_visible_rows(&self) -> (usize, bool) {
        let state = self.state.0.lock().expect("projection state poisoned");
        (state.visible.len(), state.exact_total)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
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
        let (page_rows, total, exact_total, has_more, analysis_pending, error) = {
            let state = self.state.0.lock().expect("projection state poisoned");
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
                    locate_after_key(
                        self.context.store.as_ref(),
                        &state.visible,
                        &decoded.last_key,
                    )?
                }
            };
            let end = start.saturating_add(limit).min(state.visible.len());
            (
                state.visible[start..end].to_vec(),
                state.visible.len(),
                state.exact_total,
                end < state.visible.len(),
                !state.completed,
                state.error.clone(),
            )
        };
        if let Some(error) = error {
            return Err(error);
        }
        let mut rows = Vec::with_capacity(page_rows.len());
        for source_row in page_rows {
            rows.push(self.project_row(source_row)?);
        }
        let next = if has_more || analysis_pending {
            rows.last().map(|row| {
                encode_cursor(
                    self.context.identity,
                    self.plan.projection_identity,
                    row.key(),
                )
            })
        } else {
            None
        };
        Ok(EventPage {
            rows,
            next,
            total,
            exact_total,
            completeness: self.completeness.clone(),
        })
    }

    fn project_row(&self, source_row: usize) -> Result<TimelineRow, AnalysisError> {
        let key = required_event_key(self.context.store.as_ref(), source_row)?;
        let kind = self
            .context
            .store
            .event_kind(source_row)
            .map_err(AnalysisError::store)?
            .ok_or_else(|| AnalysisError::store_shape("event kind is absent"))?;
        let provenance = self
            .context
            .store
            .provenance(source_row)
            .map_err(AnalysisError::store)?
            .ok_or_else(|| AnalysisError::store_shape("event provenance is absent"))?;
        if kind == EventKind::Discontinuity {
            let (cause, evidence) = self
                .discontinuities
                .get(&source_row)
                .copied()
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

fn derive_store_identity(store: &dyn TraceStoreView) -> Result<StoreIdentity, AnalysisError> {
    let mut hash = Sha256::new();
    hash.update(b"qtrace-store-identity-v1");
    hash.update((store.event_count() as u64).to_le_bytes());
    for row in 0..store.event_count() {
        let key = required_event_key(store, row)?;
        hash_event_key(&mut hash, &key);
        let kind = store
            .event_kind(row)
            .map_err(AnalysisError::store)?
            .ok_or_else(|| AnalysisError::store_shape("event kind is absent"))?;
        hash.update(kind.external_tag());
        let provenance = store
            .provenance(row)
            .map_err(AnalysisError::store)?
            .ok_or_else(|| AnalysisError::store_shape("event provenance is absent"))?;
        hash.update([provenance_tag(provenance)]);
    }
    let capabilities = serde_json::to_vec(store.capabilities())
        .map_err(|error| AnalysisError::store_shape(error.to_string()))?;
    hash_len_prefixed(&mut hash, &capabilities);
    let completeness = serde_json::to_vec(store.completeness())
        .map_err(|error| AnalysisError::store_shape(error.to_string()))?;
    hash_len_prefixed(&mut hash, &completeness);
    Ok(StoreIdentity(hash.finalize().into()))
}

fn derive_projection_identity(store: StoreIdentity, filter: &EventFilter) -> ProjectionIdentity {
    let mut hash = Sha256::new();
    hash.update(b"qtrace-projection-v1");
    hash.update(store.0);
    hash.update(filter.digest());
    ProjectionIdentity(hash.finalize().into())
}

fn plan_candidates(
    store: &dyn TraceStoreView,
    filter: &EventFilter,
) -> Result<(Vec<usize>, usize), AnalysisError> {
    let mut groups = Vec::new();
    if !filter.tids.is_empty() {
        groups.push(
            store
                .rows_for_tids(&filter.tids)
                .map_err(AnalysisError::store)?,
        );
    }
    if !filter.kinds.is_empty() {
        groups.push(
            store
                .rows_of_kinds(&filter.kinds)
                .map_err(AnalysisError::store)?,
        );
    }
    if !filter.modules.is_empty() {
        groups.push(
            store
                .rows_for_modules(&filter.modules)
                .map_err(AnalysisError::store)?,
        );
    }
    if !filter.sequence.is_empty() && filter.sequence.iter().all(|range| range.last < u64::MAX) {
        let lists = filter
            .sequence
            .iter()
            .map(|range| {
                store
                    .rows_for_sequence_range(range.first, range.last + 1)
                    .map_err(AnalysisError::store)
            })
            .collect::<Result<Vec<_>, _>>()?;
        groups.push(union_rows(lists));
    }
    if !filter.relative_pc.is_empty() && !filter.modules.is_empty() {
        let mut lists = Vec::new();
        for module in &filter.modules {
            for range in &filter.relative_pc {
                lists.push(
                    store
                        .rows_for_module_pc_range(*module, range.start, range.end_exclusive)
                        .map_err(AnalysisError::store)?,
                );
            }
        }
        groups.push(union_rows(lists));
    }
    if !filter.mnemonic.is_empty() {
        let mut definitions = Vec::new();
        let mut definition_id = 0_u32;
        while let Some(definition) = store.definition(definition_id) {
            let mnemonic = store
                .string_bytes(definition.mnemonic)
                .map_err(AnalysisError::store)?;
            if mnemonic_matches(&filter.mnemonic, mnemonic) {
                definitions.push(definition_id);
            }
            definition_id = definition_id
                .checked_add(1)
                .ok_or_else(|| AnalysisError::store_shape("definition ID overflow"))?;
        }
        groups.push(
            store
                .rows_for_definitions(&definitions)
                .map_err(AnalysisError::store)?,
        );
    }
    if !filter.register.reads.is_empty() {
        groups.push(register_rows(store, &filter.register.reads)?);
    }
    if !filter.register.writes.is_empty() {
        groups.push(register_rows(store, &filter.register.writes)?);
    }
    if !filter.memory.is_empty() {
        let lists = filter
            .memory
            .iter()
            .map(|memory| {
                store
                    .memory_overlaps(memory.range.start, memory.range.end_exclusive)
                    .map_err(AnalysisError::store)
            })
            .collect::<Result<Vec<_>, _>>()?;
        groups.push(union_rows(lists));
    }
    if !filter.semantic_categories.is_empty() {
        let values = filter
            .semantic_categories
            .iter()
            .map(String::as_bytes)
            .collect::<Vec<_>>();
        groups.push(
            store
                .rows_for_semantic_categories(&values)
                .map_err(AnalysisError::store)?,
        );
    }
    if !filter.semantic_names.is_empty() {
        let values = filter
            .semantic_names
            .iter()
            .map(String::as_bytes)
            .collect::<Vec<_>>();
        groups.push(
            store
                .rows_for_semantic_names(&values)
                .map_err(AnalysisError::store)?,
        );
    }
    if filter.has_semantic_detail_residual() {
        groups.push(
            store
                .rows_of_kinds(&[
                    EventKind::SemanticCall,
                    EventKind::SemanticRule,
                    EventKind::SemanticError,
                ])
                .map_err(AnalysisError::store)?,
        );
    }
    for group in &mut groups {
        group.sort_unstable();
        group.dedup();
    }
    groups.sort_by_key(Vec::len);
    let indexed_fields = groups.len();
    let candidates = if groups.is_empty() {
        (0..store.event_count()).collect()
    } else {
        let mut groups = groups.into_iter();
        let mut candidates = groups.next().expect("non-empty groups");
        for group in groups {
            candidates = intersect_rows(&candidates, &group);
        }
        candidates
    };
    Ok((candidates, indexed_fields))
}

fn register_rows(
    store: &dyn TraceStoreView,
    slots: &[RegisterSlot],
) -> Result<Vec<usize>, AnalysisError> {
    let lists = slots
        .iter()
        .map(|slot| {
            store
                .rows_observing_register(*slot)
                .map_err(AnalysisError::store)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(union_rows(lists))
}

fn union_rows(lists: Vec<Vec<usize>>) -> Vec<usize> {
    let mut rows = lists.into_iter().flatten().collect::<Vec<_>>();
    rows.sort_unstable();
    rows.dedup();
    rows
}

fn apply_synchronous_residuals(
    store: &dyn TraceStoreView,
    filter: &EventFilter,
    candidates: Vec<usize>,
) -> Result<Vec<usize>, AnalysisError> {
    candidates
        .into_iter()
        .filter_map(|row| match matches_non_detail(store, filter, row) {
            Ok(true) => Some(Ok(row)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn matches_non_detail(
    store: &dyn TraceStoreView,
    filter: &EventFilter,
    row: usize,
) -> Result<bool, AnalysisError> {
    let key = required_event_key(store, row)?;
    if !filter.tids.is_empty() && !key.tid.is_some_and(|tid| filter.tids.contains(&tid)) {
        return Ok(false);
    }
    let kind = store
        .event_kind(row)
        .map_err(AnalysisError::store)?
        .ok_or_else(|| AnalysisError::store_shape("event kind is absent"))?;
    if !filter.kinds.is_empty() && !filter.kinds.contains(&kind) {
        return Ok(false);
    }
    let position = store
        .instruction(row)
        .map(|fact| (fact.module, fact.relative_pc))
        .or_else(|| {
            store
                .memory(row)
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
        let matches = store
            .instruction(row)
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
    if !register_access_matches(store, row, &filter.register.reads, RegisterAccess::Read)
        || !register_access_matches(store, row, &filter.register.writes, RegisterAccess::Write)
    {
        return Ok(false);
    }
    if !filter.memory.is_empty()
        && !store.memory(row).is_some_and(|memory| {
            filter
                .memory
                .iter()
                .any(|query| memory_matches(query, memory))
        })
    {
        return Ok(false);
    }
    if !filter.semantic_categories.is_empty()
        && !store
            .semantic(row)
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
        && !store.semantic(row).is_some_and(|semantic| {
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
    store: &dyn TraceStoreView,
    row: usize,
    slots: &[RegisterSlot],
    access: RegisterAccess,
) -> bool {
    slots.is_empty()
        || store.register_observations(row).iter().any(|observation| {
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
    let mnemonic = String::from_utf8_lossy(mnemonic).to_ascii_lowercase();
    filters.iter().any(|filter| match filter {
        MnemonicFilter::Exact(value) => mnemonic == *value,
        MnemonicFilter::Contains(value) => mnemonic.contains(value),
    })
}

fn sort_rows_by_stable_key(
    store: &dyn TraceStoreView,
    rows: Vec<usize>,
) -> Result<Vec<usize>, AnalysisError> {
    let mut keyed = rows
        .into_iter()
        .map(|row| Ok((required_event_key(store, row)?, row)))
        .collect::<Result<Vec<_>, AnalysisError>>()?;
    keyed.sort_by(|(left, _), (right, _)| compare_event_keys(left, right));
    Ok(keyed.into_iter().map(|(_, row)| row).collect())
}

fn map_discontinuities(
    store: &dyn TraceStoreView,
) -> Result<BTreeMap<usize, (qtrace_provider::DiscontinuityCause, CompletenessRow)>, AnalysisError>
{
    let rows = store
        .rows_of_kinds(&[EventKind::Discontinuity])
        .map_err(AnalysisError::store)?;
    let rows = sort_rows_by_stable_key(store, rows)?;
    rows.into_iter()
        .map(|row| {
            let payload = store.payload_bytes(row).map_err(AnalysisError::store)?;
            let payload: EventPayload = serde_json::from_slice(payload).map_err(|error| {
                AnalysisError::store_shape(format!("invalid discontinuity payload: {error}"))
            })?;
            let EventPayload::Discontinuity(discontinuity) = payload else {
                return Err(AnalysisError::store_shape(
                    "discontinuity row payload has the wrong event kind",
                ));
            };
            let evidence = CompletenessRow {
                domain: discontinuity.evidence.domain(),
                bounds: discontinuity.evidence.bounds(),
                provenance: discontinuity.evidence.provenance(),
                cause: discontinuity.evidence.cause(),
            };
            Ok((row, (discontinuity.cause, evidence)))
        })
        .collect()
}

fn start_semantic_scan(
    context: Arc<QueryContext>,
    needles: Vec<String>,
    candidates: Vec<usize>,
    state: Arc<(Mutex<ProjectionState>, Condvar)>,
    cancelled: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        for row in candidates {
            if cancelled.load(Ordering::Acquire) {
                finish_projection(&state, false);
                return;
            }
            let result = context
                .store
                .semantic(row)
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
                    if needles
                        .iter()
                        .any(|needle| contains_bytes(detail, needle.as_bytes()))
                    {
                        state
                            .0
                            .lock()
                            .expect("projection state poisoned")
                            .visible
                            .push(row);
                        state.1.notify_all();
                    }
                }
                Err(error) => {
                    let mut projection = state.0.lock().expect("projection state poisoned");
                    projection.error = Some(error);
                    projection.completed = true;
                    state.1.notify_all();
                    return;
                }
            }
        }
        finish_projection(&state, !cancelled.load(Ordering::Acquire));
    });
}

fn finish_projection(state: &(Mutex<ProjectionState>, Condvar), exact: bool) {
    let mut projection = state.0.lock().expect("projection state poisoned");
    projection.exact_total = exact;
    projection.completed = true;
    state.1.notify_all();
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn locate_after_key(
    store: &dyn TraceStoreView,
    rows: &[usize],
    key: &EventKey,
) -> Result<usize, AnalysisError> {
    let mut left = 0;
    let mut right = rows.len();
    while left < right {
        let middle = left + (right - left) / 2;
        let candidate = required_event_key(store, rows[middle])?;
        match compare_event_keys(&candidate, key) {
            std::cmp::Ordering::Less => left = middle + 1,
            std::cmp::Ordering::Greater => right = middle,
            std::cmp::Ordering::Equal => return Ok(middle + 1),
        }
    }
    Err(AnalysisError::cursor_mismatch(
        "cursor event is absent from this projection",
    ))
}

fn required_event_key(store: &dyn TraceStoreView, row: usize) -> Result<EventKey, AnalysisError> {
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
    last_key: EventKey,
}

fn encode_cursor(
    store: StoreIdentity,
    projection: ProjectionIdentity,
    key: &EventKey,
) -> PageCursor {
    let mut bytes = Vec::with_capacity(CURSOR_BYTES);
    bytes.push(CURSOR_VERSION);
    bytes.extend_from_slice(&store.0);
    bytes.extend_from_slice(&projection.0);
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
        last_key: EventKey::new(
            artifact,
            TimelineId(timeline),
            record_ordinal,
            source_offset,
            sequence_present.then_some(sequence_value),
            tid_present.then_some(tid_value),
        ),
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

fn hash_event_key(hash: &mut Sha256, key: &EventKey) {
    hash.update(key.artifact.as_bytes());
    hash.update(key.timeline.0.to_le_bytes());
    hash.update(key.record_ordinal.to_le_bytes());
    hash.update(key.source_offset.to_le_bytes());
    hash.update([u8::from(key.sequence.is_some())]);
    hash.update(key.sequence.unwrap_or_default().to_le_bytes());
    hash.update([u8::from(key.tid.is_some())]);
    hash.update(key.tid.unwrap_or_default().to_le_bytes());
}

fn hash_len_prefixed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn provenance_tag(provenance: Provenance) -> u8 {
    match provenance {
        Provenance::Captured => 0,
        Provenance::Derived => 1,
        Provenance::Heuristic => 2,
        Provenance::Unknown => 3,
        Provenance::Damaged => 4,
    }
}
