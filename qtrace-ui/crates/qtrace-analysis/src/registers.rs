use std::{
    collections::HashMap,
    hash::{BuildHasher, Hash},
    mem::{align_of, size_of},
    sync::Arc,
};

use qtrace_provider::{
    AllocationScope, EventKey, EventKind, OperationAbort, Provenance, RegisterSlot, TimelineId,
    WorkDelta, WorkGuard,
};
use qtrace_store::{NormalizedBulkView, RegisterAccess, RegisterObservationRow};

use crate::AnalysisError;

const CHECKPOINT_EVENTS: usize = 4_096;
type ScopeKey = (TimelineId, Option<u32>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterCell {
    pub value: Option<u64>,
    pub known_mask: u64,
    pub captured_width: u8,
    pub provenance: Provenance,
    pub evidence: Option<EventKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterSnapshotState {
    cells: [RegisterCell; RegisterSlot::COUNT],
}

impl RegisterSnapshotState {
    pub fn cell(&self, slot: RegisterSlot) -> &RegisterCell {
        &self.cells[slot.index()]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterStateAtEvent {
    pub key: EventKey,
    pub before: RegisterSnapshotState,
    pub after: RegisterSnapshotState,
}

#[derive(Clone, Copy)]
struct ReplayEvent {
    row: usize,
    observations_start: usize,
    observations_end: usize,
    invalidates: bool,
}

struct ReplayCheckpoint {
    event_index: usize,
    row: usize,
    state: RegisterSnapshotState,
}

struct ScopeReplay {
    events: Vec<ReplayEvent>,
    checkpoints: Vec<ReplayCheckpoint>,
    build_state: RegisterSnapshotState,
    since_checkpoint: usize,
}

impl ScopeReplay {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            checkpoints: Vec::new(),
            build_state: unknown_snapshot(),
            since_checkpoint: 0,
        }
    }
}

pub struct RegisterReplay {
    store: Arc<dyn NormalizedBulkView + Send + Sync>,
    scopes: HashMap<ScopeKey, ScopeReplay>,
}

struct AllowStateWork;

impl WorkGuard for AllowStateWork {
    fn consume(&self, _delta: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

impl RegisterReplay {
    pub fn new<T>(store: Arc<T>) -> Result<Self, AnalysisError>
    where
        T: NormalizedBulkView + Send + Sync + 'static,
    {
        Self::new_with_guard(store, &AllowStateWork)
    }

    pub fn from_arc(
        store: Arc<dyn NormalizedBulkView + Send + Sync>,
    ) -> Result<Self, AnalysisError> {
        Self::from_arc_with_guard(store, &AllowStateWork)
    }

    pub fn new_with_guard<T>(store: Arc<T>, guard: &dyn WorkGuard) -> Result<Self, AnalysisError>
    where
        T: NormalizedBulkView + Send + Sync + 'static,
    {
        Self::from_arc_with_guard(store, guard)
    }

    pub fn from_arc_with_guard(
        store: Arc<dyn NormalizedBulkView + Send + Sync>,
        guard: &dyn WorkGuard,
    ) -> Result<Self, AnalysisError> {
        let observations = store.register_observation_rows();
        for (chunk_index, chunk) in observations.chunks(CHECKPOINT_EVENTS).enumerate() {
            guard
                .consume(WorkDelta {
                    rows: chunk.len() as u64,
                    nodes: chunk.len() as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::state_budget)?;
            if chunk
                .windows(2)
                .any(|pair| pair[0].owner_row > pair[1].owner_row)
                || (chunk_index != 0
                    && observations[chunk_index * CHECKPOINT_EVENTS - 1].owner_row
                        > chunk[0].owner_row)
            {
                return Err(AnalysisError::state_invalid(
                    "register observations are not ordered by owner row",
                ));
            }
        }

        let mut scopes = HashMap::<ScopeKey, ScopeReplay>::new();
        let mut observation = 0_usize;
        for chunk_start in (0..store.event_count()).step_by(CHECKPOINT_EVENTS) {
            let chunk_end = chunk_start
                .saturating_add(CHECKPOINT_EVENTS)
                .min(store.event_count());
            guard
                .consume(WorkDelta {
                    rows: (chunk_end - chunk_start) as u64,
                    nodes: (chunk_end - chunk_start) as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::state_budget)?;
            for row in chunk_start..chunk_end {
                while observation < observations.len() && observations[observation].owner_row < row
                {
                    observation += 1;
                }
                let observations_start = observation;
                while observation < observations.len() && observations[observation].owner_row == row
                {
                    observation += 1;
                }
                let Some(key) = store.event_key(row).map_err(AnalysisError::state_store)? else {
                    continue;
                };
                let Some(kind) = store.event_kind(row).map_err(AnalysisError::state_store)? else {
                    continue;
                };
                if !matches!(
                    kind,
                    EventKind::Instruction
                        | EventKind::RegisterCheckpoint
                        | EventKind::RegisterDelta
                        | EventKind::Discontinuity
                ) {
                    continue;
                }
                let row_observations = &observations[observations_start..observation];
                let invalidates = (kind == EventKind::Discontinuity
                    && discontinuity_affects_registers(store.as_ref(), row, guard)?)
                    || row_observations.iter().any(|item| {
                        item.access == RegisterAccess::Delta
                            && item.provenance == Provenance::Damaged
                    });
                let event = ReplayEvent {
                    row,
                    observations_start,
                    observations_end: observation,
                    invalidates,
                };

                if kind == EventKind::Discontinuity && key.tid.is_none() && invalidates {
                    let global_scope = (key.timeline, None);
                    if !scopes.contains_key(&global_scope) {
                        reserve_hash_map(&mut scopes, 1, guard)?;
                        scopes.insert(global_scope, ScopeReplay::new());
                    }
                    for ((timeline, _), scope) in &mut scopes {
                        if *timeline == key.timeline {
                            guard
                                .consume(WorkDelta {
                                    nodes: 1,
                                    ..WorkDelta::default()
                                })
                                .map_err(AnalysisError::state_budget)?;
                            append_build_event(
                                scope,
                                event,
                                &key,
                                row_observations,
                                store.as_ref(),
                                guard,
                                true,
                            )?;
                        }
                    }
                    continue;
                }

                let scope_key = (key.timeline, key.tid);
                if !scopes.contains_key(&scope_key) {
                    reserve_hash_map(&mut scopes, 1, guard)?;
                    scopes.insert(scope_key, ScopeReplay::new());
                }
                let Some(scope) = scopes.get_mut(&scope_key) else {
                    return Err(AnalysisError::state_invalid(
                        "register replay scope insertion failed",
                    ));
                };
                append_build_event(
                    scope,
                    event,
                    &key,
                    row_observations,
                    store.as_ref(),
                    guard,
                    invalidates,
                )?;
            }
        }
        Ok(Self { store, scopes })
    }

    pub fn state_at(&self, key: &EventKey) -> Result<RegisterStateAtEvent, AnalysisError> {
        self.state_at_with_guard(key, &AllowStateWork)
    }

    pub fn state_at_with_guard(
        &self,
        key: &EventKey,
        guard: &dyn WorkGuard,
    ) -> Result<RegisterStateAtEvent, AnalysisError> {
        let target = self
            .store
            .row_for_source_key(key)
            .ok_or_else(|| AnalysisError::state_invalid("event key is not in this trace"))?;
        let Some(scope) = self.scopes.get(&(key.timeline, key.tid)) else {
            let state = unknown_snapshot();
            return Ok(RegisterStateAtEvent {
                key: key.clone(),
                before: state.clone(),
                after: state,
            });
        };
        let event_end = guarded_upper_bound(scope.events.len(), guard, |index| {
            scope.events[index].row <= target
        })?;
        let checkpoint_end = guarded_upper_bound(scope.checkpoints.len(), guard, |index| {
            scope.checkpoints[index].row < target
        })?;
        let (mut state, replay_start) = if checkpoint_end == 0 {
            (unknown_snapshot(), 0)
        } else {
            let checkpoint = &scope.checkpoints[checkpoint_end - 1];
            (checkpoint.state.clone(), checkpoint.event_index + 1)
        };
        let observations = self.store.register_observation_rows();
        for chunk in scope.events[replay_start..event_end].chunks(CHECKPOINT_EVENTS) {
            guard
                .consume(WorkDelta {
                    rows: chunk.len() as u64,
                    nodes: chunk.len() as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::state_budget)?;
            for event in chunk {
                let row_key = self
                    .store
                    .event_key(event.row)
                    .map_err(AnalysisError::state_store)?
                    .ok_or_else(|| AnalysisError::state_invalid("event row has no key"))?;
                let row_observations =
                    &observations[event.observations_start..event.observations_end];
                if event.row == target {
                    let before =
                        apply_before(state, &row_key, event.invalidates, row_observations)?;
                    let mut after = before.clone();
                    apply_writes(
                        &mut after,
                        self.store.as_ref(),
                        event.row,
                        &row_key,
                        row_observations,
                        guard,
                    )?;
                    return Ok(RegisterStateAtEvent {
                        key: key.clone(),
                        before,
                        after,
                    });
                }
                apply_transition(
                    &mut state,
                    self.store.as_ref(),
                    event,
                    &row_key,
                    row_observations,
                    guard,
                )?;
            }
        }
        Ok(RegisterStateAtEvent {
            key: key.clone(),
            before: state.clone(),
            after: state,
        })
    }
}

fn append_build_event(
    scope: &mut ScopeReplay,
    event: ReplayEvent,
    key: &EventKey,
    observations: &[RegisterObservationRow],
    store: &dyn NormalizedBulkView,
    guard: &dyn WorkGuard,
    force_checkpoint: bool,
) -> Result<(), AnalysisError> {
    guarded_vec_push(&mut scope.events, event, guard, "register event index")?;
    apply_transition(
        &mut scope.build_state,
        store,
        &event,
        key,
        observations,
        guard,
    )?;
    scope.since_checkpoint = scope.since_checkpoint.saturating_add(1);
    if force_checkpoint
        || is_reliable_full_checkpoint(observations)
        || scope.since_checkpoint == CHECKPOINT_EVENTS
    {
        let checkpoint = ReplayCheckpoint {
            event_index: scope.events.len() - 1,
            row: event.row,
            state: scope.build_state.clone(),
        };
        guarded_vec_push(
            &mut scope.checkpoints,
            checkpoint,
            guard,
            "register checkpoint index",
        )?;
        scope.since_checkpoint = 0;
    }
    Ok(())
}

fn apply_transition(
    state: &mut RegisterSnapshotState,
    store: &dyn NormalizedBulkView,
    event: &ReplayEvent,
    key: &EventKey,
    observations: &[RegisterObservationRow],
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    if event.invalidates {
        invalidate(state, key);
    }
    mark_derived(state);
    apply_non_writes(state, observations, key)?;
    apply_writes(state, store, event.row, key, observations, guard)
}

fn apply_before(
    mut state: RegisterSnapshotState,
    key: &EventKey,
    invalidates: bool,
    observations: &[RegisterObservationRow],
) -> Result<RegisterSnapshotState, AnalysisError> {
    if invalidates {
        invalidate(&mut state, key);
    }
    mark_derived(&mut state);
    apply_non_writes(&mut state, observations, key)?;
    Ok(state)
}

fn mark_derived(state: &mut RegisterSnapshotState) {
    for cell in &mut state.cells {
        if cell.known_mask != 0 && cell.provenance == Provenance::Captured {
            cell.provenance = Provenance::Derived;
        }
    }
}

fn invalidate(state: &mut RegisterSnapshotState, key: &EventKey) {
    for cell in &mut state.cells {
        *cell = unknown_cell();
        cell.provenance = Provenance::Damaged;
        cell.evidence = Some(key.clone());
    }
}

fn apply_non_writes(
    state: &mut RegisterSnapshotState,
    observations: &[RegisterObservationRow],
    key: &EventKey,
) -> Result<(), AnalysisError> {
    for observation in observations.iter().filter(|item| {
        matches!(
            item.access,
            RegisterAccess::Read | RegisterAccess::Checkpoint | RegisterAccess::Delta
        ) && item.provenance != Provenance::Damaged
    }) {
        apply_observation(state, observation, key, false)?;
    }
    Ok(())
}

fn apply_writes(
    state: &mut RegisterSnapshotState,
    store: &dyn NormalizedBulkView,
    owner_row: usize,
    key: &EventKey,
    observations: &[RegisterObservationRow],
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    for observation in observations.iter().filter(|item| {
        item.access == RegisterAccess::Write && item.provenance != Provenance::Damaged
    }) {
        apply_observation(
            state,
            observation,
            key,
            is_canonical_w_write(store, owner_row, observation, guard)?,
        )?;
    }
    Ok(())
}

fn guarded_upper_bound(
    len: usize,
    guard: &dyn WorkGuard,
    before: impl Fn(usize) -> bool,
) -> Result<usize, AnalysisError> {
    let (mut low, mut high) = (0, len);
    while low < high {
        guard
            .consume(WorkDelta {
                nodes: 1,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        let middle = low + (high - low) / 2;
        if before(middle) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
}

fn guarded_vec_push<T>(
    values: &mut Vec<T>,
    value: T,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<(), AnalysisError> {
    if values.len() == values.capacity() {
        let required = values
            .len()
            .checked_add(1)
            .ok_or_else(|| AnalysisError::state_hard_limit("state index length overflows"))?;
        let capacity = values
            .capacity()
            .checked_mul(2)
            .map(|doubled| doubled.max(required).max(4))
            .ok_or_else(|| AnalysisError::state_hard_limit("state index capacity overflows"))?;
        let bytes = capacity
            .checked_mul(size_of::<T>())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| AnalysisError::state_hard_limit("state index allocation overflows"))?;
        let allocation =
            AllocationScope::begin(guard, bytes, 0).map_err(AnalysisError::state_budget)?;
        values
            .try_reserve_exact(capacity - values.len())
            .map_err(|_| AnalysisError::state_hard_limit(detail))?;
        drop(allocation);
    }
    values.push(value);
    Ok(())
}

fn reserve_hash_map<K, V, S>(
    values: &mut HashMap<K, V, S>,
    additional: usize,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    if values.capacity().saturating_sub(values.len()) >= additional {
        return Ok(());
    }
    let required = values
        .len()
        .checked_add(additional)
        .ok_or_else(|| AnalysisError::state_hard_limit("register scope count overflows"))?;
    let buckets = if required < 4 {
        4
    } else if required < 8 {
        8
    } else {
        required
            .checked_mul(8)
            .and_then(|scaled| scaled.checked_add(6))
            .map(|scaled| scaled / 7)
            .and_then(usize::checked_next_power_of_two)
            .ok_or_else(|| AnalysisError::state_hard_limit("register scope buckets overflow"))?
    };
    let alignment_slack = align_of::<(K, V)>().saturating_sub(1);
    let bytes = buckets
        .checked_mul(size_of::<(K, V)>())
        .and_then(|value| value.checked_add(alignment_slack))
        .and_then(|value| value.checked_add(buckets))
        .and_then(|value| value.checked_add(16))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| AnalysisError::state_hard_limit("register scope allocation overflows"))?;
    let allocation = AllocationScope::begin(guard, bytes, alignment_slack as u64)
        .map_err(AnalysisError::state_budget)?;
    values
        .try_reserve(additional)
        .map_err(|_| AnalysisError::state_hard_limit("register scope allocation failed"))?;
    drop(allocation);
    Ok(())
}

fn is_reliable_full_checkpoint(observations: &[RegisterObservationRow]) -> bool {
    if observations.len() != RegisterSlot::COUNT {
        return false;
    }
    let mut mask = 0_u64;
    for observation in observations {
        if observation.access != RegisterAccess::Checkpoint
            || observation.provenance == Provenance::Damaged
            || observation.slot as usize >= RegisterSlot::COUNT
        {
            return false;
        }
        mask |= 1_u64 << observation.slot;
    }
    mask == (1_u64 << RegisterSlot::COUNT) - 1
}

fn unknown_cell() -> RegisterCell {
    RegisterCell {
        value: None,
        known_mask: 0,
        captured_width: 0,
        provenance: Provenance::Unknown,
        evidence: None,
    }
}

fn unknown_snapshot() -> RegisterSnapshotState {
    RegisterSnapshotState {
        cells: std::array::from_fn(|_| unknown_cell()),
    }
}

fn discontinuity_affects_registers(
    store: &dyn NormalizedBulkView,
    row: usize,
    guard: &dyn WorkGuard,
) -> Result<bool, AnalysisError> {
    let bytes = store
        .payload_bytes(row)
        .map_err(AnalysisError::state_store)?;
    if bytes.is_empty() {
        return Ok(true);
    }
    for chunk in bytes.chunks(CHECKPOINT_EVENTS) {
        guard
            .consume(WorkDelta {
                input_bytes: chunk.len() as u64,
                nodes: chunk.len() as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
    }
    let discontinuity = crate::timeline::decode_discontinuity_payload(bytes)?;
    Ok(discontinuity.evidence.domain() != qtrace_provider::RangeDomain::MemoryAddresses)
}

fn is_canonical_w_write(
    store: &dyn NormalizedBulkView,
    owner_row: usize,
    observation: &RegisterObservationRow,
    guard: &dyn WorkGuard,
) -> Result<bool, AnalysisError> {
    if observation.captured_width != 4 {
        return Ok(false);
    }
    let Some(instruction) = store.instruction(owner_row) else {
        return Ok(false);
    };
    let Some(definition_id) = instruction.definition else {
        return Ok(false);
    };
    let Some(definition) = store.definition(definition_id) else {
        return Err(AnalysisError::state_invalid(
            "instruction definition is missing",
        ));
    };
    let bytes = store
        .blob_bytes(definition.exact_blob)
        .map_err(AnalysisError::state_store)?;
    for chunk in bytes.chunks(CHECKPOINT_EVENTS) {
        guard
            .consume(WorkDelta {
                input_bytes: chunk.len() as u64,
                nodes: chunk.len() as u64,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
    }
    let scratch = bytes.len().saturating_mul(4) as u64;
    let allocation =
        AllocationScope::begin(guard, scratch, scratch).map_err(AnalysisError::state_budget)?;
    let definition: qtrace_provider::InstructionDefinition = serde_json::from_slice(bytes)
        .map_err(|_| AnalysisError::state_invalid("instruction definition payload is malformed"))?;
    drop(allocation);
    Ok(definition.writes.iter().any(|write| {
        if write.slot != observation.slot || write.captured_width != 4 {
            return false;
        }
        if observation.slot as usize == RegisterSlot::Sp.index() {
            return write.name.eq_ignore_ascii_case("wsp");
        }
        write
            .name
            .strip_prefix(['w', 'W'])
            .is_some_and(|suffix| suffix.parse::<u8>().ok() == Some(observation.slot))
    }))
}

fn apply_observation(
    state: &mut RegisterSnapshotState,
    observation: &RegisterObservationRow,
    key: &EventKey,
    zero_extend_w: bool,
) -> Result<(), AnalysisError> {
    let slot = RegisterSlot::from_index(observation.slot as usize)
        .ok_or_else(|| AnalysisError::state_invalid("register observation slot is invalid"))?;
    if observation.captured_width == 0 || observation.captured_width > 8 {
        return Err(AnalysisError::state_invalid(
            "register observation width is outside 1..=8",
        ));
    }
    let bits = u32::from(observation.captured_width) * 8;
    let low_mask = if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    };
    state.cells[slot.index()] = RegisterCell {
        value: Some(observation.value & low_mask),
        known_mask: if zero_extend_w { u64::MAX } else { low_mask },
        captured_width: observation.captured_width,
        provenance: observation.provenance,
        evidence: Some(key.clone()),
    };
    Ok(())
}
