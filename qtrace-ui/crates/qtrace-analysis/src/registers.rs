use std::{collections::HashMap, sync::Arc};

use qtrace_provider::{
    AllocationScope, EventKey, EventKind, OperationAbort, Provenance, RegisterSlot, WorkDelta,
    WorkGuard,
};
use qtrace_store::{NormalizedBulkView, RegisterAccess, RegisterObservationRow};

use crate::AnalysisError;

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
    cells: Vec<RegisterCell>,
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

pub struct RegisterReplay {
    store: Arc<dyn NormalizedBulkView + Send + Sync>,
    checkpoints: Vec<ReplayCheckpoint>,
}

#[derive(Clone)]
struct ReplayCheckpoint {
    row: usize,
    timeline: qtrace_provider::TimelineId,
    tid: Option<u32>,
    state: RegisterSnapshotState,
}

struct BuildState {
    instructions: usize,
    state: RegisterSnapshotState,
}

const REPLAY_CHECKPOINT_ROWS: usize = 4_096;

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
        for chunk in store
            .register_observation_rows()
            .chunks(REPLAY_CHECKPOINT_ROWS)
        {
            guard
                .consume(WorkDelta {
                    rows: chunk.len() as u64,
                    nodes: chunk.len() as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::state_budget)?;
        }
        if store
            .register_observation_rows()
            .windows(2)
            .any(|rows| rows[0].owner_row > rows[1].owner_row)
        {
            return Err(AnalysisError::state_invalid(
                "register observations are not ordered by owner row",
            ));
        }
        let event_count = store.event_count();
        let mut states = HashMap::new();
        let mut checkpoints = Vec::new();
        let observations = store.register_observation_rows();
        let mut observation = 0_usize;
        for chunk_start in (0..event_count).step_by(REPLAY_CHECKPOINT_ROWS) {
            let chunk_end = chunk_start
                .saturating_add(REPLAY_CHECKPOINT_ROWS)
                .min(event_count);
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
                let start = observation;
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
                if kind != EventKind::Instruction
                    && kind != EventKind::RegisterCheckpoint
                    && kind != EventKind::RegisterDelta
                    && kind != EventKind::Discontinuity
                {
                    continue;
                }
                let scope_key = (key.timeline, key.tid);
                let state_map_grows = states.len() == states.capacity();
                let state_map_growth = states.capacity().max(3);
                if let std::collections::hash_map::Entry::Vacant(entry) = states.entry(scope_key) {
                    let state = unknown_snapshot(guard)?;
                    let allocation = if state_map_grows {
                        let bytes = state_map_growth
                            .checked_mul(std::mem::size_of::<(
                                (qtrace_provider::TimelineId, Option<u32>),
                                BuildState,
                            )>())
                            .and_then(|value| u64::try_from(value).ok())
                            .ok_or_else(|| {
                                AnalysisError::state_hard_limit(
                                    "register replay index allocation overflows",
                                )
                            })?;
                        Some(
                            AllocationScope::begin(guard, bytes, bytes)
                                .map_err(AnalysisError::state_budget)?,
                        )
                    } else {
                        None
                    };
                    entry.insert(BuildState {
                        instructions: 0,
                        state,
                    });
                    drop(allocation);
                }
                let build = states.get_mut(&scope_key).expect("state inserted above");
                let row_observations = &observations[start..observation];
                let (_, after) = apply_event(
                    store.as_ref(),
                    row,
                    &build.state,
                    &key,
                    kind,
                    row_observations,
                    guard,
                )?;
                build.state = after;
                if kind == EventKind::Instruction {
                    build.instructions += 1;
                }
                let reliable_full = is_reliable_full_checkpoint(row_observations);
                if reliable_full
                    || (kind == EventKind::Instruction
                        && build.instructions % REPLAY_CHECKPOINT_ROWS == 0)
                {
                    guarded_checkpoint_push(
                        &mut checkpoints,
                        ReplayCheckpoint {
                            row,
                            timeline: key.timeline,
                            tid: key.tid,
                            state: snapshot_clone(&build.state, guard)?,
                        },
                        guard,
                    )?;
                }
            }
        }
        Ok(Self { store, checkpoints })
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
        let mut state = unknown_snapshot(guard)?;
        let mut replay_start = 0_usize;
        let mut checkpoint_visits = 0_usize;
        for checkpoint in self.checkpoints.iter().rev() {
            checkpoint_visits += 1;
            if checkpoint_visits == REPLAY_CHECKPOINT_ROWS {
                guard
                    .consume(WorkDelta {
                        nodes: checkpoint_visits as u64,
                        ..WorkDelta::default()
                    })
                    .map_err(AnalysisError::state_budget)?;
                checkpoint_visits = 0;
            }
            if checkpoint.row < target
                && checkpoint.timeline == key.timeline
                && checkpoint.tid == key.tid
            {
                state = snapshot_clone(&checkpoint.state, guard)?;
                replay_start = checkpoint.row.saturating_add(1);
                break;
            }
        }
        if checkpoint_visits != 0 {
            guard
                .consume(WorkDelta {
                    nodes: checkpoint_visits as u64,
                    ..WorkDelta::default()
                })
                .map_err(AnalysisError::state_budget)?;
        }
        let observations = self.store.register_observation_rows();
        let mut observation = first_observation_at_or_after(observations, replay_start, guard)?;

        for chunk_start in (replay_start..=target).step_by(REPLAY_CHECKPOINT_ROWS) {
            let chunk_end = chunk_start
                .saturating_add(REPLAY_CHECKPOINT_ROWS)
                .min(target.saturating_add(1));
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
                let start = observation;
                while observation < observations.len() && observations[observation].owner_row == row
                {
                    observation += 1;
                }
                let row_key = self
                    .store
                    .event_key(row)
                    .map_err(AnalysisError::state_store)?
                    .ok_or_else(|| AnalysisError::state_invalid("event row has no key"))?;
                if row_key.timeline != key.timeline || row_key.tid != key.tid {
                    continue;
                }
                let kind = self
                    .store
                    .event_kind(row)
                    .map_err(AnalysisError::state_store)?
                    .ok_or_else(|| AnalysisError::state_invalid("event row has no kind"))?;
                let row_observations = &observations[start..observation];
                let (row_before, row_after) = apply_event(
                    self.store.as_ref(),
                    row,
                    &state,
                    &row_key,
                    kind,
                    row_observations,
                    guard,
                )?;
                if row == target {
                    return Ok(RegisterStateAtEvent {
                        key: key.clone(),
                        before: row_before,
                        after: row_after,
                    });
                }
                state = row_after;
            }
        }
        Err(AnalysisError::state_invalid(
            "target event could not be replayed",
        ))
    }
}

fn guarded_checkpoint_push(
    checkpoints: &mut Vec<ReplayCheckpoint>,
    value: ReplayCheckpoint,
    guard: &dyn WorkGuard,
) -> Result<(), AnalysisError> {
    if checkpoints.len() == checkpoints.capacity() {
        let old = checkpoints.capacity();
        let additional = old.max(1);
        let bytes = additional
            .checked_mul(std::mem::size_of::<ReplayCheckpoint>())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| AnalysisError::state_hard_limit("checkpoint allocation overflows"))?;
        let scope =
            AllocationScope::begin(guard, bytes, bytes).map_err(AnalysisError::state_budget)?;
        checkpoints
            .try_reserve_exact(additional)
            .map_err(|_| AnalysisError::state_hard_limit("checkpoint allocation failed"))?;
        drop(scope);
    }
    checkpoints.push(value);
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

fn first_observation_at_or_after(
    observations: &[RegisterObservationRow],
    row: usize,
    guard: &dyn WorkGuard,
) -> Result<usize, AnalysisError> {
    let (mut low, mut high) = (0_usize, observations.len());
    while low < high {
        guard
            .consume(WorkDelta {
                nodes: 1,
                ..WorkDelta::default()
            })
            .map_err(AnalysisError::state_budget)?;
        let middle = low + (high - low) / 2;
        if observations[middle].owner_row < row {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    Ok(low)
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

fn unknown_snapshot(guard: &dyn WorkGuard) -> Result<RegisterSnapshotState, AnalysisError> {
    let bytes = (RegisterSlot::COUNT * std::mem::size_of::<RegisterCell>()) as u64;
    let scope = AllocationScope::begin(guard, bytes, 0).map_err(AnalysisError::state_budget)?;
    let mut cells = Vec::new();
    cells
        .try_reserve_exact(RegisterSlot::COUNT)
        .map_err(|_| AnalysisError::state_invalid("register-state allocation failed"))?;
    cells.resize_with(RegisterSlot::COUNT, unknown_cell);
    drop(scope);
    Ok(RegisterSnapshotState { cells })
}

fn snapshot_clone(
    state: &RegisterSnapshotState,
    guard: &dyn WorkGuard,
) -> Result<RegisterSnapshotState, AnalysisError> {
    let bytes = (state.cells.len() * std::mem::size_of::<RegisterCell>()) as u64;
    let scope = AllocationScope::begin(guard, bytes, 0).map_err(AnalysisError::state_budget)?;
    let cells = state.cells.clone();
    drop(scope);
    Ok(RegisterSnapshotState { cells })
}

fn apply_event(
    store: &dyn NormalizedBulkView,
    owner_row: usize,
    prior: &RegisterSnapshotState,
    key: &EventKey,
    kind: EventKind,
    observations: &[RegisterObservationRow],
    guard: &dyn WorkGuard,
) -> Result<(RegisterSnapshotState, RegisterSnapshotState), AnalysisError> {
    let mut before = snapshot_clone(prior, guard)?;
    if (kind == EventKind::Discontinuity
        && discontinuity_affects_registers(store, owner_row, guard)?)
        || observations
            .iter()
            .any(|row| row.access == RegisterAccess::Delta && row.provenance == Provenance::Damaged)
    {
        before.cells.fill_with(unknown_cell);
        for cell in &mut before.cells {
            cell.provenance = Provenance::Damaged;
            cell.evidence = Some(key.clone());
        }
    }
    for cell in &mut before.cells {
        if cell.known_mask != 0 && cell.provenance == Provenance::Captured {
            cell.provenance = Provenance::Derived;
        }
    }
    for observation in observations.iter().filter(|row| {
        matches!(
            row.access,
            RegisterAccess::Read | RegisterAccess::Checkpoint | RegisterAccess::Delta
        ) && row.provenance != Provenance::Damaged
    }) {
        apply_observation(&mut before, observation, key, false)?;
    }
    let mut after = snapshot_clone(&before, guard)?;
    for observation in observations
        .iter()
        .filter(|row| row.access == RegisterAccess::Write && row.provenance != Provenance::Damaged)
    {
        apply_observation(
            &mut after,
            observation,
            key,
            is_canonical_w_write(store, owner_row, observation, guard)?,
        )?;
    }
    Ok((before, after))
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
    for chunk in bytes.chunks(REPLAY_CHECKPOINT_ROWS) {
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
    let payload: qtrace_provider::EventPayload = serde_json::from_slice(bytes)
        .map_err(|_| AnalysisError::state_invalid("discontinuity payload is malformed"))?;
    drop(allocation);
    let qtrace_provider::EventPayload::Discontinuity(discontinuity) = payload else {
        return Err(AnalysisError::state_invalid(
            "discontinuity row has the wrong payload",
        ));
    };
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
    guard
        .consume(WorkDelta {
            input_bytes: bytes.len() as u64,
            nodes: bytes.len() as u64,
            ..WorkDelta::default()
        })
        .map_err(AnalysisError::state_budget)?;
    let scratch = bytes.len().saturating_mul(4) as u64;
    let scope =
        AllocationScope::begin(guard, scratch, scratch).map_err(AnalysisError::state_budget)?;
    let definition: qtrace_provider::InstructionDefinition = serde_json::from_slice(bytes)
        .map_err(|_| AnalysisError::state_invalid("instruction definition payload is malformed"))?;
    drop(scope);
    Ok(definition.writes.iter().any(|write| {
        write.slot == observation.slot
            && write.captured_width == 4
            && write
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
