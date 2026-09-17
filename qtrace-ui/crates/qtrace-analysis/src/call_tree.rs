use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    mem::size_of,
    sync::Arc,
};

use qtrace_provider::{
    AllocationScope, EventKey, EventKind, EventPayload, OperationAbort, PcRelativeKind, Provenance,
    RegisterSlot, SignalHandlerPhase, TimelineId, WorkDelta, WorkGuard,
};
use qtrace_store::{NormalizedBulkView, RegisterAccess};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AnalysisError;

const CALL_FLAG: u32 = 1 << 2;
const RETURN_FLAG: u32 = 1 << 3;
const BRANCH_FLAG: u32 = 1;
const WORK_CHUNK: usize = 4_096;
pub const MAX_CALL_TREE_ROWS: usize = 10_000_000;
pub const MAX_CALL_TREE_NODES: usize = 2_000_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct CallTreeIdentity([u8; 32]);

impl CallTreeIdentity {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallTreeOptions {
    pub infer_tail_calls: bool,
    pub display_names: BTreeMap<u64, String>,
}

impl Default for CallTreeOptions {
    fn default() -> Self {
        Self {
            infer_tail_calls: true,
            display_names: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallTargetEvidence {
    Immediate,
    NextPc,
    CapturedRegister(RegisterSlot),
    LinkRegister,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    SourceBegin,
    SourceEnd,
    Discontinuity,
    Termination,
    UnmatchedReturn,
    SignalTransition,
    Unwind,
    TailCall,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameState {
    Complete,
    Incomplete(IncompleteReason),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticEnrichment {
    pub key: EventKey,
    pub source_row: usize,
    pub category: Option<String>,
    pub name: String,
    pub detail: String,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallNode {
    pub id: usize,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub timeline: TimelineId,
    pub tid: u32,
    pub target: Option<u64>,
    pub target_evidence: CallTargetEvidence,
    pub display: String,
    pub entry_key: EventKey,
    pub exit_key: Option<EventKey>,
    pub source_row_start: usize,
    pub source_row_end_exclusive: usize,
    pub provenance: Provenance,
    pub state: FrameState,
    pub semantics: Vec<SemanticEnrichment>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntervalKind {
    TraceBoundary,
    UnmatchedReturn,
    SignalHandler,
    Unwind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionInterval {
    pub kind: IntervalKind,
    pub timeline: TimelineId,
    pub tid: u32,
    pub entry_key: EventKey,
    pub exit_key: Option<EventKey>,
    pub source_row_start: usize,
    pub source_row_end_exclusive: usize,
    pub provenance: Provenance,
    pub state: FrameState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallTreeArtifact {
    pub identity: CallTreeIdentity,
    pub timeline: TimelineId,
    pub tid: u32,
    pub roots: Vec<usize>,
    pub nodes: Vec<CallNode>,
    pub intervals: Vec<ExecutionInterval>,
    pub standalone_semantics: Vec<SemanticEnrichment>,
}

pub struct CallTreeAnalyzer {
    store: Arc<dyn NormalizedBulkView + Send + Sync>,
}

struct AllowCallTreeWork;

impl WorkGuard for AllowCallTreeWork {
    fn consume(&self, _: WorkDelta) -> Result<(), OperationAbort> {
        Ok(())
    }
}

#[derive(Clone)]
struct SelectedEvent {
    row: usize,
    key: EventKey,
    kind: EventKind,
    provenance: Provenance,
}

#[derive(Clone, Copy)]
struct OpenFrame {
    node: usize,
    expected_return: Option<u64>,
}

impl CallTreeAnalyzer {
    pub fn new<T>(store: Arc<T>) -> Self
    where
        T: NormalizedBulkView + Send + Sync + 'static,
    {
        Self { store }
    }

    pub fn from_arc(store: Arc<dyn NormalizedBulkView + Send + Sync>) -> Self {
        Self { store }
    }

    pub fn build(
        &self,
        timeline: u64,
        tid: u32,
        options: &CallTreeOptions,
    ) -> Result<CallTreeArtifact, AnalysisError> {
        self.build_with_guard(timeline, tid, options, &AllowCallTreeWork)
    }

    pub fn build_with_guard(
        &self,
        timeline: u64,
        tid: u32,
        options: &CallTreeOptions,
        guard: &dyn WorkGuard,
    ) -> Result<CallTreeArtifact, AnalysisError> {
        if self.store.event_count() > MAX_CALL_TREE_ROWS {
            return Err(AnalysisError::state_hard_limit(
                "call-tree source exceeds row limit",
            ));
        }
        let events = self.select_events(timeline, tid, guard)?;
        self.build_selected(TimelineId(timeline), tid, options, events, guard)
    }

    pub fn build_all_threads(
        &self,
        timeline: u64,
        options: &CallTreeOptions,
    ) -> Result<BTreeMap<u32, CallTreeArtifact>, AnalysisError> {
        self.build_all_threads_with_guard(timeline, options, &AllowCallTreeWork)
    }

    pub fn build_all_threads_with_guard(
        &self,
        timeline: u64,
        options: &CallTreeOptions,
        guard: &dyn WorkGuard,
    ) -> Result<BTreeMap<u32, CallTreeArtifact>, AnalysisError> {
        if self.store.event_count() > MAX_CALL_TREE_ROWS {
            return Err(AnalysisError::state_hard_limit(
                "call-tree source exceeds row limit",
            ));
        }
        let mut tids = BTreeSet::new();
        for start in (0..self.store.event_count()).step_by(WORK_CHUNK) {
            let end = start
                .saturating_add(WORK_CHUNK)
                .min(self.store.event_count());
            consume(guard, end - start)?;
            for row in start..end {
                let Some(key) = self
                    .store
                    .event_key(row)
                    .map_err(AnalysisError::state_store)?
                else {
                    return Err(AnalysisError::store_shape("event key is absent"));
                };
                if key.timeline == TimelineId(timeline) {
                    if let Some(tid) = key.tid {
                        tids.insert(tid);
                    }
                }
            }
        }
        let mut trees = BTreeMap::new();
        for tid in tids {
            trees.insert(tid, self.build_with_guard(timeline, tid, options, guard)?);
        }
        Ok(trees)
    }

    fn select_events(
        &self,
        timeline: u64,
        tid: u32,
        guard: &dyn WorkGuard,
    ) -> Result<Vec<SelectedEvent>, AnalysisError> {
        let mut events = Vec::new();
        for start in (0..self.store.event_count()).step_by(WORK_CHUNK) {
            let end = start
                .saturating_add(WORK_CHUNK)
                .min(self.store.event_count());
            consume(guard, end - start)?;
            for row in start..end {
                let Some(key) = self
                    .store
                    .event_key(row)
                    .map_err(AnalysisError::state_store)?
                else {
                    return Err(AnalysisError::store_shape("event key is absent"));
                };
                if key.timeline != TimelineId(timeline) {
                    continue;
                }
                let Some(kind) = self
                    .store
                    .event_kind(row)
                    .map_err(AnalysisError::state_store)?
                else {
                    return Err(AnalysisError::store_shape("event kind is absent"));
                };
                let is_global_boundary = key.tid.is_none()
                    && matches!(kind, EventKind::Discontinuity | EventKind::Termination);
                if key.tid != Some(tid) && !is_global_boundary {
                    continue;
                }
                let provenance = self
                    .store
                    .provenance(row)
                    .map_err(AnalysisError::state_store)?
                    .ok_or_else(|| AnalysisError::store_shape("event provenance is absent"))?;
                guarded_push(
                    &mut events,
                    SelectedEvent {
                        row,
                        key,
                        kind,
                        provenance,
                    },
                    guard,
                    "call-tree event allocation failed",
                )?;
            }
        }
        Ok(events)
    }

    fn build_selected(
        &self,
        timeline: TimelineId,
        tid: u32,
        options: &CallTreeOptions,
        events: Vec<SelectedEvent>,
        guard: &dyn WorkGuard,
    ) -> Result<CallTreeArtifact, AnalysisError> {
        let identity = derive_identity(self.store.as_ref(), timeline, tid, options, guard)?;
        let mut artifact = CallTreeArtifact {
            identity,
            timeline,
            tid,
            roots: Vec::new(),
            nodes: Vec::new(),
            intervals: Vec::new(),
            standalone_semantics: Vec::new(),
        };
        let mut stack = Vec::<OpenFrame>::new();
        let mut open_signal: Option<usize> = None;
        let mut initial_interval: Option<usize> = None;
        let mut prefix_open = true;
        let mut previous_was_call = None::<usize>;
        let next_pcs = next_instruction_pcs(&events, self.store.as_ref(), guard)?;

        for (index, event) in events.iter().enumerate() {
            if index % WORK_CHUNK == 0 {
                consume(guard, events.len().saturating_sub(index).min(WORK_CHUNK))?;
            }
            match event.kind {
                EventKind::Instruction => {
                    let instruction = self
                        .store
                        .instruction(event.row)
                        .ok_or_else(|| AnalysisError::store_shape("instruction row is absent"))?;
                    let definition = instruction
                        .definition
                        .and_then(|id| self.store.definition(id))
                        .ok_or_else(|| {
                            AnalysisError::store_shape("instruction definition is absent")
                        })?;
                    let next_pc = next_pcs[index];
                    if definition.flags & CALL_FLAG != 0 {
                        prefix_open = false;
                        if let Some(interval) = initial_interval.take() {
                            finish_interval(
                                &mut artifact.intervals[interval],
                                &event.key,
                                event.row,
                                FrameState::Incomplete(IncompleteReason::SourceBegin),
                            );
                        }
                        let (target, evidence) = resolve_target(
                            self.store.as_ref(),
                            event.row,
                            instruction.relative_pc,
                            definition.pc_kind,
                            definition.pc_displacement,
                            next_pc,
                        );
                        let parent = stack.last().map(|frame| frame.node);
                        let node = append_node(
                            &mut artifact,
                            parent,
                            (target, evidence),
                            event,
                            options,
                            event.provenance,
                            guard,
                        )?;
                        guarded_push(
                            &mut stack,
                            OpenFrame {
                                node,
                                expected_return: instruction.relative_pc.checked_add(4),
                            },
                            guard,
                            "call-tree stack allocation failed",
                        )?;
                        previous_was_call = Some(node);
                    } else if definition.flags & RETURN_FLAG != 0 {
                        prefix_open = false;
                        previous_was_call = None;
                        if stack.is_empty() {
                            append_interval(
                                &mut artifact,
                                IntervalKind::UnmatchedReturn,
                                event,
                                FrameState::Incomplete(IncompleteReason::UnmatchedReturn),
                                guard,
                            )?;
                            continue;
                        }
                        if let Some(target) = next_pc {
                            if let Some(position) = stack
                                .iter()
                                .rposition(|frame| frame.expected_return == Some(target))
                            {
                                while stack.len() > position + 1 {
                                    let frame = stack.pop().expect("stack length checked");
                                    finish_node(
                                        &mut artifact.nodes[frame.node],
                                        event,
                                        FrameState::Incomplete(IncompleteReason::Unwind),
                                        Provenance::Heuristic,
                                    );
                                    append_interval(
                                        &mut artifact,
                                        IntervalKind::Unwind,
                                        event,
                                        FrameState::Incomplete(IncompleteReason::Unwind),
                                        guard,
                                    )?;
                                }
                            }
                        }
                        let frame = stack.pop().expect("stack is non-empty");
                        let provenance = artifact.nodes[frame.node].provenance;
                        finish_node(
                            &mut artifact.nodes[frame.node],
                            event,
                            FrameState::Complete,
                            provenance,
                        );
                    } else if options.infer_tail_calls
                        && definition.flags & BRANCH_FLAG != 0
                        && !stack.is_empty()
                    {
                        let target = immediate_target(
                            instruction.relative_pc,
                            definition.pc_kind,
                            definition.pc_displacement,
                        );
                        if target.is_some_and(|target| {
                            Some(target) == next_pc
                                && target != instruction.relative_pc.saturating_add(4)
                        }) {
                            prefix_open = false;
                            let frame = stack.pop().expect("stack is non-empty");
                            let parent = artifact.nodes[frame.node].parent;
                            finish_node(
                                &mut artifact.nodes[frame.node],
                                event,
                                FrameState::Incomplete(IncompleteReason::TailCall),
                                Provenance::Heuristic,
                            );
                            let node = append_node(
                                &mut artifact,
                                parent,
                                (target, CallTargetEvidence::Immediate),
                                event,
                                options,
                                Provenance::Heuristic,
                                guard,
                            )?;
                            guarded_push(
                                &mut stack,
                                OpenFrame {
                                    node,
                                    expected_return: None,
                                },
                                guard,
                                "call-tree stack allocation failed",
                            )?;
                        }
                        previous_was_call = None;
                    } else {
                        if prefix_open && stack.is_empty() && initial_interval.is_none() {
                            initial_interval = Some(append_interval(
                                &mut artifact,
                                IntervalKind::TraceBoundary,
                                event,
                                FrameState::Incomplete(IncompleteReason::SourceBegin),
                                guard,
                            )?);
                        }
                        previous_was_call = None;
                    }
                }
                EventKind::SemanticCall => {
                    let semantic = semantic(self.store.as_ref(), event, guard)?;
                    if let Some(node) = previous_was_call.take() {
                        guarded_push(
                            &mut artifact.nodes[node].semantics,
                            semantic,
                            guard,
                            "call-tree semantic allocation failed",
                        )?;
                    } else {
                        guarded_push(
                            &mut artifact.standalone_semantics,
                            semantic,
                            guard,
                            "standalone semantic allocation failed",
                        )?;
                    }
                }
                EventKind::SignalHandlerBoundary => {
                    prefix_open = false;
                    previous_was_call = None;
                    let payload = decode_payload(self.store.as_ref(), event.row)?;
                    let EventPayload::SignalHandlerBoundary(boundary) = payload else {
                        return Err(AnalysisError::store_shape(
                            "signal-handler payload kind mismatch",
                        ));
                    };
                    match boundary.phase {
                        SignalHandlerPhase::Begin => {
                            close_stack(
                                &mut artifact,
                                &mut stack,
                                event,
                                IncompleteReason::SignalTransition,
                            );
                            if let Some(open) = open_signal.take() {
                                finish_interval(
                                    &mut artifact.intervals[open],
                                    &event.key,
                                    event.row,
                                    FrameState::Incomplete(IncompleteReason::SignalTransition),
                                );
                            }
                            open_signal = Some(append_interval(
                                &mut artifact,
                                IntervalKind::SignalHandler,
                                event,
                                FrameState::Incomplete(IncompleteReason::SignalTransition),
                                guard,
                            )?);
                        }
                        SignalHandlerPhase::Return => {
                            if let Some(open) = open_signal.take() {
                                finish_interval(
                                    &mut artifact.intervals[open],
                                    &event.key,
                                    event.row,
                                    FrameState::Complete,
                                );
                            } else {
                                append_interval(
                                    &mut artifact,
                                    IntervalKind::SignalHandler,
                                    event,
                                    FrameState::Incomplete(IncompleteReason::SignalTransition),
                                    guard,
                                )?;
                            }
                        }
                    }
                }
                EventKind::Discontinuity | EventKind::CoverageGap => {
                    prefix_open = false;
                    previous_was_call = None;
                    close_stack(
                        &mut artifact,
                        &mut stack,
                        event,
                        IncompleteReason::Discontinuity,
                    );
                    if let Some(open) = open_signal.take() {
                        finish_interval(
                            &mut artifact.intervals[open],
                            &event.key,
                            event.row,
                            FrameState::Incomplete(IncompleteReason::Discontinuity),
                        );
                    }
                    initial_interval = None;
                }
                EventKind::Termination => {
                    prefix_open = false;
                    previous_was_call = None;
                    close_stack(
                        &mut artifact,
                        &mut stack,
                        event,
                        IncompleteReason::Termination,
                    );
                    initial_interval = None;
                }
                _ => previous_was_call = None,
            }
        }

        if let Some(last) = events.last() {
            close_stack(&mut artifact, &mut stack, last, IncompleteReason::SourceEnd);
            if let Some(open) = open_signal {
                finish_interval(
                    &mut artifact.intervals[open],
                    &last.key,
                    last.row,
                    FrameState::Incomplete(IncompleteReason::SourceEnd),
                );
            }
            if let Some(open) = initial_interval {
                finish_interval(
                    &mut artifact.intervals[open],
                    &last.key,
                    last.row,
                    FrameState::Incomplete(IncompleteReason::SourceBegin),
                );
            }
        }
        Ok(artifact)
    }
}

fn consume(guard: &dyn WorkGuard, rows: usize) -> Result<(), AnalysisError> {
    guard
        .consume(WorkDelta {
            rows: rows as u64,
            nodes: rows as u64,
            ..WorkDelta::default()
        })
        .map_err(AnalysisError::control)
}

fn derive_identity(
    store: &dyn NormalizedBulkView,
    timeline: TimelineId,
    tid: u32,
    options: &CallTreeOptions,
    guard: &dyn WorkGuard,
) -> Result<CallTreeIdentity, AnalysisError> {
    let mut hash = Sha256::new();
    hash.update(b"qtrace-analysis/call-tree/v1\0sha256");
    let layout = store.normalized_layout_identity();
    hash.update(layout.schema_version().to_le_bytes());
    hash.update(layout.layout_fingerprint());
    hash.update(store.normalized_content_identity().as_bytes());
    hash.update([match store.normalized_source_format() {
        qtrace_store::NormalizedSourceFormat::Qtrb => 0,
        qtrace_store::NormalizedSourceFormat::Flight => 1,
        qtrace_store::NormalizedSourceFormat::Other => 2,
    }]);
    hash.update(timeline.0.to_le_bytes());
    hash.update(tid.to_le_bytes());
    hash.update([u8::from(options.infer_tail_calls)]);
    hash.update((options.display_names.len() as u64).to_le_bytes());
    for (index, (address, name)) in options.display_names.iter().enumerate() {
        if index % WORK_CHUNK == 0 {
            consume(
                guard,
                options
                    .display_names
                    .len()
                    .saturating_sub(index)
                    .min(WORK_CHUNK),
            )?;
        }
        hash.update(address.to_le_bytes());
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
    }
    Ok(CallTreeIdentity(hash.finalize().into()))
}

fn next_instruction_pcs(
    events: &[SelectedEvent],
    store: &dyn NormalizedBulkView,
    guard: &dyn WorkGuard,
) -> Result<Vec<Option<u64>>, AnalysisError> {
    let bytes = events
        .len()
        .checked_mul(size_of::<Option<u64>>())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| AnalysisError::state_hard_limit("next-PC allocation overflows"))?;
    let allocation =
        AllocationScope::begin(guard, bytes, 0).map_err(AnalysisError::state_budget)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(events.len())
        .map_err(|_| AnalysisError::state_hard_limit("next-PC allocation failed"))?;
    result.resize(events.len(), None);
    drop(allocation);
    let mut next = None;
    for (index, event) in events.iter().enumerate().rev() {
        if index % WORK_CHUNK == 0 {
            consume(guard, index.saturating_add(1).min(WORK_CHUNK))?;
        }
        result[index] = next;
        if matches!(
            event.kind,
            EventKind::Discontinuity
                | EventKind::CoverageGap
                | EventKind::Termination
                | EventKind::SignalHandlerBoundary
        ) {
            next = None;
            continue;
        }
        if event.kind == EventKind::Instruction {
            next = store
                .instruction(event.row)
                .map(|instruction| instruction.relative_pc);
            if next.is_none() {
                return Err(AnalysisError::store_shape("instruction row is absent"));
            }
        }
    }
    Ok(result)
}

fn immediate_target(pc: u64, kind: PcRelativeKind, displacement: i64) -> Option<u64> {
    let base = match kind {
        PcRelativeKind::Instruction => pc,
        PcRelativeKind::Page => pc & !0xfff,
        PcRelativeKind::None => return None,
    };
    if displacement >= 0 {
        base.checked_add(displacement as u64)
    } else {
        base.checked_sub(displacement.unsigned_abs())
    }
}

fn resolve_target(
    store: &dyn NormalizedBulkView,
    row: usize,
    pc: u64,
    kind: PcRelativeKind,
    displacement: i64,
    next_pc: Option<u64>,
) -> (Option<u64>, CallTargetEvidence) {
    if let Some(target) = immediate_target(pc, kind, displacement) {
        return (Some(target), CallTargetEvidence::Immediate);
    }
    if let Some(target) = next_pc {
        return (Some(target), CallTargetEvidence::NextPc);
    }
    let observations = store.register_observations(row);
    if let Some(observation) = observations.iter().find(|observation| {
        observation.access == RegisterAccess::Read
            && RegisterSlot::from_index(observation.slot as usize) != Some(RegisterSlot::X30)
    }) {
        if let Some(slot) = RegisterSlot::from_index(observation.slot as usize) {
            return (
                Some(observation.value),
                CallTargetEvidence::CapturedRegister(slot),
            );
        }
    }
    if let Some(observation) = observations.iter().find(|observation| {
        observation.access == RegisterAccess::Read
            && RegisterSlot::from_index(observation.slot as usize) == Some(RegisterSlot::X30)
    }) {
        return (Some(observation.value), CallTargetEvidence::LinkRegister);
    }
    (None, CallTargetEvidence::Unknown)
}

fn append_node(
    artifact: &mut CallTreeArtifact,
    parent: Option<usize>,
    target: (Option<u64>, CallTargetEvidence),
    event: &SelectedEvent,
    options: &CallTreeOptions,
    provenance: Provenance,
    guard: &dyn WorkGuard,
) -> Result<usize, AnalysisError> {
    let (target, evidence) = target;
    if artifact.nodes.len() >= MAX_CALL_TREE_NODES {
        return Err(AnalysisError::state_hard_limit(
            "call-tree node limit exceeded",
        ));
    }
    let id = artifact.nodes.len();
    let display = match target {
        Some(address) => match options.display_names.get(&address) {
            Some(name) => guarded_string(name, guard, "call-tree display allocation failed")?,
            None => {
                let allocation =
                    AllocationScope::begin(guard, 18, 0).map_err(AnalysisError::state_budget)?;
                let mut display = String::new();
                display.try_reserve_exact(18).map_err(|_| {
                    AnalysisError::state_hard_limit("call-tree display allocation failed")
                })?;
                write!(&mut display, "0x{address:x}").map_err(|_| {
                    AnalysisError::state_hard_limit("call-tree display formatting failed")
                })?;
                drop(allocation);
                display
            }
        },
        None => guarded_string(
            "unknown target",
            guard,
            "call-tree display allocation failed",
        )?,
    };
    guarded_push(
        &mut artifact.nodes,
        CallNode {
            id,
            parent,
            children: Vec::new(),
            timeline: artifact.timeline,
            tid: artifact.tid,
            target,
            target_evidence: evidence,
            display,
            entry_key: event.key.clone(),
            exit_key: None,
            source_row_start: event.row,
            source_row_end_exclusive: event.row.saturating_add(1),
            provenance,
            state: FrameState::Incomplete(IncompleteReason::SourceEnd),
            semantics: Vec::new(),
        },
        guard,
        "call-tree node allocation failed",
    )?;
    if let Some(parent) = parent {
        guarded_push(
            &mut artifact.nodes[parent].children,
            id,
            guard,
            "call-tree child allocation failed",
        )?;
    } else {
        guarded_push(
            &mut artifact.roots,
            id,
            guard,
            "call-tree root allocation failed",
        )?;
    }
    Ok(id)
}

fn finish_node(
    node: &mut CallNode,
    event: &SelectedEvent,
    state: FrameState,
    provenance: Provenance,
) {
    node.exit_key = Some(event.key.clone());
    node.source_row_end_exclusive = event.row.saturating_add(1);
    node.state = state;
    node.provenance = provenance;
}

fn close_stack(
    artifact: &mut CallTreeArtifact,
    stack: &mut Vec<OpenFrame>,
    event: &SelectedEvent,
    reason: IncompleteReason,
) {
    while let Some(frame) = stack.pop() {
        let provenance = if reason == IncompleteReason::Discontinuity {
            Provenance::Damaged
        } else {
            artifact.nodes[frame.node].provenance
        };
        finish_node(
            &mut artifact.nodes[frame.node],
            event,
            FrameState::Incomplete(reason),
            provenance,
        );
    }
}

fn append_interval(
    artifact: &mut CallTreeArtifact,
    kind: IntervalKind,
    event: &SelectedEvent,
    state: FrameState,
    guard: &dyn WorkGuard,
) -> Result<usize, AnalysisError> {
    if artifact.intervals.len() >= MAX_CALL_TREE_NODES {
        return Err(AnalysisError::state_hard_limit(
            "call-tree interval limit exceeded",
        ));
    }
    let index = artifact.intervals.len();
    guarded_push(
        &mut artifact.intervals,
        ExecutionInterval {
            kind,
            timeline: artifact.timeline,
            tid: artifact.tid,
            entry_key: event.key.clone(),
            exit_key: None,
            source_row_start: event.row,
            source_row_end_exclusive: event.row.saturating_add(1),
            provenance: event.provenance,
            state,
        },
        guard,
        "call-tree interval allocation failed",
    )?;
    Ok(index)
}

fn finish_interval(
    interval: &mut ExecutionInterval,
    key: &EventKey,
    row: usize,
    state: FrameState,
) {
    interval.exit_key = Some(key.clone());
    interval.source_row_end_exclusive = row.saturating_add(1);
    interval.state = state;
}

fn decode_payload(
    store: &dyn NormalizedBulkView,
    row: usize,
) -> Result<EventPayload, AnalysisError> {
    serde_json::from_slice(
        store
            .payload_bytes(row)
            .map_err(AnalysisError::state_store)?,
    )
    .map_err(|_| AnalysisError::store_shape("event payload is malformed"))
}

fn semantic(
    store: &dyn NormalizedBulkView,
    event: &SelectedEvent,
    guard: &dyn WorkGuard,
) -> Result<SemanticEnrichment, AnalysisError> {
    let row = store
        .semantic(event.row)
        .ok_or_else(|| AnalysisError::store_shape("semantic row is absent"))?;
    let category = row
        .category
        .map(|id| decode_text(store.string_bytes(id), "semantic category", guard))
        .transpose()?;
    let name = decode_text(store.string_bytes(row.name), "semantic name", guard)?;
    let detail = decode_text(store.blob_bytes(row.detail_blob), "semantic detail", guard)?;
    Ok(SemanticEnrichment {
        key: event.key.clone(),
        source_row: event.row,
        category,
        name,
        detail,
        provenance: event.provenance,
    })
}

fn decode_text(
    bytes: Result<&[u8], qtrace_store::IndexError>,
    field: &'static str,
    guard: &dyn WorkGuard,
) -> Result<String, AnalysisError> {
    let bytes = bytes.map_err(AnalysisError::state_store)?;
    let value = std::str::from_utf8(bytes)
        .map_err(|_| AnalysisError::store_shape(format!("{field} is not UTF-8")))?;
    guarded_string(value, guard, "semantic text allocation failed")
}

fn guarded_string(
    value: &str,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<String, AnalysisError> {
    let bytes = u64::try_from(value.len())
        .map_err(|_| AnalysisError::state_hard_limit("string allocation overflows"))?;
    let allocation =
        AllocationScope::begin(guard, bytes, 0).map_err(AnalysisError::state_budget)?;
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| AnalysisError::state_hard_limit(detail))?;
    result.push_str(value);
    drop(allocation);
    Ok(result)
}

fn guarded_push<T>(
    values: &mut Vec<T>,
    value: T,
    guard: &dyn WorkGuard,
    detail: &'static str,
) -> Result<(), AnalysisError> {
    if values.len() == values.capacity() {
        let required = values
            .len()
            .checked_add(1)
            .ok_or_else(|| AnalysisError::state_hard_limit("call-tree length overflows"))?;
        let capacity = values
            .capacity()
            .checked_mul(2)
            .map(|value| value.max(required).max(4))
            .ok_or_else(|| AnalysisError::state_hard_limit("call-tree capacity overflows"))?;
        let bytes = capacity
            .checked_mul(size_of::<T>())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| AnalysisError::state_hard_limit("call-tree allocation overflows"))?;
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
