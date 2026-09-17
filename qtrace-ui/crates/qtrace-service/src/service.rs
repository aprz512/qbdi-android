use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use qtrace_analysis::{
    ByteState, CallTreeAnalyzer, CallTreeOptions, EventFilter, FrameState, MemoryAnalyzer,
    MemoryEvidence, PageCursor, QueryContext, RegisterReplay, RegisterSnapshotState,
    TimelineProjection, TimelineRow, query_events,
};
use qtrace_provider::{ArtifactDigest, EventKey, EventKind, Provenance, RegisterSlot};
use qtrace_store::{
    AnnotationOpenRequest, AnnotationStore, AuthorizedPath, BuildOptions, ElfLoadRequest,
    ElfProducerIdentity, ElfSymbolIndex, EventAnnotation, IndexBuilder, ModuleIdentity, OpenPolicy,
    SessionLoader,
};

use crate::workspace::{ArtifactWorkspace, ProjectionWorkspace, Workspace};
use crate::{
    AnnotationDto, AppError, ArtifactSummaryDto, CallNodeDto, CallTreeDto, DecimalU64Dto,
    EventDetailDto, EventFilterDto, EventKeyDto, EventRowDto, HexU64Dto, JobId, JobRegistry,
    MemoryByteDto, MemoryEvidenceDto, MemoryStateDto, OpenWorkspaceDto, ProjectionId,
    ProjectionJobDto, RegisterCellDto, RegisterStateDto, ServiceBudget, ServiceLimits, SymbolDto,
    TimelinePageDto, WorkspaceId, WorkspaceSummaryDto,
};

pub struct QtraceService {
    next: AtomicU64,
    workspaces: Mutex<HashMap<WorkspaceId, Workspace>>,
    jobs: JobRegistry,
}

impl Default for QtraceService {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(0),
            workspaces: Mutex::new(HashMap::new()),
            jobs: JobRegistry::default(),
        }
    }
}

impl QtraceService {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn new_for_tests() -> Self {
        Self::default()
    }

    pub fn open_session(&self, selected: AuthorizedPath) -> Result<OpenWorkspaceDto, AppError> {
        let budget = ServiceBudget::new(open_limits());
        let session = SessionLoader::open_report(selected, OpenPolicy::default(), &budget)?;
        self.publish_session(session, &budget)
    }

    pub fn open_artifact(&self, selected: AuthorizedPath) -> Result<OpenWorkspaceDto, AppError> {
        let budget = ServiceBudget::new(open_limits());
        let session = SessionLoader::open_artifact(selected, OpenPolicy::default(), &budget)?;
        self.publish_session(session, &budget)
    }

    fn publish_session(
        &self,
        session: qtrace_store::SessionSource,
        budget: &ServiceBudget,
    ) -> Result<OpenWorkspaceDto, AppError> {
        let mut artifacts = Vec::new();
        let mut warnings = session
            .warnings()
            .iter()
            .map(|warning| format!("{}: {}", warning.code(), warning.detail()))
            .collect::<Vec<_>>();
        warnings.extend(session.failures().iter().map(|failure| {
            format!(
                "{}: {}",
                failure.local_path().unwrap_or("artifact"),
                failure.error()
            )
        }));
        for source in session.artifacts() {
            match IndexBuilder::build(source, &BuildOptions::default(), budget) {
                Ok(store) => {
                    let store = Arc::new(store);
                    let context = Arc::new(QueryContext::new_with_guard(store.clone(), budget)?);
                    artifacts.push(ArtifactWorkspace {
                        name: source.local_path().to_owned(),
                        store,
                        context,
                    });
                }
                Err(error) => warnings.push(format!("{}: {error}", source.local_path())),
            }
        }
        if artifacts.is_empty() {
            return Err(AppError::new(
                "workspace.no_valid_artifact",
                "open",
                "no artifact could be indexed",
            ));
        }
        let id = WorkspaceId::from_u64(self.next_id());
        let artifact_count = u32::try_from(artifacts.len()).map_err(|_| {
            AppError::new(
                "workspace.too_many_artifacts",
                "open",
                "artifact count exceeds u32",
            )
        })?;
        let summary = WorkspaceSummaryDto {
            id: id.clone(),
            generation: 0,
            artifact_count,
        };
        let artifact_dtos = artifacts
            .iter()
            .enumerate()
            .map(|(index, artifact)| ArtifactSummaryDto {
                index: u32::try_from(index).unwrap_or(u32::MAX),
                name: artifact.name.clone(),
                event_count: u32::try_from(artifact.store.event_count()).unwrap_or(u32::MAX),
            })
            .collect();
        self.workspaces
            .lock()
            .map_err(|_| AppError::worker_failed())?
            .insert(
                id.clone(),
                Workspace {
                    generation: 0,
                    current: None,
                    artifacts,
                    projections: HashMap::new(),
                    symbols: HashMap::new(),
                },
            );
        self.jobs.record_completed(id, "open");
        Ok(OpenWorkspaceDto {
            workspace: summary,
            artifacts: artifact_dtos,
            warnings,
        })
    }

    pub fn create_projection(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
        filter: EventFilterDto,
    ) -> Result<ProjectionJobDto, AppError> {
        let (context, generation) = {
            let mut all = self
                .workspaces
                .lock()
                .map_err(|_| AppError::worker_failed())?;
            let item = all
                .get_mut(workspace)
                .ok_or_else(AppError::stale_workspace)?;
            item.generation = item.generation.checked_add(1).ok_or_else(|| {
                AppError::new(
                    "workspace.generation_overflow",
                    "workspace",
                    "generation overflow",
                )
            })?;
            let artifact = item.artifacts.get(artifact_index as usize).ok_or_else(|| {
                AppError::new(
                    "workspace.artifact_missing",
                    "projection",
                    "artifact index is invalid",
                )
            })?;
            (artifact.context.clone(), item.generation)
        };
        let projection = Arc::new(TimelineProjection::new(context, convert_filter(filter)?)?);
        let projection_id = ProjectionId::from_u64(self.next_id());
        let job_id = self.jobs.record_completed(workspace.clone(), "projection");
        let mut all = self
            .workspaces
            .lock()
            .map_err(|_| AppError::worker_failed())?;
        let item = all
            .get_mut(workspace)
            .ok_or_else(AppError::stale_workspace)?;
        if item.generation == generation {
            item.current = Some(projection_id.clone());
        }
        item.projections
            .insert(projection_id.clone(), ProjectionWorkspace { projection });
        Ok(ProjectionJobDto {
            projection_id,
            job_id,
            generation,
        })
    }

    pub fn query_timeline(
        &self,
        workspace: &WorkspaceId,
        projection: &ProjectionId,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<TimelinePageDto, AppError> {
        let projection = {
            let all = self
                .workspaces
                .lock()
                .map_err(|_| AppError::worker_failed())?;
            all.get(workspace)
                .and_then(|item| item.projections.get(projection))
                .map(|item| item.projection.clone())
                .ok_or_else(AppError::stale_workspace)?
        };
        let cursor = cursor.map(PageCursor::from_encoded);
        let page = query_events(&projection, cursor.as_ref(), limit as usize)?;
        let rows = page
            .rows
            .into_iter()
            .map(event_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(TimelinePageDto {
            rows,
            next_cursor: page.next.map(|value| value.as_str().to_owned()),
            total: u32::try_from(page.total).unwrap_or(u32::MAX),
            exact_total: page.exact_total,
        })
    }

    pub fn get_event_detail(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
        row: u32,
    ) -> Result<EventDetailDto, AppError> {
        let store = self.artifact_store(workspace, artifact_index)?;
        let row_index = row as usize;
        let key = store.event_key(row_index).ok_or_else(event_missing)?;
        let kind = store.event_kind(row_index).ok_or_else(event_missing)?;
        let provenance = store.provenance(row_index).ok_or_else(event_missing)?;
        Ok(EventDetailDto {
            artifact_index,
            row,
            key: event_key_dto(&key),
            kind: String::from_utf8_lossy(kind.external_tag()).into_owned(),
            provenance: provenance_name(provenance).into(),
        })
    }

    pub fn get_register_state(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
        row: u32,
    ) -> Result<RegisterStateDto, AppError> {
        let store = self.artifact_store(workspace, artifact_index)?;
        let key = store.event_key(row as usize).ok_or_else(event_missing)?;
        let budget = ServiceBudget::new(ServiceLimits::interactive());
        let replay = RegisterReplay::new_with_guard(store, &budget)?;
        let state = replay.state_at_with_guard(&key, &budget)?;
        Ok(RegisterStateDto {
            key: event_key_dto(&state.key),
            before: register_cells(&state.before),
            after: register_cells(&state.after),
        })
    }

    pub fn get_memory_state(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
        row: u32,
        start: u64,
        end_exclusive: u64,
    ) -> Result<MemoryStateDto, AppError> {
        let store = self.artifact_store(workspace, artifact_index)?;
        let key = store.event_key(row as usize).ok_or_else(event_missing)?;
        let budget = ServiceBudget::new(ServiceLimits::interactive());
        let state = MemoryAnalyzer::new_with_guard(store, &budget)?.state_at_with_guard(
            &key,
            start..end_exclusive,
            &budget,
        )?;
        Ok(MemoryStateDto {
            key: event_key_dto(&state.key),
            start: HexU64Dto::new(state.range.start),
            end_exclusive: HexU64Dto::new(state.range.end),
            observed: memory_bytes(state.observed),
            before: memory_bytes(state.before),
            after: memory_bytes(state.after),
            last_written: memory_bytes(state.last_written),
        })
    }

    pub fn get_memory_history(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
        row: u32,
        start: u64,
        end_exclusive: u64,
    ) -> Result<Vec<MemoryEvidenceDto>, AppError> {
        let store = self.artifact_store(workspace, artifact_index)?;
        let key = store.event_key(row as usize).ok_or_else(event_missing)?;
        let budget = ServiceBudget::new(ServiceLimits::interactive());
        MemoryAnalyzer::new_with_guard(store, &budget)?
            .history_with_guard(&key, start..end_exclusive, &budget)?
            .into_iter()
            .map(memory_evidence)
            .collect()
    }

    pub fn get_call_tree(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
        timeline_id: u64,
        tid: u32,
    ) -> Result<CallTreeDto, AppError> {
        let store = self.artifact_store(workspace, artifact_index)?;
        let budget = ServiceBudget::new(ServiceLimits::interactive());
        let tree = CallTreeAnalyzer::new(store).build_with_guard(
            timeline_id,
            tid,
            &CallTreeOptions::default(),
            &budget,
        )?;
        Ok(CallTreeDto {
            identity: hex_bytes(tree.identity.as_bytes()),
            timeline_id: DecimalU64Dto::new(tree.timeline.0),
            tid: tree.tid,
            roots: tree
                .roots
                .into_iter()
                .map(as_u32)
                .collect::<Result<_, _>>()?,
            nodes: tree
                .nodes
                .into_iter()
                .map(|node| {
                    Ok(CallNodeDto {
                        id: as_u32(node.id)?,
                        parent: node.parent.map(as_u32).transpose()?,
                        children: node
                            .children
                            .into_iter()
                            .map(as_u32)
                            .collect::<Result<_, _>>()?,
                        tid: node.tid,
                        target: node.target.map(HexU64Dto::new),
                        display: node.display,
                        source_row_start: as_u32(node.source_row_start)?,
                        source_row_end_exclusive: as_u32(node.source_row_end_exclusive)?,
                        provenance: provenance_name(node.provenance).into(),
                        state: frame_state(node.state),
                    })
                })
                .collect::<Result<_, AppError>>()?,
        })
    }

    pub fn attach_elf(
        &self,
        workspace: &WorkspaceId,
        selected: AuthorizedPath,
        module_name: String,
        module_digest: String,
        expected_build_id: Option<Vec<u8>>,
    ) -> Result<(), AppError> {
        let digest = ArtifactDigest::from_hex(&module_digest).ok_or_else(|| {
            AppError::new(
                "symbol.module_identity_invalid",
                "symbol",
                "invalid module digest",
            )
        })?;
        let budget = ServiceBudget::new(ServiceLimits::interactive());
        let request = ElfLoadRequest::new(
            selected,
            true,
            ModuleIdentity::new(module_name.clone(), digest),
            ElfProducerIdentity::aarch64_android(),
            expected_build_id,
        );
        let index = Arc::new(ElfSymbolIndex::load(request, &budget)?);
        let mut all = self
            .workspaces
            .lock()
            .map_err(|_| AppError::worker_failed())?;
        all.get_mut(workspace)
            .ok_or_else(AppError::stale_workspace)?
            .symbols
            .insert(module_name, index);
        Ok(())
    }

    pub fn list_symbols(
        &self,
        workspace: &WorkspaceId,
        module: &str,
        relative_pcs: &[u64],
    ) -> Result<Vec<SymbolDto>, AppError> {
        let index = {
            let all = self
                .workspaces
                .lock()
                .map_err(|_| AppError::worker_failed())?;
            all.get(workspace)
                .and_then(|item| item.symbols.get(module))
                .cloned()
                .ok_or_else(|| {
                    AppError::new("symbol.not_attached", "symbol", "ELF is not attached")
                })?
        };
        Ok(relative_pcs
            .iter()
            .filter_map(|pc| index.resolve(*pc))
            .map(|symbol| SymbolDto {
                module: module.to_owned(),
                name: symbol.name().to_owned(),
                relative_address: HexU64Dto::new(symbol.relative_address()),
                size: DecimalU64Dto::new(symbol.size()),
                offset: DecimalU64Dto::new(symbol.offset()),
            })
            .collect())
    }

    pub fn get_annotation(
        &self,
        workspace: &WorkspaceId,
        data_home: AuthorizedPath,
        artifact_index: u32,
        row: u32,
    ) -> Result<Option<AnnotationDto>, AppError> {
        let (key, identity) = self.annotation_target(workspace, artifact_index, row)?;
        let store = AnnotationStore::open(AnnotationOpenRequest::new(data_home, identity))?;
        Ok(store
            .event_annotation(&key)?
            .map(|annotation| AnnotationDto {
                key: event_key_dto(annotation.event()),
                comment: annotation.comment().to_owned(),
            }))
    }

    pub fn upsert_annotation(
        &self,
        workspace: &WorkspaceId,
        data_home: AuthorizedPath,
        artifact_index: u32,
        row: u32,
        comment: String,
    ) -> Result<(), AppError> {
        let (key, identity) = self.annotation_target(workspace, artifact_index, row)?;
        let mut store = AnnotationStore::open(AnnotationOpenRequest::new(data_home, identity))?;
        let annotation = EventAnnotation::new(key, comment)?;
        let mut tx = store.begin_transaction()?;
        tx.put_event_annotation(&annotation)?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_annotation(
        &self,
        workspace: &WorkspaceId,
        data_home: AuthorizedPath,
        artifact_index: u32,
        row: u32,
    ) -> Result<(), AppError> {
        let (key, identity) = self.annotation_target(workspace, artifact_index, row)?;
        let mut store = AnnotationStore::open(AnnotationOpenRequest::new(data_home, identity))?;
        let mut tx = store.begin_transaction()?;
        tx.delete_event_annotation(&key)?;
        tx.commit()?;
        Ok(())
    }

    pub fn insert_empty_workspace(&self) -> WorkspaceId {
        let id = WorkspaceId::from_u64(self.next_id());
        self.workspaces
            .lock()
            .unwrap()
            .insert(id.clone(), Workspace::empty());
        id
    }
    pub fn create_projection_for_tests(
        &self,
        workspace: &WorkspaceId,
        _: EventFilterDto,
    ) -> Result<ProjectionJobDto, AppError> {
        let mut all = self.workspaces.lock().unwrap();
        let item = all
            .get_mut(workspace)
            .ok_or_else(AppError::stale_workspace)?;
        item.generation += 1;
        let projection_id = ProjectionId::from_u64(self.next_id());
        item.current = Some(projection_id.clone());
        Ok(ProjectionJobDto {
            projection_id,
            job_id: JobId::from_u64(self.next_id()),
            generation: item.generation,
        })
    }
    pub fn complete_projection_for_tests(&self, _: &ProjectionJobDto) -> Result<(), AppError> {
        Ok(())
    }
    pub fn current_projection(&self, workspace: &WorkspaceId) -> Result<ProjectionId, AppError> {
        self.workspaces
            .lock()
            .map_err(|_| AppError::worker_failed())?
            .get(workspace)
            .and_then(|item| item.current.clone())
            .ok_or_else(AppError::stale_workspace)
    }
    pub fn close_workspace(&self, workspace: &WorkspaceId) -> Result<(), AppError> {
        self.jobs.cancel_workspace(workspace);
        self.workspaces
            .lock()
            .map_err(|_| AppError::worker_failed())?
            .remove(workspace)
            .map(|_| ())
            .ok_or_else(AppError::stale_workspace)
    }
    pub fn workspace_summary(
        &self,
        workspace: &WorkspaceId,
    ) -> Result<WorkspaceSummaryDto, AppError> {
        let all = self
            .workspaces
            .lock()
            .map_err(|_| AppError::worker_failed())?;
        let item = all.get(workspace).ok_or_else(AppError::stale_workspace)?;
        Ok(WorkspaceSummaryDto {
            id: workspace.clone(),
            generation: item.generation,
            artifact_count: item.artifacts.len() as u32,
        })
    }
    pub fn list_jobs(&self) -> Vec<crate::JobDto> {
        self.jobs.list()
    }
    pub fn cancel_job(&self, id: &JobId) -> Result<(), AppError> {
        self.jobs.cancel(id)
    }
    fn artifact_store(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
    ) -> Result<Arc<qtrace_store::OwnedTraceStore>, AppError> {
        self.workspaces
            .lock()
            .map_err(|_| AppError::worker_failed())?
            .get(workspace)
            .and_then(|item| item.artifacts.get(artifact_index as usize))
            .map(|artifact| artifact.store.clone())
            .ok_or_else(AppError::stale_workspace)
    }
    fn annotation_target(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
        row: u32,
    ) -> Result<(EventKey, ArtifactDigest), AppError> {
        let store = self.artifact_store(workspace, artifact_index)?;
        let key = store.event_key(row as usize).ok_or_else(event_missing)?;
        let identity = store
            .event_key(0)
            .map(|first| first.artifact)
            .unwrap_or(key.artifact);
        Ok((key, identity))
    }
    fn next_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }
}

fn open_limits() -> ServiceLimits {
    ServiceLimits {
        deadline: Instant::now() + Duration::from_secs(30 * 60),
        input_bytes: u64::MAX,
        decompressed_bytes: 4 * 1024 * 1024 * 1024,
        events: 20_000_000,
        nodes: u64::MAX,
        rows: u64::MAX,
        resident_bytes: 2 * 1024 * 1024 * 1024,
    }
}
fn convert_filter(value: EventFilterDto) -> Result<EventFilter, AppError> {
    let mut filter = EventFilter {
        tids: value.tids,
        ..EventFilter::default()
    };
    for kind in value.kinds {
        filter.kinds.push(
            EventKind::from_external_tag(kind.as_bytes()).ok_or_else(|| {
                AppError::new(
                    "filter.kind_invalid",
                    "projection",
                    format!("unknown event kind: {kind}"),
                )
            })?,
        );
    }
    Ok(filter)
}
fn event_row(row: TimelineRow) -> Result<EventRowDto, AppError> {
    let (source_row, key, kind, provenance, discontinuity) = match row {
        TimelineRow::Event(row) => (row.source_row, row.key, row.kind, row.provenance, false),
        TimelineRow::Discontinuity(row) => (
            row.source_row,
            row.key,
            EventKind::Discontinuity,
            row.provenance,
            true,
        ),
    };
    Ok(EventRowDto {
        source_row: u32::try_from(source_row).map_err(|_| {
            AppError::new("timeline.row_overflow", "query", "source row exceeds u32")
        })?,
        key: event_key_dto(&key),
        kind: String::from_utf8_lossy(kind.external_tag()).into_owned(),
        provenance: provenance_name(provenance).into(),
        discontinuity,
    })
}
fn event_key_dto(key: &EventKey) -> EventKeyDto {
    EventKeyDto {
        artifact_sha256: key.artifact.to_hex(),
        timeline_id: DecimalU64Dto::new(key.timeline.0),
        record_ordinal: DecimalU64Dto::new(key.record_ordinal),
        source_offset: DecimalU64Dto::new(key.source_offset),
        sequence: key.sequence.map(DecimalU64Dto::new),
        tid: key.tid,
    }
}
fn event_missing() -> AppError {
    AppError::new("event.not_found", "query", "event row is invalid")
}
fn register_cells(state: &RegisterSnapshotState) -> Vec<RegisterCellDto> {
    (0..RegisterSlot::COUNT)
        .filter_map(RegisterSlot::from_index)
        .map(|slot| {
            let cell = state.cell(slot);
            RegisterCellDto {
                slot: register_name(slot),
                value: cell.value.map(HexU64Dto::new),
                known_mask: HexU64Dto::new(cell.known_mask),
                captured_width: cell.captured_width,
                provenance: provenance_name(cell.provenance).into(),
            }
        })
        .collect()
}
fn register_name(slot: RegisterSlot) -> String {
    match slot {
        RegisterSlot::Sp => "sp".into(),
        RegisterSlot::Pc => "pc".into(),
        RegisterSlot::Nzcv => "nzcv".into(),
        other => format!("x{}", other.index()),
    }
}
fn memory_bytes(values: Vec<ByteState>) -> Vec<MemoryByteDto> {
    values
        .into_iter()
        .map(|value| MemoryByteDto {
            address: HexU64Dto::new(value.address),
            value: value.value,
            provenance: provenance_name(value.provenance).into(),
        })
        .collect()
}
fn memory_evidence(value: MemoryEvidence) -> Result<MemoryEvidenceDto, AppError> {
    Ok(MemoryEvidenceDto {
        key: event_key_dto(&value.key),
        tid: value.tid,
        direction: value.direction.as_str().into(),
        provenance: provenance_name(value.provenance).into(),
        address: HexU64Dto::new(value.address),
        size: value.size,
    })
}
fn as_u32(value: usize) -> Result<u32, AppError> {
    u32::try_from(value)
        .map_err(|_| AppError::new("analysis.index_overflow", "analysis", "index exceeds u32"))
}
fn frame_state(value: FrameState) -> String {
    match value {
        FrameState::Complete => "complete".into(),
        FrameState::Incomplete(reason) => format!("incomplete_{reason:?}").to_ascii_lowercase(),
    }
}
fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0xf) as usize] as char);
    }
    output
}
fn provenance_name(value: Provenance) -> &'static str {
    match value {
        Provenance::Captured => "captured",
        Provenance::Derived => "derived",
        Provenance::Heuristic => "heuristic",
        Provenance::Unknown => "unknown",
        Provenance::Damaged => "damaged",
    }
}
