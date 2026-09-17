use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use qtrace_analysis::{
    AddressRange, ByteState, CallTreeAnalyzer, CallTreeOptions, EventFilter, FrameState,
    MemoryAnalyzer, MemoryEvidence, MemoryFilter, MnemonicFilter, PageCursor, QueryContext,
    RegisterReplay, RegisterSnapshotState, SequenceRange, TimelineProjection, TimelineRow,
    query_events,
};
use qtrace_provider::{
    ArtifactDigest, CompletenessCause, EventKey, EventKind, MemoryDirection, OperationAbort,
    Provenance, RangeBounds, RangeDomain, RegisterSlot, WorkDelta, WorkGuard,
};
use qtrace_store::{
    AnnotationOpenRequest, AnnotationStore, AuthorizedPath, BuildOptions, ElfLoadRequest,
    ElfProducerIdentity, ElfSymbolIndex, EventAnnotation, Highlight, LocalSymbolName,
    ModuleIdentity, OpenPolicy, SessionLoader, TraceStore, TraceStoreView,
};

use crate::workspace::{ArtifactWorkspace, ProjectionWorkspace, Workspace};
use crate::{
    AddressRangeDto, AnnotationDto, AppError, ArtifactSummaryDto, CallNodeDto, CallTreeDto,
    CompletenessRangeDto, DecimalU64Dto, EventDetailDto, EventFilterDto, EventKeyDto, EventRowDto,
    HexU64Dto, JobId, JobRegistry, LocalSymbolNameDto, MemoryByteDto, MemoryEvidenceDto,
    MemoryStateDto, OpenWorkspaceDto, ProjectionId, ProjectionJobDto, RegisterCellDto,
    RegisterStateDto, ServiceBudget, ServiceLimits, SymbolDto, TimelinePageDto, WorkspaceId,
    WorkspaceSummaryDto,
};

pub struct QtraceService {
    next: AtomicU64,
    cache_root: PathBuf,
    workspaces: Arc<Mutex<HashMap<WorkspaceId, Workspace>>>,
    jobs: JobRegistry,
}

impl Default for QtraceService {
    fn default() -> Self {
        Self::with_cache_root(default_cache_root())
    }
}

impl QtraceService {
    pub fn with_cache_root(cache_root: PathBuf) -> Self {
        Self {
            next: AtomicU64::new(0),
            cache_root,
            workspaces: Arc::new(Mutex::new(HashMap::new())),
            jobs: JobRegistry::default(),
        }
    }
    pub fn new() -> Self {
        Self::default()
    }
    pub fn new_for_tests() -> Self {
        Self::default()
    }

    pub fn open_session(&self, selected: AuthorizedPath) -> Result<OpenWorkspaceDto, AppError> {
        self.open_selected(selected, true)
    }

    pub async fn open_session_task(
        self: Arc<Self>,
        selected: AuthorizedPath,
    ) -> Result<OpenWorkspaceDto, AppError> {
        tokio::task::spawn_blocking(move || self.open_session(selected))
            .await
            .map_err(|_| AppError::worker_failed())?
    }

    pub fn open_artifact(&self, selected: AuthorizedPath) -> Result<OpenWorkspaceDto, AppError> {
        self.open_selected(selected, false)
    }

    pub async fn open_artifact_task(
        self: Arc<Self>,
        selected: AuthorizedPath,
    ) -> Result<OpenWorkspaceDto, AppError> {
        tokio::task::spawn_blocking(move || self.open_artifact(selected))
            .await
            .map_err(|_| AppError::worker_failed())?
    }

    fn open_selected(
        &self,
        selected: AuthorizedPath,
        session_report: bool,
    ) -> Result<OpenWorkspaceDto, AppError> {
        let workspace_id = WorkspaceId::from_u64(self.next_id());
        let (job_id, cancellation) = self.jobs.begin(workspace_id.clone(), "open");
        let result = (|| {
            let selected_file_bytes = selected
                .as_path()
                .metadata()
                .ok()
                .filter(|metadata| metadata.is_file())
                .map(|metadata| metadata.len());
            let discovery = ServiceBudget::with_cancellation(
                discovery_limits(selected_file_bytes),
                cancellation.clone(),
            );
            let session = if session_report {
                SessionLoader::open_report(selected, OpenPolicy::cache_aware(), &discovery)?
            } else {
                SessionLoader::open_artifact(selected, OpenPolicy::cache_aware(), &discovery)?
            };
            let budget = ServiceBudget::with_cancellation(
                open_limits(session_input_bytes(&session)?),
                cancellation.clone(),
            );
            self.publish_session(
                workspace_id.clone(),
                &job_id,
                session,
                &budget,
                &cancellation,
            )
        })();
        self.jobs.finish(
            &job_id,
            result.as_ref().map(|_| ()).map_err(Clone::clone),
            cancellation.is_cancelled(),
        );
        self.jobs.prune_workspace(&workspace_id, 64);
        self.jobs.prune_terminal(256);
        result
    }

    fn publish_session(
        &self,
        id: WorkspaceId,
        job_id: &JobId,
        session: qtrace_store::SessionSource,
        source_budget: &ServiceBudget,
        cancellation: &crate::JobCancellation,
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
        let artifact_total = u64::try_from(session.artifacts().len()).unwrap_or(u64::MAX);
        self.jobs.set_progress(job_id, 0, Some(artifact_total))?;
        let cache_budget = ServiceBudget::with_cancellation(cache_limits(), cancellation.clone());
        for (artifact_position, source) in session.artifacts().iter().enumerate() {
            let probe_adjusted = InputProbeAdjustedGuard::new(source_budget);
            let artifact_guard: &dyn WorkGuard =
                if matches!(source.format(), qtrace_store::ArtifactFormat::QtrbLz4) {
                    &probe_adjusted
                } else {
                    source_budget
                };
            match TraceStore::open_or_build_with_guards(
                &self.cache_root,
                source,
                &BuildOptions::default(),
                artifact_guard,
                &cache_budget,
            ) {
                Ok(store) => {
                    let store = Arc::new(store);
                    let context =
                        Arc::new(QueryContext::new_with_guard(store.clone(), &cache_budget)?);
                    artifacts.push(ArtifactWorkspace {
                        name: source.local_path().to_owned(),
                        store,
                        context,
                    });
                }
                Err(error) => warnings.push(format!("{}: {error}", source.local_path())),
            }
            self.jobs.set_progress(
                job_id,
                u64::try_from(artifact_position + 1).unwrap_or(u64::MAX),
                Some(artifact_total),
            )?;
        }
        if artifacts.is_empty() {
            let detail = if warnings.is_empty() {
                "no artifact could be indexed".to_owned()
            } else {
                format!("no artifact could be indexed: {}", warnings.join("; "))
            };
            return Err(AppError::new("workspace.no_valid_artifact", "open", detail));
        }
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
                completeness: artifact
                    .store
                    .completeness()
                    .iter()
                    .copied()
                    .map(completeness_range)
                    .collect(),
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
        let (context, generation, projection_id) =
            self.prepare_projection(workspace, artifact_index)?;
        let (job_id, cancellation) = self.jobs.begin(workspace.clone(), "projection");
        self.jobs.set_progress(&job_id, 0, Some(1))?;
        let result = build_and_publish_projection(
            &self.workspaces,
            workspace,
            context,
            generation,
            projection_id.clone(),
            filter,
            &cancellation,
        );
        self.jobs.finish(
            &job_id,
            result.as_ref().map(|_| ()).map_err(Clone::clone),
            cancellation.is_cancelled(),
        );
        self.jobs.prune_workspace(workspace, 64);
        result?;
        Ok(ProjectionJobDto {
            projection_id,
            job_id,
            generation,
        })
    }

    pub async fn create_projection_task(
        self: Arc<Self>,
        workspace: WorkspaceId,
        artifact_index: u32,
        filter: EventFilterDto,
    ) -> Result<ProjectionJobDto, AppError> {
        let (context, generation, projection_id) =
            self.prepare_projection(&workspace, artifact_index)?;
        let (job_id, cancellation) = self.jobs.begin(workspace.clone(), "projection");
        self.jobs.set_progress(&job_id, 0, Some(1))?;
        let dto = ProjectionJobDto {
            projection_id: projection_id.clone(),
            job_id: job_id.clone(),
            generation,
        };
        let workspaces = self.workspaces.clone();
        let jobs = self.jobs.clone();
        tokio::spawn(async move {
            let cancelled = cancellation.clone();
            let work_workspace = workspace.clone();
            let result = tokio::task::spawn_blocking(move || {
                build_and_publish_projection(
                    &workspaces,
                    &work_workspace,
                    context,
                    generation,
                    projection_id,
                    filter,
                    &cancellation,
                )
            })
            .await
            .map_err(|_| AppError::worker_failed())
            .and_then(|result| result);
            jobs.finish(&job_id, result, cancelled.is_cancelled());
            jobs.prune_workspace(&workspace, 64);
        });
        Ok(dto)
    }

    fn prepare_projection(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
    ) -> Result<(Arc<QueryContext>, u32, ProjectionId), AppError> {
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
        Ok((
            artifact.context.clone(),
            item.generation,
            ProjectionId::from_u64(self.next_id()),
        ))
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
        let key = store.event_key(row_index)?.ok_or_else(event_missing)?;
        let kind = store.event_kind(row_index)?.ok_or_else(event_missing)?;
        let provenance = store.provenance(row_index)?.ok_or_else(event_missing)?;
        let instruction = store.instruction(row_index);
        let memory = store.memory(row_index);
        let (module, relative_pc) = instruction
            .map(|value| (value.module, Some(value.relative_pc)))
            .or_else(|| memory.map(|value| (value.module, Some(value.relative_pc))))
            .unwrap_or((None, None));
        Ok(EventDetailDto {
            artifact_index,
            row,
            key: event_key_dto(&key),
            kind: String::from_utf8_lossy(kind.external_tag()).into_owned(),
            provenance: provenance_name(provenance).into(),
            raw_payload: String::from_utf8_lossy(store.payload_bytes(row_index)?).into_owned(),
            module,
            relative_pc: relative_pc.map(HexU64Dto::new),
            memory_range: memory.map(|value| AddressRangeDto {
                start: HexU64Dto::new(value.address),
                end_exclusive: HexU64Dto::new(value.end_exclusive),
            }),
        })
    }

    pub fn get_register_state(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
        row: u32,
    ) -> Result<RegisterStateDto, AppError> {
        let store = self.artifact_store(workspace, artifact_index)?;
        let key = store.event_key(row as usize)?.ok_or_else(event_missing)?;
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
        let key = store.event_key(row as usize)?.ok_or_else(event_missing)?;
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
        let key = store.event_key(row as usize)?.ok_or_else(event_missing)?;
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
        let comment = store.event_annotation(&key)?;
        let highlight = store.highlight(&key)?;
        if comment.is_none() && highlight.is_none() {
            return Ok(None);
        }
        Ok(Some(AnnotationDto {
            key: event_key_dto(&key),
            comment: comment
                .as_ref()
                .map_or_else(String::new, |annotation| annotation.comment().to_owned()),
            highlight: highlight.map(|value| value.value().to_owned()),
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

    pub fn upsert_highlight(
        &self,
        workspace: &WorkspaceId,
        data_home: AuthorizedPath,
        artifact_index: u32,
        row: u32,
        value: String,
    ) -> Result<(), AppError> {
        let (key, identity) = self.annotation_target(workspace, artifact_index, row)?;
        let mut store = AnnotationStore::open(AnnotationOpenRequest::new(data_home, identity))?;
        let highlight = Highlight::new(key, value)?;
        let mut tx = store.begin_transaction()?;
        tx.put_highlight(&highlight)?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_highlight(
        &self,
        workspace: &WorkspaceId,
        data_home: AuthorizedPath,
        artifact_index: u32,
        row: u32,
    ) -> Result<(), AppError> {
        let (key, identity) = self.annotation_target(workspace, artifact_index, row)?;
        let mut store = AnnotationStore::open(AnnotationOpenRequest::new(data_home, identity))?;
        let mut tx = store.begin_transaction()?;
        tx.delete_highlight(&key)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_local_symbol_name(
        &self,
        workspace: &WorkspaceId,
        data_home: AuthorizedPath,
        artifact_index: u32,
        module_digest: String,
        relative_pc: u64,
    ) -> Result<Option<LocalSymbolNameDto>, AppError> {
        let digest = parse_module_digest(&module_digest)?;
        let identity = self.annotation_identity(workspace, artifact_index)?;
        let store = AnnotationStore::open(AnnotationOpenRequest::new(data_home, identity))?;
        Ok(store
            .local_symbol_name(digest, relative_pc)?
            .map(|value| LocalSymbolNameDto {
                module_digest,
                relative_pc: HexU64Dto::new(relative_pc),
                name: value.name().to_owned(),
            }))
    }

    pub fn upsert_local_symbol_name(
        &self,
        workspace: &WorkspaceId,
        data_home: AuthorizedPath,
        artifact_index: u32,
        module_digest: String,
        relative_pc: u64,
        name: String,
    ) -> Result<(), AppError> {
        let digest = parse_module_digest(&module_digest)?;
        let identity = self.annotation_identity(workspace, artifact_index)?;
        let mut store = AnnotationStore::open(AnnotationOpenRequest::new(data_home, identity))?;
        let value = LocalSymbolName::new(digest, relative_pc, name)?;
        let mut tx = store.begin_transaction()?;
        tx.put_local_symbol_name(&value)?;
        tx.commit()?;
        Ok(())
    }

    pub fn delete_local_symbol_name(
        &self,
        workspace: &WorkspaceId,
        data_home: AuthorizedPath,
        artifact_index: u32,
        module_digest: String,
        relative_pc: u64,
    ) -> Result<(), AppError> {
        let digest = parse_module_digest(&module_digest)?;
        let identity = self.annotation_identity(workspace, artifact_index)?;
        let mut store = AnnotationStore::open(AnnotationOpenRequest::new(data_home, identity))?;
        let mut tx = store.begin_transaction()?;
        tx.delete_local_symbol_name(digest, relative_pc)?;
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
        let result = self
            .workspaces
            .lock()
            .map_err(|_| AppError::worker_failed())?
            .remove(workspace)
            .map(|_| ())
            .ok_or_else(AppError::stale_workspace);
        self.jobs.remove_workspace(workspace);
        result
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
    pub fn cancel_all(&self) {
        self.jobs.cancel_all();
    }
    fn artifact_store(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
    ) -> Result<Arc<qtrace_store::TraceStore>, AppError> {
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
        let key = store.event_key(row as usize)?.ok_or_else(event_missing)?;
        let identity = store
            .event_key(0)?
            .map(|first| first.artifact)
            .unwrap_or(key.artifact);
        Ok((key, identity))
    }
    fn annotation_identity(
        &self,
        workspace: &WorkspaceId,
        artifact_index: u32,
    ) -> Result<ArtifactDigest, AppError> {
        self.artifact_store(workspace, artifact_index)?
            .event_key(0)?
            .map(|key| key.artifact)
            .ok_or_else(event_missing)
    }
    fn next_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }
}

fn build_and_publish_projection(
    workspaces: &Mutex<HashMap<WorkspaceId, Workspace>>,
    workspace: &WorkspaceId,
    context: Arc<QueryContext>,
    generation: u32,
    projection_id: ProjectionId,
    filter: EventFilterDto,
    cancellation: &crate::JobCancellation,
) -> Result<(), AppError> {
    if cancellation.is_cancelled() {
        return Err(AppError::cancelled());
    }
    let projection = Arc::new(TimelineProjection::new(context, convert_filter(filter)?)?);
    if cancellation.is_cancelled() {
        projection.cancel();
        return Err(AppError::cancelled());
    }
    let mut all = workspaces.lock().map_err(|_| AppError::worker_failed())?;
    let item = all
        .get_mut(workspace)
        .ok_or_else(AppError::stale_workspace)?;
    if item.generation == generation {
        item.current = Some(projection_id.clone());
    }
    item.projections.insert(
        projection_id,
        ProjectionWorkspace {
            projection,
            generation,
        },
    );
    while item.projections.len() > 16 {
        let oldest = item
            .projections
            .iter()
            .filter(|(id, _)| Some(*id) != item.current.as_ref())
            .min_by_key(|(_, value)| value.generation)
            .map(|(id, _)| id.clone());
        match oldest {
            Some(id) => {
                item.projections.remove(&id);
            }
            None => break,
        }
    }
    Ok(())
}

fn parse_module_digest(value: &str) -> Result<ArtifactDigest, AppError> {
    ArtifactDigest::from_hex(value).ok_or_else(|| {
        AppError::new(
            "symbol.module_identity_invalid",
            "annotation",
            "invalid module digest",
        )
    })
}

fn open_limits(input_bytes: u64) -> ServiceLimits {
    ServiceLimits {
        deadline: Instant::now() + Duration::from_secs(30 * 60),
        input_bytes,
        decompressed_bytes: 4 * 1024 * 1024 * 1024,
        events: 20_000_000,
        nodes: u64::MAX,
        rows: u64::MAX,
        resident_bytes: 2 * 1024 * 1024 * 1024,
    }
}

fn discovery_limits(selected_file_bytes: Option<u64>) -> ServiceLimits {
    let input_bytes = selected_file_bytes.map_or(4 * 1024 * 1024 * 1024, |size| {
        // Single-artifact discovery hashes the file, then probes its provider stream.
        size.saturating_mul(2).saturating_add(4 * 1024)
    });
    open_limits(input_bytes)
}

fn cache_limits() -> ServiceLimits {
    ServiceLimits {
        deadline: Instant::now() + Duration::from_secs(30 * 60),
        input_bytes: 4 * 1024 * 1024 * 1024,
        decompressed_bytes: 4 * 1024 * 1024 * 1024,
        events: 20_000_000,
        nodes: u64::MAX,
        rows: u64::MAX,
        resident_bytes: 2 * 1024 * 1024 * 1024,
    }
}

fn session_input_bytes(session: &qtrace_store::SessionSource) -> Result<u64, AppError> {
    session
        .artifacts()
        .iter()
        .try_fold(0_u64, |total, artifact| {
            total
                .checked_add(artifact.identity().file().size)
                .ok_or_else(|| {
                    AppError::new(
                        "workspace.input_size_overflow",
                        "open",
                        "selected artifact sizes overflow the input budget",
                    )
                })
        })
}

/// Normalizes QTRB's one pre-authorized probe unit so cumulative input work is
/// exactly the verified compressed size, including the final EOF check.
struct InputProbeAdjustedGuard<'a> {
    inner: &'a dyn WorkGuard,
    pending_probe: AtomicU64,
}

impl<'a> InputProbeAdjustedGuard<'a> {
    fn new(inner: &'a dyn WorkGuard) -> Self {
        Self {
            inner,
            pending_probe: AtomicU64::new(1),
        }
    }
}

impl WorkGuard for InputProbeAdjustedGuard<'_> {
    fn consume(&self, mut delta: WorkDelta) -> Result<(), OperationAbort> {
        if delta.input_bytes != 0
            && self
                .pending_probe
                .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            delta.input_bytes -= 1;
        }
        self.inner.consume(delta)
    }
}

fn default_cache_root() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| Path::new(value).is_absolute())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("qtrace-ui")
        .join("indexes")
}

fn completeness_range(value: qtrace_store::CompletenessRow) -> CompletenessRangeDto {
    let (domain, start, end, end_inclusive) = match (value.domain, value.bounds) {
        (RangeDomain::CapturedSequence, RangeBounds::InclusiveSequence { first, last }) => {
            ("captured_sequence", first, last, true)
        }
        (
            RangeDomain::SourceBytes,
            RangeBounds::HalfOpen {
                start,
                end_exclusive,
            },
        ) => ("source_bytes", start, end_exclusive, false),
        (RangeDomain::MemoryAddresses, RangeBounds::InclusiveSequence { first, last }) => {
            ("memory_addresses", first, last, true)
        }
        (
            RangeDomain::MemoryAddresses,
            RangeBounds::HalfOpen {
                start,
                end_exclusive,
            },
        ) => ("memory_addresses", start, end_exclusive, false),
        (RangeDomain::SourceBytes, RangeBounds::InclusiveSequence { first, last }) => {
            ("source_bytes", first, last, true)
        }
        (
            RangeDomain::CapturedSequence,
            RangeBounds::HalfOpen {
                start,
                end_exclusive,
            },
        ) => ("captured_sequence", start, end_exclusive, false),
    };
    CompletenessRangeDto {
        domain: domain.into(),
        start: DecimalU64Dto::new(start),
        end: DecimalU64Dto::new(end),
        end_inclusive,
        cause: completeness_cause(value.cause).into(),
        provenance: provenance_name(value.provenance).into(),
    }
}

fn completeness_cause(value: CompletenessCause) -> &'static str {
    match value {
        CompletenessCause::Retained => "retained",
        CompletenessCause::MissingTerminal => "missing_terminal",
        CompletenessCause::Active => "active",
        CompletenessCause::Stale => "stale",
        CompletenessCause::Rotating => "rotating",
        CompletenessCause::Unreliable => "unreliable",
        CompletenessCause::Incomplete => "incomplete",
        CompletenessCause::Lost => "lost",
        CompletenessCause::Overwritten => "overwritten",
        CompletenessCause::CoverageGap => "coverage_gap",
        CompletenessCause::Checksum => "checksum",
        CompletenessCause::UnterminatedThread => "unterminated_thread",
        CompletenessCause::Truncation => "truncation",
        CompletenessCause::Unknown => "unknown",
    }
}
fn convert_filter(value: EventFilterDto) -> Result<EventFilter, AppError> {
    let mut filter = EventFilter {
        tids: value.tids,
        modules: value.modules,
        relative_pc: value
            .relative_pc
            .into_iter()
            .map(|range| AddressRange::new(range.start.value(), range.end_exclusive.value()))
            .collect::<Result<_, _>>()?,
        absolute_pc: value
            .absolute_pc
            .into_iter()
            .map(|range| AddressRange::new(range.start.value(), range.end_exclusive.value()))
            .collect::<Result<_, _>>()?,
        sequence: value
            .sequence
            .into_iter()
            .map(|range| SequenceRange::new(range.first.value(), range.last.value()))
            .collect::<Result<_, _>>()?,
        mnemonic: value
            .mnemonic
            .into_iter()
            .map(|matcher| match matcher.mode.as_str() {
                "exact" => Ok(MnemonicFilter::Exact(matcher.value)),
                "contains" => Ok(MnemonicFilter::Contains(matcher.value)),
                _ => Err(AppError::new(
                    "filter.mnemonic_mode_invalid",
                    "projection",
                    "mnemonic mode must be exact or contains",
                )),
            })
            .collect::<Result<_, _>>()?,
        memory: value
            .memory
            .into_iter()
            .map(|memory| {
                Ok(MemoryFilter {
                    range: AddressRange::new(
                        memory.range.start.value(),
                        memory.range.end_exclusive.value(),
                    )?,
                    directions: memory
                        .directions
                        .into_iter()
                        .map(|direction| memory_direction(&direction))
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect::<Result<_, AppError>>()?,
        semantic_categories: value.semantic_categories,
        semantic_names: value.semantic_names,
        semantic_detail_contains: value.semantic_detail_contains,
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
    filter.register.reads = value
        .register_reads
        .iter()
        .map(|slot| register_slot(slot))
        .collect::<Result<_, _>>()?;
    filter.register.writes = value
        .register_writes
        .iter()
        .map(|slot| register_slot(slot))
        .collect::<Result<_, _>>()?;
    Ok(filter)
}
fn register_slot(value: &str) -> Result<RegisterSlot, AppError> {
    match value.to_ascii_lowercase().as_str() {
        "sp" => Ok(RegisterSlot::Sp),
        "pc" => Ok(RegisterSlot::Pc),
        "nzcv" => Ok(RegisterSlot::Nzcv),
        name if name.starts_with('x') => name[1..]
            .parse::<usize>()
            .ok()
            .filter(|index| *index <= 30)
            .and_then(RegisterSlot::from_index)
            .ok_or_else(|| {
                AppError::new("filter.register_invalid", "projection", "invalid register")
            }),
        _ => Err(AppError::new(
            "filter.register_invalid",
            "projection",
            "invalid register",
        )),
    }
}
fn memory_direction(value: &str) -> Result<MemoryDirection, AppError> {
    match value {
        "read" => Ok(MemoryDirection::Read),
        "write" => Ok(MemoryDirection::Write),
        "readwrite" => Ok(MemoryDirection::ReadWrite),
        "unknown" => Ok(MemoryDirection::Unknown),
        _ => Err(AppError::new(
            "filter.memory_direction_invalid",
            "projection",
            "invalid memory direction",
        )),
    }
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
