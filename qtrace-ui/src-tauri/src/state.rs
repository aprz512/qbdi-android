use std::{path::PathBuf, sync::Arc};

use qtrace_service::{
    AnnotationDto, AppError, CallTreeDto, EventDetailDto, JobDto, LocalSymbolNameDto,
    MemoryEvidenceDto, MemoryStateDto, OpenWorkspaceDto, ProjectionJobDto, RegisterStateDto,
    SymbolDto, TimelineLocationDto, TimelinePageDto, WorkspaceSummaryDto,
};
use qtrace_store::AuthorizedPath;
#[cfg(feature = "desktop")]
use tauri_plugin_dialog::DialogExt;

use crate::commands::*;

pub trait NativePicker: Send + Sync + 'static {
    fn pick_session(&self) -> Result<Option<PathBuf>, AppError>;
    fn pick_artifact(&self) -> Result<Option<PathBuf>, AppError>;
    fn pick_elf(&self) -> Result<Option<PathBuf>, AppError>;
}

pub struct CommandAdapter<P> {
    service: Arc<qtrace_service::QtraceService>,
    picker: P,
    data_home: PathBuf,
}

impl<P: NativePicker> CommandAdapter<P> {
    pub fn new(service: Arc<qtrace_service::QtraceService>, picker: P, data_home: PathBuf) -> Self {
        Self {
            service,
            picker,
            data_home,
        }
    }

    pub fn pick_and_open_session(&self) -> Result<Option<OpenWorkspaceDto>, AppError> {
        self.picker
            .pick_session()?
            .map(|path| self.service.open_session(AuthorizedPath::new(path)))
            .transpose()
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn pick_session_path(&self) -> Result<Option<PathBuf>, AppError> {
        self.picker.pick_session()
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn pick_artifact_path(&self) -> Result<Option<PathBuf>, AppError> {
        self.picker.pick_artifact()
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn service(&self) -> Arc<qtrace_service::QtraceService> {
        self.service.clone()
    }

    pub fn pick_and_open_artifact(&self) -> Result<Option<OpenWorkspaceDto>, AppError> {
        self.picker
            .pick_artifact()?
            .map(|path| self.service.open_artifact(AuthorizedPath::new(path)))
            .transpose()
    }

    pub fn close_workspace(&self, request: WorkspaceRequest) -> Result<(), AppError> {
        self.service.close_workspace(&request.workspace_id)
    }

    pub fn get_workspace_summary(
        &self,
        request: WorkspaceRequest,
    ) -> Result<WorkspaceSummaryDto, AppError> {
        self.service.workspace_summary(&request.workspace_id)
    }

    pub fn create_projection(
        &self,
        request: CreateProjectionRequest,
    ) -> Result<ProjectionJobDto, AppError> {
        self.service.create_projection(
            &request.workspace_id,
            request.artifact_index,
            request.filter,
        )
    }

    pub fn query_timeline(
        &self,
        request: QueryTimelineRequest,
    ) -> Result<TimelinePageDto, AppError> {
        self.service.query_timeline(
            &request.workspace_id,
            &request.projection_id,
            request.cursor,
            request.limit,
        )
    }

    pub fn locate_timeline(
        &self,
        request: LocateTimelineRequest,
    ) -> Result<Option<TimelineLocationDto>, AppError> {
        self.service.locate_timeline(
            &request.workspace_id,
            &request.projection_id,
            request.source_row,
            request.limit,
        )
    }

    pub fn locate_timeline_offset(
        &self,
        request: LocateTimelineOffsetRequest,
    ) -> Result<Option<TimelineLocationDto>, AppError> {
        self.service.locate_timeline_offset(
            &request.workspace_id,
            &request.projection_id,
            request.offset,
            request.limit,
        )
    }

    pub fn get_event_detail(&self, request: EventRequest) -> Result<EventDetailDto, AppError> {
        self.service
            .get_event_detail(&request.workspace_id, request.artifact_index, request.row)
    }

    pub fn get_register_state(&self, request: EventRequest) -> Result<RegisterStateDto, AppError> {
        self.service
            .get_register_state(&request.workspace_id, request.artifact_index, request.row)
    }

    pub fn get_memory_state(&self, request: MemoryRequest) -> Result<MemoryStateDto, AppError> {
        self.service.get_memory_state(
            &request.workspace_id,
            request.artifact_index,
            request.row,
            request.start.value(),
            request.end_exclusive.value(),
        )
    }

    pub fn get_memory_history(
        &self,
        request: MemoryRequest,
    ) -> Result<Vec<MemoryEvidenceDto>, AppError> {
        self.service.get_memory_history(
            &request.workspace_id,
            request.artifact_index,
            request.row,
            request.start.value(),
            request.end_exclusive.value(),
        )
    }

    pub fn get_call_tree(&self, request: CallTreeRequest) -> Result<CallTreeDto, AppError> {
        self.service.get_call_tree(
            &request.workspace_id,
            request.artifact_index,
            request.timeline_id.value(),
            request.tid,
        )
    }

    pub fn pick_and_attach_elf(&self, request: AttachElfRequest) -> Result<Option<()>, AppError> {
        self.picker
            .pick_elf()?
            .map(|path| {
                self.service.attach_elf(
                    &request.workspace_id,
                    AuthorizedPath::new(path),
                    request.module_name,
                    request.module_digest,
                    request.expected_build_id,
                )
            })
            .transpose()
    }

    pub fn list_symbols(&self, request: ListSymbolsRequest) -> Result<Vec<SymbolDto>, AppError> {
        let addresses = request
            .relative_pcs
            .iter()
            .map(qtrace_service::HexU64Dto::value)
            .collect::<Vec<_>>();
        self.service
            .list_symbols(&request.workspace_id, &request.module_name, &addresses)
    }

    pub fn upsert_annotation(&self, request: UpsertAnnotationRequest) -> Result<(), AppError> {
        self.service.upsert_annotation(
            &request.workspace_id,
            AuthorizedPath::new(self.data_home.clone()),
            request.artifact_index,
            request.row,
            request.comment,
        )
    }

    pub fn delete_annotation(&self, request: EventRequest) -> Result<(), AppError> {
        self.service.delete_annotation(
            &request.workspace_id,
            AuthorizedPath::new(self.data_home.clone()),
            request.artifact_index,
            request.row,
        )
    }

    pub fn get_annotation(&self, request: EventRequest) -> Result<Option<AnnotationDto>, AppError> {
        self.service.get_annotation(
            &request.workspace_id,
            AuthorizedPath::new(self.data_home.clone()),
            request.artifact_index,
            request.row,
        )
    }

    pub fn upsert_highlight(&self, request: UpsertHighlightRequest) -> Result<(), AppError> {
        self.service.upsert_highlight(
            &request.workspace_id,
            AuthorizedPath::new(self.data_home.clone()),
            request.artifact_index,
            request.row,
            request.value,
        )
    }

    pub fn delete_highlight(&self, request: EventRequest) -> Result<(), AppError> {
        self.service.delete_highlight(
            &request.workspace_id,
            AuthorizedPath::new(self.data_home.clone()),
            request.artifact_index,
            request.row,
        )
    }

    pub fn get_local_symbol_name(
        &self,
        request: LocalSymbolRequest,
    ) -> Result<Option<LocalSymbolNameDto>, AppError> {
        self.service.get_local_symbol_name(
            &request.workspace_id,
            AuthorizedPath::new(self.data_home.clone()),
            request.artifact_index,
            request.module_digest,
            request.relative_pc.value(),
        )
    }

    pub fn upsert_local_symbol_name(
        &self,
        request: UpsertLocalSymbolRequest,
    ) -> Result<(), AppError> {
        self.service.upsert_local_symbol_name(
            &request.workspace_id,
            AuthorizedPath::new(self.data_home.clone()),
            request.artifact_index,
            request.module_digest,
            request.relative_pc.value(),
            request.name,
        )
    }

    pub fn delete_local_symbol_name(&self, request: LocalSymbolRequest) -> Result<(), AppError> {
        self.service.delete_local_symbol_name(
            &request.workspace_id,
            AuthorizedPath::new(self.data_home.clone()),
            request.artifact_index,
            request.module_digest,
            request.relative_pc.value(),
        )
    }

    pub fn list_jobs(&self) -> Vec<JobDto> {
        self.service.list_jobs()
    }

    pub fn cancel_job(&self, request: CancelJobRequest) -> Result<(), AppError> {
        self.service.cancel_job(&request.job_id)
    }

    pub fn cancel_all(&self) {
        self.service.cancel_all();
    }
}

#[cfg(feature = "desktop")]
#[derive(Clone)]
pub struct TauriNativePicker(pub tauri::AppHandle);

#[cfg(feature = "desktop")]
impl NativePicker for TauriNativePicker {
    fn pick_session(&self) -> Result<Option<PathBuf>, AppError> {
        Ok(self
            .0
            .dialog()
            .file()
            .blocking_pick_folder()
            .and_then(|path| path.into_path().ok()))
    }

    fn pick_artifact(&self) -> Result<Option<PathBuf>, AppError> {
        Ok(self
            .0
            .dialog()
            .file()
            .blocking_pick_file()
            .and_then(|path| path.into_path().ok()))
    }

    fn pick_elf(&self) -> Result<Option<PathBuf>, AppError> {
        self.pick_artifact()
    }
}

#[cfg(feature = "desktop")]
pub type DesktopState = CommandAdapter<TauriNativePicker>;
