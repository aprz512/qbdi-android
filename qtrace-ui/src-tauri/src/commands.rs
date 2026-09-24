#[cfg(feature = "desktop")]
use qtrace_service::{
    AnnotationDto, AppError, CallTreeDto, EventDetailDto, JobDto, LocalSymbolNameDto,
    MemoryEvidenceDto, MemoryStateDto, OpenWorkspaceDto, ProjectionJobDto, RegisterStateDto,
    SymbolDto, TimelineLocationDto, TimelinePageDto, WorkspaceSummaryDto,
};
use qtrace_service::{DecimalU64Dto, EventFilterDto, HexU64Dto, JobId, ProjectionId, WorkspaceId};
use serde::Deserialize;
#[cfg(feature = "desktop")]
use tauri::State;

#[cfg(feature = "desktop")]
use crate::state::DesktopState;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyPickerRequest {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRequest {
    pub workspace_id: WorkspaceId,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProjectionRequest {
    pub workspace_id: WorkspaceId,
    pub artifact_index: u32,
    pub filter: EventFilterDto,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryTimelineRequest {
    pub workspace_id: WorkspaceId,
    pub projection_id: ProjectionId,
    pub cursor: Option<String>,
    pub limit: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocateTimelineRequest {
    pub workspace_id: WorkspaceId,
    pub projection_id: ProjectionId,
    pub source_row: u32,
    pub limit: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocateTimelineOffsetRequest {
    pub workspace_id: WorkspaceId,
    pub projection_id: ProjectionId,
    pub offset: u32,
    pub limit: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRequest {
    pub workspace_id: WorkspaceId,
    pub artifact_index: u32,
    pub row: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryRequest {
    pub workspace_id: WorkspaceId,
    pub artifact_index: u32,
    pub row: u32,
    pub start: HexU64Dto,
    pub end_exclusive: HexU64Dto,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallTreeRequest {
    pub workspace_id: WorkspaceId,
    pub artifact_index: u32,
    pub timeline_id: DecimalU64Dto,
    pub tid: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachElfRequest {
    pub workspace_id: WorkspaceId,
    pub module_name: String,
    pub module_digest: String,
    pub expected_build_id: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListSymbolsRequest {
    pub workspace_id: WorkspaceId,
    pub module_name: String,
    pub relative_pcs: Vec<HexU64Dto>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertAnnotationRequest {
    pub workspace_id: WorkspaceId,
    pub artifact_index: u32,
    pub row: u32,
    pub comment: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertHighlightRequest {
    pub workspace_id: WorkspaceId,
    pub artifact_index: u32,
    pub row: u32,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSymbolRequest {
    pub workspace_id: WorkspaceId,
    pub artifact_index: u32,
    pub module_digest: String,
    pub relative_pc: HexU64Dto,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertLocalSymbolRequest {
    pub workspace_id: WorkspaceId,
    pub artifact_index: u32,
    pub module_digest: String,
    pub relative_pc: HexU64Dto,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelJobRequest {
    pub job_id: JobId,
}

#[cfg(feature = "desktop")]
mod desktop {
    use super::*;

    #[tauri::command]
    pub async fn pick_and_open_session(
        _request: EmptyPickerRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Option<OpenWorkspaceDto>, AppError> {
        let Some(path) = state.pick_session_path()? else {
            return Ok(None);
        };
        let service = state.service();
        service
            .open_session_task(qtrace_store::AuthorizedPath::new(path))
            .await
            .map(Some)
    }

    #[tauri::command]
    pub async fn pick_and_open_artifact(
        _request: EmptyPickerRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Option<OpenWorkspaceDto>, AppError> {
        let Some(path) = state.pick_artifact_path()? else {
            return Ok(None);
        };
        let service = state.service();
        service
            .open_artifact_task(qtrace_store::AuthorizedPath::new(path))
            .await
            .map(Some)
    }

    #[tauri::command]
    pub fn close_workspace(
        request: WorkspaceRequest,
        state: State<'_, DesktopState>,
    ) -> Result<(), AppError> {
        state.close_workspace(request)
    }

    #[tauri::command]
    pub fn get_workspace_summary(
        request: WorkspaceRequest,
        state: State<'_, DesktopState>,
    ) -> Result<WorkspaceSummaryDto, AppError> {
        state.get_workspace_summary(request)
    }

    #[tauri::command]
    pub async fn create_projection(
        request: CreateProjectionRequest,
        state: State<'_, DesktopState>,
    ) -> Result<ProjectionJobDto, AppError> {
        let service = state.service();
        service
            .create_projection_task(request.workspace_id, request.artifact_index, request.filter)
            .await
    }

    #[tauri::command]
    pub fn query_timeline(
        request: QueryTimelineRequest,
        state: State<'_, DesktopState>,
    ) -> Result<TimelinePageDto, AppError> {
        state.query_timeline(request)
    }

    #[tauri::command]
    pub fn locate_timeline(
        request: LocateTimelineRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Option<TimelineLocationDto>, AppError> {
        state.locate_timeline(request)
    }

    #[tauri::command]
    pub fn locate_timeline_offset(
        request: LocateTimelineOffsetRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Option<TimelineLocationDto>, AppError> {
        state.locate_timeline_offset(request)
    }

    #[tauri::command]
    pub fn get_event_detail(
        request: EventRequest,
        state: State<'_, DesktopState>,
    ) -> Result<EventDetailDto, AppError> {
        state.get_event_detail(request)
    }

    #[tauri::command]
    pub async fn get_register_state(
        request: EventRequest,
        state: State<'_, DesktopState>,
    ) -> Result<RegisterStateDto, AppError> {
        let service = state.service();
        tokio::task::spawn_blocking(move || {
            service.get_register_state(&request.workspace_id, request.artifact_index, request.row)
        })
        .await
        .map_err(|_| AppError::worker_failed())?
    }

    #[tauri::command]
    pub fn get_memory_state(
        request: MemoryRequest,
        state: State<'_, DesktopState>,
    ) -> Result<MemoryStateDto, AppError> {
        state.get_memory_state(request)
    }

    #[tauri::command]
    pub fn get_memory_history(
        request: MemoryRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Vec<MemoryEvidenceDto>, AppError> {
        state.get_memory_history(request)
    }

    #[tauri::command]
    pub fn get_call_tree(
        request: CallTreeRequest,
        state: State<'_, DesktopState>,
    ) -> Result<CallTreeDto, AppError> {
        state.get_call_tree(request)
    }

    #[tauri::command]
    pub fn pick_and_attach_elf(
        request: AttachElfRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Option<()>, AppError> {
        state.pick_and_attach_elf(request)
    }

    #[tauri::command]
    pub fn list_symbols(
        request: ListSymbolsRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Vec<SymbolDto>, AppError> {
        state.list_symbols(request)
    }

    #[tauri::command]
    pub fn upsert_annotation(
        request: UpsertAnnotationRequest,
        state: State<'_, DesktopState>,
    ) -> Result<(), AppError> {
        state.upsert_annotation(request)
    }

    #[tauri::command]
    pub fn delete_annotation(
        request: EventRequest,
        state: State<'_, DesktopState>,
    ) -> Result<(), AppError> {
        state.delete_annotation(request)
    }

    #[tauri::command]
    pub fn get_annotation(
        request: EventRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Option<AnnotationDto>, AppError> {
        state.get_annotation(request)
    }

    #[tauri::command]
    pub fn upsert_highlight(
        request: UpsertHighlightRequest,
        state: State<'_, DesktopState>,
    ) -> Result<(), AppError> {
        state.upsert_highlight(request)
    }

    #[tauri::command]
    pub fn delete_highlight(
        request: EventRequest,
        state: State<'_, DesktopState>,
    ) -> Result<(), AppError> {
        state.delete_highlight(request)
    }

    #[tauri::command]
    pub fn get_local_symbol_name(
        request: LocalSymbolRequest,
        state: State<'_, DesktopState>,
    ) -> Result<Option<LocalSymbolNameDto>, AppError> {
        state.get_local_symbol_name(request)
    }

    #[tauri::command]
    pub fn upsert_local_symbol_name(
        request: UpsertLocalSymbolRequest,
        state: State<'_, DesktopState>,
    ) -> Result<(), AppError> {
        state.upsert_local_symbol_name(request)
    }

    #[tauri::command]
    pub fn delete_local_symbol_name(
        request: LocalSymbolRequest,
        state: State<'_, DesktopState>,
    ) -> Result<(), AppError> {
        state.delete_local_symbol_name(request)
    }

    #[tauri::command]
    pub fn list_jobs(state: State<'_, DesktopState>) -> Vec<JobDto> {
        state.list_jobs()
    }

    #[tauri::command]
    pub fn cancel_job(
        request: CancelJobRequest,
        state: State<'_, DesktopState>,
    ) -> Result<(), AppError> {
        state.cancel_job(request)
    }
}

#[cfg(feature = "desktop")]
pub use desktop::*;
