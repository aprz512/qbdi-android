import { invoke } from "@tauri-apps/api/core";
import type { AppError } from "./generated";
import type { QtraceApi } from "./QtraceApi";

const request = <T>(command: string, value?: object): Promise<T> =>
  invoke<T>(command, value === undefined ? undefined : { request: value }).catch((error: unknown) => {
    throw normalizeAppError(error);
  });

export function normalizeAppError(value: unknown): AppError {
  if (
    typeof value === "object" &&
    value !== null &&
    typeof (value as AppError).code === "string" &&
    typeof (value as AppError).stage === "string" &&
    typeof (value as AppError).retryable === "boolean" &&
    typeof (value as AppError).detail === "string" &&
    ((value as AppError).source === null || typeof (value as AppError).source === "object")
  ) {
    return value as AppError;
  }
  return {
    code: "client.contract_invalid",
    stage: "client",
    source: null,
    retryable: false,
    detail: "backend returned an invalid error envelope",
  };
}

export class TauriQtraceApi implements QtraceApi {
  pickAndOpenSession: QtraceApi["pickAndOpenSession"] = () => request("pick_and_open_session", {});
  pickAndOpenArtifact: QtraceApi["pickAndOpenArtifact"] = () => request("pick_and_open_artifact", {});
  closeWorkspace: QtraceApi["closeWorkspace"] = (workspace_id) => request("close_workspace", { workspace_id });
  getWorkspaceSummary: QtraceApi["getWorkspaceSummary"] = (workspace_id) =>
    request<Awaited<ReturnType<QtraceApi["getWorkspaceSummary"]>>>("get_workspace_summary", {
      workspace_id,
    });
  createProjection: QtraceApi["createProjection"] = (workspace_id, artifact_index, filter) =>
    request("create_projection", { workspace_id, artifact_index, filter });
  queryTimeline: QtraceApi["queryTimeline"] = (workspace_id, projection_id, cursor, limit) =>
    request("query_timeline", { workspace_id, projection_id, cursor, limit });
  locateTimeline: QtraceApi["locateTimeline"] = (workspace_id, projection_id, source_row, limit) =>
    request("locate_timeline", { workspace_id, projection_id, source_row, limit });
  locateTimelineOffset: QtraceApi["locateTimelineOffset"] = (workspace_id, projection_id, offset, limit) =>
    request("locate_timeline_offset", { workspace_id, projection_id, offset, limit });
  getEventDetail: QtraceApi["getEventDetail"] = (workspace_id, artifact_index, row) =>
    request("get_event_detail", { workspace_id, artifact_index, row });
  getRegisterState: QtraceApi["getRegisterState"] = (workspace_id, artifact_index, row) =>
    request("get_register_state", { workspace_id, artifact_index, row });
  getMemoryState: QtraceApi["getMemoryState"] = (workspace_id, artifact_index, row, start, end_exclusive) =>
    request("get_memory_state", { workspace_id, artifact_index, row, start, end_exclusive });
  getMemoryHistory: QtraceApi["getMemoryHistory"] = (workspace_id, artifact_index, row, start, end_exclusive) =>
    request("get_memory_history", { workspace_id, artifact_index, row, start, end_exclusive });
  getCallTree: QtraceApi["getCallTree"] = (workspace_id, artifact_index, timeline_id, tid) =>
    request("get_call_tree", { workspace_id, artifact_index, timeline_id, tid });
  pickAndAttachElf: QtraceApi["pickAndAttachElf"] = (workspace_id, module_name, module_digest, expected_build_id) =>
    request("pick_and_attach_elf", { workspace_id, module_name, module_digest, expected_build_id });
  listSymbols: QtraceApi["listSymbols"] = (workspace_id, module_name, relative_pcs) =>
    request("list_symbols", { workspace_id, module_name, relative_pcs });
  getAnnotation: QtraceApi["getAnnotation"] = (workspace_id, artifact_index, row) =>
    request("get_annotation", { workspace_id, artifact_index, row });
  upsertAnnotation: QtraceApi["upsertAnnotation"] = (workspace_id, artifact_index, row, comment) =>
    request("upsert_annotation", { workspace_id, artifact_index, row, comment });
  deleteAnnotation: QtraceApi["deleteAnnotation"] = (workspace_id, artifact_index, row) =>
    request("delete_annotation", { workspace_id, artifact_index, row });
  upsertHighlight: QtraceApi["upsertHighlight"] = (workspace_id, artifact_index, row, value) =>
    request("upsert_highlight", { workspace_id, artifact_index, row, value });
  deleteHighlight: QtraceApi["deleteHighlight"] = (workspace_id, artifact_index, row) =>
    request("delete_highlight", { workspace_id, artifact_index, row });
  getLocalSymbolName: QtraceApi["getLocalSymbolName"] = (workspace_id, artifact_index, module_digest, relative_pc) =>
    request("get_local_symbol_name", { workspace_id, artifact_index, module_digest, relative_pc });
  upsertLocalSymbolName: QtraceApi["upsertLocalSymbolName"] = (workspace_id, artifact_index, module_digest, relative_pc, name) =>
    request("upsert_local_symbol_name", { workspace_id, artifact_index, module_digest, relative_pc, name });
  deleteLocalSymbolName: QtraceApi["deleteLocalSymbolName"] = (workspace_id, artifact_index, module_digest, relative_pc) =>
    request("delete_local_symbol_name", { workspace_id, artifact_index, module_digest, relative_pc });
  listJobs: QtraceApi["listJobs"] = () => request("list_jobs");
  cancelJob: QtraceApi["cancelJob"] = (job_id) => request("cancel_job", { job_id });
}
