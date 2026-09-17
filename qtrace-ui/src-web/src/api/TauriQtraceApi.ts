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
  listJobs: QtraceApi["listJobs"] = () => request("list_jobs");
  cancelJob: QtraceApi["cancelJob"] = (job_id) => request("cancel_job", { job_id });
}
