import type { QtraceApi } from "./QtraceApi";
import { normalizeAppError } from "./TauriQtraceApi";

const baseUrl = import.meta.env.VITE_E2E_URL as string | undefined;
const token = import.meta.env.VITE_E2E_TOKEN as string | undefined;

async function request<T>(command: string, value: object = {}): Promise<T> {
  if (import.meta.env.MODE !== "e2e" || baseUrl === undefined || token === undefined) {
    throw normalizeAppError(null);
  }
  const response = await fetch(`${baseUrl}/${command}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(value),
    signal: AbortSignal.timeout(30_000),
  });
  const envelope = await response.json() as { ok?: T; error?: unknown };
  if (!response.ok || !("ok" in envelope)) throw normalizeAppError(envelope.error);
  return envelope.ok as T;
}

export class E2eQtraceApi implements QtraceApi {
  pickAndOpenSession: QtraceApi["pickAndOpenSession"] = () => request("pick_and_open_session", { fixture: new URLSearchParams(window.location.search).get("fixture") });
  pickAndOpenArtifact: QtraceApi["pickAndOpenArtifact"] = () => request("pick_and_open_artifact");
  closeWorkspace: QtraceApi["closeWorkspace"] = (workspace_id) => request("close_workspace", { workspace_id });
  getWorkspaceSummary: QtraceApi["getWorkspaceSummary"] = (workspace_id) => request("get_workspace_summary", { workspace_id });
  createProjection: QtraceApi["createProjection"] = (workspace_id, artifact_index, filter) => request("create_projection", { workspace_id, artifact_index, filter });
  queryTimeline: QtraceApi["queryTimeline"] = (workspace_id, projection_id, cursor, limit) => request("query_timeline", { workspace_id, projection_id, cursor, limit });
  getEventDetail: QtraceApi["getEventDetail"] = (workspace_id, artifact_index, row) => request("get_event_detail", { workspace_id, artifact_index, row });
  getRegisterState: QtraceApi["getRegisterState"] = (workspace_id, artifact_index, row) => request("get_register_state", { workspace_id, artifact_index, row });
  getMemoryState: QtraceApi["getMemoryState"] = (workspace_id, artifact_index, row, start, end_exclusive) => request("get_memory_state", { workspace_id, artifact_index, row, start, end_exclusive });
  getMemoryHistory: QtraceApi["getMemoryHistory"] = (workspace_id, artifact_index, row, start, end_exclusive) => request("get_memory_history", { workspace_id, artifact_index, row, start, end_exclusive });
  getCallTree: QtraceApi["getCallTree"] = (workspace_id, artifact_index, timeline_id, tid) => request("get_call_tree", { workspace_id, artifact_index, timeline_id, tid });
  pickAndAttachElf: QtraceApi["pickAndAttachElf"] = () => Promise.resolve(null);
  listSymbols: QtraceApi["listSymbols"] = (workspace_id, module_name, relative_pcs) => request("list_symbols", { workspace_id, module_name, relative_pcs });
  getAnnotation: QtraceApi["getAnnotation"] = (workspace_id, artifact_index, row) => request("get_annotation", { workspace_id, artifact_index, row });
  upsertAnnotation: QtraceApi["upsertAnnotation"] = (workspace_id, artifact_index, row, comment) => request("upsert_annotation", { workspace_id, artifact_index, row, comment });
  deleteAnnotation: QtraceApi["deleteAnnotation"] = (workspace_id, artifact_index, row) => request("delete_annotation", { workspace_id, artifact_index, row });
  upsertHighlight: QtraceApi["upsertHighlight"] = (workspace_id, artifact_index, row, value) => request("upsert_highlight", { workspace_id, artifact_index, row, value });
  deleteHighlight: QtraceApi["deleteHighlight"] = (workspace_id, artifact_index, row) => request("delete_highlight", { workspace_id, artifact_index, row });
  getLocalSymbolName: QtraceApi["getLocalSymbolName"] = (workspace_id, artifact_index, module_digest, relative_pc) => request("get_local_symbol_name", { workspace_id, artifact_index, module_digest, relative_pc });
  upsertLocalSymbolName: QtraceApi["upsertLocalSymbolName"] = (workspace_id, artifact_index, module_digest, relative_pc, name) => request("upsert_local_symbol_name", { workspace_id, artifact_index, module_digest, relative_pc, name });
  deleteLocalSymbolName: QtraceApi["deleteLocalSymbolName"] = (workspace_id, artifact_index, module_digest, relative_pc) => request("delete_local_symbol_name", { workspace_id, artifact_index, module_digest, relative_pc });
  listJobs: QtraceApi["listJobs"] = () => request("list_jobs");
  cancelJob: QtraceApi["cancelJob"] = (job_id) => request("cancel_job", { job_id });
}
