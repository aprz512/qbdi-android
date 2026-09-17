import { normalizeAppError } from "../api/TauriQtraceApi";
import { useQtraceApi } from "../api/ApiContext";
import { useRef } from "react";
import { useAppDispatch, useAppState } from "../state/AppStateProvider";

export function AppHeader() {
  const api = useQtraceApi();
  const state = useAppState();
  const dispatch = useAppDispatch();
  const openRequest = useRef(0);

  const open = async (artifact = false) => {
    const request = ++openRequest.current;
    const previousWorkspace = state.opened?.workspace.id ?? null;
    dispatch({ type: "openStarted" });
    try {
      const opened = artifact ? await api.pickAndOpenArtifact() : await api.pickAndOpenSession();
      if (request !== openRequest.current) {
        if (opened !== null) await api.closeWorkspace(opened.workspace.id);
        return;
      }
      if (opened === null) {
        dispatch({ type: "pickerCancelled" });
        return;
      }
      dispatch({ type: "workspaceOpened", opened });
      if (previousWorkspace !== null && previousWorkspace !== opened.workspace.id) {
        try { await api.closeWorkspace(previousWorkspace); }
        catch { /* The newly adopted workspace remains usable; stale cleanup can be retried. */ }
      }
    } catch (error) {
      dispatch({ type: "failed", error: normalizeAppError(error) });
    }
  };

  const close = async () => {
    openRequest.current += 1;
    if (state.opened !== null) await api.closeWorkspace(state.opened.workspace.id);
    dispatch({ type: "closed" });
  };

  return (
    <header className="app-header">
      <strong>qtrace-ui</strong>
      <span className="header-status">{state.phase}</span>
      <button onClick={() => void open(false)}>Open session</button>
      <button onClick={() => void open(true)}>Open artifact</button>
      <button disabled={state.opened === null} onClick={() => void close()}>Close</button>
    </header>
  );
}
