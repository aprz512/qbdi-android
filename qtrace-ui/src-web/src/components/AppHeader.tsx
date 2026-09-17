import { normalizeAppError } from "../api/TauriQtraceApi";
import { useQtraceApi } from "../api/ApiContext";
import { useCallback, useEffect, useRef } from "react";
import { useAppDispatch, useAppState } from "../state/AppStateProvider";

export function AppHeader() {
  const api = useQtraceApi();
  const state = useAppState();
  const dispatch = useAppDispatch();
  const openRequest = useRef(0);
  const staleWorkspaces = useRef(new Set<string>());

  const retryStaleClosures = useCallback(async () => {
    for (const workspaceId of [...staleWorkspaces.current]) {
      try {
        await api.closeWorkspace(workspaceId);
        staleWorkspaces.current.delete(workspaceId);
      } catch { /* Keep the workspace queued for the next retry. */ }
    }
  }, [api]);

  useEffect(() => {
    const timer = window.setInterval(() => void retryStaleClosures(), 1_000);
    return () => window.clearInterval(timer);
  }, [retryStaleClosures]);

  const open = async (artifact = false) => {
    void retryStaleClosures();
    const request = ++openRequest.current;
    const previousWorkspace = state.opened?.workspace.id ?? null;
    dispatch({ type: "openStarted" });
    try {
      const opened = artifact ? await api.pickAndOpenArtifact() : await api.pickAndOpenSession();
      if (request !== openRequest.current) {
        if (opened !== null) {
          try { await api.closeWorkspace(opened.workspace.id); }
          catch { staleWorkspaces.current.add(opened.workspace.id); }
        }
        return;
      }
      if (opened === null) {
        dispatch({ type: "pickerCancelled" });
        return;
      }
      dispatch({ type: "workspaceOpened", opened });
      if (previousWorkspace !== null && previousWorkspace !== opened.workspace.id) {
        try { await api.closeWorkspace(previousWorkspace); }
        catch { staleWorkspaces.current.add(previousWorkspace); }
      }
    } catch (error) {
      dispatch({ type: "failed", error: normalizeAppError(error) });
    }
  };

  const close = async () => {
    openRequest.current += 1;
    void retryStaleClosures();
    if (state.opened === null) return;
    try {
      await api.closeWorkspace(state.opened.workspace.id);
      dispatch({ type: "closed" });
    } catch (error) {
      dispatch({ type: "failed", error: normalizeAppError(error) });
    }
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
