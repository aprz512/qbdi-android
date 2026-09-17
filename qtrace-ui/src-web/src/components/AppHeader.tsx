import { normalizeAppError } from "../api/TauriQtraceApi";
import { useQtraceApi } from "../api/ApiContext";
import { useAppDispatch, useAppState } from "../state/AppStateProvider";

export function AppHeader() {
  const api = useQtraceApi();
  const state = useAppState();
  const dispatch = useAppDispatch();

  const open = async (artifact = false) => {
    dispatch({ type: "openStarted" });
    try {
      const opened = artifact ? await api.pickAndOpenArtifact() : await api.pickAndOpenSession();
      dispatch(opened === null ? { type: "pickerCancelled" } : { type: "workspaceOpened", opened });
    } catch (error) {
      dispatch({ type: "failed", error: normalizeAppError(error) });
    }
  };

  const close = async () => {
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
