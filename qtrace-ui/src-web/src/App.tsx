import { AppHeader } from "./components/AppHeader";
import { BottomDock } from "./components/BottomDock";
import { LeftDock } from "./components/LeftDock";
import { RightDock } from "./components/RightDock";
import { SessionOverview } from "./components/SessionOverview";
import { useAppState } from "./state/AppStateProvider";
import { VirtualTimeline } from "./timeline/VirtualTimeline";
import { FilterBar } from "./components/FilterBar";
import { useQtraceApi } from "./api/ApiContext";
import { useAppDispatch } from "./state/AppStateProvider";
import { normalizeAppError } from "./api/TauriQtraceApi";
import type { EventFilterDto } from "./api/generated";

export default function App() {
  const state = useAppState();
  const api = useQtraceApi();
  const dispatch = useAppDispatch();
  const applyFilter = async (filter: EventFilterDto) => {
    if (state.opened === null) return;
    const generation = state.generation + 1;
    dispatch({ type: "filterChanged", filter });
    dispatch({ type: "indexingStarted", generation });
    try {
      const projection = await api.createProjection(state.opened.workspace.id, 0, filter);
      dispatch({ type: "projectionReady", generation, projectionId: projection.projection_id });
      const page = await api.queryTimeline(state.opened.workspace.id, projection.projection_id, null, 2_000);
      dispatch({ type: "timelinePageReceived", generation, page });
    } catch (error) {
      dispatch({ type: "failed", generation, error: normalizeAppError(error) });
    }
  };
  return (
    <div className="app-shell">
      <AppHeader />
      <LeftDock />
      <main className="workspace">
        {state.opened !== null && <FilterBar onApply={(filter) => void applyFilter(filter)} />}
        {state.phase === "failed" && state.error !== null ? (
          <section role="alert"><h1>{state.error.code}</h1><p>{state.error.detail}</p></section>
        ) : state.opened === null || state.projectionId === null ? (
          <SessionOverview opened={state.opened} />
        ) : (
          <VirtualTimeline rows={state.timelinePages.flatMap((page) => page.rows)} onSelect={(row) => dispatch({ type: "selectionChanged", event: row.key })} />
        )}
      </main>
      <RightDock />
      <BottomDock />
    </div>
  );
}
