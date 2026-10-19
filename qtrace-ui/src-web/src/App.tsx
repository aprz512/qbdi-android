import { useEffect, useMemo } from "react";
import { useQtraceApi } from "./api/ApiContext";
import { AppHeader } from "./components/AppHeader";
import { BottomDock } from "./components/BottomDock";
import { FilterBar } from "./components/FilterBar";
import { LeftDock } from "./components/LeftDock";
import { RightDock } from "./components/RightDock";
import { SessionOverview } from "./components/SessionOverview";
import { useAppDispatch, useAppState } from "./state/AppStateProvider";
import { useEventDetails } from "./state/useEventDetails";
import { usePersistentEdits } from "./state/usePersistentEdits";
import { useTimelineNavigation } from "./state/useTimelineNavigation";
import { VirtualTimeline } from "./timeline/VirtualTimeline";

export default function App() {
  const state = useAppState();
  const api = useQtraceApi();
  const dispatch = useAppDispatch();
  const details = useEventDetails();
  const { selectedRow, detail, registers, memory, memoryHistory, callTree, paneErrors, addError } = details;
  const { annotation, writeAnnotation } = usePersistentEdits(details.selection, addError);
  const { rows, visibleSegments, hiddenHistoryTarget, applyFilter, selectArtifact, selectTid,
    loadPage, loadNextPage, loadPreviousPage, selectRow, jumpToRow, reveal, refreshSymbols,
    canGoBack, canGoForward, goBack, goForward } = useTimelineNavigation(details);
  const tids = useMemo(
    () => state.opened?.artifacts.find((artifact) => artifact.index === state.selectedArtifactIndex)?.tids ?? [],
    [state.opened, state.selectedArtifactIndex],
  );
  const selectedTid = selectedRow?.key.tid ?? state.filter.tids[0] ?? null;

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const jobs = await api.listJobs();
        if (active) dispatch({ type: "jobsReceived", jobs });
      } catch { /* Jobs are auxiliary; pane operations remain usable. */ }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 1_000);
    return () => { active = false; window.clearInterval(timer); };
  }, [api, dispatch]);

  const cancelJob = async (id: string) => {
    try { await api.cancelJob(id); dispatch({ type: "jobsReceived", jobs: await api.listJobs() }); }
    catch (error) { addError(error); throw error; }
  };

  return (
    <div className="app-shell">
      <nav className="panel-shortcuts" aria-label="Panel shortcuts">
        <a href="#timeline-panel">Timeline</a><a href="#trace-panel">Trace</a><a href="#details-panel">Details</a><a href="#results-panel">Results</a>
      </nav>
      <AppHeader />
      <LeftDock workspaceId={state.opened?.workspace.id ?? null} tids={tids} selectedTid={selectedTid} callTree={callTree} onSelectTid={selectTid} onJump={jumpToRow}
        onLoadCallTreePage={(parent, offset, identity) => {
          if (state.opened === null || callTree === null) return Promise.reject(new Error("Call tree closed"));
          return api.getCallTree(state.opened.workspace.id, callTree.artifact_index, callTree.timeline_id, callTree.tid, parent, offset, identity);
        }} />
      <main id="timeline-panel" tabIndex={-1} className="workspace">
        {state.opened !== null && <FilterBar filter={state.filter} onApply={(filter) => void applyFilter(filter)} />}
        {state.opened !== null && state.projectionId !== null && <nav aria-label="Artifacts" className="artifact-selector">{state.opened.artifacts.map((artifact) => <button key={artifact.index} aria-pressed={artifact.index === state.selectedArtifactIndex} onClick={() => selectArtifact(artifact.index)}>{artifact.name}</button>)}</nav>}
        {state.phase === "failed" && state.error !== null ? (
          <section role="alert"><h1>{state.error.code}</h1><p>{state.error.detail}</p></section>
        ) : state.opened === null || state.projectionId === null ? (
          <SessionOverview opened={state.opened} selectedArtifactIndex={state.selectedArtifactIndex} onSelectArtifact={selectArtifact} />
        ) : (
          <VirtualTimeline rows={rows} pageStart={visibleSegments[0]?.start ?? 0} totalRows={state.timelinePages.at(-1)?.total ?? rows.length} hasMore={visibleSegments.at(-1)?.page.next_cursor !== null} hasPrevious={(visibleSegments[0]?.start ?? 0) > 0} workspaceId={state.opened.workspace.id} projectionId={state.projectionId} generation={state.generation} onRequestRange={async (start, end, signal) => { await loadPage({ start, end }, signal); }} onLoadMore={loadNextPage} onLoadPrevious={loadPreviousPage} onSelect={selectRow} />
        )}
      </main>
      <RightDock row={selectedRow} selectionRevision={details.selection?.request.revision} detail={detail} registers={registers} memory={memory} history={memoryHistory} annotation={annotation} errors={paneErrors} workspaceId={state.opened?.workspace.id ?? null} artifactIndex={state.selectedArtifactIndex} completeness={state.opened?.artifacts.find((artifact) => artifact.index === state.selectedArtifactIndex)?.completeness ?? []} onSaveComment={(value) => writeAnnotation("comment", value)} onDeleteComment={() => writeAnnotation("comment")} onSaveHighlight={(value) => writeAnnotation("highlight", value)} onDeleteHighlight={() => writeAnnotation("highlight")} onSymbolsChanged={refreshSymbols} />
      <BottomDock initialResultsPage={state.timelinePages[0] ?? null} workspaceId={state.opened?.workspace.id ?? null} projectionId={state.projectionId} generation={state.generation} jobs={state.jobs} canGoBack={canGoBack} canGoForward={canGoForward} hiddenHistoryTarget={hiddenHistoryTarget !== null} onJump={jumpToRow} onCancel={cancelJob} onBack={goBack} onForward={goForward} onReveal={reveal} />
    </div>
  );
}
