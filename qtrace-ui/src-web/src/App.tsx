import { useEffect, useMemo, useRef, useState } from "react";
import { useQtraceApi } from "./api/ApiContext";
import type { AnnotationDto, AppError, CallTreeDto, EventDetailDto, EventFilterDto, EventKeyDto, EventRowDto, MemoryEvidenceDto, MemoryStateDto, RegisterStateDto } from "./api/generated";
import { normalizeAppError } from "./api/TauriQtraceApi";
import { AppHeader } from "./components/AppHeader";
import { BottomDock } from "./components/BottomDock";
import { FilterBar } from "./components/FilterBar";
import { LeftDock } from "./components/LeftDock";
import { RightDock } from "./components/RightDock";
import { SessionOverview } from "./components/SessionOverview";
import { useAppDispatch, useAppState } from "./state/AppStateProvider";
import { emptyFilter } from "./state/model";
import { NavigationHistory, type NavigationEntry } from "./state/navigation";
import { VirtualTimeline } from "./timeline/VirtualTimeline";
import { SegmentCache } from "./timeline/SegmentCache";

const sameKey = (left: EventKeyDto, right: EventKeyDto) =>
  left.artifact_sha256 === right.artifact_sha256 && left.timeline_id === right.timeline_id && left.record_ordinal === right.record_ordinal;

export default function App() {
  const state = useAppState();
  const api = useQtraceApi();
  const dispatch = useAppDispatch();
  const [selectedRow, setSelectedRow] = useState<EventRowDto | null>(null);
  const [detail, setDetail] = useState<EventDetailDto | null>(null);
  const [registers, setRegisters] = useState<RegisterStateDto | null>(null);
  const [memory, setMemory] = useState<MemoryStateDto | null>(null);
  const [memoryHistory, setMemoryHistory] = useState<MemoryEvidenceDto[]>([]);
  const [callTree, setCallTree] = useState<CallTreeDto | null>(null);
  const [annotation, setAnnotation] = useState<AnnotationDto | null>(null);
  const [paneErrors, setPaneErrors] = useState<AppError[]>([]);
  const [, setHistoryVersion] = useState(0);
  const [hiddenHistoryTarget, setHiddenHistoryTarget] = useState<NavigationEntry | null>(null);
  const selectionRequest = useRef(0);
  const projectionGeneration = useRef(0);
  const paginationRequest = useRef(false);
  const requestedCursors = useRef(new Set<string>());
  const segmentCache = useRef(new SegmentCache<Awaited<ReturnType<typeof api.queryTimeline>>>());
  const navigation = useRef(new NavigationHistory());
  const rows = useMemo(() => state.timelinePages.flatMap((page) => page.rows), [state.timelinePages]);
  const tids = useMemo(() => [...new Set(rows.flatMap((row) => row.key.tid === null ? [] : [row.key.tid]))].sort((a, b) => a - b), [rows]);
  const selectedTid = selectedRow?.key.tid ?? state.filter.tids[0] ?? null;

  useEffect(() => {
    if (state.opened === null) {
      selectionRequest.current += 1;
      setSelectedRow(null); setDetail(null); setRegisters(null); setMemory(null);
      setMemoryHistory([]); setCallTree(null); setAnnotation(null); setPaneErrors([]);
    }
  }, [state.opened]);

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

  useEffect(() => { projectionGeneration.current = Math.max(projectionGeneration.current, state.generation); }, [state.generation]);

  const applyFilter = async (filter: EventFilterDto, artifactIndex = state.selectedArtifactIndex) => {
    if (state.opened === null) return;
    const generation = ++projectionGeneration.current;
    selectionRequest.current += 1;
    setSelectedRow(null); setDetail(null); setRegisters(null); setMemory(null);
    setMemoryHistory([]); setCallTree(null); setAnnotation(null); setPaneErrors([]);
    dispatch({ type: "filterChanged", filter });
    dispatch({ type: "indexingStarted", generation });
    try {
      const projection = await api.createProjection(state.opened.workspace.id, artifactIndex, filter);
      dispatch({ type: "projectionReady", generation, projectionId: projection.projection_id });
      const page = await api.queryTimeline(state.opened.workspace.id, projection.projection_id, null, 2_000);
      segmentCache.current.set(`${state.opened.workspace.id}:${projection.projection_id}:first`, page);
      dispatch({ type: "timelinePageReceived", generation, page });
    } catch (error) {
      dispatch({ type: "failed", generation, error: normalizeAppError(error) });
    }
  };

  const selectArtifact = (artifactIndex: number) => {
    dispatch({ type: "artifactSelected", artifactIndex });
    void applyFilter(state.filter, artifactIndex);
  };

  const loadNextPage = async () => {
    if (paginationRequest.current || state.opened === null || state.projectionId === null) return;
    const cursor = state.timelinePages.at(-1)?.next_cursor ?? null;
    if (cursor === null) return;
    const cacheKey = `${state.opened.workspace.id}:${state.projectionId}:${cursor}`;
    if (requestedCursors.current.has(cacheKey)) return;
    requestedCursors.current.add(cacheKey);
    paginationRequest.current = true;
    const generation = state.generation;
    try {
      const cached = segmentCache.current.get(cacheKey);
      const page = cached ?? await api.queryTimeline(state.opened.workspace.id, state.projectionId, cursor, 2_000);
      if (cached === undefined) segmentCache.current.set(cacheKey, page);
      dispatch({ type: "timelinePageReceived", generation, page });
    } catch (error) {
      requestedCursors.current.delete(cacheKey);
      if (projectionGeneration.current === generation) setPaneErrors((values) => [...values, normalizeAppError(error)]);
    } finally {
      paginationRequest.current = false;
    }
  };

  const selectRow = (row: EventRowDto, recordHistory = true) => {
    if (state.opened === null || state.projectionId === null) return;
    const request = ++selectionRequest.current;
    const workspaceId = state.opened.workspace.id;
    setSelectedRow(row);
    setDetail(null); setRegisters(null); setMemory(null); setMemoryHistory([]); setCallTree(null); setAnnotation(null);
    setHiddenHistoryTarget(null);
    setPaneErrors([]);
    dispatch({ type: "selectionChanged", event: row.key });
    if (recordHistory) {
      navigation.current.push({ workspaceId, projectionId: state.projectionId, eventKey: row.key });
      setHistoryVersion((value) => value + 1);
    }
    const accept = (update: () => void) => { if (selectionRequest.current === request) update(); };
    const fail = (error: unknown) => accept(() => setPaneErrors((values) => [...values, normalizeAppError(error)]));
    const artifactIndex = state.selectedArtifactIndex;
    void api.getEventDetail(workspaceId, artifactIndex, row.source_row).then((value) => {
      accept(() => setDetail(value));
      if (value.memory_range !== null && selectionRequest.current === request) {
        void api.getMemoryState(workspaceId, artifactIndex, row.source_row, value.memory_range.start, value.memory_range.end_exclusive).then((result) => accept(() => setMemory(result)), fail);
        void api.getMemoryHistory(workspaceId, artifactIndex, row.source_row, value.memory_range.start, value.memory_range.end_exclusive).then((result) => accept(() => setMemoryHistory(result)), fail);
      }
    }, fail);
    void api.getRegisterState(workspaceId, artifactIndex, row.source_row).then((value) => accept(() => setRegisters(value)), fail);
    void api.getAnnotation(workspaceId, artifactIndex, row.source_row).then((value) => accept(() => setAnnotation(value)), fail);
    if (row.key.tid === null) setCallTree(null);
    else void api.getCallTree(workspaceId, artifactIndex, row.key.timeline_id, row.key.tid).then((value) => accept(() => setCallTree(value)), fail);
  };

  const jumpToRow = (sourceRow: number) => {
    const row = rows.find((value) => value.source_row === sourceRow);
    if (row !== undefined) selectRow(row);
  };

  const visitHistory = (entry: NavigationEntry | null) => {
    setHistoryVersion((value) => value + 1);
    if (entry === null) return;
    const row = rows.find((value) => sameKey(value.key, entry.eventKey));
    if (row === undefined) setHiddenHistoryTarget(entry);
    else selectRow(row, false);
  };

  const writeAnnotation = async (kind: "comment" | "highlight", value?: string) => {
    if (state.opened === null || selectedRow === null) return;
    const workspaceId = state.opened.workspace.id;
    if (kind === "comment") {
      if (value === undefined) await api.deleteAnnotation(workspaceId, state.selectedArtifactIndex, selectedRow.source_row);
      else await api.upsertAnnotation(workspaceId, state.selectedArtifactIndex, selectedRow.source_row, value);
      setAnnotation((current) => current === null ? { key: selectedRow.key, comment: value ?? "", highlight: null } : { ...current, comment: value ?? "" });
    } else {
      if (value === undefined) await api.deleteHighlight(workspaceId, state.selectedArtifactIndex, selectedRow.source_row);
      else await api.upsertHighlight(workspaceId, state.selectedArtifactIndex, selectedRow.source_row, value);
      setAnnotation((current) => current === null ? { key: selectedRow.key, comment: "", highlight: value ?? null } : { ...current, highlight: value ?? null });
    }
  };

  const selectTid = (tid: number) => void applyFilter({ ...state.filter, tids: [tid] });
  const reveal = () => { setHiddenHistoryTarget(null); void applyFilter(emptyFilter()); };
  const cancelJob = async (id: string) => {
    try { await api.cancelJob(id); dispatch({ type: "jobsReceived", jobs: await api.listJobs() }); }
    catch (error) { setPaneErrors((values) => [...values, normalizeAppError(error)]); }
  };

  return (
    <div className="app-shell">
      <AppHeader />
      <LeftDock tids={tids} selectedTid={selectedTid} callTree={callTree} onSelectTid={selectTid} onJump={jumpToRow} />
      <main className="workspace">
        {state.opened !== null && <FilterBar onApply={(filter) => void applyFilter(filter)} />}
        {state.phase === "failed" && state.error !== null ? (
          <section role="alert"><h1>{state.error.code}</h1><p>{state.error.detail}</p></section>
        ) : state.opened === null || state.projectionId === null ? (
          <SessionOverview opened={state.opened} selectedArtifactIndex={state.selectedArtifactIndex} onSelectArtifact={selectArtifact} />
        ) : (
          <VirtualTimeline rows={rows} totalRows={state.timelinePages.at(-1)?.total ?? rows.length} hasMore={state.timelinePages.at(-1)?.next_cursor !== null} workspaceId={state.opened.workspace.id} projectionId={state.projectionId} generation={state.generation} onLoadMore={() => void loadNextPage()} onSelect={selectRow} />
        )}
      </main>
      <RightDock row={selectedRow} detail={detail} registers={registers} memory={memory} history={memoryHistory} annotation={annotation} errors={paneErrors} workspaceId={state.opened?.workspace.id ?? null} completeness={state.opened?.artifacts.find((artifact) => artifact.index === state.selectedArtifactIndex)?.completeness ?? []} onSaveComment={(value) => writeAnnotation("comment", value)} onDeleteComment={() => writeAnnotation("comment")} onSaveHighlight={(value) => writeAnnotation("highlight", value)} onDeleteHighlight={() => writeAnnotation("highlight")} />
      <BottomDock pages={state.timelinePages} jobs={state.jobs} canGoBack={navigation.current.canGoBack} canGoForward={navigation.current.canGoForward} hiddenHistoryTarget={hiddenHistoryTarget !== null} onJump={jumpToRow} onCancel={(id) => void cancelJob(id)} onBack={() => visitHistory(navigation.current.back())} onForward={() => visitHistory(navigation.current.forward())} onReveal={reveal} />
    </div>
  );
}
