import { useEffect, useMemo, useRef, useState } from "react";
import { useQtraceApi } from "./api/ApiContext";
import type { AnnotationDto, AppError, CallTreeDto, EventDetailDto, EventFilterDto, EventKeyDto, EventRowDto, MemoryEvidenceDto, MemoryStateDto, RegisterStateDto, TimelinePageDto } from "./api/generated";
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
  const [visibleSegments, setVisibleSegments] = useState<Array<{ start: number; page: Awaited<ReturnType<typeof api.queryTimeline>> }>>([]);
  const [paneErrors, setPaneErrors] = useState<AppError[]>([]);
  const [, setHistoryVersion] = useState(0);
  const [hiddenHistoryTarget, setHiddenHistoryTarget] = useState<NavigationEntry | null>(null);
  const selectionRequest = useRef(0);
  const projectionGeneration = useRef(0);
  const pageCursors = useRef<Array<string | null>>([null]);
  const pageStarts = useRef([0]);
  const pageIndex = useRef(0);
  const segmentCache = useRef(new SegmentCache<Awaited<ReturnType<typeof api.queryTimeline>>>({ maxSegments: import.meta.env.MODE === "e2e" ? 4 : 128 }));
  const navigation = useRef(new NavigationHistory());
  const navigationWorkspace = useRef<string | null>(null);
  const pendingHistoryTarget = useRef<NavigationEntry | null>(null);
  const rows = useMemo(() => visibleSegments.flatMap((segment) => segment.page.rows), [visibleSegments]);
  const tids = useMemo(
    () => state.opened?.artifacts.find((artifact) => artifact.index === state.selectedArtifactIndex)?.tids ?? [],
    [state.opened, state.selectedArtifactIndex],
  );
  const selectedTid = selectedRow?.key.tid ?? state.filter.tids[0] ?? null;

  useEffect(() => {
    const workspaceId = state.opened?.workspace.id ?? null;
    if (workspaceId !== navigationWorkspace.current) {
      navigationWorkspace.current = workspaceId;
      navigation.current = new NavigationHistory();
      pendingHistoryTarget.current = null;
      setHiddenHistoryTarget(null);
      setHistoryVersion((value) => value + 1);
    }
    if (state.opened === null) {
      selectionRequest.current += 1;
      setSelectedRow(null); setDetail(null); setRegisters(null); setMemory(null);
      setMemoryHistory([]); setCallTree(null); setAnnotation(null); setPaneErrors([]); setVisibleSegments([]);
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

  const waitForJob = async (jobId: string, generation: number) => {
    while (projectionGeneration.current === generation) {
      const jobs = await api.listJobs();
      dispatch({ type: "jobsReceived", jobs });
      const job = jobs.find((value) => value.id === jobId);
      if (job?.state === "completed") return;
      if (job?.state === "failed") throw job.error ?? new Error("Projection job failed");
      if (job?.state === "cancelled") throw job.error ?? new Error("Projection job was cancelled");
      await new Promise((resolve) => window.setTimeout(resolve, 25));
    }
  };

  const applyFilter = async (filter: EventFilterDto, artifactIndex = state.selectedArtifactIndex) => {
    if (state.opened === null) return;
    const generation = Math.max(projectionGeneration.current, state.generation) + 1;
    projectionGeneration.current = generation;
    selectionRequest.current += 1;
    setSelectedRow(null); setDetail(null); setRegisters(null); setMemory(null);
    setMemoryHistory([]); setCallTree(null); setAnnotation(null); setPaneErrors([]); setVisibleSegments([]);
    dispatch({ type: "filterChanged", filter });
    dispatch({ type: "indexingStarted", generation });
    try {
      const projection = await api.createProjection(state.opened.workspace.id, artifactIndex, filter);
      if (projectionGeneration.current !== generation) return;
      await waitForJob(projection.job_id, generation);
      if (projectionGeneration.current !== generation) return;
      dispatch({ type: "projectionReady", generation, projectionId: projection.projection_id });
      const page = await api.queryTimeline(state.opened.workspace.id, projection.projection_id, null, 2_000);
      if (projectionGeneration.current !== generation) return;
      pageCursors.current = [null];
      pageStarts.current = [0];
      pageIndex.current = 0;
      segmentCache.current.set(`${state.opened.workspace.id}:${projection.projection_id}:first`, page);
      setVisibleSegments([{ start: 0, page }]);
      dispatch({ type: "timelinePageReceived", generation, page });
      const pending = pendingHistoryTarget.current;
      if (pending !== null && pending.artifactIndex === artifactIndex) {
        let targetPage = page;
        let targetIndex = 0;
        let targetStart = 0;
        let target = targetPage.rows.find((row) => sameKey(row.key, pending.eventKey));
        if (target === undefined) {
          const location = await api.locateTimeline(state.opened.workspace.id, projection.projection_id, pending.sourceRow, 2_000);
          if (projectionGeneration.current !== generation) return;
          if (location !== null) {
            const cacheKey = location.cursor === null
              ? `${state.opened.workspace.id}:${projection.projection_id}:first`
              : `${state.opened.workspace.id}:${projection.projection_id}:${location.cursor}`;
            const cached = segmentCache.current.get(cacheKey);
            targetPage = cached ?? await api.queryTimeline(state.opened.workspace.id, projection.projection_id, location.cursor, 2_000);
            if (projectionGeneration.current !== generation) return;
            if (cached === undefined) segmentCache.current.set(cacheKey, targetPage);
            targetIndex = Math.floor(location.start / 2_000);
            targetStart = location.start;
            pageCursors.current[targetIndex] = location.cursor;
            pageStarts.current[targetIndex] = targetStart;
            target = targetPage.rows.find((row) => sameKey(row.key, pending.eventKey));
          }
        }
        if (target !== undefined) {
          pageIndex.current = targetIndex;
          setVisibleSegments([{ start: targetStart, page: targetPage }]);
          dispatch({ type: "timelinePageReceived", generation, page: targetPage });
          pendingHistoryTarget.current = null;
          setHiddenHistoryTarget(null);
          selectRow(target, false, artifactIndex);
        }
      }
    } catch (error) {
      if (projectionGeneration.current === generation) {
        dispatch({ type: "failed", generation, error: normalizeAppError(error) });
      }
    }
  };

  const selectArtifact = (artifactIndex: number) => {
    dispatch({ type: "artifactSelected", artifactIndex });
    void applyFilter(state.filter, artifactIndex);
  };

  const loadPage = async (requestTarget: { index?: number; start?: number; end?: number }, signal?: AbortSignal) => {
    if ((requestTarget.index !== undefined && requestTarget.index < 0) || state.opened === null || state.projectionId === null || state.timelinePages.length === 0) return;
    const workspaceId = state.opened.workspace.id;
    const projectionId = state.projectionId;
    const generation = projectionGeneration.current;
    try {
      let currentIndex = pageIndex.current;
      let currentStart = pageStarts.current[currentIndex] ?? 0;
      let page = state.timelinePages[0];
      const targetOffset = requestTarget.end === undefined ? undefined : Math.max(requestTarget.start ?? 0, requestTarget.end - 1);
      if (targetOffset !== undefined && (requestTarget.start ?? targetOffset) >= currentStart && targetOffset < currentStart + page.rows.length) return;
      if (targetOffset !== undefined) {
        const rangeStart = requestTarget.start ?? targetOffset;
        let knownIndex = -1;
        for (let index = 0; index < pageStarts.current.length; index += 1) {
          const knownStart = pageStarts.current[index];
          if (knownStart !== undefined && knownStart <= rangeStart && rangeStart < knownStart + 2_000) knownIndex = index;
        }
        if (knownIndex >= 0) {
          currentIndex = knownIndex;
          currentStart = pageStarts.current[currentIndex] ?? 0;
          const cursor = pageCursors.current[currentIndex];
          if (cursor === undefined) return;
          const cacheKey = cursor === null ? `${workspaceId}:${projectionId}:first` : `${workspaceId}:${projectionId}:${cursor}`;
          const cached = segmentCache.current.get(cacheKey);
          page = cached ?? await api.queryTimeline(workspaceId, projectionId, cursor, 2_000);
          if (signal?.aborted || projectionGeneration.current !== generation) return;
          if (cached === undefined) segmentCache.current.set(cacheKey, page);
        } else {
          const location = await api.locateTimelineOffset(workspaceId, projectionId, rangeStart, 2_000);
          if (signal?.aborted || projectionGeneration.current !== generation || location === null) return;
          const cursor = location.cursor;
          const cacheKey = cursor === null ? `${workspaceId}:${projectionId}:first` : `${workspaceId}:${projectionId}:${cursor}`;
          const cached = segmentCache.current.get(cacheKey);
          page = cached ?? await api.queryTimeline(workspaceId, projectionId, cursor, 2_000);
          if (signal?.aborted || projectionGeneration.current !== generation) return;
          if (cached === undefined) segmentCache.current.set(cacheKey, page);
          currentIndex = Math.floor(location.start / 2_000);
          currentStart = location.start;
          pageCursors.current[currentIndex] = cursor;
          pageStarts.current[currentIndex] = currentStart;
        }
      } else if (requestTarget.index !== undefined) {
        currentIndex = Math.min(currentIndex, requestTarget.index);
      }
      if (currentIndex !== pageIndex.current) {
        const cursor = pageCursors.current[currentIndex];
        if (cursor === undefined) return;
        const cacheKey = cursor === null ? `${workspaceId}:${projectionId}:first` : `${workspaceId}:${projectionId}:${cursor}`;
        const cached = segmentCache.current.get(cacheKey);
        page = cached ?? await api.queryTimeline(workspaceId, projectionId, cursor, 2_000);
        if (signal?.aborted || projectionGeneration.current !== generation) return;
        if (cached === undefined) segmentCache.current.set(cacheKey, page);
        currentStart = pageStarts.current[currentIndex] ?? 0;
      }
      const visited = new Set<string>();
      const needsNext = () => requestTarget.index !== undefined
        ? currentIndex < requestTarget.index
        : targetOffset !== undefined && targetOffset >= currentStart + page.rows.length;
      while (needsNext() && page.next_cursor !== null) {
          const cursor = page.next_cursor;
          if (visited.has(cursor)) throw new Error("Timeline cursor cycle detected");
          visited.add(cursor);
          const cacheKey = `${workspaceId}:${projectionId}:${cursor}`;
          const cached = segmentCache.current.get(cacheKey);
          const next = cached ?? await api.queryTimeline(workspaceId, projectionId, cursor, 2_000);
          if (signal?.aborted || projectionGeneration.current !== generation) return;
          if (cached === undefined) segmentCache.current.set(cacheKey, next);
          currentStart += page.rows.length;
          page = next;
          currentIndex += 1;
          pageCursors.current[currentIndex] = cursor;
          pageStarts.current[currentIndex] = currentStart;
      }
      if (signal?.aborted || projectionGeneration.current !== generation) return;
      pageIndex.current = currentIndex;
      if (requestTarget.start !== undefined && requestTarget.end !== undefined) {
        let firstIndex = 0;
        for (let index = 0; index < pageStarts.current.length; index += 1) {
          if (pageStarts.current[index] <= requestTarget.start) firstIndex = index;
        }
        const segments: Array<{ start: number; page: Awaited<ReturnType<typeof api.queryTimeline>> }> = [];
        for (let index = firstIndex; index <= currentIndex; index += 1) {
          const cursor = pageCursors.current[index];
          if (cursor === undefined) continue;
          const cacheKey = cursor === null ? `${workspaceId}:${projectionId}:first` : `${workspaceId}:${projectionId}:${cursor}`;
          const segmentPage = index === currentIndex ? page : segmentCache.current.get(cacheKey) ?? await api.queryTimeline(workspaceId, projectionId, cursor, 2_000);
          if (signal?.aborted || projectionGeneration.current !== generation) return;
          segmentCache.current.set(cacheKey, segmentPage);
          segments.push({ start: pageStarts.current[index] ?? 0, page: segmentPage });
        }
        setVisibleSegments(segments);
      } else {
        setVisibleSegments([{ start: currentStart, page }]);
      }
      dispatch({ type: "timelinePageReceived", generation, page });
      const pending = pendingHistoryTarget.current;
      const target = pending?.artifactIndex === state.selectedArtifactIndex
        ? page.rows.find((row) => sameKey(row.key, pending.eventKey))
        : undefined;
      if (target !== undefined) {
        pendingHistoryTarget.current = null;
        setHiddenHistoryTarget(null);
        selectRow(target, false, state.selectedArtifactIndex);
      }
    } catch (error) {
      if (!signal?.aborted && projectionGeneration.current === generation) setPaneErrors((values) => [...values, normalizeAppError(error)]);
    }
  };

  const loadNextPage = async () => { await loadPage({ index: pageIndex.current + 1 }); return pageStarts.current[pageIndex.current] ?? 0; };
  const loadPreviousPage = async () => { await loadPage({ index: pageIndex.current - 1 }); return pageStarts.current[pageIndex.current] ?? 0; };

  const selectRow = (row: EventRowDto, recordHistory = true, artifactIndex = state.selectedArtifactIndex) => {
    if (state.opened === null || state.projectionId === null) return;
    const request = ++selectionRequest.current;
    const workspaceId = state.opened.workspace.id;
    setSelectedRow(row);
    setDetail(null); setRegisters(null); setMemory(null); setMemoryHistory([]); setCallTree(null); setAnnotation(null);
    setHiddenHistoryTarget(null);
    setPaneErrors([]);
    dispatch({ type: "selectionChanged", event: row.key });
    if (recordHistory) {
      navigation.current.push({ workspaceId, projectionId: state.projectionId, artifactIndex, sourceRow: row.source_row, eventKey: row.key });
      setHistoryVersion((value) => value + 1);
    }
    const accept = (update: () => void) => { if (selectionRequest.current === request) update(); };
    const fail = (error: unknown) => accept(() => setPaneErrors((values) => [...values, normalizeAppError(error)]));
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

  const jumpToRow = async (sourceRow: number) => {
    const row = rows.find((value) => value.source_row === sourceRow);
    if (row !== undefined) {
      selectRow(row);
      return;
    }
    if (state.opened === null || state.projectionId === null) return;

    const request = ++selectionRequest.current;
    const workspaceId = state.opened.workspace.id;
    const projectionId = state.projectionId;
    const generation = projectionGeneration.current;
    try {
      const location = await api.locateTimeline(workspaceId, projectionId, sourceRow, 2_000);
      if (selectionRequest.current !== request || projectionGeneration.current !== generation) return;
      if (location === null) throw new Error(`Event row ${sourceRow} is not visible in the current projection`);
      const cacheKey = location.cursor === null
        ? `${workspaceId}:${projectionId}:first`
        : `${workspaceId}:${projectionId}:${location.cursor}`;
      const cached = segmentCache.current.get(cacheKey);
      const page: TimelinePageDto = cached ?? await api.queryTimeline(workspaceId, projectionId, location.cursor, 2_000);
      if (selectionRequest.current !== request || projectionGeneration.current !== generation) return;
      if (cached === undefined) segmentCache.current.set(cacheKey, page);
      const target = page.rows.find((value) => value.source_row === sourceRow);
      if (target === undefined) throw new Error("Located timeline page does not contain the requested event");
      const index = Math.floor(location.start / 2_000);
      pageCursors.current[index] = location.cursor;
      pageStarts.current[index] = location.start;
      pageIndex.current = index;
      setVisibleSegments([{ start: location.start, page }]);
      dispatch({ type: "timelinePageReceived", generation, page });
      selectRow(target);
    } catch (error) {
      if (selectionRequest.current === request && projectionGeneration.current === generation) {
        setPaneErrors((values) => [...values, normalizeAppError(error)]);
      }
    }
  };

  const visitHistory = (entry: NavigationEntry | null) => {
    setHistoryVersion((value) => value + 1);
    if (entry === null) return;
    const row = entry.artifactIndex === state.selectedArtifactIndex ? rows.find((value) => sameKey(value.key, entry.eventKey)) : undefined;
    if (row === undefined) {
      pendingHistoryTarget.current = entry;
      setHiddenHistoryTarget(entry);
    }
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
  const reveal = () => {
    const target = hiddenHistoryTarget;
    if (target === null) return;
    pendingHistoryTarget.current = target;
    if (target.artifactIndex !== state.selectedArtifactIndex) {
      dispatch({ type: "artifactSelected", artifactIndex: target.artifactIndex });
    }
    void applyFilter(emptyFilter(), target.artifactIndex);
  };
  const cancelJob = async (id: string) => {
    try { await api.cancelJob(id); dispatch({ type: "jobsReceived", jobs: await api.listJobs() }); }
    catch (error) { setPaneErrors((values) => [...values, normalizeAppError(error)]); }
  };

  return (
    <div className="app-shell">
      <AppHeader />
      <LeftDock workspaceId={state.opened?.workspace.id ?? null} tids={tids} selectedTid={selectedTid} callTree={callTree} onSelectTid={selectTid} onJump={jumpToRow}
        onLoadCallTreePage={(parent, offset, identity) => {
          if (state.opened === null || callTree === null) return Promise.reject(new Error("Call tree closed"));
          return api.getCallTree(state.opened.workspace.id, callTree.artifact_index, callTree.timeline_id, callTree.tid, parent, offset, identity);
        }} />
      <main className="workspace">
        {state.opened !== null && <FilterBar filter={state.filter} onApply={(filter) => void applyFilter(filter)} />}
        {state.opened !== null && state.projectionId !== null && <nav aria-label="Artifacts" className="artifact-selector">{state.opened.artifacts.map((artifact) => <button key={artifact.index} aria-pressed={artifact.index === state.selectedArtifactIndex} onClick={() => selectArtifact(artifact.index)}>{artifact.name}</button>)}</nav>}
        {state.phase === "failed" && state.error !== null ? (
          <section role="alert"><h1>{state.error.code}</h1><p>{state.error.detail}</p></section>
        ) : state.opened === null || state.projectionId === null ? (
          <SessionOverview opened={state.opened} selectedArtifactIndex={state.selectedArtifactIndex} onSelectArtifact={selectArtifact} />
        ) : (
          <VirtualTimeline rows={rows} pageStart={visibleSegments[0]?.start ?? 0} totalRows={state.timelinePages.at(-1)?.total ?? rows.length} hasMore={visibleSegments.at(-1)?.page.next_cursor !== null} hasPrevious={(visibleSegments[0]?.start ?? 0) > 0} workspaceId={state.opened.workspace.id} projectionId={state.projectionId} generation={state.generation} onRequestRange={(start, end, signal) => loadPage({ start, end }, signal)} onLoadMore={loadNextPage} onLoadPrevious={loadPreviousPage} onSelect={selectRow} />
        )}
      </main>
      <RightDock row={selectedRow} detail={detail} registers={registers} memory={memory} history={memoryHistory} annotation={annotation} errors={paneErrors} workspaceId={state.opened?.workspace.id ?? null} artifactIndex={state.selectedArtifactIndex} completeness={state.opened?.artifacts.find((artifact) => artifact.index === state.selectedArtifactIndex)?.completeness ?? []} onSaveComment={(value) => writeAnnotation("comment", value)} onDeleteComment={() => writeAnnotation("comment")} onSaveHighlight={(value) => writeAnnotation("highlight", value)} onDeleteHighlight={() => writeAnnotation("highlight")} />
      <BottomDock initialResultsPage={state.timelinePages[0] ?? null} workspaceId={state.opened?.workspace.id ?? null} projectionId={state.projectionId} generation={state.generation} jobs={state.jobs} canGoBack={navigation.current.canGoBack} canGoForward={navigation.current.canGoForward} hiddenHistoryTarget={hiddenHistoryTarget !== null} onJump={jumpToRow} onCancel={(id) => void cancelJob(id)} onBack={() => visitHistory(navigation.current.back())} onForward={() => visitHistory(navigation.current.forward())} onReveal={reveal} />
    </div>
  );
}
