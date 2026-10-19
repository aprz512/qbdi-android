import { useEffect, useMemo, useRef, useState } from "react";
import { useQtraceApi } from "../api/ApiContext";
import type { EventFilterDto, EventKeyDto, EventRowDto } from "../api/generated";
import { normalizeAppError } from "../api/TauriQtraceApi";
import { isTimelineCancelled, TimelinePages, type TimelineSegment } from "../timeline/TimelinePages";
import { useAppDispatch, useAppState } from "./AppStateProvider";
import { emptyFilter } from "./model";
import { NavigationHistory, type NavigationEntry } from "./navigation";
import type { SelectionContext, useEventDetails } from "./useEventDetails";
import type { RequestGuard } from "./RequestScope";
import { useRequestScope } from "./useRequestScope";

const sameKey = (left: EventKeyDto, right: EventKeyDto) =>
  left.artifact_sha256 === right.artifact_sha256 && left.timeline_id === right.timeline_id && left.record_ordinal === right.record_ordinal;

export function useTimelineNavigation(details: ReturnType<typeof useEventDetails>) {
  const state = useAppState();
  const api = useQtraceApi();
  const dispatch = useAppDispatch();
  const requests = useRequestScope(state.opened?.workspace.id ?? null);
  const latestDetails = useRef(details);
  latestDetails.current = details;
  const { reset: resetDetails } = details;
  const [visibleSegments, setVisibleSegments] = useState<TimelineSegment[]>([]);
  const latestSegments = useRef(visibleSegments);
  latestSegments.current = visibleSegments;
  const latestProjection = useRef({ workspaceId: state.opened?.workspace.id, projectionId: state.projectionId, generation: state.generation });
  latestProjection.current = { workspaceId: state.opened?.workspace.id, projectionId: state.projectionId, generation: state.generation };
  const [, setHistoryVersion] = useState(0);
  const [hiddenHistoryTarget, setHiddenHistoryTarget] = useState<NavigationEntry | null>(null);
  const projectionGeneration = useRef(0);
  const timelinePages = useRef<TimelinePages | null>(null);
  const navigation = useRef(new NavigationHistory());
  const navigationWorkspace = useRef<string | null>(null);
  const pendingHistoryTarget = useRef<NavigationEntry | null>(null);
  const rows = useMemo(() => visibleSegments.flatMap((segment) => segment.page.rows), [visibleSegments]);

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
      resetDetails(); setVisibleSegments([]);
    }
  }, [state.opened, resetDetails]);

  useEffect(() => {
    if (state.generation > projectionGeneration.current) requests.invalidate();
    projectionGeneration.current = Math.max(projectionGeneration.current, state.generation);
    const pages = timelinePages.current;
    if (pages !== null && (pages.identity.workspaceId !== state.opened?.workspace.id || pages.identity.generation < state.generation)) {
      pages.dispose();
      timelinePages.current = null;
    }
  }, [requests, state.generation, state.opened?.workspace.id]);
  useEffect(() => () => timelinePages.current?.dispose(), []);

  const pagesFor = (workspaceId: string, projectionId: string, generation: number) => {
    const identity = { workspaceId, projectionId, generation };
    if (!timelinePages.current?.matches(identity)) {
      timelinePages.current?.dispose();
      timelinePages.current = new TimelinePages(api, identity, { maxSegments: import.meta.env.MODE === "e2e" ? 4 : 128 });
    }
    return timelinePages.current;
  };

  const waitForJob = async (jobId: string, request: RequestGuard) => {
    while (request.isCurrent()) {
      const jobs = await api.listJobs();
      if (!request.isCurrent()) return;
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
    const request = requests.next();
    const generation = Math.max(projectionGeneration.current, state.generation) + 1;
    projectionGeneration.current = generation;
    timelinePages.current?.dispose();
    timelinePages.current = null;
    resetDetails(); setVisibleSegments([]);
    dispatch({ type: "filterChanged", filter });
    dispatch({ type: "indexingStarted", generation });
    try {
      const projection = await api.createProjection(state.opened.workspace.id, artifactIndex, filter);
      if (!request.isCurrent()) return;
      await waitForJob(projection.job_id, request);
      if (!request.isCurrent()) return;
      dispatch({ type: "projectionReady", generation, projectionId: projection.projection_id });
      const pages = pagesFor(state.opened.workspace.id, projection.projection_id, generation);
      const segments = await pages.first();
      if (!request.isCurrent()) return;
      const page = segments[0].page;
      setVisibleSegments(segments);
      dispatch({ type: "timelinePageReceived", generation, page });
      const pending = pendingHistoryTarget.current;
      if (pending !== null && pending.artifactIndex === artifactIndex) {
        let targetPage = page;
        let targetSegments = segments;
        let target = targetPage.rows.find((row) => sameKey(row.key, pending.eventKey));
        if (target === undefined) {
          const located = await pages.locate(pending.sourceRow);
          if (!request.isCurrent()) return;
          if (located.length > 0) {
            targetSegments = located;
            targetPage = located[0].page;
            target = targetPage.rows.find((row) => sameKey(row.key, pending.eventKey));
          }
        }
        if (target !== undefined) {
          setVisibleSegments(targetSegments);
          dispatch({ type: "timelinePageReceived", generation, page: targetPage });
          pendingHistoryTarget.current = null;
          setHiddenHistoryTarget(null);
          selectRow(target, false, artifactIndex, { workspaceId: state.opened.workspace.id, projectionId: projection.projection_id, generation });
        }
      }
    } catch (error) {
      if (!isTimelineCancelled(error) && request.isCurrent()) {
        dispatch({ type: "failed", generation, error: normalizeAppError(error) });
      }
    }
  };

  const selectArtifact = (artifactIndex: number) => {
    dispatch({ type: "artifactSelected", artifactIndex });
    void applyFilter(state.filter, artifactIndex);
  };

  const loadPage = async (requestTarget: { direction: "next" | "previous" } | { start: number; end: number }, signal?: AbortSignal) => {
    if (state.opened === null || state.projectionId === null || visibleSegments.length === 0 || state.generation !== projectionGeneration.current) return;
    const first = visibleSegments[0];
    const last = visibleSegments[visibleSegments.length - 1];
    if ("start" in requestTarget && requestTarget.start >= first.start && requestTarget.end <= last.start + last.page.rows.length) return;
    const generation = projectionGeneration.current;
    const request = requests.capture();
    const pages = pagesFor(state.opened.workspace.id, state.projectionId, generation);
    try {
      const segments = "direction" in requestTarget
        ? await (requestTarget.direction === "next" ? pages.next(last, signal) : pages.previous(first, signal))
        : await pages.range(requestTarget.start, requestTarget.end, signal);
      if (!request.isCurrent(signal) || segments.length === 0) return;
      const current = segments[segments.length - 1];
      const page = current.page;
      setVisibleSegments(segments);
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
      return current.start;
    } catch (error) {
      if (!isTimelineCancelled(error) && request.isCurrent(signal)) latestDetails.current.addError(error);
    }
  };

  const loadNextPage = () => loadPage({ direction: "next" });
  const loadPreviousPage = () => loadPage({ direction: "previous" });

  const refreshSymbols = async () => {
    const current = latestProjection.current;
    if (state.opened === null || state.projectionId === null || current.workspaceId !== state.opened.workspace.id ||
      current.projectionId !== state.projectionId || current.generation !== state.generation) return;
    const request = requests.capture();
    const segments = latestSegments.current;
    if (!request.isCurrent() || segments.length === 0) return;
    timelinePages.current?.dispose();
    timelinePages.current = null;
    const pages = pagesFor(state.opened.workspace.id, state.projectionId, state.generation);
    try {
      const refreshed = await pages.range(segments[0].start, segments.at(-1)!.start + segments.at(-1)!.page.rows.length);
      if (!request.isCurrent() || refreshed.length === 0) return;
      setVisibleSegments(refreshed);
      dispatch({ type: "timelinePageReceived", generation: state.generation, page: refreshed.at(-1)!.page });
    } catch (error) {
      if (!isTimelineCancelled(error) && request.isCurrent()) latestDetails.current.addError(error);
    }
  };

  const selectRow = (row: EventRowDto, recordHistory = true, artifactIndex = state.selectedArtifactIndex, context?: SelectionContext) => {
    if (context === undefined && (state.opened === null || state.projectionId === null)) return;
    const selected = latestDetails.current.select(row, artifactIndex, context);
    if (selected === null) return;
    setHiddenHistoryTarget(null);
    if (recordHistory) {
      navigation.current.push({ workspaceId: selected.workspaceId, projectionId: selected.projectionId, artifactIndex, sourceRow: row.source_row, eventKey: row.key });
      setHistoryVersion((value) => value + 1);
    }
  };

  const jumpToRow = async (sourceRow: number) => {
    const row = rows.find((value) => value.source_row === sourceRow);
    if (row !== undefined) {
      selectRow(row);
      return;
    }
    if (state.opened === null || state.projectionId === null || state.generation !== projectionGeneration.current) return;

    const request = requests.capture();
    const selection = latestDetails.current.reserveSelection();
    const generation = projectionGeneration.current;
    const pages = pagesFor(state.opened.workspace.id, state.projectionId, generation);
    try {
      const segments = await pages.locate(sourceRow);
      if (!selection.isCurrent() || !request.isCurrent()) return;
      if (segments.length === 0) throw new Error(`Event row ${sourceRow} is not visible in the current projection`);
      const page = segments[0].page;
      const target = page.rows.find((value) => value.source_row === sourceRow);
      if (target === undefined) throw new Error("Located timeline page does not contain the requested event");
      setVisibleSegments(segments);
      dispatch({ type: "timelinePageReceived", generation, page });
      selectRow(target);
    } catch (error) {
      if (!isTimelineCancelled(error) && selection.isCurrent() && request.isCurrent()) {
        latestDetails.current.addError(error);
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

  return {
    rows, visibleSegments, hiddenHistoryTarget, applyFilter, selectArtifact, selectTid,
    loadPage, loadNextPage, loadPreviousPage, selectRow, jumpToRow, reveal, refreshSymbols,
    canGoBack: navigation.current.canGoBack, canGoForward: navigation.current.canGoForward,
    goBack: () => visitHistory(navigation.current.back()),
    goForward: () => visitHistory(navigation.current.forward()),
  };
}
