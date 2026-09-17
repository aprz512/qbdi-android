import type { AppError, EventFilterDto, EventKeyDto, JobDto, OpenWorkspaceDto, TimelinePageDto } from "../api/generated";
import { initialState, type AppState } from "./model";

export type Action =
  | { type: "openStarted" }
  | { type: "pickerCancelled" }
  | { type: "workspaceOpened"; opened: OpenWorkspaceDto }
  | { type: "indexingStarted"; generation: number }
  | { type: "projectionReady"; generation: number; projectionId: string }
  | { type: "timelinePageReceived"; generation: number; page: TimelinePageDto }
  | { type: "filterChanged"; filter: EventFilterDto }
  | { type: "selectionChanged"; event: EventKeyDto | null }
  | { type: "viewportChanged"; start: number; end: number }
  | { type: "jobsReceived"; jobs: JobDto[] }
  | { type: "failed"; error: AppError; generation?: number }
  | { type: "closed" };

const stale = (state: AppState, generation: number | undefined) =>
  generation !== undefined && generation < state.generation;

export function reducer(state: AppState, action: Action): AppState {
  if ("generation" in action && stale(state, action.generation)) return state;
  switch (action.type) {
    case "openStarted":
      return { ...initialState, phase: "opening", generation: state.generation + 1 };
    case "pickerCancelled":
      return state.phase === "opening" ? { ...initialState, generation: state.generation } : state;
    case "workspaceOpened":
      return {
        ...state,
        phase: action.opened.warnings.length > 0 ? "partial" : "ready",
        opened: action.opened,
        warnings: action.opened.warnings,
        error: null,
      };
    case "indexingStarted":
      return {
        ...state,
        phase: "indexing",
        generation: action.generation,
        timelinePages: [],
        projectionId: null,
      };
    case "projectionReady":
      return { ...state, phase: "ready", generation: action.generation, projectionId: action.projectionId };
    case "timelinePageReceived":
      return { ...state, timelinePages: [...state.timelinePages, action.page] };
    case "filterChanged":
      return {
        ...state,
        filter: action.filter,
        generation: state.generation + 1,
        projectionId: null,
        timelinePages: [],
      };
    case "selectionChanged":
      return { ...state, selectedEvent: action.event };
    case "viewportChanged":
      return { ...state, viewport: { start: action.start, end: action.end } };
    case "jobsReceived":
      return { ...state, jobs: action.jobs };
    case "failed":
      return { ...state, phase: "failed", error: action.error };
    case "closed":
      return { ...initialState, generation: state.generation + 1 };
  }
}
