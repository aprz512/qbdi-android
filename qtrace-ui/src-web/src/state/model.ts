import type {
  AppError,
  EventFilterDto,
  EventKeyDto,
  JobDto,
  OpenWorkspaceDto,
  ProjectionId,
  TimelinePageDto,
} from "../api/generated";

export type WorkspacePhase = "empty" | "opening" | "indexing" | "ready" | "partial" | "failed";

export interface AppState {
  phase: WorkspacePhase;
  generation: number;
  opened: OpenWorkspaceDto | null;
  projectionId: ProjectionId | null;
  filter: EventFilterDto;
  timelinePages: TimelinePageDto[];
  selectedEvent: EventKeyDto | null;
  viewport: { start: number; end: number };
  panels: { left: boolean; right: boolean; bottom: boolean };
  warnings: string[];
  jobs: JobDto[];
  error: AppError | null;
}

export const initialState: AppState = {
  phase: "empty",
  generation: 0,
  opened: null,
  projectionId: null,
  filter: { tids: [], kinds: [] },
  timelinePages: [],
  selectedEvent: null,
  viewport: { start: 0, end: 0 },
  panels: { left: true, right: true, bottom: true },
  warnings: [],
  jobs: [],
  error: null,
};
