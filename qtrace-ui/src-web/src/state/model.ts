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
export const emptyFilter = (): EventFilterDto => ({
  tids: [], kinds: [], modules: [], relative_pc: [], absolute_pc: [], sequence: [], mnemonic: [],
  register_reads: [], register_writes: [], memory: [], semantic_categories: [], semantic_names: [],
  semantic_detail_contains: [],
});

export interface AppState {
  phase: WorkspacePhase;
  generation: number;
  opened: OpenWorkspaceDto | null;
  selectedArtifactIndex: number;
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
  selectedArtifactIndex: 0,
  projectionId: null,
  filter: emptyFilter(),
  timelinePages: [],
  selectedEvent: null,
  viewport: { start: 0, end: 0 },
  panels: { left: true, right: true, bottom: true },
  warnings: [],
  jobs: [],
  error: null,
};
