import type {
  AnnotationDto,
  CallTreeDto,
  EventDetailDto,
  EventFilterDto,
  JobDto,
  LocalSymbolNameDto,
  MemoryEvidenceDto,
  MemoryStateDto,
  OpenWorkspaceDto,
  ProjectionJobDto,
  RegisterStateDto,
  SymbolDto,
  TimelineLocationDto,
  TimelinePageDto,
  WorkspaceSummaryDto,
} from "./generated";

export interface QtraceApi {
  pickAndOpenSession(): Promise<OpenWorkspaceDto | null>;
  pickAndOpenArtifact(): Promise<OpenWorkspaceDto | null>;
  closeWorkspace(workspaceId: string): Promise<void>;
  getWorkspaceSummary(workspaceId: string): Promise<WorkspaceSummaryDto>;
  createProjection(
    workspaceId: string,
    artifactIndex: number,
    filter: EventFilterDto,
  ): Promise<ProjectionJobDto>;
  queryTimeline(
    workspaceId: string,
    projectionId: string,
    cursor: string | null,
    limit: number,
  ): Promise<TimelinePageDto>;
  locateTimeline(
    workspaceId: string,
    projectionId: string,
    sourceRow: number,
    limit: number,
  ): Promise<TimelineLocationDto | null>;
  locateTimelineOffset(
    workspaceId: string,
    projectionId: string,
    offset: number,
    limit: number,
  ): Promise<TimelineLocationDto | null>;
  getEventDetail(workspaceId: string, artifactIndex: number, row: number): Promise<EventDetailDto>;
  getRegisterState(workspaceId: string, artifactIndex: number, row: number): Promise<RegisterStateDto>;
  getMemoryState(
    workspaceId: string,
    artifactIndex: number,
    row: number,
    start: string,
    endExclusive: string,
  ): Promise<MemoryStateDto>;
  getMemoryHistory(
    workspaceId: string,
    artifactIndex: number,
    row: number,
    start: string,
    endExclusive: string,
  ): Promise<MemoryEvidenceDto[]>;
  getCallTree(
    workspaceId: string,
    artifactIndex: number,
    timelineId: string,
    tid: number,
  ): Promise<CallTreeDto>;
  pickAndAttachElf(
    workspaceId: string,
    moduleName: string,
    moduleDigest: string,
    expectedBuildId: number[] | null,
  ): Promise<void | null>;
  listSymbols(workspaceId: string, moduleName: string, relativePcs: string[]): Promise<SymbolDto[]>;
  getAnnotation(workspaceId: string, artifactIndex: number, row: number): Promise<AnnotationDto | null>;
  upsertAnnotation(
    workspaceId: string,
    artifactIndex: number,
    row: number,
    comment: string,
  ): Promise<void>;
  deleteAnnotation(workspaceId: string, artifactIndex: number, row: number): Promise<void>;
  upsertHighlight(workspaceId: string, artifactIndex: number, row: number, value: string): Promise<void>;
  deleteHighlight(workspaceId: string, artifactIndex: number, row: number): Promise<void>;
  getLocalSymbolName(workspaceId: string, artifactIndex: number, moduleDigest: string, relativePc: string): Promise<LocalSymbolNameDto | null>;
  upsertLocalSymbolName(workspaceId: string, artifactIndex: number, moduleDigest: string, relativePc: string, name: string): Promise<void>;
  deleteLocalSymbolName(workspaceId: string, artifactIndex: number, moduleDigest: string, relativePc: string): Promise<void>;
  listJobs(): Promise<JobDto[]>;
  cancelJob(jobId: string): Promise<void>;
}
