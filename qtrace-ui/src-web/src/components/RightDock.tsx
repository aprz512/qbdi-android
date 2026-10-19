import type { AnnotationDto, AppError, CompletenessRangeDto, EventDetailDto, EventRowDto, MemoryEvidenceDto, MemoryStateDto, RegisterStateDto } from "../api/generated";
import { AnnotationEditor } from "./AnnotationEditor";
import { CompletenessPane } from "./CompletenessPane";
import { EventDetailPane } from "./EventDetailPane";
import { MemoryPane } from "./MemoryPane";
import { RegisterPane } from "./RegisterPane";
import { SymbolPane } from "./SymbolPane";

interface RightDockProps {
  selectionRevision?: number;
  row: EventRowDto | null;
  detail: EventDetailDto | null;
  registers: RegisterStateDto | null;
  memory: MemoryStateDto | null;
  history: MemoryEvidenceDto[];
  annotation: AnnotationDto | null;
  errors: AppError[];
  workspaceId: string | null;
  artifactIndex: number;
  completeness: CompletenessRangeDto[];
  onSaveComment(value: string): Promise<void>;
  onDeleteComment(): Promise<void>;
  onSaveHighlight(value: string): Promise<void>;
  onDeleteHighlight(): Promise<void>;
  onSymbolsChanged?(): Promise<void>;
}

export function RightDock({ row, selectionRevision, detail, registers, memory, history, annotation, errors, workspaceId, artifactIndex, completeness, onSaveComment, onDeleteComment, onSaveHighlight, onDeleteHighlight, onSymbolsChanged }: RightDockProps) {
  return <aside id="details-panel" tabIndex={-1} className="right-dock" aria-label="Event details"><h2>Details</h2><EventDetailPane detail={detail} /><CompletenessPane row={row} ranges={completeness} /><RegisterPane state={registers} /><MemoryPane state={memory} history={history} /><SymbolPane key={`${workspaceId}:${artifactIndex}`} workspaceId={workspaceId} artifactIndex={artifactIndex} onSymbolsChanged={onSymbolsChanged} />{row !== null && <AnnotationEditor key={`${workspaceId}:${artifactIndex}:${row.key.record_ordinal}:${selectionRevision}`} comment={annotation?.comment ?? ""} highlight={annotation?.highlight ?? ""} onSave={onSaveComment} onDelete={onDeleteComment} onSaveHighlight={onSaveHighlight} onDeleteHighlight={onDeleteHighlight} />}{errors.map((error) => <p role="alert" key={`${error.stage}:${error.code}`}>{error.code}: {error.detail}</p>)}</aside>;
}
