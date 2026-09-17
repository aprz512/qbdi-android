import type { AnnotationDto, AppError, CompletenessRangeDto, EventDetailDto, EventRowDto, MemoryEvidenceDto, MemoryStateDto, RegisterStateDto } from "../api/generated";
import { AnnotationEditor } from "./AnnotationEditor";
import { CompletenessPane } from "./CompletenessPane";
import { EventDetailPane } from "./EventDetailPane";
import { MemoryPane } from "./MemoryPane";
import { RegisterPane } from "./RegisterPane";
import { SymbolPane } from "./SymbolPane";

interface RightDockProps {
  row: EventRowDto | null;
  detail: EventDetailDto | null;
  registers: RegisterStateDto | null;
  memory: MemoryStateDto | null;
  history: MemoryEvidenceDto[];
  annotation: AnnotationDto | null;
  errors: AppError[];
  workspaceId: string | null;
  completeness: CompletenessRangeDto[];
  onSaveComment(value: string): Promise<void>;
  onDeleteComment(): Promise<void>;
  onSaveHighlight(value: string): Promise<void>;
  onDeleteHighlight(): Promise<void>;
}

export function RightDock({ row, detail, registers, memory, history, annotation, errors, workspaceId, completeness, onSaveComment, onDeleteComment, onSaveHighlight, onDeleteHighlight }: RightDockProps) {
  return <aside className="right-dock" aria-label="Event details"><h2>Details</h2><EventDetailPane detail={detail} /><CompletenessPane row={row} ranges={completeness} /><RegisterPane state={registers} /><MemoryPane state={memory} history={history} /><SymbolPane workspaceId={workspaceId} />{row !== null && <AnnotationEditor comment={annotation?.comment ?? ""} highlight={annotation?.highlight ?? ""} onSave={onSaveComment} onDelete={onDeleteComment} onSaveHighlight={onSaveHighlight} onDeleteHighlight={onDeleteHighlight} />}{errors.map((error) => <p role="alert" key={`${error.stage}:${error.code}`}>{error.code}: {error.detail}</p>)}</aside>;
}
