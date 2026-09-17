import type { TimelinePageDto } from "../api/generated";

export interface FoldRange { startRow: number; endRow: number }
export interface RowRange { start: number; end: number }
export interface ViewportGeometry {
  scrollOffset: number;
  canvasHeight: number;
  rowHeight: number;
  totalRows: number;
}
export interface PageRequest extends RowRange {
  workspaceId: string;
  projectionId: string;
  generation: number;
}
export interface TimelineSegment {
  page: TimelinePageDto;
  generation: number;
}
