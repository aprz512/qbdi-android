import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { EventRowDto } from "../api/generated";
import { InteractionLayer } from "./InteractionLayer";
import { TraceCanvasRenderer, type RenderRow } from "./TraceCanvasRenderer";
import { ViewportController } from "./ViewportController";
import "../styles/timeline.css";

interface Props {
  rows: EventRowDto[];
  pageStart?: number;
  totalRows?: number;
  hasMore?: boolean;
  hasPrevious?: boolean;
  workspaceId?: string;
  projectionId?: string;
  generation?: number;
  onLoadMore?(): void;
  onLoadPrevious?(): void;
  onRequestRange?(start: number, end: number): void;
  onSelect?(row: EventRowDto): void;
}

export function VirtualTimeline({ rows, pageStart = 0, totalRows = rows.length, hasMore = false, hasPrevious = false, workspaceId = "workspace", projectionId = "projection", generation = 0, onLoadMore, onLoadPrevious, onRequestRange, onSelect }: Props) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const viewport = useRef<HTMLElement>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [visible, setVisible] = useState({ start: 0, end: Math.min(rows.length, 64) });
  const controller = useMemo(() => new ViewportController(async (request) => {
    onRequestRange?.(request.start, request.end);
    return { rows: [], next_cursor: null, total: totalRows, exact_total: !hasMore };
  }), [hasMore, onRequestRange, totalRows]);
  useEffect(() => () => controller.cancel(), [controller]);
  const localStart = Math.max(0, visible.start - pageStart);
  const localEnd = Math.max(localStart, Math.min(rows.length, visible.end - pageStart));
  const displayRows = useMemo(() => rows.slice(localStart, localEnd).map(toRenderRow), [localEnd, localStart, rows]);
  const updateViewport = useCallback(() => {
    const element = viewport.current;
    if (element === null) return;
    const range = ViewportController.rangeForViewport({ scrollOffset: element.scrollTop, canvasHeight: Math.max(320, element.clientHeight), rowHeight: 24, totalRows });
    setVisible(range);
    controller.request({ workspaceId, projectionId, generation, ...range });
  }, [controller, generation, projectionId, totalRows, workspaceId]);
  useEffect(updateViewport, [updateViewport]);
  useEffect(() => {
    const element = viewport.current;
    if (element !== null && (visible.end <= pageStart || visible.start >= pageStart + rows.length)) {
      element.scrollTop = pageStart * 24;
      updateViewport();
    }
  }, [pageStart, rows.length, updateViewport, visible.end, visible.start]);
  useEffect(() => {
    const element = canvas.current;
    const context = element?.getContext("2d");
    if (element === null || context === null || context === undefined) return;
    const ratio = window.devicePixelRatio || 1;
    const bounds = element.getBoundingClientRect();
    element.width = Math.ceil(bounds.width * ratio);
    element.height = Math.ceil(bounds.height * ratio);
    new TraceCanvasRenderer().render(context, {
      rows: displayRows,
      width: bounds.width,
      height: bounds.height,
      rowHeight: 24,
      devicePixelRatio: ratio,
      selectedSourceRow: selected,
      theme: { background: "#111827", foreground: "#e5e7eb", selected: "#1d4ed8", muted: "#9ca3af", damaged: "#7f1d1d", gap: "#422006" },
    });
  }, [displayRows, selected]);
  return (
    <section ref={viewport} className="virtual-timeline" aria-label="Timeline" onScroll={updateViewport}>
      <div className="timeline-scroll-space" style={{ height: Math.max(320, totalRows * 24) }}>
        <div className="timeline-window" style={{ transform: `translateY(${(pageStart + localStart) * 24}px)` }}>
          <canvas ref={canvas} aria-hidden="true" />
          <InteractionLayer rows={displayRows} selectedSourceRow={selected} onSelect={(sourceRow) => { setSelected(sourceRow); const row = rows.find((item) => item.source_row === sourceRow); if (row !== undefined) onSelect?.(row); }} onExpand={setSelected} />
        </div>
      </div>
      {hasPrevious && <button className="timeline-load-previous" onClick={onLoadPrevious}>Load previous 2,000 events</button>}
      {hasMore && <button className="timeline-load-more" onClick={onLoadMore}>Load next 2,000 events</button>}
    </section>
  );
}

function toRenderRow(row: EventRowDto): RenderRow {
  const kind = row.kind.toLowerCase();
  const special = row.discontinuity ? "gap" : kind.includes("termination") ? "termination" : kind.includes("signal") ? "signal" : kind.includes("lifecycle") ? "lifecycle" : undefined;
  return {
    sourceRow: row.source_row,
    sequence: row.key.sequence ?? row.key.record_ordinal,
    tid: row.key.tid,
    location: row.key.source_offset,
    symbol: "",
    instruction: row.kind,
    badges: row.discontinuity ? ["gap"] : [],
    provenance: row.provenance as RenderRow["provenance"],
    special,
  };
}
