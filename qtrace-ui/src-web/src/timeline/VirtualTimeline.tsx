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
  onLoadMore?(): Promise<number | void>;
  onLoadPrevious?(): Promise<number | void>;
  onRequestRange?(start: number, end: number, signal: AbortSignal): Promise<void>;
  onSelect?(row: EventRowDto): void;
}

export function VirtualTimeline({ rows, pageStart = 0, totalRows = rows.length, hasMore = false, hasPrevious = false, workspaceId = "workspace", projectionId = "projection", generation = 0, onLoadMore, onLoadPrevious, onRequestRange, onSelect }: Props) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const viewport = useRef<HTMLElement>(null);
  const requestRange = useRef(onRequestRange);
  requestRange.current = onRequestRange;
  const controllerIdentity = `${workspaceId}\0${projectionId}\0${generation}`;
  const [selected, setSelected] = useState<number | null>(null);
  const [visible, setVisible] = useState({ start: 0, end: Math.min(rows.length, 64) });
  const [scrollPosition, setScrollPosition] = useState({ physical: 0, logical: 0 });
  const controller = useMemo(() => {
    void controllerIdentity;
    return new ViewportController(async (request, signal) => {
      await requestRange.current?.(request.start, request.end, signal);
    });
  }, [controllerIdentity]);
  useEffect(() => () => controller.cancel(), [controller]);
  const localStart = Math.max(0, visible.start - pageStart);
  const localEnd = Math.max(localStart, Math.min(rows.length, visible.end - pageStart));
  const displayRows = useMemo(() => rows.slice(localStart, localEnd).map(toRenderRow), [localEnd, localStart, rows]);
  const updateViewport = useCallback(() => {
    const element = viewport.current;
    if (element === null) return;
    const geometry = { canvasHeight: Math.max(320, element.clientHeight), rowHeight: 24, totalRows };
    const logical = ViewportController.logicalOffsetForScroll(element.scrollTop, geometry);
    const range = ViewportController.rangeForViewport({ ...geometry, scrollOffset: logical });
    setScrollPosition({ physical: element.scrollTop, logical });
    setVisible(range);
    controller.request({ workspaceId, projectionId, generation, ...range });
  }, [controller, generation, projectionId, totalRows, workspaceId]);
  const loadAndFocus = async (load: (() => Promise<number | void>) | undefined) => {
    const start = await load?.();
    if (typeof start === "number" && viewport.current !== null) {
      viewport.current.scrollTop = ViewportController.scrollOffsetForRow(start, { canvasHeight: Math.max(320, viewport.current.clientHeight), rowHeight: 24, totalRows });
      updateViewport();
    }
  };
  useEffect(updateViewport, [updateViewport]);
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
  const scrollHeight = ViewportController.scrollHeight({ canvasHeight: 320, rowHeight: 24, totalRows });
  const windowOffset = scrollPosition.physical + (pageStart + localStart) * 24 - scrollPosition.logical;
  return (
    <section ref={viewport} className="virtual-timeline" aria-label="Timeline" onScroll={updateViewport}>
      <div className="timeline-scroll-space" style={{ height: scrollHeight }}>
        <div className="timeline-window" style={{ transform: `translateY(${windowOffset}px)` }}>
          <canvas ref={canvas} aria-hidden="true" />
          <InteractionLayer rows={displayRows} selectedSourceRow={selected} onSelect={(sourceRow) => { setSelected(sourceRow); const row = rows.find((item) => item.source_row === sourceRow); if (row !== undefined) onSelect?.(row); }} onExpand={setSelected} />
        </div>
      </div>
      {hasPrevious && <button className="timeline-load-previous" onClick={() => void loadAndFocus(onLoadPrevious)}>Load previous 2,000 events</button>}
      {hasMore && <button className="timeline-load-more" onClick={() => void loadAndFocus(onLoadMore)}>Load next 2,000 events</button>}
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
    location: row.location,
    symbol: row.symbol ?? "",
    instruction: row.summary,
    badges: row.discontinuity ? ["gap"] : [],
    provenance: row.provenance as RenderRow["provenance"],
    special,
  };
}
