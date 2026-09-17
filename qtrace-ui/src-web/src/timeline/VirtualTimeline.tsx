import { useEffect, useMemo, useRef, useState } from "react";
import type { EventRowDto } from "../api/generated";
import { InteractionLayer } from "./InteractionLayer";
import { TraceCanvasRenderer, type RenderRow } from "./TraceCanvasRenderer";
import "../styles/timeline.css";

export function VirtualTimeline({ rows }: { rows: EventRowDto[] }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const displayRows = useMemo(() => rows.map(toRenderRow), [rows]);
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
    <section className="virtual-timeline" aria-label="Timeline">
      <canvas ref={canvas} aria-hidden="true" />
      <InteractionLayer rows={displayRows} selectedSourceRow={selected} onSelect={setSelected} onExpand={setSelected} />
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
