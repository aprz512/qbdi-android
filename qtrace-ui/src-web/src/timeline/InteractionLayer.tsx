import { useEffect, useMemo, useRef, type KeyboardEvent } from "react";
import type { RenderRow } from "./TraceCanvasRenderer";

interface Props {
  rows: RenderRow[];
  selectedSourceRow: number | null;
  onSelect(sourceRow: number): void;
  onExpand(sourceRow: number): void;
  onCopy?(row: RenderRow): void;
  onAnnotate?(row: RenderRow): void;
}

export function InteractionLayer({ rows, selectedSourceRow, onSelect, onExpand, onCopy, onAnnotate }: Props) {
  const grid = useRef<HTMLDivElement>(null);
  const selectedIndex = useMemo(() => Math.max(0, rows.findIndex((row) => row.sourceRow === selectedSourceRow)), [rows, selectedSourceRow]);
  useEffect(() => { if (document.activeElement === document.body) grid.current?.focus(); }, [rows]);

  const keyDown = (event: KeyboardEvent) => {
    if (rows.length === 0) return;
    const page = 10;
    let next = selectedIndex;
    if (event.key === "ArrowDown") next += 1;
    else if (event.key === "ArrowUp") next -= 1;
    else if (event.key === "PageDown") next += page;
    else if (event.key === "PageUp") next -= page;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = rows.length - 1;
    else if (event.key === "Enter") onExpand(rows[selectedIndex].sourceRow);
    else if (event.key.toLowerCase() === "c") onCopy?.(rows[selectedIndex]);
    else if (event.key.toLowerCase() === "a") onAnnotate?.(rows[selectedIndex]);
    else return;
    event.preventDefault();
    if (next !== selectedIndex) onSelect(rows[Math.max(0, Math.min(rows.length - 1, next))].sourceRow);
  };

  return (
    <div ref={grid} className="interaction-layer" role="grid" aria-label="Visible trace rows" tabIndex={0} onKeyDown={keyDown}>
      {rows.map((row) => (
        <div
          role="row"
          aria-selected={row.sourceRow === selectedSourceRow}
          aria-label={accessibleName(row)}
          title={`${row.symbol} ${row.instruction}`.trim()}
          key={`${row.sourceRow}:${row.sequence}`}
          onClick={() => onSelect(row.sourceRow)}
          onDoubleClick={() => onExpand(row.sourceRow)}
        />
      ))}
    </div>
  );
}

function accessibleName(row: RenderRow): string {
  const special = row.special === undefined ? "" : `${row.special} `;
  const evidence = row.provenance === "damaged" ? "damaged evidence " : row.provenance === "unknown" ? "unknown evidence " : "";
  return `${special}${evidence}${row.sequence} thread ${row.tid ?? "unknown"} ${row.location} ${row.symbol} ${row.instruction} ${row.badges.join(" ")}`.trim();
}
