export type EvidenceStyle = "captured" | "derived" | "heuristic" | "unknown" | "damaged";

export interface RenderRow {
  sourceRow: number;
  sequence: string;
  tid: number | null;
  location: string;
  symbol: string;
  instruction: string;
  badges: string[];
  provenance: EvidenceStyle;
  special?: "gap" | "lost" | "damaged" | "signal" | "lifecycle" | "termination";
}

export interface RenderTheme {
  background: string;
  foreground: string;
  selected: string;
  muted: string;
  damaged: string;
  gap: string;
}

export interface RenderFrame {
  rows: RenderRow[];
  width: number;
  height: number;
  rowHeight: number;
  devicePixelRatio: number;
  selectedSourceRow: number | null;
  theme: RenderTheme;
}

export interface HitRegion { sourceRow: number; x: number; y: number; width: number; height: number }

export class TraceCanvasRenderer {
  render(context: CanvasRenderingContext2D, frame: RenderFrame): HitRegion[] {
    const ratio = Math.max(1, frame.devicePixelRatio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, frame.width, frame.height);
    context.save();
    context.beginPath();
    context.rect(0, 0, frame.width, frame.height);
    context.clip();
    context.font = "12px ui-monospace, monospace";
    context.textBaseline = "middle";
    const hits: HitRegion[] = [];
    for (let index = 0; index < frame.rows.length; index += 1) {
      const y = index * frame.rowHeight;
      if (y >= frame.height || y + frame.rowHeight <= 0) continue;
      const row = frame.rows[index];
      context.fillStyle = row.sourceRow === frame.selectedSourceRow ? frame.theme.selected : rowBackground(row, frame.theme);
      context.fillRect(0, y, frame.width, frame.rowHeight);
      context.fillStyle = row.provenance === "damaged" ? frame.theme.damaged : frame.theme.foreground;
      context.setLineDash(row.provenance === "unknown" ? [3, 3] : []);
      const values = [row.sequence, row.tid?.toString() ?? "—", row.location, row.symbol, row.instruction, row.badges.join(" ")];
      const columns = [8, 82, 132, 286, 430, Math.max(600, frame.width - 100)];
      values.forEach((value, column) => context.fillText(value, columns[column], y + frame.rowHeight / 2));
      hits.push({ sourceRow: row.sourceRow, x: 0, y, width: frame.width, height: frame.rowHeight });
    }
    context.setLineDash([]);
    context.restore();
    return hits;
  }
}

function rowBackground(row: RenderRow, theme: RenderTheme): string {
  if (row.special === "damaged" || row.special === "lost") return theme.damaged;
  if (row.special !== undefined) return theme.gap;
  return theme.background;
}
