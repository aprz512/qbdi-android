import { describe, expect, it } from "vitest";
import { TraceCanvasRenderer, type RenderFrame, type RenderRow } from "./TraceCanvasRenderer";

class RecordingContext {
  calls: Array<[string, ...unknown[]]> = [];
  fillStyle = "";
  font = "";
  textBaseline: CanvasTextBaseline = "alphabetic";
  setTransform(...args: unknown[]) { this.calls.push(["setTransform", ...args]); }
  clearRect(...args: unknown[]) { this.calls.push(["clearRect", ...args]); }
  save() { this.calls.push(["save"]); }
  beginPath() { this.calls.push(["beginPath"]); }
  rect(...args: unknown[]) { this.calls.push(["rect", ...args]); }
  clip() { this.calls.push(["clip"]); }
  fillRect(...args: unknown[]) { this.calls.push(["fillRect", this.fillStyle, ...args]); }
  fillText(...args: unknown[]) { this.calls.push(["fillText", this.fillStyle, ...args]); }
  setLineDash(value: number[]) { this.calls.push(["dash", value]); }
  restore() { this.calls.push(["restore"]); }
}

const row = (sourceRow: number, overrides: Partial<RenderRow> = {}): RenderRow => ({
  sourceRow, sequence: String(sourceRow), tid: 7, location: "lib+0x4", symbol: "work", instruction: "bl x0",
  badges: ["R", "C"], provenance: "captured", ...overrides,
});
const frame = (rows: RenderRow[]): RenderFrame => ({
  rows, width: 800, height: 48, rowHeight: 24, devicePixelRatio: 2, selectedSourceRow: 1,
  theme: { background: "bg", foreground: "fg", selected: "selected", muted: "muted", damaged: "damaged", gap: "gap" },
});

describe("TraceCanvasRenderer", () => {
  it("clips rows, scales for DPR, aligns columns and styles evidence", () => {
    const context = new RecordingContext();
    const hits = new TraceCanvasRenderer().render(context as unknown as CanvasRenderingContext2D, frame([
      row(0, { provenance: "unknown" }), row(1), row(2),
    ]));
    expect(context.calls[0]).toEqual(["setTransform", 2, 0, 0, 2, 0, 0]);
    expect(hits.map((hit) => hit.sourceRow)).toEqual([0, 1]);
    expect(context.calls).toContainEqual(["fillRect", "selected", 0, 24, 800, 24]);
    expect(context.calls).toContainEqual(["dash", [3, 3]]);
    expect(context.calls).toContainEqual(["fillText", "fg", "7", 82, 12]);
  });

  it("draws explicit gap, lost, damaged, signal, lifecycle and termination rows", () => {
    const context = new RecordingContext();
    const specials = ["gap", "lost", "damaged", "signal", "lifecycle", "termination"] as const;
    new TraceCanvasRenderer().render(context as unknown as CanvasRenderingContext2D, { ...frame(specials.map((special, index) => row(index, { special }))), height: 200, selectedSourceRow: null });
    const backgrounds = context.calls.filter(([name]) => name === "fillRect").map((call) => call[1]);
    expect(backgrounds).toEqual(["gap", "damaged", "damaged", "gap", "gap", "gap"]);
  });
});
