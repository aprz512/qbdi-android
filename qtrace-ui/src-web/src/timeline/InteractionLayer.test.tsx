import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { InteractionLayer } from "./InteractionLayer";
import type { RenderRow } from "./TraceCanvasRenderer";

const rows: RenderRow[] = [
  { sourceRow: 4, sequence: "4", tid: 1, location: "lib+0x4", symbol: "start", instruction: "mov x0", badges: [], provenance: "captured" },
  { sourceRow: 9, sequence: "9", tid: 1, location: "lib+0x8", symbol: "broken", instruction: "checksum gap", badges: ["M"], provenance: "damaged", special: "damaged" },
];

describe("InteractionLayer", () => {
  it("announces damaged evidence instead of reading it as a normal row", () => {
    render(<InteractionLayer rows={rows} selectedSourceRow={null} onSelect={() => undefined} onExpand={() => undefined} />);
    expect(screen.getByRole("row", { name: /damaged.*checksum gap/i })).toBeVisible();
    expect(screen.getAllByRole("row")).toHaveLength(2);
  });

  it("handles pointer, keyboard, copy and annotation actions while preserving focus", () => {
    const select = vi.fn();
    const expand = vi.fn();
    const copy = vi.fn();
    const annotate = vi.fn();
    const view = render(<InteractionLayer rows={rows} selectedSourceRow={4} onSelect={select} onExpand={expand} onCopy={copy} onAnnotate={annotate} />);
    const grid = screen.getByRole("grid");
    grid.focus();
    fireEvent.keyDown(grid, { key: "ArrowDown" });
    expect(select).toHaveBeenCalledWith(9);
    fireEvent.keyDown(grid, { key: "Enter" });
    fireEvent.keyDown(grid, { key: "c" });
    fireEvent.keyDown(grid, { key: "a" });
    expect(expand).toHaveBeenCalledWith(4);
    expect(copy).toHaveBeenCalledWith(rows[0]);
    expect(annotate).toHaveBeenCalledWith(rows[0]);
    fireEvent.doubleClick(screen.getAllByRole("row")[1]);
    expect(expand).toHaveBeenCalledWith(9);
    view.rerender(<InteractionLayer rows={[...rows]} selectedSourceRow={4} onSelect={select} onExpand={expand} />);
    expect(grid).toHaveFocus();
  });
});
