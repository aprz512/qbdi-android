import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AnnotationEditor } from "./AnnotationEditor";
import { FilterBar } from "./FilterBar";
import { ResultsPane } from "./ResultsPane";
import { CallTreePane } from "./CallTreePane";
import { initialState } from "../state/model";

describe("workspace workflows", () => {
  it("constructs same-field OR filter terms and validates 64-bit inputs", () => {
    const apply = vi.fn();
    render(<FilterBar filter={initialState.filter} onApply={apply} />);
    fireEvent.change(screen.getByLabelText("TID"), { target: { value: "7,9" } });
    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "instruction,memory" } });
    fireEvent.change(screen.getByLabelText("Module"), { target: { value: "2,4" } });
    fireEvent.change(screen.getByLabelText("Sequence"), { target: { value: "1:18446744073709551615" } });
    fireEvent.change(screen.getByLabelText("PC range"), { target: { value: "0x10:0x20" } });
    fireEvent.change(screen.getByLabelText("Absolute PC range"), { target: { value: "0x1000:0x2000" } });
    fireEvent.change(screen.getByLabelText("Mnemonic mode"), { target: { value: "exact" } });
    fireEvent.change(screen.getByLabelText("Mnemonic"), { target: { value: "ldr" } });
    fireEvent.change(screen.getByLabelText("Register"), { target: { value: "x0,x1" } });
    fireEvent.change(screen.getByLabelText("Register writes"), { target: { value: "x2" } });
    fireEvent.change(screen.getByLabelText("Memory range"), { target: { value: "0x2000:0x2010" } });
    fireEvent.change(screen.getByLabelText("Memory directions"), { target: { value: "write" } });
    fireEvent.change(screen.getByLabelText("Semantic category"), { target: { value: "crypto" } });
    fireEvent.change(screen.getByLabelText("Semantic name"), { target: { value: "round" } });
    fireEvent.change(screen.getByLabelText("Semantic"), { target: { value: "key" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    expect(apply).toHaveBeenCalledWith(expect.objectContaining({
      tids: [7, 9], kinds: ["instruction", "memory"], modules: [2, 4],
      sequence: [{ first: "1", last: "18446744073709551615" }],
      relative_pc: [{ start: "0x10", end_exclusive: "0x20" }], absolute_pc: [{ start: "0x1000", end_exclusive: "0x2000" }],
      mnemonic: [{ mode: "exact", value: "ldr" }], register_reads: ["x0", "x1"], register_writes: ["x2"],
      memory: [{ range: { start: "0x2000", end_exclusive: "0x2010" }, directions: ["write"] }],
      semantic_categories: ["crypto"], semantic_names: ["round"], semantic_detail_contains: ["key"],
    }));
  });

  it("keeps an annotation draft when the committed write fails", async () => {
    const error = { code: "annotation.io", stage: "annotation", source: null, retryable: true, detail: "busy" };
    render(<AnnotationEditor comment="old" onSave={vi.fn().mockRejectedValue(error)} onDelete={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Comment"), { target: { value: "new draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("annotation.io"));
    expect(screen.getByLabelText("Comment")).toHaveValue("new draft");
    expect(screen.getByText("Committed: old")).toBeVisible();
  });

  it("commits and deletes highlight independently from the comment", async () => {
    const saveHighlight = vi.fn().mockResolvedValue(undefined);
    const deleteHighlight = vi.fn().mockResolvedValue(undefined);
    render(
      <AnnotationEditor
        comment="reviewed"
        highlight="#ffcc00"
        onSave={vi.fn().mockResolvedValue(undefined)}
        onDelete={vi.fn().mockResolvedValue(undefined)}
        onSaveHighlight={saveHighlight}
        onDeleteHighlight={deleteHighlight}
      />,
    );
    fireEvent.change(screen.getByLabelText("Highlight"), { target: { value: "critical" } });
    fireEvent.click(screen.getByRole("button", { name: "Save highlight" }));
    await waitFor(() => expect(saveHighlight).toHaveBeenCalledWith("critical"));
    expect(screen.getByText("Committed highlight: critical")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Delete highlight" }));
    await waitFor(() => expect(deleteHighlight).toHaveBeenCalled());
    expect(screen.getByLabelText("Comment")).toHaveValue("reviewed");
  });

  it("jumps to call entries and folds nested frames", () => {
    const jump = vi.fn();
    render(<CallTreePane tree={{ identity: "tree-1", timeline_id: "1", tid: 7, roots: [1], nodes: [
      { id: 1, parent: null, children: [2], tid: 7, target: "0x1000", display: "root", source_row_start: 10, source_row_end_exclusive: 20, provenance: "captured", state: "complete" },
      { id: 2, parent: 1, children: [], tid: 7, target: "0x1100", display: "child", source_row_start: 12, source_row_end_exclusive: 18, provenance: "derived", state: "incomplete" },
    ] }} onJump={jump} />);
    expect(screen.getByText(/child · incomplete/)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Collapse root" }));
    expect(screen.queryByText(/child · incomplete/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Expand root" }));
    fireEvent.click(screen.getByRole("button", { name: /child · incomplete/ }));
    expect(jump).toHaveBeenCalledWith(12);
  });

  it("bounds result rendering and state has no full-trace collection", () => {
    const rows = Array.from({ length: 2_001 }, (_, source_row) => ({ source_row, key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(source_row), source_offset: String(source_row), sequence: String(source_row), tid: 1 }, kind: "instruction", provenance: "captured", discontinuity: false }));
    render(<ResultsPane pages={[{ rows, next_cursor: null, total: 2_001, exact_total: false }]} onJump={() => undefined} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(2_000);
    expect(screen.getByText(/indexing/)).toBeVisible();
    expect(Object.keys(initialState).some((key) => /allEvents|eventsById/i.test(key))).toBe(false);
  });
});
