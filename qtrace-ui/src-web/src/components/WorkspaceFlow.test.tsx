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

  it("loads child frames on expansion and jumps to entries", async () => {
    const jump = vi.fn();
    const child = { id: 2, parent: 1, child_count: 0, tid: 7, target: "0x1100", display: "child", source_row_start: 12, source_row_end_exclusive: 18, provenance: "derived", state: "incomplete" };
    const loadPage = vi.fn().mockResolvedValue({ identity: "tree-1", artifact_index: 0, timeline_id: "1", tid: 7, parent: 1, offset: 0, total: 1, nodes: [child] });
    render(<CallTreePane tree={{ identity: "tree-1", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0, total: 1, nodes: [
      { id: 1, parent: null, child_count: 1, tid: 7, target: "0x1000", display: "root", source_row_start: 10, source_row_end_exclusive: 20, provenance: "captured", state: "complete" },
    ] }} onJump={jump} loadPage={loadPage} />);
    expect(screen.queryByText(/child · incomplete/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Expand root" }));
    expect(await screen.findByText(/child · incomplete/)).toBeVisible();
    expect(loadPage).toHaveBeenCalledWith(1, 0, "tree-1");
    fireEvent.click(screen.getByRole("button", { name: "Collapse root" }));
    expect(screen.queryByText(/child · incomplete/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Expand root" }));
    fireEvent.click(screen.getByRole("button", { name: /child · incomplete/ }));
    expect(jump).toHaveBeenCalledWith(12);
  });

  it("keeps the call frame DOM bounded while loading a wide root page", async () => {
    const nodes = Array.from({ length: 100 }, (_, id) => ({ id, parent: null, child_count: 0, tid: 7, target: null, display: `call ${id}`, source_row_start: id, source_row_end_exclusive: id + 1, provenance: "captured", state: "complete" }));
    const nextNodes = nodes.map((node) => ({ ...node, id: node.id + 100 }));
    const loadPage = vi.fn().mockResolvedValue({ identity: "wide", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 100, total: 10_000, nodes: nextNodes });
    render(<CallTreePane tree={{ identity: "wide", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0, total: 10_000, nodes }} onJump={() => undefined} loadPage={loadPage} />);
    expect(screen.getAllByRole("treeitem").length).toBeLessThan(20);
    fireEvent.scroll(screen.getByRole("tree"), { target: { scrollTop: 3000 } });
    fireEvent.click(screen.getByRole("button", { name: "Load more calls" }));
    await waitFor(() => expect(loadPage).toHaveBeenCalledWith(null, 100, "wide"));
    expect(screen.getAllByRole("treeitem").length).toBeLessThan(20);
  });

  it("drops a child page from a previous tree identity", async () => {
    const root = { id: 1, parent: null, child_count: 1, tid: 7, target: null, display: "old root", source_row_start: 1, source_row_end_exclusive: 3, provenance: "captured", state: "complete" };
    const child = { ...root, id: 2, parent: 1, child_count: 0, display: "stale child" };
    let resolvePage: (value: unknown) => void = () => undefined;
    const loadPage = vi.fn().mockImplementation(() => new Promise((resolve) => { resolvePage = resolve; }));
    const oldTree = { identity: "old", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0, total: 1, nodes: [root] };
    const { rerender } = render(<CallTreePane tree={oldTree} onJump={() => undefined} loadPage={loadPage} />);
    fireEvent.click(screen.getByRole("button", { name: "Expand old root" }));
    rerender(<CallTreePane tree={{ ...oldTree, identity: "new", nodes: [{ ...root, display: "new root" }] }} onJump={() => undefined} loadPage={loadPage} />);
    resolvePage({ ...oldTree, parent: 1, nodes: [child] });
    await waitFor(() => expect(screen.getByText(/new root · complete/)).toBeVisible());
    expect(screen.queryByText(/stale child/)).not.toBeInTheDocument();
  });

  it("bounds result rendering and state has no full-trace collection", () => {
    const rows = Array.from({ length: 2_001 }, (_, source_row) => ({ source_row, key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(source_row), source_offset: String(source_row), sequence: String(source_row), tid: 1 }, kind: "instruction", provenance: "captured", discontinuity: false, location: `lib.so+0x${source_row.toString(16)}`, symbol: null, summary: "mov x0, x1" }));
    render(<ResultsPane pages={[{ rows, next_cursor: null, total: 2_001, exact_total: false }]} onJump={() => undefined} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(2_000);
    expect(screen.getByText(/indexing/)).toBeVisible();
    expect(Object.keys(initialState).some((key) => /allEvents|eventsById/i.test(key))).toBe(false);
  });
});
