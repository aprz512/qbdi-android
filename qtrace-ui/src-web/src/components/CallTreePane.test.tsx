import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { CallNodeDto, CallTreeDto } from "../api/generated";
import { CallTreePane } from "./CallTreePane";

const node = (id: number, parent: number | null, child_count = 0): CallNodeDto => ({
  id, parent, child_count, tid: 7, target: null, display: `call ${id}`,
  source_row_start: id, source_row_end_exclusive: id + 1, provenance: "captured", state: "complete",
});
const tree = (nodes: CallNodeDto[], total = nodes.length): CallTreeDto => ({
  identity: "bounded-tree", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0, total, nodes,
});
const scroll = (row: number) => fireEvent.scroll(screen.getByRole("tree"), { target: { scrollTop: row * 32 } });

describe("bounded call tree browsing", () => {
  it("reloads evicted collapsed branches and preserves event jumps", async () => {
    const roots = tree(Array.from({ length: 6 }, (_, id) => node(id, null, 100)));
    const loadPage = vi.fn(async (parent: number | null, offset: number) => ({ ...roots, parent, offset, total: 100,
      nodes: Array.from({ length: 100 }, (_, index) => {
        const child = node(100 + parent! * 100 + index, parent);
        return { ...child, display: `${child.display} ${"x".repeat(5_000)}` };
      }) }));
    const jump = vi.fn();
    render(<CallTreePane tree={roots} onJump={jump} loadPage={loadPage} />);
    for (let id = 0; id < 6; id++) {
      scroll(id);
      fireEvent.click(screen.getByRole("button", { name: `Expand call ${id}` }));
      await screen.findByRole("button", { name: new RegExp(`^call ${100 + id * 100} `) });
      fireEvent.click(screen.getByRole("button", { name: `Collapse call ${id}` }));
    }
    expect(loadPage).toHaveBeenCalledTimes(6);
    scroll(0);
    fireEvent.click(screen.getByRole("button", { name: "Expand call 0" }));
    await waitFor(() => expect(loadPage).toHaveBeenCalledTimes(7));
    fireEvent.click(await screen.findByRole("button", { name: /^call 100 / }));
    expect(jump).toHaveBeenCalledWith(100);
    expect(screen.getAllByRole("treeitem").length).toBeLessThan(25);
  });

  it("pages siblings in both directions without accumulating rows or losing the scroll target", async () => {
    const roots = tree(Array.from({ length: 100 }, (_, id) => node(id, null)), 10_000);
    const loadPage = vi.fn(async (parent: number | null, offset: number) => ({ ...roots, parent, offset,
      nodes: Array.from({ length: 100 }, (_, index) => node(offset + index, parent)) }));
    render(<CallTreePane tree={roots} onJump={() => undefined} loadPage={loadPage} />);
    for (let page = 1; page <= 3; page++) {
      scroll(95);
      fireEvent.click(screen.getByRole("button", { name: "Load more calls" }));
      const first = await screen.findByRole("button", { name: `call ${page * 100} · complete` });
      expect(first.closest('[role="treeitem"]')).toHaveAttribute("aria-posinset", String(page * 100 + 1));
      expect(screen.getByRole("tree").scrollTop).toBe(0);
      expect(Number.parseInt((screen.getByRole("tree").firstChild as HTMLElement).style.height)).toBeLessThanOrEqual(102 * 32);
    }
    fireEvent.click(screen.getByRole("button", { name: "Previous calls" }));
    expect(await screen.findByRole("button", { name: "call 200 · complete" })).toBeVisible();
    expect(loadPage).toHaveBeenLastCalledWith(null, 200, "bounded-tree");
  });

  it("coalesces repeated expansion while a page request is pending", async () => {
    const roots = tree([node(0, null, 1)]);
    let resolvePage!: (page: CallTreeDto) => void;
    const loadPage = vi.fn(() => new Promise<CallTreeDto>(resolve => { resolvePage = resolve; }));
    render(<CallTreePane tree={roots} onJump={() => undefined} loadPage={loadPage} />);
    fireEvent.click(screen.getByRole("button", { name: "Expand call 0" }));
    fireEvent.click(screen.getByRole("button", { name: "Collapse call 0" }));
    fireEvent.click(screen.getByRole("button", { name: "Expand call 0" }));
    expect(loadPage).toHaveBeenCalledTimes(1);
    await act(async () => resolvePage({ ...roots, parent: 0, total: 1, nodes: [node(1, 0)] }));
    expect(screen.getByRole("button", { name: "call 1 · complete" })).toBeVisible();
  });

  it("does not resurrect children whose parent leaves the sibling window", async () => {
    const roots = tree(Array.from({ length: 100 }, (_, id) => node(id, null, id === 0 ? 1 : 0)), 200);
    let resolveChild!: (page: CallTreeDto) => void;
    const loadPage = vi.fn((parent: number | null, offset: number) => parent === 0
      ? new Promise<CallTreeDto>(resolve => { resolveChild = resolve; })
      : Promise.resolve({ ...roots, parent, offset, nodes: Array.from({ length: 100 }, (_, id) => node(offset + id, null)) }));
    render(<CallTreePane tree={roots} onJump={() => undefined} loadPage={loadPage} />);
    fireEvent.click(screen.getByRole("button", { name: "Expand call 0" }));
    scroll(96);
    fireEvent.click(screen.getByRole("button", { name: "Load more calls" }));
    await screen.findByRole("button", { name: "call 100 · complete" });
    await act(async () => resolveChild({ ...roots, parent: 0, total: 1, nodes: [node(1_000, 0)] }));
    expect(screen.queryByRole("button", { name: "call 1000 · complete" })).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("allows retry after page failure and rejects mismatched page context", async () => {
    const roots = tree([node(0, null, 1)]);
    const loadPage = vi.fn().mockRejectedValueOnce(new Error("retry page"))
      .mockResolvedValueOnce({ ...roots, artifact_index: 1, parent: 0, nodes: [node(1, 0)] })
      .mockResolvedValueOnce({ ...roots, parent: 0, nodes: [node(1, 0)] });
    render(<CallTreePane tree={roots} onJump={() => undefined} loadPage={loadPage} />);
    fireEvent.click(screen.getByRole("button", { name: "Expand call 0" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("retry page");
    fireEvent.click(screen.getByRole("button", { name: "Load calls" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Load calls" })).toBeEnabled());
    expect(screen.queryByRole("button", { name: "call 1 · complete" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load calls" }));
    expect(await screen.findByRole("button", { name: "call 1 · complete" })).toBeVisible();
  });
});
