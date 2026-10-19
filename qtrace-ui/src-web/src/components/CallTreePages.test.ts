import { describe, expect, it } from "vitest";
import type { CallNodeDto } from "../api/generated";
import { CALL_CACHE_BYTES, CALL_CACHE_NODES, callPageUsage, retainCallPage, touchCallPage, type CallPage, type CallPages } from "./CallTreePages";

const node = (id: number, parent: number | null, display = `call ${id}`): CallNodeDto => ({
  id, parent, child_count: 100, tid: 7, target: null, display, source_row_start: id,
  source_row_end_exclusive: id + 1, provenance: "captured", state: "incomplete",
});
const page = (parent: number | null, start = 0, offset = 0, display?: string): CallPage => ({
  parent, offset, total: 10_000, nodes: Array.from({ length: 100 }, (_, index) => node(start + index, parent, display)),
});

describe("call tree page retention", () => {
  it("bounds cumulative browsing and retains the most recently visited branches", () => {
    let pages = retainCallPage(new Map(), page(null))!;
    for (let parent = 0; parent < 100; parent++) {
      pages = retainCallPage(pages, page(parent, 100 + parent * 100))!;
      expect(callPageUsage(pages).nodes).toBeLessThanOrEqual(CALL_CACHE_NODES);
      expect(callPageUsage(pages).bytes).toBeLessThanOrEqual(CALL_CACHE_BYTES);
    }
    expect(pages.has(-1)).toBe(true);
    expect(pages.has(0)).toBe(false);
    expect(pages.has(99)).toBe(true);
    const oldest = [...pages.keys()].find(key => key !== -1)!;
    pages = touchCallPage(pages, oldest);
    pages = retainCallPage(pages, page(0, 100))!;
    expect(pages.has(oldest)).toBe(true);
    expect(pages.has(oldest + 1)).toBe(false);
  });

  it("evicts by string weight before reaching the node limit", () => {
    let pages = retainCallPage(new Map(), page(null))!;
    for (let parent = 0; parent < 8; parent++) {
      pages = retainCallPage(pages, page(parent, 100 + parent * 100, 0, "x".repeat(5_000)))!;
    }
    expect(pages.has(0)).toBe(false);
    expect(pages.has(7)).toBe(true);
    expect(callPageUsage(pages).nodes).toBeLessThan(CALL_CACHE_NODES);
    expect(callPageUsage(pages).bytes).toBeLessThanOrEqual(CALL_CACHE_BYTES);
  });

  it("replaces sibling windows and drops unreachable descendant pages", () => {
    let pages = retainCallPage(new Map(), page(null))!;
    pages = retainCallPage(pages, page(0, 100))!;
    pages = retainCallPage(pages, page(100, 200))!;
    pages = retainCallPage(pages, page(0, 300, 100))!;
    expect(pages.has(100)).toBe(false);
    expect(pages.get(0)?.offset).toBe(100);
    expect(retainCallPage(pages, page(100, 200))).toBeNull();
    pages = retainCallPage(pages, page(0, 100))!;
    expect(pages.get(0)?.nodes[0].id).toBe(100);
  });

  it("keeps the requested ancestor path and rejects a path beyond the budget", () => {
    let pages: CallPages = retainCallPage(new Map(), page(null))!;
    let parent = 0;
    for (let depth = 1; depth < Math.floor(CALL_CACHE_NODES / 100); depth++) {
      const start = depth * 100;
      pages = retainCallPage(pages, page(parent, start))!;
      parent = start;
    }
    const retainedCount = Math.floor(CALL_CACHE_NODES / 100) * 100;
    expect(callPageUsage(pages).nodes).toBe(retainedCount);
    expect(retainCallPage(pages, page(parent, retainedCount))).toBeNull();
    expect(callPageUsage(pages).nodes).toBe(retainedCount);
    expect(pages.get(0)?.nodes[0].id).toBe(100);
  });

  it("retains the existing 5,000-frame deep-tree navigation case", () => {
    const pages = new Map<number, CallPage>();
    for (let id = 0; id < 4_999; id++) {
      const parent = id === 0 ? null : id - 1;
      pages.set(parent ?? -1, { parent, offset: 0, total: 1, nodes: [{ ...node(id, parent), child_count: 1 }] });
    }
    const next = retainCallPage(pages, { parent: 4_998, offset: 0, total: 1, nodes: [{ ...node(4_999, 4_998), child_count: 0 }] });
    expect(next).not.toBeNull();
    expect(callPageUsage(next!).nodes).toBe(5_000);
    expect(next!.has(-1)).toBe(true);
    expect(next!.has(4_998)).toBe(true);
  });

  it("rejects oversized responses without changing the existing cache", () => {
    const pages = retainCallPage(new Map(), page(null))!;
    const oversized = { ...page(0, 100), nodes: [node(100, 0, "x".repeat(CALL_CACHE_BYTES))] };
    expect(retainCallPage(pages, oversized)).toBeNull();
    expect(retainCallPage(pages, { ...page(0, 100), nodes: Array.from({ length: 101 }, (_, id) => node(100 + id, 0)) })).toBeNull();
    expect(pages.size).toBe(1);
  });
});
