import type { CallNodeDto, CallTreeDto } from "../api/generated";

export const CALL_PAGE_SIZE = 100;
export const CALL_CACHE_NODES = 8_192;
export const CALL_CACHE_BYTES = 4 * 1024 * 1024;
export type CallPage = Pick<CallTreeDto, "parent" | "offset" | "total" | "nodes">;
export type CallPages = ReadonlyMap<number, CallPage>;
const parentKey = (parent: number | null) => parent ?? -1;

// This accounts for string storage and a fixed allowance for nodes, rows, and
// map entries. It is a cache weight, not a measurement of the browser heap.
export function callPageWeight(page: CallPage): number {
  return 128 + page.nodes.reduce((sum, node) => sum + 256 + 2 * (
    node.display.length + (node.target?.length ?? 0) + node.provenance.length + node.state.length
  ), 0);
}

export function callPageUsage(pages: CallPages): { nodes: number; bytes: number } {
  let nodes = 0, bytes = 0;
  for (const page of pages.values()) {
    nodes += page.nodes.length;
    bytes += callPageWeight(page);
  }
  return { nodes, bytes };
}

export function callPageNodes(pages: CallPages): Map<number, CallNodeDto> {
  const nodes = new Map<number, CallNodeDto>();
  for (const page of pages.values()) for (const node of page.nodes) nodes.set(node.id, node);
  return nodes;
}

function pruneOrphans(pages: Map<number, CallPage>): void {
  const reachable = new Set([-1]);
  const stack = [-1];
  while (stack.length > 0) {
    const page = pages.get(stack.pop()!);
    if (page === undefined) continue;
    for (const node of page.nodes) {
      if (!reachable.has(node.id)) { reachable.add(node.id); stack.push(node.id); }
    }
  }
  for (const key of pages.keys()) if (!reachable.has(key)) pages.delete(key);
}

export function retainCallPage(pages: CallPages, page: CallPage): CallPages | null {
  if (page.nodes.length > CALL_PAGE_SIZE || callPageWeight(page) > CALL_CACHE_BYTES) return null;
  const key = parentKey(page.parent);
  const nodes = callPageNodes(pages);
  const protectedParents = new Set([-1]);
  let parent = page.parent;
  while (parent !== null) {
    const node = nodes.get(parent);
    if (node === undefined || protectedParents.has(parent)) return null;
    protectedParents.add(parent);
    parent = node.parent;
  }
  const next = new Map(pages);
  next.delete(key);
  next.set(key, page);
  pruneOrphans(next);
  for (;;) {
    const usage = callPageUsage(next);
    if (usage.nodes <= CALL_CACHE_NODES && usage.bytes <= CALL_CACHE_BYTES) return next;
    const victim = [...next.keys()].find(candidate => !protectedParents.has(candidate));
    // Keep the path to the requested parent intact. A path that alone reaches
    // the budget requires the user to collapse it before loading further.
    if (victim === undefined) return null;
    next.delete(victim);
    pruneOrphans(next);
  }
}

export function touchCallPage(pages: CallPages, parent: number): CallPages {
  const page = pages.get(parent);
  if (page === undefined) return pages;
  const next = new Map(pages);
  next.delete(parent);
  next.set(parent, page);
  return next;
}
