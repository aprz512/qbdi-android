import { useEffect, useMemo, useRef, useState } from "react";
import type { CallNodeDto, CallTreeDto } from "../api/generated";

const ROW_HEIGHT = 32;
const VIEW_HEIGHT = 320;
const OVERSCAN = 4;
type LoadedPage = { nodes: CallNodeDto[]; total: number };
type VisibleRow = { node: CallNodeDto; depth: number } | { more: number | null; depth: number; offset: number };

export function CallTreePane({ tree, onJump, loadPage }: {
  tree: CallTreeDto | null;
  onJump(row: number): void;
  loadPage(parent: number | null, offset: number, identity: string): Promise<CallTreeDto>;
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [pages, setPages] = useState<Map<number, LoadedPage>>(new Map());
  const [scrollTop, setScrollTop] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const identity = useRef<string | null>(null);
  useEffect(() => {
    identity.current = tree?.identity ?? null;
    setExpanded(new Set()); setPages(new Map()); setScrollTop(0); setError(null);
  }, [tree?.identity]);

  const rows = useMemo(() => {
    if (tree === null) return [];
    const root = pages.get(-1) ?? { nodes: tree.nodes, total: tree.total };
    const result: VisibleRow[] = [];
    const stack: Array<{ siblings: CallNodeDto[]; total: number; index: number; depth: number; parent: number | null }> = [
      { siblings: root.nodes, total: root.total, index: 0, depth: 0, parent: null },
    ];
    while (stack.length > 0) {
      const current = stack[stack.length - 1];
      if (current.index >= current.siblings.length) {
        if (current.siblings.length < current.total) result.push({ more: current.parent, depth: current.depth, offset: current.siblings.length });
        stack.pop();
        continue;
      }
      const node = current.siblings[current.index++];
      result.push({ node, depth: current.depth });
      if (expanded.has(node.id) && node.child_count > 0) {
        const page = pages.get(node.id);
        stack.push({ siblings: page?.nodes ?? [], total: page?.total ?? node.child_count, index: 0, depth: current.depth + 1, parent: node.id });
      }
    }
    return result;
  }, [tree, expanded, pages]);

  const fetchPage = async (parent: number | null, offset: number) => {
    if (tree === null) return;
    try {
      const page = await loadPage(parent, offset, tree.identity);
      if (identity.current !== tree.identity || page.identity !== tree.identity || page.parent !== parent || page.offset !== offset) return;
      setPages((current) => {
        const next = new Map(current);
        const key = parent ?? -1;
        const siblings = next.get(key)?.nodes ?? (parent === null ? tree.nodes : []);
        if (siblings.length !== offset) return current;
        next.set(key, { nodes: siblings.concat(page.nodes), total: page.total });
        return next;
      });
    } catch (cause) {
      if (identity.current === tree.identity) setError(cause instanceof Error ? cause.message : "Call tree page failed");
    }
  };
  const toggle = (node: CallNodeDto) => {
    if (node.child_count === 0) return;
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(node.id)) next.delete(node.id); else next.add(node.id);
      return next;
    });
    if (!expanded.has(node.id) && !pages.has(node.id)) void fetchPage(node.id, 0);
  };

  if (tree === null) return <section aria-label="Call tree"><h3>Call tree</h3><p>unsupported</p></section>;
  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + VIEW_HEIGHT) / ROW_HEIGHT) + OVERSCAN);
  return <section aria-label="Call tree"><h3>Call tree</h3>
    {error !== null && <p role="alert">{error}</p>}
    <div role="tree" aria-label="Call frames" style={{ height: VIEW_HEIGHT, overflowY: "auto" }} onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}>
      <div style={{ position: "relative", height: rows.length * ROW_HEIGHT }}>
        {rows.slice(first, last).map((row, index) => <div key={"node" in row ? `node-${row.node.id}` : `more-${row.more}`} style={{ position: "absolute", top: (first + index) * ROW_HEIGHT, height: ROW_HEIGHT, left: row.depth * 16, whiteSpace: "nowrap" }}>
          {"node" in row ? <div role="treeitem" aria-level={row.depth + 1} aria-expanded={row.node.child_count > 0 ? expanded.has(row.node.id) : undefined}>
            <button aria-label={`${expanded.has(row.node.id) ? "Collapse" : "Expand"} ${row.node.display}`} disabled={row.node.child_count === 0} onClick={() => toggle(row.node)}>{expanded.has(row.node.id) ? "−" : "+"}</button>
            <button onClick={() => onJump(row.node.source_row_start)}>{row.node.display} · {row.node.state}</button>
          </div> : <button onClick={() => void fetchPage(row.more, row.offset)}>Load more calls</button>}
        </div>)}
      </div>
    </div>
  </section>;
}
