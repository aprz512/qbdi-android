import { useEffect, useLayoutEffect, useMemo, useReducer, useRef, useState } from "react";
import type { CallNodeDto, CallTreeDto } from "../api/generated";
import { CALL_PAGE_SIZE, callPageNodes, retainCallPage, touchCallPage, type CallPages } from "./CallTreePages";

const ROW_HEIGHT = 32;
const VIEW_HEIGHT = 320;
const OVERSCAN = 4;
type VisibleRow = { node: CallNodeDto; depth: number; position: number; total: number }
  | { parent: number | null; depth: number; offset: number; previous: boolean };
type Props = {
  tree: CallTreeDto | null;
  onJump(row: number): void;
  loadPage(parent: number | null, offset: number, identity: string): Promise<CallTreeDto>;
};
type View = { pages: CallPages; expanded: Set<number>; pending: Set<number>; error: string | null };
type Action = { type: "toggle"; node: CallNodeDto }
  | { type: "pending"; parent: number | null }
  | { type: "received"; page: CallTreeDto }
  | { type: "settled"; parent: number | null; error?: string };

function reduceView(state: View, action: Action): View {
  if (action.type === "toggle") {
    const expanded = new Set(state.expanded);
    if (expanded.has(action.node.id)) expanded.delete(action.node.id); else expanded.add(action.node.id);
    return { ...state, expanded, pages: touchCallPage(state.pages, action.node.id) };
  }
  const parent = action.type === "received" ? action.page.parent : action.parent;
  const pending = new Set(state.pending);
  if (action.type === "pending") {
    pending.add(parent ?? -1);
    return { ...state, pending, error: null };
  }
  pending.delete(parent ?? -1);
  if (action.type === "settled") return { ...state, pending, error: action.error ?? state.error };
  // A sibling page may have replaced this parent while its request was running.
  if (parent !== null && !callPageNodes(state.pages).has(parent)) return { ...state, pending };
  const pages = retainCallPage(state.pages, action.page);
  if (pages === null) return { ...state, pending, error: "This call path exceeds the view limit. Navigate from a shallower frame." };
  const retained = callPageNodes(pages);
  const expanded = new Set([...state.expanded].filter(id => retained.has(id)));
  return { pages, expanded, pending, error: null };
}

export function CallTreePane({ tree, ...props }: Props) {
  if (tree === null) return <section aria-label="Call tree"><h3>Call tree</h3><p>unsupported</p></section>;
  return <CallTreeView key={`${tree.identity}:${tree.artifact_index}:${tree.timeline_id}:${tree.tid}`} tree={tree} {...props} />;
}

function CallTreeView({ tree, onJump, loadPage }: Omit<Props, "tree"> & { tree: CallTreeDto }) {
  const [view, dispatch] = useReducer(reduceView, tree, initial => {
    const pages = retainCallPage(new Map(), initial);
    return { pages: pages ?? new Map(), expanded: new Set<number>(), pending: new Set<number>(),
      error: pages === null ? "The initial call page exceeds the view limit." : null };
  });
  const [scrollTop, setScrollTop] = useState(0);
  const viewport = useRef<HTMLDivElement>(null);
  const active = useRef(true);
  const requests = useRef(new Map<number, symbol>());
  const anchor = useRef<{ id: number | undefined; fallback: number | undefined; inset: number; root: boolean } | null>(null);
  useEffect(() => {
    active.current = true;
    const pending = requests.current;
    return () => { active.current = false; pending.clear(); };
  }, []);

  const rows = useMemo(() => {
    const result: VisibleRow[] = [];
    const stack: Array<{ parent: number | null; total: number; index: number; depth: number }> = [
      { parent: null, total: tree.total, index: -1, depth: 0 },
    ];
    while (stack.length > 0) {
      const current = stack[stack.length - 1];
      const page = view.pages.get(current.parent ?? -1);
      if (current.index === -1) {
        current.index = 0;
        if (page !== undefined && page.offset > 0) result.push({ parent: current.parent, depth: current.depth, offset: Math.max(0, page.offset - CALL_PAGE_SIZE), previous: true });
      }
      if (current.index >= (page?.nodes.length ?? 0)) {
        const offset = (page?.offset ?? 0) + (page?.nodes.length ?? 0);
        if (offset < (page?.total ?? current.total)) result.push({ parent: current.parent, depth: current.depth, offset, previous: false });
        stack.pop();
        continue;
      }
      const node = page!.nodes[current.index++];
      result.push({ node, depth: current.depth, position: page!.offset + current.index, total: page!.total });
      if (view.expanded.has(node.id) && node.child_count > 0) {
        stack.push({ parent: node.id, total: node.child_count, index: -1, depth: current.depth + 1 });
      }
    }
    return result;
  }, [tree.total, view.expanded, view.pages]);
  const latestRows = useRef(rows);
  useLayoutEffect(() => {
    latestRows.current = rows;
    const element = viewport.current;
    if (element === null) return;
    let top = element.scrollTop;
    if (anchor.current !== null) {
      const saved = anchor.current;
      const index = rows.findIndex(row => "node" in row && row.node.id === saved.id);
      const fallback = rows.findIndex(row => "node" in row && row.node.id === saved.fallback);
      top = saved.root ? 0 : index >= 0 ? index * ROW_HEIGHT + saved.inset : fallback >= 0 ? fallback * ROW_HEIGHT : top;
      anchor.current = null;
    }
    top = Math.max(0, Math.min(top, rows.length * ROW_HEIGHT - VIEW_HEIGHT));
    element.scrollTop = top;
    setScrollTop(top);
  }, [rows, view.pending]);

  const fetchPage = async (parent: number | null, offset: number) => {
    const key = parent ?? -1;
    if (requests.current.has(key) || requests.current.size >= 4) return;
    const token = Symbol();
    requests.current.set(key, token);
    dispatch({ type: "pending", parent });
    try {
      const page = await loadPage(parent, offset, tree.identity);
      if (!active.current || requests.current.get(key) !== token) return;
      if (page.identity !== tree.identity || page.artifact_index !== tree.artifact_index || page.timeline_id !== tree.timeline_id || page.tid !== tree.tid || page.parent !== parent || page.offset !== offset) {
        dispatch({ type: "settled", parent });
        return;
      }
      const top = viewport.current?.scrollTop ?? 0;
      const row = latestRows.current[Math.floor(top / ROW_HEIGHT)];
      anchor.current = { id: row !== undefined && "node" in row ? row.node.id : undefined,
        fallback: page.nodes[0]?.id, inset: top % ROW_HEIGHT, root: parent === null };
      dispatch({ type: "received", page });
    } catch (cause) {
      if (active.current && requests.current.get(key) === token) dispatch({ type: "settled", parent,
        error: cause instanceof Error ? cause.message : "Call tree page failed" });
    } finally {
      if (requests.current.get(key) === token) requests.current.delete(key);
    }
  };
  const toggle = (node: CallNodeDto) => {
    if (node.child_count === 0) return;
    dispatch({ type: "toggle", node });
    if (!view.expanded.has(node.id) && !view.pages.has(node.id)) void fetchPage(node.id, 0);
  };

  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + VIEW_HEIGHT) / ROW_HEIGHT) + OVERSCAN);
  return <section aria-label="Call tree"><h3>Call tree</h3>
    {view.error !== null && <p role="alert">{view.error}</p>}
    <div ref={viewport} role="tree" aria-label="Call frames" style={{ height: VIEW_HEIGHT, overflowY: "auto" }} onScroll={event => setScrollTop(event.currentTarget.scrollTop)}>
      <div style={{ position: "relative", height: rows.length * ROW_HEIGHT }}>
        {rows.slice(first, last).map((row, index) => <div key={"node" in row ? `node-${row.node.id}` : `page-${row.parent}-${row.previous}`} style={{ position: "absolute", top: (first + index) * ROW_HEIGHT, height: ROW_HEIGHT, left: row.depth * 16, whiteSpace: "nowrap" }}>
          {"node" in row ? <div role="treeitem" aria-level={row.depth + 1} aria-posinset={row.position} aria-setsize={row.total} aria-expanded={row.node.child_count > 0 ? view.expanded.has(row.node.id) : undefined}>
            <button aria-label={`${view.expanded.has(row.node.id) ? "Collapse" : "Expand"} ${row.node.display}`} disabled={row.node.child_count === 0} onClick={() => toggle(row.node)}>{view.expanded.has(row.node.id) ? "−" : "+"}</button>
            <button onClick={() => onJump(row.node.source_row_start)}>{row.node.display} · {row.node.state}</button>
          </div> : <button disabled={view.pending.has(row.parent ?? -1)} onClick={() => void fetchPage(row.parent, row.offset)}>{row.previous ? "Previous calls" : row.offset === 0 ? "Load calls" : "Load more calls"}</button>}
        </div>)}
      </div>
    </div>
  </section>;
}
