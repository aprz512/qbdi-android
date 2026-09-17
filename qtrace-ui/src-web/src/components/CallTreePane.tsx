import { useEffect, useState, type ReactElement } from "react";
import type { CallNodeDto, CallTreeDto } from "../api/generated";

export function CallTreePane({ tree, onJump }: { tree: CallTreeDto | null; onJump(row: number): void }) {
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  useEffect(() => setCollapsed(new Set()), [tree?.identity]);
  if (tree === null) return <section aria-label="Call tree"><h3>Call tree</h3><p>unsupported</p></section>;
  const byId = new Map(tree.nodes.map((node) => [node.id, node]));
  const renderNode = (node: CallNodeDto): ReactElement => (
    <li key={node.id}>
      <button
        aria-label={`${collapsed.has(node.id) ? "Expand" : "Collapse"} ${node.display}`}
        disabled={node.children.length === 0}
        onClick={() => setCollapsed((current) => {
          const next = new Set(current);
          if (next.has(node.id)) next.delete(node.id); else next.add(node.id);
          return next;
        })}
      >{collapsed.has(node.id) ? "+" : "−"}</button>
      <button onClick={() => onJump(node.source_row_start)}>{node.display} · {node.state}</button>
      {!collapsed.has(node.id) && node.children.length > 0 && (
        <ul>{node.children.flatMap((id) => { const child = byId.get(id); return child === undefined ? [] : [renderNode(child)]; })}</ul>
      )}
    </li>
  );
  return <section aria-label="Call tree"><h3>Call tree</h3><ul>{tree.roots.flatMap((id) => { const node = byId.get(id); return node === undefined ? [] : [renderNode(node)]; })}</ul></section>;
}
