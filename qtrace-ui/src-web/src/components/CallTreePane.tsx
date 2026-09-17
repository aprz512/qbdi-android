import type { CallTreeDto } from "../api/generated";
export function CallTreePane({ tree, onJump }: { tree: CallTreeDto | null; onJump(row: number): void }) {
  return <section aria-label="Call tree"><h3>Call tree</h3>{tree === null ? <p>unsupported</p> : <ul>{tree.nodes.map((node) => <li key={node.id}><button onClick={() => onJump(node.source_row_start)}>{node.display} · {node.state}</button></li>)}</ul>}</section>;
}
