export function ThreadPane({ tids, selected, onSelect }: { tids: number[]; selected: number | null; onSelect(tid: number): void }) {
  return <section aria-label="Threads"><h3>Threads</h3>{tids.length === 0 ? <p>unsupported</p> : <ul>{tids.map((tid) => <li key={tid}><button aria-pressed={tid === selected} onClick={() => onSelect(tid)}>TID {tid}</button></li>)}</ul>}</section>;
}
