import type { TimelinePageDto } from "../api/generated";
export function ResultsPane({ pages, onJump }: { pages: TimelinePageDto[]; onJump(row: number): void }) {
  const rows = pages.flatMap((page) => page.rows).slice(0, 2_000);
  const exact = pages.every((page) => page.exact_total);
  return <section aria-label="Search results"><h3>Results</h3><p>{rows.length} {exact ? "results" : "results · indexing"}</p><ol>{rows.map((row) => <li key={`${row.key.artifact_sha256}:${row.key.record_ordinal}`}><button onClick={() => onJump(row.source_row)}>{row.kind} · {row.key.sequence ?? row.key.record_ordinal}</button></li>)}</ol></section>;
}
