import { useEffect, useState } from "react";
import type { TimelinePageDto } from "../api/generated";

export function ResultsPane({ pages, onJump }: { pages: TimelinePageDto[]; onJump(row: number): void }) {
  const rows = pages.flatMap((page) => page.rows).slice(0, 2_000);
  const exact = pages.every((page) => page.exact_total);
  const [hit, setHit] = useState(-1);
  useEffect(() => setHit(-1), [pages]);
  const jump = (index: number) => {
    if (rows.length === 0) return;
    const bounded = Math.max(0, Math.min(rows.length - 1, index));
    setHit(bounded);
    onJump(rows[bounded].source_row);
  };
  return <section aria-label="Search results"><h3>Results</h3><p>{rows.length} {exact ? "results" : "results · indexing"}</p><button disabled={rows.length === 0 || hit <= 0} onClick={() => jump(hit - 1)}>Previous hit</button><button disabled={rows.length === 0 || hit >= rows.length - 1} onClick={() => jump(hit + 1)}>Next hit</button><ol>{rows.map((row, index) => <li key={`${row.key.artifact_sha256}:${row.key.record_ordinal}`}><button aria-current={index === hit} onClick={() => jump(index)}>{row.kind} · {row.key.sequence ?? row.key.record_ordinal}</button></li>)}</ol></section>;
}
