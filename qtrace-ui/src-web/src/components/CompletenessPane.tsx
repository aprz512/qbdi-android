import type { CompletenessRangeDto, EventRowDto } from "../api/generated";
export function CompletenessPane({ row, ranges }: { row: EventRowDto | null; ranges: CompletenessRangeDto[] }) {
  const status = row === null ? "No event selected" : `Selected evidence: ${row.provenance}${row.discontinuity ? " · discontinuity" : ""}`;
  return <section aria-label="Completeness"><h3>Completeness</h3><p>{status}</p>{ranges.length === 0 ? <p>Completeness unavailable</p> : <ul>{ranges.map((range, index) => <li key={`${range.domain}:${range.start}:${range.end}:${range.cause}:${index}`}>{range.cause} · {range.provenance} · {range.domain} {range.start}–{range.end}{range.end_inclusive ? " inclusive" : " exclusive"}</li>)}</ul>}</section>;
}
