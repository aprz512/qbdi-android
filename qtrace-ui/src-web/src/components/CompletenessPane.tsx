import type { EventRowDto } from "../api/generated";
export function CompletenessPane({ row }: { row: EventRowDto | null }) {
  const status = row === null ? "unknown" : row.provenance === "damaged" ? "damaged" : row.discontinuity ? "gap or lost evidence" : "complete at selected event";
  return <section aria-label="Completeness"><h3>Completeness</h3><p>{status}</p></section>;
}
