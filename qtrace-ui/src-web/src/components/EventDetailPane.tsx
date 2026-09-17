import type { EventDetailDto } from "../api/generated";
export function EventDetailPane({ detail }: { detail: EventDetailDto | null }) {
  return <section aria-label="Event detail"><h3>Event detail</h3>{detail === null ? <p>Select an event</p> : <dl><dt>Kind</dt><dd>{detail.kind}</dd><dt>Source offset</dt><dd>{detail.key.source_offset}</dd><dt>Record</dt><dd>{detail.key.record_ordinal}</dd><dt>Provenance</dt><dd>{detail.provenance}</dd><dt>Artifact</dt><dd>{detail.key.artifact_sha256}</dd></dl>}</section>;
}
