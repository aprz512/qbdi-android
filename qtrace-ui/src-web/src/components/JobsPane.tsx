import type { JobDto } from "../api/generated";
export function JobsPane({ jobs, onCancel, onRetry }: { jobs: JobDto[]; onCancel(id: string): void; onRetry?(job: JobDto): void }) {
  return <section aria-label="Jobs"><h3>Jobs</h3><ul>{jobs.map((job) => <li key={job.id}><span>{job.kind} · {job.state} · {job.progress.completed}/{job.progress.total ?? "?"}</span>{job.state === "running" || job.state === "queued" ? <button onClick={() => onCancel(job.id)}>Cancel</button> : null}{job.state === "failed" && <button onClick={() => onRetry?.(job)}>Retry</button>}{job.error !== null && <p role="alert">{job.error.code}: {job.error.detail}</p>}</li>)}</ul></section>;
}
