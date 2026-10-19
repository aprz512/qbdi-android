import { useState } from "react";
import type { JobDto, OpenStageDto } from "../api/generated";

const stageLabels: Record<OpenStageDto, string> = {
  verify_source: "Verifying source",
  open_cache: "Validating cache",
  build_index: "Building index",
  publish_cache: "Publishing cache",
  reopen_cache: "Reopening cache",
  prepare_analysis: "Preparing analysis",
  publish_workspace: "Publishing workspace",
};
const formatCount = (value: string) => BigInt(value).toLocaleString("en-US");

type CancelJob = (id: string) => void | Promise<void>;

function JobItem({ job, onCancel, onRetry }: { job: JobDto; onCancel: CancelJob; onRetry?(job: JobDto): void }) {
  const [cancelling, setCancelling] = useState(false);
  const active = job.state === "running" || job.state === "queued";
  const detail = job.progress.detail;
  const cancel = () => {
    setCancelling(true);
    void Promise.resolve().then(() => onCancel(job.id)).catch(() => setCancelling(false));
  };
  return (
    <li>
      <span>{job.kind} · {job.state} · {job.progress.completed}/{job.progress.total ?? "?"}</span>
      {detail != null && <p className="job-progress" role="status">
        {stageLabels[detail.stage]}{detail.artifact !== null && <> · {detail.artifact}</>}
        {` · ${formatCount(detail.processed_bytes)} bytes processed · ${formatCount(detail.processed_events)} events processed`}
        {detail.processed_rows !== "0" && ` · ${formatCount(detail.processed_rows)} rows checked`}
      </p>}
      {active && <button disabled={cancelling} onClick={cancel}>{cancelling ? "Cancelling…" : "Cancel"}</button>}
      {job.state === "failed" && <button onClick={() => onRetry?.(job)}>Retry</button>}
      {job.error !== null && <p role="alert">{job.error.code}: {job.error.detail}</p>}
    </li>
  );
}

export function JobsPane({ jobs, onCancel, onRetry }: { jobs: JobDto[]; onCancel: CancelJob; onRetry?(job: JobDto): void }) {
  return <section aria-label="Jobs"><h3>Jobs</h3><ul>{jobs.map((job) => <JobItem key={job.id} job={job} onCancel={onCancel} onRetry={onRetry} />)}</ul></section>;
}
