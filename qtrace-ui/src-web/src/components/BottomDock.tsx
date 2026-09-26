import type { JobDto, TimelinePageDto } from "../api/generated";
import { JobsPane } from "./JobsPane";
import { ResultsPane } from "./ResultsPane";

interface BottomDockProps {
  initialResultsPage: TimelinePageDto | null;
  workspaceId: string | null;
  projectionId: string | null;
  generation: number;
  jobs: JobDto[];
  canGoBack: boolean;
  canGoForward: boolean;
  hiddenHistoryTarget: boolean;
  onJump(row: number): void;
  onCancel(id: string): void;
  onBack(): void;
  onForward(): void;
  onReveal(): void;
}

export function BottomDock({ initialResultsPage, workspaceId, projectionId, generation, jobs, canGoBack, canGoForward, hiddenHistoryTarget, onJump, onCancel, onBack, onForward, onReveal }: BottomDockProps) {
  return (
    <footer className="bottom-dock" aria-label="Results and jobs">
      <nav aria-label="Navigation history">
        <button disabled={!canGoBack} onClick={onBack}>Back</button>
        <button disabled={!canGoForward} onClick={onForward}>Forward</button>
        {hiddenHistoryTarget && <button onClick={onReveal}>Reveal in unfiltered timeline</button>}
      </nav>
      {initialResultsPage !== null && workspaceId !== null && projectionId !== null
        ? <ResultsPane key={`${workspaceId}:${projectionId}:${generation}`} workspaceId={workspaceId} projectionId={projectionId} initialPage={initialResultsPage} onJump={onJump} />
        : <section aria-label="Search results"><h3>Results</h3></section>}
      <JobsPane jobs={jobs} onCancel={onCancel} />
    </footer>
  );
}
