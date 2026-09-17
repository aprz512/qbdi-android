import type { JobDto, TimelinePageDto } from "../api/generated";
import { JobsPane } from "./JobsPane";
import { ResultsPane } from "./ResultsPane";

interface BottomDockProps {
  pages: TimelinePageDto[];
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

export function BottomDock({ pages, jobs, canGoBack, canGoForward, hiddenHistoryTarget, onJump, onCancel, onBack, onForward, onReveal }: BottomDockProps) {
  return <footer className="bottom-dock" aria-label="Results and jobs"><nav aria-label="Navigation history"><button disabled={!canGoBack} onClick={onBack}>Back</button><button disabled={!canGoForward} onClick={onForward}>Forward</button>{hiddenHistoryTarget && <button onClick={onReveal}>Reveal in unfiltered timeline</button>}</nav><ResultsPane pages={pages} onJump={onJump} /><JobsPane jobs={jobs} onCancel={onCancel} /></footer>;
}
