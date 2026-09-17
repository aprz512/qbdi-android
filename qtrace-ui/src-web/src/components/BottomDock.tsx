import { useAppState } from "../state/AppStateProvider";
import { JobsPane } from "./JobsPane";
import { ResultsPane } from "./ResultsPane";

export function BottomDock() {
  const { jobs } = useAppState();
  return <footer className="bottom-dock" aria-label="Results and jobs"><ResultsPane pages={[]} onJump={() => undefined} /><JobsPane jobs={jobs} onCancel={() => undefined} /></footer>;
}
