import { useAppState } from "../state/AppStateProvider";

export function BottomDock() {
  const { jobs } = useAppState();
  return <footer className="bottom-dock" aria-label="Results and jobs"><strong>Results</strong><span>{jobs.length} jobs</span></footer>;
}
