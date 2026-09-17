import { ThreadPane } from "./ThreadPane";
export function LeftDock() {
  return <nav className="left-dock" aria-label="Trace navigation"><h2>Trace</h2><ThreadPane tids={[]} selected={null} onSelect={() => undefined} /></nav>;
}
