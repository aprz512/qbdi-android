import type { CallTreeDto } from "../api/generated";
import { CallTreePane } from "./CallTreePane";
import { ThreadPane } from "./ThreadPane";

interface LeftDockProps {
  tids: number[];
  selectedTid: number | null;
  callTree: CallTreeDto | null;
  onSelectTid(tid: number): void;
  onJump(row: number): void;
}

export function LeftDock({ tids, selectedTid, callTree, onSelectTid, onJump }: LeftDockProps) {
  return <nav className="left-dock" aria-label="Trace navigation"><h2>Trace</h2><ThreadPane tids={tids} selected={selectedTid} onSelect={onSelectTid} /><CallTreePane tree={callTree} onJump={onJump} /></nav>;
}
