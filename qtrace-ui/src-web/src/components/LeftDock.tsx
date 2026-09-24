import type { CallTreeDto } from "../api/generated";
import { CallTreePane } from "./CallTreePane";
import { ThreadPane } from "./ThreadPane";

interface LeftDockProps {
  workspaceId: string | null;
  tids: number[];
  selectedTid: number | null;
  callTree: CallTreeDto | null;
  onSelectTid(tid: number): void;
  onJump(row: number): void;
  onLoadCallTreePage(parent: number | null, offset: number, identity: string): Promise<CallTreeDto>;
}

export function LeftDock({ workspaceId, tids, selectedTid, callTree, onSelectTid, onJump, onLoadCallTreePage }: LeftDockProps) {
  return <nav className="left-dock" aria-label="Trace navigation"><h2>Trace</h2><ThreadPane tids={tids} selected={selectedTid} onSelect={onSelectTid} /><CallTreePane key={`${workspaceId}:${callTree?.identity ?? "none"}`} tree={callTree} onJump={onJump} loadPage={onLoadCallTreePage} /></nav>;
}
