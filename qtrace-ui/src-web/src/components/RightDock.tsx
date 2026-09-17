import { CompletenessPane } from "./CompletenessPane";
import { EventDetailPane } from "./EventDetailPane";
export function RightDock() {
  return <aside className="right-dock" aria-label="Event details"><h2>Details</h2><EventDetailPane detail={null} /><CompletenessPane row={null} /></aside>;
}
