import { AppHeader } from "./components/AppHeader";
import { BottomDock } from "./components/BottomDock";
import { LeftDock } from "./components/LeftDock";
import { RightDock } from "./components/RightDock";
import { SessionOverview } from "./components/SessionOverview";
import { useAppState } from "./state/AppStateProvider";

export default function App() {
  const state = useAppState();
  return (
    <div className="app-shell">
      <AppHeader />
      <LeftDock />
      <main className="workspace">
        {state.phase === "failed" && state.error !== null ? (
          <section role="alert"><h1>{state.error.code}</h1><p>{state.error.detail}</p></section>
        ) : state.opened === null || state.projectionId === null ? (
          <SessionOverview opened={state.opened} />
        ) : (
          <section aria-label="Timeline"><canvas aria-label="Trace timeline" /></section>
        )}
      </main>
      <RightDock />
      <BottomDock />
    </div>
  );
}
