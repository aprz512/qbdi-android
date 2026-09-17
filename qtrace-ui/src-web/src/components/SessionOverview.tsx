import type { OpenWorkspaceDto } from "../api/generated";

export function SessionOverview({ opened }: { opened: OpenWorkspaceDto | null }) {
  if (opened === null) {
    return <section aria-label="Session overview"><h1>No workspace open</h1><p>Select a session report or trace artifact.</p></section>;
  }
  return (
    <section aria-label="Session overview" className="session-overview">
      <h1>Workspace {opened.workspace.id}</h1>
      <p>{opened.workspace.artifact_count} artifacts · generation {opened.workspace.generation}</p>
      <ul aria-label="Artifacts">
        {opened.artifacts.map((artifact) => (
          <li key={artifact.index}>{artifact.name} — {artifact.event_count} events</li>
        ))}
      </ul>
      {opened.warnings.length > 0 && (
        <aside aria-label="Workspace warnings"><h2>Warnings</h2><ul>{opened.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></aside>
      )}
    </section>
  );
}
