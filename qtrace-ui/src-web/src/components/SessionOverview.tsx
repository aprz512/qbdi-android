import type { OpenWorkspaceDto } from "../api/generated";

export function SessionOverview({ opened, selectedArtifactIndex = 0, onSelectArtifact }: { opened: OpenWorkspaceDto | null; selectedArtifactIndex?: number; onSelectArtifact?(index: number): void }) {
  if (opened === null) {
    return <section aria-label="Session overview"><h1>No workspace open</h1><p>Select a session report or trace artifact.</p></section>;
  }
  return (
    <section aria-label="Session overview" className="session-overview">
      <h1>Workspace {opened.workspace.id}</h1>
      <p>{opened.workspace.artifact_count} artifacts · generation {opened.workspace.generation}</p>
      {opened.context === null ? <p>Single artifact. Session context is unavailable.</p> : (
        <dl className="session-context" aria-label="Session context">
          <dt>Session</dt><dd>{opened.context.session_id}</dd>
          <dt>State</dt><dd>{[opened.context.mode, opened.context.status, opened.context.stage].filter(Boolean).join(" · ") || "unavailable"}</dd>
          <dt>Package</dt><dd>{opened.context.package ?? "unavailable"}</dd>
          <dt>Device</dt><dd>{[opened.context.device_serial, opened.context.device_access_mode].filter(Boolean).join(" · ") || "unavailable"}</dd>
          <dt>Target</dt><dd>{opened.context.target_module ?? "unavailable"}</dd>
          <dt>Profile</dt><dd>{opened.context.profile ?? "unavailable"}</dd>
          <dt>Scenes</dt><dd>{opened.context.scenes.join(", ") || "unavailable"}</dd>
        </dl>
      )}
      {opened.missing_capabilities.length > 0 && <p>Unavailable context: {opened.missing_capabilities.join(", ")}</p>}
      <ul aria-label="Artifacts">
        {opened.artifacts.map((artifact) => (
          <li key={artifact.index}>
            <button aria-pressed={artifact.index === selectedArtifactIndex} onClick={() => onSelectArtifact?.(artifact.index)}>
              {artifact.name} — {artifact.event_count} events · {artifact.status}
            </button>
          </li>
        ))}
      </ul>
      {opened.warnings.length > 0 && (
        <aside aria-label="Workspace warnings"><h2>Warnings</h2><ul>{opened.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></aside>
      )}
    </section>
  );
}
