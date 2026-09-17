import type { MemoryEvidenceDto, MemoryStateDto } from "../api/generated";
export function MemoryPane({ state, history }: { state: MemoryStateDto | null; history: MemoryEvidenceDto[] }) {
  return <section aria-label="Memory"><h3>Memory</h3>{state === null ? <p>unsupported</p> : <><p>{state.start}–{state.end_exclusive}</p>{(["observed", "before", "after", "last_written"] as const).map((name) => <div key={name}><strong>{name.replace("_", " ")}</strong>: {state[name].map((byte) => byte.value === null ? "??" : byte.value.toString(16).padStart(2, "0")).join(" ") || "unknown"}</div>)}<p>{history.length} overlapping accesses</p></>}</section>;
}
