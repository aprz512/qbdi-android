import type { RegisterStateDto } from "../api/generated";
export function RegisterPane({ state }: { state: RegisterStateDto | null }) {
  return <section aria-label="Registers"><h3>Registers</h3>{state === null ? <p>unsupported</p> : <table><thead><tr><th>Register</th><th>Before</th><th>After</th></tr></thead><tbody>{state.before.map((cell, index) => <tr key={cell.slot}><th>{cell.slot}</th><td>{label(cell.value, cell.provenance)}</td><td>{label(state.after[index]?.value ?? null, state.after[index]?.provenance ?? "unknown")}</td></tr>)}</tbody></table>}</section>;
}
const label = (value: string | null, provenance: string) => provenance === "damaged" ? "damaged" : value ?? "unknown";
