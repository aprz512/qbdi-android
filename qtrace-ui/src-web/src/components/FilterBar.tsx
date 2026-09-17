import { useState } from "react";
import type { EventFilterDto } from "../api/generated";
import { emptyFilter } from "../state/model";

export function FilterBar({ onApply }: { onApply(filter: EventFilterDto): void }) {
  const [tid, setTid] = useState("");
  const [kind, setKind] = useState("");
  const [moduleId, setModuleId] = useState("");
  const [sequence, setSequence] = useState("");
  const [pc, setPc] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [register, setRegister] = useState("");
  const [memory, setMemory] = useState("");
  const [semantic, setSemantic] = useState("");
  const [error, setError] = useState<string | null>(null);
  const apply = () => {
    try {
      const filter = emptyFilter();
      filter.tids = numbers(tid, 0xffff_ffff, "TID");
      filter.kinds = words(kind);
      filter.modules = numbers(moduleId, 0xffff_ffff, "module");
      if (sequence !== "") {
        const [first, last] = pair(sequence, decimal, "sequence");
        filter.sequence = [{ first, last }];
      }
      if (pc !== "") {
        const [start, end_exclusive] = pair(pc, hex, "PC range");
        filter.relative_pc = [{ start, end_exclusive }];
      }
      if (mnemonic !== "") filter.mnemonic = [{ mode: "contains", value: mnemonic }];
      filter.register_reads = words(register);
      if (memory !== "") {
        const [start, end_exclusive] = pair(memory, hex, "memory range");
        filter.memory = [{ range: { start, end_exclusive }, directions: ["read", "write"] }];
      }
      filter.semantic_detail_contains = words(semantic);
      setError(null);
      onApply(filter);
    } catch (value) { setError(value instanceof Error ? value.message : "Invalid filter"); }
  };
  return (
    <form className="filter-bar" aria-label="Trace filters" onSubmit={(event) => { event.preventDefault(); apply(); }}>
      <input aria-label="TID" value={tid} onChange={(e) => setTid(e.target.value)} placeholder="TID" />
      <input aria-label="Kind" value={kind} onChange={(e) => setKind(e.target.value)} placeholder="kind" />
      <input aria-label="Module" value={moduleId} onChange={(e) => setModuleId(e.target.value)} placeholder="module ID" />
      <input aria-label="Sequence" value={sequence} onChange={(e) => setSequence(e.target.value)} placeholder="first:last" />
      <input aria-label="PC range" value={pc} onChange={(e) => setPc(e.target.value)} placeholder="0xstart:0xend" />
      <input aria-label="Mnemonic" value={mnemonic} onChange={(e) => setMnemonic(e.target.value)} placeholder="mnemonic" />
      <input aria-label="Register" value={register} onChange={(e) => setRegister(e.target.value)} placeholder="register reads" />
      <input aria-label="Memory range" value={memory} onChange={(e) => setMemory(e.target.value)} placeholder="memory range" />
      <input aria-label="Semantic" value={semantic} onChange={(e) => setSemantic(e.target.value)} placeholder="semantic detail" />
      <button type="submit">Apply filters</button>
      {error !== null && <span role="alert">{error}</span>}
    </form>
  );
}
const words = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);
const numbers = (value: string, max: number, label: string) => words(value).map((item) => { const number = Number(item); if (!Number.isInteger(number) || number < 0 || number > max) throw new Error(`Invalid ${label}`); return number; });
const decimal = (value: string) => { if (!/^(0|[1-9]\d*)$/.test(value) || BigInt(value) > 0xffff_ffff_ffff_ffffn) throw new Error("Invalid 64-bit decimal"); return value; };
const hex = (value: string) => { if (!/^0x(0|[1-9a-f][0-9a-f]*)$/.test(value) || BigInt(value) > 0xffff_ffff_ffff_ffffn) throw new Error("Invalid 64-bit hex"); return value; };
const pair = (value: string, parse: (part: string) => string, label: string): [string, string] => { const parts = value.split(":"); if (parts.length !== 2) throw new Error(`Invalid ${label}`); const first = parse(parts[0]); const last = parse(parts[1]); if (BigInt(first) > BigInt(last)) throw new Error(`Invalid ${label}`); return [first, last]; };
