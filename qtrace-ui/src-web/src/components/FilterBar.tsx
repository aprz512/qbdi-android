import { useEffect, useState } from "react";
import type { EventFilterDto } from "../api/generated";
import { emptyFilter } from "../state/model";

export function FilterBar({ filter, onApply }: { filter: EventFilterDto; onApply(filter: EventFilterDto): void }) {
  const [tid, setTid] = useState("");
  const [kind, setKind] = useState("");
  const [moduleId, setModuleId] = useState("");
  const [sequence, setSequence] = useState("");
  const [pc, setPc] = useState("");
  const [absolutePc, setAbsolutePc] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [mnemonicMode, setMnemonicMode] = useState("contains");
  const [registerReads, setRegisterReads] = useState("");
  const [registerWrites, setRegisterWrites] = useState("");
  const [memory, setMemory] = useState("");
  const [memoryDirections, setMemoryDirections] = useState("read,write");
  const [semanticCategory, setSemanticCategory] = useState("");
  const [semanticName, setSemanticName] = useState("");
  const [semanticDetail, setSemanticDetail] = useState("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setTid(filter.tids.join(","));
    setKind(filter.kinds.join(","));
    setModuleId(filter.modules.join(","));
    setSequence(formatRange(filter.sequence[0]?.first, filter.sequence[0]?.last));
    setPc(formatRange(filter.relative_pc[0]?.start, filter.relative_pc[0]?.end_exclusive));
    setAbsolutePc(formatRange(filter.absolute_pc[0]?.start, filter.absolute_pc[0]?.end_exclusive));
    setMnemonic(filter.mnemonic[0]?.value ?? "");
    setMnemonicMode(filter.mnemonic[0]?.mode ?? "contains");
    setRegisterReads(filter.register_reads.join(","));
    setRegisterWrites(filter.register_writes.join(","));
    setMemory(formatRange(filter.memory[0]?.range.start, filter.memory[0]?.range.end_exclusive));
    setMemoryDirections(filter.memory[0]?.directions.join(",") || "read,write");
    setSemanticCategory(filter.semantic_categories.join(","));
    setSemanticName(filter.semantic_names.join(","));
    setSemanticDetail(filter.semantic_detail_contains.join(","));
    setError(null);
  }, [filter]);
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
        const [start, end_exclusive] = addressPair(pc, "PC range");
        filter.relative_pc = [{ start, end_exclusive }];
      }
      if (absolutePc !== "") {
        const [start, end_exclusive] = addressPair(absolutePc, "absolute PC range");
        filter.absolute_pc = [{ start, end_exclusive }];
      }
      if (mnemonic !== "") filter.mnemonic = [{ mode: mnemonicMode, value: mnemonic }];
      filter.register_reads = words(registerReads);
      filter.register_writes = words(registerWrites);
      if (memory !== "") {
        const [start, end_exclusive] = addressPair(memory, "memory range");
        const directions = words(memoryDirections);
        if (directions.some((direction) => direction !== "read" && direction !== "write")) throw new Error("Invalid memory direction");
        filter.memory = [{ range: { start, end_exclusive }, directions }];
      }
      filter.semantic_categories = words(semanticCategory);
      filter.semantic_names = words(semanticName);
      filter.semantic_detail_contains = words(semanticDetail);
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
      <input aria-label="Absolute PC range" value={absolutePc} onChange={(e) => setAbsolutePc(e.target.value)} placeholder="0xstart:0xend" />
      <select aria-label="Mnemonic mode" value={mnemonicMode} onChange={(e) => setMnemonicMode(e.target.value)}><option value="contains">contains</option><option value="exact">exact</option></select>
      <input aria-label="Mnemonic" value={mnemonic} onChange={(e) => setMnemonic(e.target.value)} placeholder="mnemonic" />
      <input aria-label="Register" value={registerReads} onChange={(e) => setRegisterReads(e.target.value)} placeholder="register reads" />
      <input aria-label="Register writes" value={registerWrites} onChange={(e) => setRegisterWrites(e.target.value)} placeholder="register writes" />
      <input aria-label="Memory range" value={memory} onChange={(e) => setMemory(e.target.value)} placeholder="memory range" />
      <input aria-label="Memory directions" value={memoryDirections} onChange={(e) => setMemoryDirections(e.target.value)} placeholder="read,write" />
      <input aria-label="Semantic category" value={semanticCategory} onChange={(e) => setSemanticCategory(e.target.value)} placeholder="semantic category" />
      <input aria-label="Semantic name" value={semanticName} onChange={(e) => setSemanticName(e.target.value)} placeholder="semantic name" />
      <input aria-label="Semantic" value={semanticDetail} onChange={(e) => setSemanticDetail(e.target.value)} placeholder="semantic detail" />
      <button type="submit">Apply filters</button>
      {error !== null && <span role="alert">{error}</span>}
    </form>
  );
}
const words = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);
const formatRange = (first: string | undefined, last: string | undefined) => first === undefined || last === undefined ? "" : `${first}:${last}`;
const numbers = (value: string, max: number, label: string) => words(value).map((item) => { const number = Number(item); if (!Number.isInteger(number) || number < 0 || number > max) throw new Error(`Invalid ${label}`); return number; });
const decimal = (value: string) => { if (!/^(0|[1-9]\d*)$/.test(value) || BigInt(value) > 0xffff_ffff_ffff_ffffn) throw new Error("Invalid 64-bit decimal"); return value; };
const hex = (value: string) => { if (!/^0x(0|[1-9a-f][0-9a-f]*)$/.test(value) || BigInt(value) > 0xffff_ffff_ffff_ffffn) throw new Error("Invalid 64-bit hex"); return value; };
const pair = (value: string, parse: (part: string) => string, label: string): [string, string] => { const parts = value.split(":"); if (parts.length !== 2) throw new Error(`Invalid ${label}`); const first = parse(parts[0]); const last = parse(parts[1]); if (BigInt(first) > BigInt(last)) throw new Error(`Invalid ${label}`); return [first, last]; };
const addressPair = (value: string, label: string): [string, string] => { const [start, end] = pair(value, hex, label); if (BigInt(start) >= BigInt(end)) throw new Error(`Invalid ${label}`); return [start, end]; };
