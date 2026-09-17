import { useState } from "react";
import { useQtraceApi } from "../api/ApiContext";
import type { AppError, SymbolDto } from "../api/generated";
import { normalizeAppError } from "../api/TauriQtraceApi";

export function SymbolPane({ workspaceId, artifactIndex = 0 }: { workspaceId: string | null; artifactIndex?: number }) {
  const api = useQtraceApi();
  const [moduleName, setModuleName] = useState("");
  const [moduleDigest, setModuleDigest] = useState("");
  const [relativePc, setRelativePc] = useState("");
  const [localName, setLocalName] = useState("");
  const [symbols, setSymbols] = useState<SymbolDto[]>([]);
  const [committedName, setCommittedName] = useState("");
  const [error, setError] = useState<AppError | null>(null);

  const valid = () => {
    if (workspaceId === null) throw new Error("Open a workspace first");
    if (!/^[0-9a-f]{64}$/i.test(moduleDigest)) throw new Error("Module digest must be 64 hex characters");
    if (!/^0x[0-9a-f]+$/i.test(relativePc)) throw new Error("Relative PC must be hexadecimal");
    return workspaceId;
  };
  const run = async (action: (id: string) => Promise<void>) => {
    try { await action(valid()); setError(null); }
    catch (value) { setError(normalizeAppError(value)); }
  };
  const resolve = () => run(async (id) => {
    const [resolved, local] = await Promise.all([
      api.listSymbols(id, moduleName, [relativePc]),
      api.getLocalSymbolName(id, artifactIndex, moduleDigest, relativePc),
    ]);
    setSymbols(resolved);
    setCommittedName(local?.name ?? "");
    setLocalName(local?.name ?? "");
  });
  const save = () => run(async (id) => {
    await api.upsertLocalSymbolName(id, artifactIndex, moduleDigest, relativePc, localName);
    setCommittedName(localName);
  });
  const remove = () => run(async (id) => {
    await api.deleteLocalSymbolName(id, artifactIndex, moduleDigest, relativePc);
    setCommittedName("");
    setLocalName("");
  });

  return <section aria-label="Symbols"><h3>Symbols</h3><input aria-label="Module name" value={moduleName} onChange={(event) => setModuleName(event.target.value)} /><input aria-label="Module digest" value={moduleDigest} onChange={(event) => setModuleDigest(event.target.value)} /><input aria-label="Relative PC" value={relativePc} onChange={(event) => setRelativePc(event.target.value)} /><button onClick={() => void run(async (id) => { await api.pickAndAttachElf(id, moduleName, moduleDigest, null); })}>Attach ELF</button><button onClick={() => void resolve()}>Resolve symbol</button><ul>{symbols.map((symbol) => <li key={`${symbol.module}:${symbol.relative_address}`}><strong>{committedName || symbol.name}</strong> <small>{symbol.module}+{symbol.relative_address} · ELF {symbol.name}</small></li>)}</ul><input aria-label="Local symbol name" value={localName} onChange={(event) => setLocalName(event.target.value)} /><button onClick={() => void save()}>Save rename</button><button onClick={() => void remove()}>Delete rename</button>{error !== null && <p role="alert">{error.code}: {error.detail}</p>}</section>;
}
