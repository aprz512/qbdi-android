import type { SymbolDto } from "../api/generated";
export function SymbolPane({ symbols, localNames = {} }: { symbols: SymbolDto[]; localNames?: Record<string, string> }) {
  return <section aria-label="Symbols"><h3>Symbols</h3><ul>{symbols.map((symbol) => <li key={`${symbol.module}:${symbol.relative_address}`}><strong>{localNames[symbol.relative_address] ?? symbol.name}</strong> <small>{symbol.module}+{symbol.relative_address} · ELF {symbol.name}</small></li>)}</ul></section>;
}
