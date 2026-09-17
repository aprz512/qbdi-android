/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, type ReactNode } from "react";
import type { QtraceApi } from "./QtraceApi";

const ApiContext = createContext<QtraceApi | null>(null);

export function ApiProvider({ api, children }: { api: QtraceApi; children: ReactNode }) {
  return <ApiContext.Provider value={api}>{children}</ApiContext.Provider>;
}

export function useQtraceApi(): QtraceApi {
  const api = useContext(ApiContext);
  if (api === null) throw new Error("QtraceApi provider is missing");
  return api;
}
