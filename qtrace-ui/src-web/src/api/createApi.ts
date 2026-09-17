import type { QtraceApi } from "./QtraceApi";
import { E2eQtraceApi } from "./E2eQtraceApi";
import { TauriQtraceApi } from "./TauriQtraceApi";

export function createApi(): QtraceApi {
  return import.meta.env.MODE === "e2e" ? new E2eQtraceApi() : new TauriQtraceApi();
}
