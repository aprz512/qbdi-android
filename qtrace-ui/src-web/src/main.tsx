import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { ApiProvider } from "./api/ApiContext";
import { TauriQtraceApi } from "./api/TauriQtraceApi";
import { AppStateProvider } from "./state/AppStateProvider";
import "./styles/global.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ApiProvider api={new TauriQtraceApi()}>
      <AppStateProvider><App /></AppStateProvider>
    </ApiProvider>
  </StrictMode>,
);
