import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "../App";
import { ApiProvider } from "../api/ApiContext";
import type { QtraceApi } from "../api/QtraceApi";
import { AppStateProvider } from "../state/AppStateProvider";

function fakeApi(): QtraceApi {
  const unsupported = async (): Promise<never> => { throw new Error("not used"); };
  return {
    pickAndOpenSession: vi.fn().mockResolvedValue({
      workspace: { id: "workspace-7", generation: 0, artifact_count: 1 },
      artifacts: [{ index: 0, name: "main.trace.bin", event_count: 42 }],
      warnings: ["worker artifact isolated"],
    }),
    pickAndOpenArtifact: vi.fn().mockResolvedValue(null),
    closeWorkspace: vi.fn().mockResolvedValue(undefined),
    getWorkspaceSummary: unsupported,
    createProjection: unsupported,
    queryTimeline: unsupported,
    getEventDetail: unsupported,
    getRegisterState: unsupported,
    getMemoryState: unsupported,
    getMemoryHistory: unsupported,
    getCallTree: unsupported,
    pickAndAttachElf: unsupported,
    listSymbols: unsupported,
    getAnnotation: unsupported,
    upsertAnnotation: unsupported,
    deleteAnnotation: unsupported,
    listJobs: vi.fn().mockResolvedValue([]),
    cancelJob: unsupported,
  };
}

describe("desktop shell", () => {
  it("renders fixed semantic regions and session identity/warnings", async () => {
    render(<ApiProvider api={fakeApi()}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    expect(screen.getByRole("banner")).toBeVisible();
    expect(screen.getByRole("navigation", { name: "Trace navigation" })).toBeVisible();
    expect(screen.getByRole("main")).toBeVisible();
    expect(screen.getByRole("complementary", { name: "Event details" })).toBeVisible();
    expect(screen.getByRole("contentinfo")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await waitFor(() => expect(screen.getByText(/Workspace workspace-7/)).toBeVisible());
    expect(screen.getByText(/main\.trace\.bin/)).toBeVisible();
    expect(screen.getByText("worker artifact isolated")).toBeVisible();
  });
});
