import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "../App";
import { ApiProvider } from "../api/ApiContext";
import type { QtraceApi } from "../api/QtraceApi";
import type { EventDetailDto } from "../api/generated";
import { AppStateProvider } from "../state/AppStateProvider";
import { SymbolPane } from "./SymbolPane";

function fakeApi(overrides: Partial<QtraceApi> = {}): QtraceApi {
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
    upsertHighlight: unsupported,
    deleteHighlight: unsupported,
    getLocalSymbolName: unsupported,
    upsertLocalSymbolName: unsupported,
    deleteLocalSymbolName: unsupported,
    listJobs: vi.fn().mockResolvedValue([]),
    cancelJob: unsupported,
    ...overrides,
  };
}

const eventRow = (source_row: number) => ({
  source_row,
  key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(source_row), source_offset: String(source_row * 8), sequence: String(source_row), tid: 7 },
  kind: "instruction", provenance: "captured", discontinuity: false,
});

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

  it("synchronizes panes and rejects a late response from the previous selection", async () => {
    const resolvers = new Map<number, (value: EventDetailDto) => void>();
    const rows = [eventRow(1), eventRow(2)];
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "projection-1", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn().mockResolvedValue({ rows, next_cursor: null, total: 2, exact_total: true }),
      getEventDetail: vi.fn((_workspace, _artifact, row) => new Promise<EventDetailDto>((resolve) => resolvers.set(row, resolve))),
      getRegisterState: vi.fn((_workspace, _artifact, row) => Promise.resolve({ key: rows[row - 1].key, before: [], after: [] })),
      getMemoryState: vi.fn((_workspace, _artifact, row) => Promise.resolve({ key: rows[row - 1].key, start: "0x0", end_exclusive: "0x1", observed: [], before: [], after: [], last_written: [] })),
      getMemoryHistory: vi.fn().mockResolvedValue([]),
      getCallTree: vi.fn().mockResolvedValue({ identity: "tree", timeline_id: "1", tid: 7, roots: [], nodes: [] }),
      getAnnotation: vi.fn().mockResolvedValue(null),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await waitFor(() => expect(screen.getByText(/Workspace workspace-7/)).toBeVisible());
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    const timelineRows = await screen.findAllByRole("row");
    fireEvent.click(timelineRows[0]);
    fireEvent.click(timelineRows[1]);
    resolvers.get(2)?.({ artifact_index: 0, row: 2, key: rows[1].key, kind: "newest", provenance: "captured", raw_payload: "{\"kind\":\"newest\"}", module: 1, relative_pc: "0x124", memory_range: { start: "0x2000", end_exclusive: "0x2004" } });
    await waitFor(() => expect(screen.getByText("newest")).toBeVisible());
    resolvers.get(1)?.({ artifact_index: 0, row: 1, key: rows[0].key, kind: "stale", provenance: "captured", raw_payload: "{\"kind\":\"stale\"}", module: null, relative_pc: null, memory_range: null });
    await waitFor(() => expect(screen.queryByText("stale")).not.toBeInTheDocument());
    expect(screen.getByText("newest")).toBeVisible();
    expect(api.getRegisterState).toHaveBeenCalledWith("workspace-7", 0, 2);
    expect(api.getCallTree).toHaveBeenCalledWith("workspace-7", 0, "1", 7);
  });

  it("shows a local rename above ELF identity and supports edit/delete", async () => {
    const digest = "b".repeat(64);
    const api = fakeApi({
      listSymbols: vi.fn().mockResolvedValue([{ module: "libdemo.so", name: "elf_name", relative_address: "0x120", size: "32", offset: "4" }]),
      getLocalSymbolName: vi.fn().mockResolvedValue({ module_digest: digest, relative_pc: "0x124", name: "local_name" }),
      upsertLocalSymbolName: vi.fn().mockResolvedValue(undefined),
      deleteLocalSymbolName: vi.fn().mockResolvedValue(undefined),
    });
    render(<ApiProvider api={api}><SymbolPane workspaceId="workspace-7" /></ApiProvider>);
    fireEvent.change(screen.getByLabelText("Module name"), { target: { value: "libdemo.so" } });
    fireEvent.change(screen.getByLabelText("Module digest"), { target: { value: digest } });
    fireEvent.change(screen.getByLabelText("Relative PC"), { target: { value: "0x124" } });
    fireEvent.click(screen.getByRole("button", { name: "Resolve symbol" }));
    await waitFor(() => expect(screen.getByText("local_name")).toBeVisible());
    expect(screen.getByText(/ELF elf_name/)).toBeVisible();
    fireEvent.change(screen.getByLabelText("Local symbol name"), { target: { value: "edited_name" } });
    fireEvent.click(screen.getByRole("button", { name: "Save rename" }));
    await waitFor(() => expect(api.upsertLocalSymbolName).toHaveBeenCalledWith("workspace-7", 0, digest, "0x124", "edited_name"));
    expect(screen.getByText("edited_name")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Delete rename" }));
    await waitFor(() => expect(api.deleteLocalSymbolName).toHaveBeenCalledWith("workspace-7", 0, digest, "0x124"));
    expect(screen.getByText("elf_name", { selector: "strong" })).toBeVisible();
  });
});
