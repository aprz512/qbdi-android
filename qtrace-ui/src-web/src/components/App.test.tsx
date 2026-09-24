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
      artifacts: [{ index: 0, name: "main.trace.bin", event_count: 42, tids: [7], completeness: [] }],
      warnings: ["worker artifact isolated"],
    }),
    pickAndOpenArtifact: vi.fn().mockResolvedValue(null),
    closeWorkspace: vi.fn().mockResolvedValue(undefined),
    getWorkspaceSummary: unsupported,
    createProjection: unsupported,
    queryTimeline: unsupported,
    locateTimeline: unsupported,
    locateTimelineOffset: unsupported,
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
    listJobs: vi.fn().mockResolvedValue([{ id: "job-1", workspace_id: "workspace-7", kind: "projection", state: "completed", progress: { completed: "1", total: "1" }, error: null }]),
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
  it("retries cleanup when replacing a workspace whose close initially fails", async () => {
    const closeWorkspace = vi.fn()
      .mockRejectedValueOnce(new Error("busy"))
      .mockResolvedValue(undefined);
    const api = fakeApi({
      pickAndOpenSession: vi.fn()
        .mockResolvedValueOnce({ workspace: { id: "workspace-old", generation: 0, artifact_count: 0 }, artifacts: [], warnings: [] })
        .mockResolvedValueOnce({ workspace: { id: "workspace-new", generation: 0, artifact_count: 0 }, artifacts: [], warnings: [] }),
      closeWorkspace,
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await screen.findByText(/Workspace workspace-old/);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await screen.findByText(/Workspace workspace-new/);
    await waitFor(() => expect(closeWorkspace).toHaveBeenCalledTimes(2), { timeout: 1_500 });
    expect(closeWorkspace).toHaveBeenLastCalledWith("workspace-old");
  });

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
      getCallTree: vi.fn().mockResolvedValue({ identity: "tree", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0, total: 0, nodes: [] }),
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

  it("switches artifacts, shows completeness, and traverses cursor pages", async () => {
    const firstRows = Array.from({ length: 2_000 }, (_, index) => eventRow(index + 1));
    const secondRows = [eventRow(2_001)];
    const api = fakeApi({
      pickAndOpenSession: vi.fn().mockResolvedValue({
        workspace: { id: "workspace-7", generation: 0, artifact_count: 2 },
        artifacts: [
          { index: 0, name: "main.qtrb", event_count: 1, tids: [7], completeness: [] },
          { index: 1, name: "capture.flight", event_count: 2, tids: [7], completeness: [{ domain: "captured_sequence", start: "9", end: "9", end_inclusive: true, cause: "overwritten", provenance: "damaged" }] },
        ],
        warnings: [],
      }),
      createProjection: vi.fn().mockResolvedValue({ projection_id: "projection-flight", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn()
        .mockResolvedValueOnce({ rows: firstRows, next_cursor: "cursor-2", total: 2_001, exact_total: true })
        .mockResolvedValueOnce({ rows: secondRows, next_cursor: null, total: 2_001, exact_total: true }),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    fireEvent.click(await screen.findByRole("button", { name: /capture\.flight/ }));
    await waitFor(() => expect(api.createProjection).toHaveBeenCalledWith("workspace-7", 1, expect.any(Object)));
    expect(screen.getByRole("navigation", { name: "Artifacts" })).toBeVisible();
    expect(await screen.findByText(/overwritten · damaged/)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Load next 2,000 events" }));
    await waitFor(() => expect(api.queryTimeline).toHaveBeenLastCalledWith("workspace-7", "projection-flight", "cursor-2", 2_000));
    await waitFor(() => expect(screen.getByRole("row", { name: /2001 thread 7/ })).toBeVisible());
    expect(screen.getByRole("row", { name: /1997 thread 7/ })).toBeVisible();
  });

  it("reveals a history target by walking later cursor pages", async () => {
    const first = eventRow(1);
    const second = eventRow(2);
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "projection-history", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn()
        .mockResolvedValueOnce({ rows: [first], next_cursor: null, total: 1, exact_total: true })
        .mockResolvedValueOnce({ rows: [second], next_cursor: null, total: 1, exact_total: true })
        .mockResolvedValueOnce({ rows: [second], next_cursor: "history-next", total: 2, exact_total: true })
        .mockResolvedValueOnce({ rows: [first], next_cursor: null, total: 2, exact_total: true }),
      locateTimeline: vi.fn().mockResolvedValue({ start: 1, cursor: "history-next" }),
      getEventDetail: vi.fn((_workspace, _artifact, row) => Promise.resolve({ artifact_index: 0, row, key: row === 1 ? first.key : second.key, kind: `detail-${row}`, provenance: "captured", raw_payload: "{}", module: null, relative_pc: null, memory_range: null })),
      getRegisterState: vi.fn().mockResolvedValue({ key: first.key, before: [], after: [] }),
      getCallTree: vi.fn().mockResolvedValue({ identity: "tree", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0, total: 0, nodes: [] }),
      getAnnotation: vi.fn().mockResolvedValue(null),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await screen.findByText(/Workspace workspace-7/);
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    fireEvent.click(await screen.findByRole("row", { name: /1 thread 7/ }));
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    fireEvent.click(await screen.findByRole("row", { name: /2 thread 7/ }));
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    fireEvent.click(await screen.findByRole("button", { name: "Reveal in unfiltered timeline" }));
    await waitFor(() => expect(api.locateTimeline).toHaveBeenCalledWith("workspace-7", "projection-history", 1, 2_000));
    await waitFor(() => expect(api.queryTimeline).toHaveBeenCalledWith("workspace-7", "projection-history", "history-next", 2_000));
    await waitFor(() => expect(api.getEventDetail).toHaveBeenLastCalledWith("workspace-7", 0, 1));
  });

  it("jumps from the call tree to an event on a later timeline page", async () => {
    const firstPage = Array.from({ length: 100 }, (_, index) => eventRow(index + 1));
    const first = firstPage[0];
    const deepCall = eventRow(101);
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "projection-calls", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn()
        .mockResolvedValueOnce({ rows: firstPage, next_cursor: "calls-next", total: 101, exact_total: true })
        .mockResolvedValueOnce({ rows: [deepCall], next_cursor: null, total: 101, exact_total: true }),
      locateTimeline: vi.fn().mockResolvedValue({ start: 100, cursor: "calls-next" }),
      getEventDetail: vi.fn((_workspace, _artifact, row) => Promise.resolve({
        artifact_index: 0,
        row,
        key: row === 1 ? first.key : deepCall.key,
        kind: row === 1 ? "origin-detail" : "deep-call-detail",
        provenance: "captured",
        raw_payload: "{}",
        module: null,
        relative_pc: null,
        memory_range: null,
      })),
      getRegisterState: vi.fn((_workspace, _artifact, row) => Promise.resolve({ key: row === 1 ? first.key : deepCall.key, before: [], after: [] })),
      getCallTree: vi.fn().mockResolvedValue({
        identity: "tree-deep",
        artifact_index: 0,
        timeline_id: "1",
        tid: 7,
        parent: null, offset: 0, total: 1,
        nodes: [{ id: 1, parent: null, child_count: 0, tid: 7, target: "0x1000", display: "deep call", source_row_start: 101, source_row_end_exclusive: 102, provenance: "captured", state: "complete" }],
      }),
      getAnnotation: vi.fn().mockResolvedValue(null),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await screen.findByText(/Workspace workspace-7/);
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    fireEvent.click(await screen.findByRole("row", { name: /^1 thread 7/ }));
    fireEvent.click(await screen.findByRole("button", { name: /deep call · complete/ }));

    await waitFor(() => expect(screen.getByText("deep-call-detail")).toBeVisible());
    expect(api.locateTimeline).toHaveBeenCalledWith("workspace-7", "projection-calls", 101, 2_000);
    expect(api.queryTimeline).toHaveBeenLastCalledWith("workspace-7", "projection-calls", "calls-next", 2_000);
  });

  it("keeps the filter editor synchronized with thread navigation", async () => {
    const row = eventRow(1);
    const createProjection = vi.fn().mockResolvedValue({ projection_id: "projection-thread", job_id: "job-1", generation: 1 });
    const api = fakeApi({
      createProjection,
      queryTimeline: vi.fn().mockResolvedValue({ rows: [row], next_cursor: null, total: 1, exact_total: true }),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await screen.findByText(/Workspace workspace-7/);
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    fireEvent.click(await screen.findByRole("button", { name: "TID 7" }));

    await waitFor(() => expect(screen.getByLabelText("TID")).toHaveValue("7"));
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(createProjection).toHaveBeenLastCalledWith(
      "workspace-7",
      0,
      expect.objectContaining({ tids: [7] }),
    ));
  });

  it("lists artifact threads that are absent from the current timeline page", async () => {
    const api = fakeApi({
      pickAndOpenSession: vi.fn().mockResolvedValue({
        workspace: { id: "workspace-7", generation: 0, artifact_count: 1 },
        artifacts: [{ index: 0, name: "main.trace.bin", event_count: 2_001, tids: [7, 9], completeness: [] }],
        warnings: [],
      }),
      createProjection: vi.fn().mockResolvedValue({ projection_id: "projection-threads", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn().mockResolvedValue({ rows: [eventRow(1)], next_cursor: "later-page", total: 2_001, exact_total: true }),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await screen.findByText(/Workspace workspace-7/);
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

    expect(await screen.findByRole("button", { name: "TID 9" })).toBeVisible();
  });

  it("locates a distant virtual viewport without walking intermediate pages", async () => {
    const distant = eventRow(8_001);
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "projection-scroll", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn()
        .mockResolvedValueOnce({ rows: [eventRow(1)], next_cursor: "second-page", total: 10_000, exact_total: true })
        .mockResolvedValueOnce({ rows: [distant], next_cursor: null, total: 10_000, exact_total: true }),
      locateTimelineOffset: vi.fn().mockResolvedValue({ start: 8_000, cursor: "distant-page" }),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await screen.findByText(/Workspace workspace-7/);
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    const timeline = await screen.findByLabelText("Timeline");
    Object.defineProperty(timeline, "clientHeight", { configurable: true, value: 320 });
    fireEvent.scroll(timeline, { target: { scrollTop: 120_000 } });

    await waitFor(() => expect(api.locateTimelineOffset).toHaveBeenCalled());
    const offset = vi.mocked(api.locateTimelineOffset).mock.calls.at(-1)?.[2] ?? 0;
    expect(offset).toBeGreaterThan(2_000);
    expect(api.queryTimeline).toHaveBeenCalledWith("workspace-7", "projection-scroll", "distant-page", 2_000);
  });

  it("shows a local rename above ELF identity and supports edit/delete", async () => {
    const digest = "b".repeat(64);
    const api = fakeApi({
      listSymbols: vi.fn().mockResolvedValue([{ module: "libdemo.so", name: "elf_name", relative_address: "0x120", size: "32", offset: "4" }]),
      getLocalSymbolName: vi.fn().mockResolvedValue({ module_digest: digest, relative_pc: "0x124", name: "local_name" }),
      upsertLocalSymbolName: vi.fn().mockResolvedValue(undefined),
      deleteLocalSymbolName: vi.fn().mockResolvedValue(undefined),
    });
    render(<ApiProvider api={api}><SymbolPane workspaceId="workspace-7" artifactIndex={2} /></ApiProvider>);
    fireEvent.change(screen.getByLabelText("Module name"), { target: { value: "libdemo.so" } });
    fireEvent.change(screen.getByLabelText("Module digest"), { target: { value: digest } });
    fireEvent.change(screen.getByLabelText("Relative PC"), { target: { value: "0x124" } });
    fireEvent.click(screen.getByRole("button", { name: "Resolve symbol" }));
    await waitFor(() => expect(screen.getByText("local_name")).toBeVisible());
    expect(screen.getByText(/ELF elf_name/)).toBeVisible();
    fireEvent.change(screen.getByLabelText("Local symbol name"), { target: { value: "edited_name" } });
    fireEvent.click(screen.getByRole("button", { name: "Save rename" }));
    await waitFor(() => expect(api.upsertLocalSymbolName).toHaveBeenCalledWith("workspace-7", 2, digest, "0x124", "edited_name"));
    expect(screen.getByText("edited_name")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Delete rename" }));
    await waitFor(() => expect(api.deleteLocalSymbolName).toHaveBeenCalledWith("workspace-7", 2, digest, "0x124"));
    expect(screen.getByText("elf_name", { selector: "strong" })).toBeVisible();
  });
});
