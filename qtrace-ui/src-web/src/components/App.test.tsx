import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "../App";
import { ApiProvider } from "../api/ApiContext";
import type { QtraceApi } from "../api/QtraceApi";
import type { AnnotationDto, EventDetailDto, TimelinePageDto } from "../api/generated";
import { AppStateProvider } from "../state/AppStateProvider";
import { SymbolPane } from "./SymbolPane";

function fakeApi(overrides: Partial<QtraceApi> = {}): QtraceApi {
  const unsupported = async (): Promise<never> => { throw new Error("not used"); };
  return {
    pickAndOpenSession: vi.fn().mockResolvedValue({
      workspace: { id: "workspace-7", generation: 0, artifact_count: 1 },
      artifacts: [{ index: 0, name: "main.trace.bin", status: "indexed", event_count: 42, tids: [7], completeness: [] }],
      warnings: ["worker artifact isolated"],
      context: { session_id: "session-7", mode: "run", status: "sealed", stage: "sealed", package: "com.example.fixture", device_serial: "fixture-device", device_access_mode: "run-as", target_module: "libtarget.so", profile: "full", scenes: ["entry"] },
      missing_capabilities: [],
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
    listJobs: vi.fn().mockResolvedValue([{ id: "job-1", workspace_id: "workspace-7", kind: "projection", state: "completed", progress: { completed: "1", total: "1", detail: null }, error: null }]),
    cancelJob: unsupported,
    ...overrides,
  };
}

const eventRow = (source_row: number) => ({
  source_row,
  key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(source_row), source_offset: String(source_row * 8), sequence: String(source_row), tid: 7 },
  kind: "instruction", provenance: "captured", discontinuity: false,
  location: `lib.so+0x${(source_row * 4).toString(16)}`, symbol: null, summary: "mov x0, x1",
});

describe("desktop shell", () => {
  it.each(["workspace", "projection"])("ignores an ELF attachment after replacing its %s", async replacement => {
    let attached!: () => void;
    const opened = await fakeApi().pickAndOpenSession();
    if (opened === null) throw new Error("Missing test workspace");
    const api = fakeApi({
      pickAndOpenSession: vi.fn()
        .mockResolvedValueOnce(opened)
        .mockResolvedValueOnce({ ...opened, workspace: { ...opened.workspace, id: "replacement" } }),
      createProjection: vi.fn()
        .mockResolvedValueOnce({ projection_id: "original", job_id: "job-1", generation: 1 })
        .mockResolvedValueOnce({ projection_id: "replacement", job_id: "job-1", generation: 2 }),
      queryTimeline: vi.fn()
        .mockResolvedValueOnce({ rows: [eventRow(1)], next_cursor: null, total: 1, exact_total: true })
        .mockResolvedValueOnce({ rows: [eventRow(2)], next_cursor: null, total: 1, exact_total: true }),
      pickAndAttachElf: vi.fn(() => new Promise<void>(resolve => { attached = resolve; })),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    fireEvent.click(await screen.findByRole("button", { name: "Apply filters" }));
    await screen.findByRole("row", { name: /^1 thread 7/ });
    fireEvent.change(screen.getByLabelText("Module digest"), { target: { value: "b".repeat(64) } });
    fireEvent.change(screen.getByLabelText("Relative PC"), { target: { value: "0x5" } });
    fireEvent.click(screen.getByRole("button", { name: "Attach ELF" }));
    await waitFor(() => expect(api.pickAndAttachElf).toHaveBeenCalledTimes(1));
    if (replacement === "workspace") {
      fireEvent.click(screen.getByRole("button", { name: "Open session" }));
      await screen.findByText(/Workspace replacement/);
    }
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await screen.findByRole("row", { name: /^2 thread 7/ });
    await act(async () => attached());
    expect(api.queryTimeline).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("row", { name: /^2 thread 7/ })).toBeVisible();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("refreshes cached timeline symbols after attaching ELF without rebuilding the projection", async () => {
    const row = eventRow(1);
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "symbols", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn()
        .mockResolvedValueOnce({ rows: [row], next_cursor: null, total: 1, exact_total: true })
        .mockResolvedValueOnce({ rows: [{ ...row, symbol: "native_work+0x5" }], next_cursor: null, total: 1, exact_total: true }),
      pickAndAttachElf: vi.fn().mockResolvedValue(undefined),
      locateTimelineOffset: vi.fn().mockResolvedValue({ start: 0, cursor: null }),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    fireEvent.click(await screen.findByRole("button", { name: "Apply filters" }));
    await screen.findByRole("row", { name: /^1 thread 7/ });
    fireEvent.change(screen.getByLabelText("Module name"), { target: { value: "lib.so" } });
    fireEvent.change(screen.getByLabelText("Module digest"), { target: { value: "b".repeat(64) } });
    fireEvent.change(screen.getByLabelText("Relative PC"), { target: { value: "0x5" } });
    fireEvent.click(screen.getByRole("button", { name: "Attach ELF" }));
    expect(await screen.findByRole("row", { name: /native_work\+0x5/ })).toBeVisible();
    expect(api.createProjection).toHaveBeenCalledTimes(1);
    expect(api.queryTimeline).toHaveBeenLastCalledWith("workspace-7", "symbols", null, 2_000);
  });

  it("keeps a late annotation save on its original event", async () => {
    let saved!: () => void;
    const rows = [eventRow(1), eventRow(2)];
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "edit-race", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn().mockResolvedValue({ rows, next_cursor: null, total: 2, exact_total: true }),
      getEventDetail: vi.fn((_workspace, _artifact, row) => Promise.resolve({ artifact_index: 0, row, key: rows[row - 1].key, kind: "instruction", provenance: "captured", raw_payload: "{}", module: null, relative_pc: null, memory_range: null })),
      getRegisterState: vi.fn().mockResolvedValue({ key: rows[0].key, before: [], after: [] }),
      getCallTree: vi.fn().mockResolvedValue({ identity: "tree", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0, total: 0, nodes: [] }),
      getAnnotation: vi.fn((_workspace, _artifact, row) => Promise.resolve({ key: rows[row - 1].key, comment: row === 2 ? "second event" : "", highlight: null })),
      upsertAnnotation: vi.fn(() => new Promise<void>(resolve => { saved = resolve; })),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    fireEvent.click(await screen.findByRole("button", { name: "Apply filters" }));
    fireEvent.click(await screen.findByRole("row", { name: /^1 thread 7/ }));
    fireEvent.change(await screen.findByLabelText("Comment"), { target: { value: "first event edit" } });
    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    fireEvent.click(screen.getByRole("row", { name: /^2 thread 7/ }));
    await waitFor(() => expect(screen.getByLabelText("Comment")).toHaveValue("second event"));
    saved();
    await waitFor(() => expect(screen.getByLabelText("Comment")).toHaveValue("second event"));
    expect(screen.getByText("Committed: second event")).toBeVisible();
    expect(api.upsertAnnotation).toHaveBeenCalledWith("workspace-7", 0, 1, "first event edit");
  });

  it("keeps a saved comment when its earlier annotation read arrives", async () => {
    let read!: (value: { key: ReturnType<typeof eventRow>["key"]; comment: string; highlight: string }) => void;
    const row = eventRow(1);
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "read-edit-race", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn().mockResolvedValue({ rows: [row], next_cursor: null, total: 1, exact_total: true }),
      getEventDetail: vi.fn().mockResolvedValue({ artifact_index: 0, row: 1, key: row.key, kind: "instruction", provenance: "captured", raw_payload: "{}", module: null, relative_pc: null, memory_range: null }),
      getRegisterState: vi.fn().mockResolvedValue({ key: row.key, before: [], after: [] }),
      getCallTree: vi.fn().mockResolvedValue({ identity: "tree", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0, total: 0, nodes: [] }),
      getAnnotation: vi.fn(() => new Promise<AnnotationDto>(resolve => { read = resolve; })),
      upsertAnnotation: vi.fn().mockResolvedValue(undefined),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    fireEvent.click(await screen.findByRole("button", { name: "Apply filters" }));
    fireEvent.click(await screen.findByRole("row", { name: /^1 thread 7/ }));
    fireEvent.change(await screen.findByLabelText("Comment"), { target: { value: "new comment" } });
    fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));
    await screen.findByText("Committed: new comment");
    read({ key: row.key, comment: "old comment", highlight: "preserved highlight" });
    await waitFor(() => expect(screen.getByLabelText("Highlight")).toHaveValue("preserved highlight"));
    expect(screen.getByLabelText("Comment")).toHaveValue("new comment");
  });

  it("shares a page request when adjacent virtual viewports supersede one another", async () => {
    const firstPage = { rows: Array.from({ length: 2_000 }, (_, index) => eventRow(index + 1)), next_cursor: "second", total: 6_000, exact_total: true };
    const pending: Array<(page: TimelinePageDto) => void> = [];
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "shared-page", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn((_workspace, _projection, cursor) => cursor === null
        ? Promise.resolve(firstPage)
        : new Promise<TimelinePageDto>(resolve => pending.push(resolve))),
      locateTimelineOffset: vi.fn().mockResolvedValue({ start: 2_000, cursor: "second" }),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    fireEvent.click(await screen.findByRole("button", { name: "Apply filters" }));
    await screen.findByRole("row", { name: /^1 thread 7/ });
    const timeline = screen.getByLabelText("Timeline");
    Object.defineProperty(timeline, "clientHeight", { configurable: true, value: 320 });
    fireEvent.scroll(timeline, { target: { scrollTop: 2_200 * 24 } });
    await waitFor(() => expect(pending.length).toBeGreaterThan(0));
    fireEvent.scroll(timeline, { target: { scrollTop: 2_210 * 24 } });
    await waitFor(() => expect(api.locateTimelineOffset).toHaveBeenCalledTimes(2));
    const secondPage = { rows: Array.from({ length: 2_000 }, (_, index) => eventRow(index + 2_001)), next_cursor: "third", total: 6_000, exact_total: true };
    for (const resolve of pending) resolve(secondPage);
    await screen.findByRole("row", { name: /^2211 thread 7/ });
    expect(api.queryTimeline).toHaveBeenCalledTimes(2);
  });

  it("ignores a timeline response after closing its workspace", async () => {
    let resolve!: (page: TimelinePageDto) => void;
    const api = fakeApi({
      createProjection: vi.fn().mockResolvedValue({ projection_id: "closing-page", job_id: "job-1", generation: 1 }),
      queryTimeline: vi.fn(() => new Promise<TimelinePageDto>(done => { resolve = done; })),
    });
    render(<ApiProvider api={api}><AppStateProvider><App /></AppStateProvider></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    fireEvent.click(await screen.findByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(api.queryTimeline).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Close" })).toBeDisabled());
    resolve({ rows: [eventRow(123)], next_cursor: null, total: 1, exact_total: true });
    await waitFor(() => expect(screen.queryByLabelText("Timeline")).not.toBeInTheDocument());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open session" }));
    await screen.findByText(/Workspace workspace-7/);
    expect(screen.queryByLabelText("Timeline")).not.toBeInTheDocument();
  });

  it("retries cleanup when replacing a workspace whose close initially fails", async () => {
    const closeWorkspace = vi.fn()
      .mockRejectedValueOnce(new Error("busy"))
      .mockResolvedValue(undefined);
    const api = fakeApi({
      pickAndOpenSession: vi.fn()
        .mockResolvedValueOnce({ workspace: { id: "workspace-old", generation: 0, artifact_count: 0 }, artifacts: [], warnings: [], context: null, missing_capabilities: ["package", "device", "target", "effective_config"] })
        .mockResolvedValueOnce({ workspace: { id: "workspace-new", generation: 0, artifact_count: 0 }, artifacts: [], warnings: [], context: null, missing_capabilities: ["package", "device", "target", "effective_config"] }),
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
    expect(screen.getByText("com.example.fixture")).toBeVisible();
    expect(screen.getByText("fixture-device · run-as")).toBeVisible();
    expect(screen.getByText("libtarget.so")).toBeVisible();
    expect(screen.getByText("full")).toBeVisible();
    expect(screen.getByText("entry")).toBeVisible();
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
          { index: 0, name: "main.qtrb", status: "indexed", event_count: 1, tids: [7], completeness: [] },
          { index: 1, name: "capture.flight", status: "indexed", event_count: 2, tids: [7], completeness: [{ domain: "captured_sequence", start: "9", end: "9", end_inclusive: true, cause: "overwritten", provenance: "damaged" }] },
        ],
        warnings: [],
        context: null,
        missing_capabilities: ["package", "device", "target", "effective_config"],
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
    const results = within(screen.getByRole("region", { name: "Search results" }));
    expect(results.getByText("2001 results · exact total")).toBeVisible();
    expect(results.getByText("Page 1 of 2 · Results 1–2000")).toBeVisible();
    expect(results.getByText("instruction · 1")).toBeVisible();
    expect(results.queryByText("instruction · 2001")).not.toBeInTheDocument();
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
    expect(await screen.findByText("detail-1")).toBeVisible();
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
        artifacts: [{ index: 0, name: "main.trace.bin", status: "indexed", event_count: 2_001, tids: [7, 9], completeness: [] }],
        warnings: [],
        context: null,
        missing_capabilities: ["package", "device", "target", "effective_config"],
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
