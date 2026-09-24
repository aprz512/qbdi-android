import { describe, expect, it } from "vitest";
import type { TimelinePageDto } from "../api/generated";
import { emptyFilter, initialState } from "./model";
import { reducer } from "./reducer";

const page: TimelinePageDto = { rows: [], next_cursor: null, total: 0, exact_total: true };

describe("application reducer", () => {
  it("ignores a response from an older generation", () => {
    const state = { ...initialState, phase: "ready" as const, generation: 4, timelinePages: [page] };
    const next = reducer(state, { type: "timelinePageReceived", generation: 3, page });
    expect(next.timelinePages).toBe(state.timelinePages);
  });

  it("retains only the current bounded timeline page", () => {
    const first = { ...page, total: 4, next_cursor: "next" };
    const second = { ...page, total: 4 };
    const ready = { ...initialState, phase: "ready" as const, generation: 1 };
    const withFirst = reducer(ready, { type: "timelinePageReceived", generation: 1, page: first });
    const withSecond = reducer(withFirst, { type: "timelinePageReceived", generation: 1, page: second });
    expect(withSecond.timelinePages).toEqual([second]);
  });

  it("covers cancel, open, partial, indexing, failure, filter and close transitions", () => {
    const opening = reducer(initialState, { type: "openStarted" });
    expect(reducer(opening, { type: "pickerCancelled" }).phase).toBe("empty");
    const opened = reducer(opening, {
      type: "workspaceOpened",
      opened: {
        workspace: { id: "w", generation: 0, artifact_count: 1 },
        artifacts: [{ index: 0, name: "trace", status: "indexed", event_count: 2, tids: [7], completeness: [] }],
        warnings: ["one artifact was isolated"],
        context: null,
        missing_capabilities: ["package", "device", "target", "effective_config"],
      },
    });
    expect(opened.phase).toBe("partial");
    const replacement = reducer(opened, { type: "openStarted" });
    const cancelledReplacement = reducer(replacement, { type: "pickerCancelled" });
    expect(cancelledReplacement.opened?.workspace.id).toBe("w");
    expect(cancelledReplacement.phase).toBe("partial");
    const indexing = reducer(opened, { type: "indexingStarted", generation: 2 });
    expect(indexing.phase).toBe("indexing");
    const filtered = reducer(indexing, { type: "filterChanged", filter: { ...emptyFilter(), tids: [7] } });
    expect(filtered.generation).toBe(3);
    const failed = reducer(filtered, {
      type: "failed",
      error: { code: "x", stage: "test", source: null, retryable: false, detail: "failed" },
    });
    expect(failed.phase).toBe("failed");
    expect(reducer(failed, { type: "closed" }).phase).toBe("empty");
  });
});
