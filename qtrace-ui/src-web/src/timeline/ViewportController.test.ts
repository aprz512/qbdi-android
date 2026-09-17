import { describe, expect, it } from "vitest";
import type { TimelinePageDto } from "../api/generated";
import type { PageRequest } from "./types";
import { ViewportController } from "./ViewportController";

const page = (total: number): TimelinePageDto => ({ rows: [], next_cursor: null, total, exact_total: true });
const request = (generation: number, start: number, end: number): PageRequest => ({ workspaceId: "w", projectionId: "p", generation, start, end });
const flush = async () => { await Promise.resolve(); await Promise.resolve(); };

describe("ViewportController", () => {
  it("calculates a bounded viewport with 25% overscan", () => {
    expect(ViewportController.rangeForViewport({ scrollOffset: 200, canvasHeight: 100, rowHeight: 10, totalRows: 100 })).toEqual({ start: 17, end: 33 });
  });

  it("coalesces adjacent requests within one frame", () => {
    const scheduled: Array<() => void> = [];
    const seen: PageRequest[] = [];
    const controller = new ViewportController(async (value) => { seen.push(value); return page(1); }, (callback) => scheduled.push(callback));
    controller.request(request(1, 0, 100));
    controller.request(request(1, 100, 200));
    scheduled[0]();
    expect(seen[0]).toMatchObject({ start: 0, end: 200 });
  });

  it("does not publish an older generation that resolves last", async () => {
    const resolvers: Array<(value: TimelinePageDto) => void> = [];
    const controller = new ViewportController(() => new Promise((resolve) => resolvers.push(resolve)), (callback) => callback());
    controller.request(request(3, 0, 100));
    controller.request(request(4, 100, 200));
    resolvers[1](page(4));
    resolvers[0](page(3));
    await flush();
    expect(controller.currentPages()).toEqual([page(4)]);
  });
});
