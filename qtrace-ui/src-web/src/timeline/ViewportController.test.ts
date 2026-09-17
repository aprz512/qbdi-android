import { describe, expect, it } from "vitest";
import type { PageRequest } from "./types";
import { ViewportController } from "./ViewportController";

const request = (generation: number, start: number, end: number): PageRequest => ({ workspaceId: "w", projectionId: "p", generation, start, end });
const flush = async () => { await Promise.resolve(); await Promise.resolve(); };

describe("ViewportController", () => {
  it("calculates a bounded viewport with 25% overscan", () => {
    expect(ViewportController.rangeForViewport({ scrollOffset: 200, canvasHeight: 100, rowHeight: 10, totalRows: 100 })).toEqual({ start: 17, end: 33 });
  });

  it("coalesces adjacent requests within one frame", () => {
    const scheduled: Array<() => void> = [];
    const seen: PageRequest[] = [];
    const controller = new ViewportController(async (value) => { seen.push(value); }, (callback) => scheduled.push(callback));
    controller.request(request(1, 0, 100));
    controller.request(request(1, 100, 200));
    scheduled[0]();
    expect(seen[0]).toMatchObject({ start: 0, end: 200 });
  });

  it("does not publish an older generation that resolves last", async () => {
    const resolvers: Array<() => void> = [];
    const signals: AbortSignal[] = [];
    const controller = new ViewportController((_value, signal) => new Promise((resolve) => { signals.push(signal); resolvers.push(resolve); }), (callback) => callback());
    controller.request(request(3, 0, 100));
    controller.request(request(4, 100, 200));
    expect(signals[0].aborted).toBe(true);
    resolvers[1]();
    resolvers[0]();
    await flush();
    expect(controller.completedRequests()).toEqual([request(4, 100, 200)]);
  });

  it("aborts an overlapping request when its exact range changes", () => {
    const signals: AbortSignal[] = [];
    const controller = new ViewportController((_value, signal) => new Promise(() => { signals.push(signal); }), (callback) => callback());
    controller.request(request(1, 0, 100));
    controller.request(request(1, 50, 150));
    expect(signals[0].aborted).toBe(true);
  });
});
