import { describe, expect, it, vi } from "vitest";
import type { EventRowDto, TimelinePageDto } from "../api/generated";
import { SegmentCache } from "./SegmentCache";
import { TimelinePages } from "./TimelinePages";

const identity = { workspaceId: "w", projectionId: "p", generation: 1 };
const row = (source_row: number): EventRowDto => ({
  source_row, key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(source_row),
    source_offset: String(source_row * 8), sequence: null, tid: null },
  kind: "instruction", provenance: "captured", discontinuity: false, location: "lib.so+0x0", symbol: null, summary: "mov x0, x1",
});
const page = (start = 0): TimelinePageDto => ({ rows: Array.from({ length: 2_000 }, (_, i) => row(start + i)),
  next_cursor: start < 8_000 ? `page-${start + 2_000}` : null, total: 10_000, exact_total: true });
const location = (offset: number) => {
  const start = Math.floor(offset / 2_000) * 2_000;
  return { start, cursor: start === 0 ? null : `page-${start}` };
};
const fakeApi = () => ({
  queryTimeline: vi.fn(async (_workspace: string, _projection: string, cursor: string | null) => page(cursor === null ? 0 : Number(cursor.slice(5)))),
  locateTimeline: vi.fn(async (_workspace: string, _projection: string, offset: number) => location(offset)),
  locateTimelineOffset: vi.fn(async (_workspace: string, _projection: string, offset: number) => location(offset)),
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

describe("TimelinePages", () => {
  it("stops a superseded location before requesting its page", async () => {
    const pending = deferred<ReturnType<typeof location>>();
    const api = fakeApi();
    api.locateTimeline.mockReturnValue(pending.promise);
    const pages = new TimelinePages(api, identity);
    const old = pages.locate(2_010).catch(error => error);
    await pages.range(4_010, 4_030);
    pending.resolve(location(2_010));
    expect(await old).toMatchObject({ name: "AbortError" });
    expect(api.queryTimeline).toHaveBeenCalledTimes(1);
    expect(api.queryTimeline).toHaveBeenCalledWith("w", "p", "page-4000", 2_000);
  });

  it("shares an in-flight page across adjacent viewports and accepts only the latest navigation", async () => {
    const pending = deferred<TimelinePageDto>();
    const api = fakeApi();
    api.queryTimeline.mockReturnValue(pending.promise);
    const pages = new TimelinePages(api, identity);
    const first = pages.range(2_010, 2_030).catch(error => error);
    await vi.waitFor(() => expect(api.queryTimeline).toHaveBeenCalledTimes(1));
    const second = pages.range(2_020, 2_040);
    await vi.waitFor(() => expect(api.locateTimelineOffset).toHaveBeenCalledTimes(2));
    pending.resolve(page(2_000));
    expect(await first).toMatchObject({ name: "AbortError" });
    expect((await second)[0].start).toBe(2_000);
    await pages.range(2_050, 2_060);
    expect(api.queryTimeline).toHaveBeenCalledTimes(1);
  });

  it("coalesces repeated locations and preserves a shared request after one consumer cancels", async () => {
    const pending = deferred<TimelinePageDto>();
    const located = deferred<ReturnType<typeof location>>();
    const api = fakeApi();
    api.queryTimeline.mockReturnValue(pending.promise);
    api.locateTimelineOffset.mockReturnValue(located.promise);
    const pages = new TimelinePages(api, identity);
    const controller = new AbortController();
    const first = pages.range(2_010, 2_030, controller.signal).catch(error => error);
    const second = pages.range(2_010, 2_040);
    controller.abort();
    located.resolve(location(2_010));
    await vi.waitFor(() => expect(api.queryTimeline).toHaveBeenCalledTimes(1));
    pending.resolve(page(2_000));
    expect(await first).toMatchObject({ name: "AbortError" });
    expect((await second)[0].page.rows[0].source_row).toBe(2_000);
    expect(api.locateTimelineOffset).toHaveBeenCalledTimes(1);
    await expect(pages.first(controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    expect(api.queryTimeline).toHaveBeenCalledTimes(1);
  });

  it("discards a closed projection's late response without caching or affecting the replacement", async () => {
    const pending = deferred<TimelinePageDto>();
    const api = fakeApi();
    api.queryTimeline.mockReturnValueOnce(pending.promise);
    const writes = vi.spyOn(SegmentCache.prototype, "set");
    const pages = new TimelinePages(api, identity);
    const first = pages.first().catch(error => error);
    pages.dispose();
    pending.resolve(page());
    expect(await first).toMatchObject({ name: "AbortError" });
    expect(writes).not.toHaveBeenCalled();
    const replacement = new TimelinePages(api, { ...identity, generation: 2 });
    expect(pages.matches(identity)).toBe(false);
    expect(replacement.matches(identity)).toBe(false);
    expect(replacement.matches({ ...identity, generation: 2 })).toBe(true);
    await replacement.first();
    expect(api.queryTimeline).toHaveBeenCalledTimes(2);
    writes.mockRestore();
  });

  it("retains LRU pages and refetches both page and location after eviction", async () => {
    const api = fakeApi();
    const pages = new TimelinePages(api, identity, { maxSegments: 2 });
    await pages.first();
    await pages.range(2_010, 2_030);
    await pages.range(10, 30);
    await pages.range(4_010, 4_030);
    await pages.range(2_010, 2_030);
    expect(api.queryTimeline.mock.calls.map(call => call[2])).toEqual([null, "page-2000", "page-4000", "page-2000"]);
    expect(api.locateTimelineOffset.mock.calls.map(call => call[2])).toEqual([2_010, 4_010, 2_010]);
  });

  it("loads a range spanning page boundaries and pages in both directions", async () => {
    const api = fakeApi();
    const pages = new TimelinePages(api, identity);
    const segments = await pages.range(1_995, 2_005);
    expect(segments.map(segment => segment.start)).toEqual([0, 2_000]);
    expect((await pages.previous(segments[1]))[0].start).toBe(0);
    expect((await pages.next(segments[1]))[0].start).toBe(4_000);
    expect((await pages.locate(4_050))[0].start).toBe(4_000);
    expect(api.queryTimeline).toHaveBeenCalledTimes(3);
    expect(api.locateTimeline).toHaveBeenCalledWith("w", "p", 4_050, 2_000);
  });

  it("locates distant offsets directly, including an evicted first page", async () => {
    const api = fakeApi();
    const pages = new TimelinePages(api, identity, { maxSegments: 1 });
    await pages.first();
    expect((await pages.range(4_000_000_010, 4_000_000_030))[0].start).toBe(4_000_000_000);
    await pages.range(0, 30);
    expect(api.queryTimeline.mock.calls.map(call => call[2])).toEqual([null, "page-4000000000", null]);
    expect(api.locateTimelineOffset).toHaveBeenCalledTimes(2);
  });

  it("accounts for a page once without serializing it, and keeps oversized pages uncached", async () => {
    const api = fakeApi();
    const pages = new TimelinePages(api, identity);
    const stringify = vi.spyOn(JSON, "stringify");
    await pages.first();
    await pages.range(10, 30);
    const calls = stringify.mock.calls.length;
    stringify.mockRestore();
    expect(calls).toBe(0);
    expect(api.queryTimeline).toHaveBeenCalledTimes(1);
    const small = new TimelinePages(api, identity, { maxBytes: 1 });
    await small.first();
    await small.first();
    expect(api.queryTimeline).toHaveBeenCalledTimes(3);
  });

  it("retries failed transport calls and suppresses a superseded transport failure", async () => {
    const api = fakeApi();
    const pending = deferred<TimelinePageDto>();
    api.queryTimeline.mockReturnValueOnce(pending.promise);
    const pages = new TimelinePages(api, identity);
    const first = pages.first().catch(error => error);
    await pages.range(2_010, 2_030);
    pending.reject(new Error("old failure"));
    expect(await first).toMatchObject({ name: "AbortError" });
    api.queryTimeline.mockRejectedValueOnce(new Error("offline"));
    await expect(pages.first()).rejects.toThrow("offline");
    expect((await pages.first())[0].start).toBe(0);
    expect(api.queryTimeline).toHaveBeenCalledTimes(4);
  });

  it("reports cursor cycles and returns no view for a missing location", async () => {
    const api = fakeApi();
    api.queryTimeline.mockResolvedValue({ rows: [row(0)], next_cursor: "cycle", total: 5, exact_total: true });
    const pages = new TimelinePages(api, identity);
    await expect(pages.range(0, 5)).rejects.toThrow("Timeline cursor cycle detected");
    expect(api.queryTimeline).toHaveBeenCalledTimes(2);
    const missingApi = { ...api, locateTimeline: vi.fn(async () => null), locateTimelineOffset: vi.fn(async () => null) };
    const missing = new TimelinePages(missingApi, identity);
    expect(await missing.locate(1)).toEqual([]);
    expect(await missing.range(1, 5)).toEqual([]);
  });
});
