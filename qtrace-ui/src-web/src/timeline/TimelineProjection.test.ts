import { describe, expect, it } from "vitest";
import { TimelineProjection } from "./TimelineProjection";

describe("TimelineProjection", () => {
  it("maps ten million rows without allocating ten million entries", () => {
    const projection = new TimelineProjection(10_000_000, [{ startRow: 100, endRow: 1_000_000 }]);
    expect(projection.visibleCount).toBe(9_000_101);
    expect(projection.debugIntervalCount()).toBe(1);
    expect(projection.sourceToVisible(999_999)).toBe(100);
    expect(projection.visibleToSource(101)).toBe(1_000_000);
  });

  it("merges nested and overlapping folds and maps hidden events to their visible parent", () => {
    const projection = new TimelineProjection(100, [
      { startRow: 10, endRow: 30 },
      { startRow: 15, endRow: 40 },
      { startRow: 12, endRow: 20 },
    ]);
    expect(projection.debugIntervalCount()).toBe(1);
    expect(projection.visibleParentForSource(35)).toBe(10);
    for (const source of [0, 9, 10, 40, 99]) {
      expect(projection.visibleToSource(projection.sourceToVisible(source))).toBe(source);
    }
  });

  it("handles empty and one-row projections and rejects invalid ranges", () => {
    expect(new TimelineProjection(0).visibleCount).toBe(0);
    expect(new TimelineProjection(1).visibleToSource(0)).toBe(0);
    expect(() => new TimelineProjection(10, [{ startRow: 5, endRow: 5 }])).toThrow(RangeError);
    expect(() => new TimelineProjection(10, [{ startRow: 0, endRow: 11 }])).toThrow(RangeError);
  });
});
