import { describe, expect, it } from "vitest";
import { SegmentCache } from "./SegmentCache";

describe("SegmentCache", () => {
  it("evicts by weight and recency and rejects oversize entries", () => {
    const cache = new SegmentCache<string>({ maxBytes: 10, maxSegments: 2 });
    expect(cache.set("w:p:1:0", "a", 4)).toBe(true);
    expect(cache.set("w:p:1:1", "b", 4)).toBe(true);
    expect(cache.get("w:p:1:0")).toBe("a");
    cache.set("w:p:1:2", "c", 4);
    expect(cache.get("w:p:1:1")).toBeUndefined();
    expect(cache.count).toBe(2);
    expect(cache.currentWeight).toBe(8);
    expect(cache.set("oversize", "x", 11)).toBe(false);
  });

  it("accounts for replacement weight and isolates full identity keys", () => {
    const cache = new SegmentCache<string>({ maxBytes: 20, maxSegments: 4 });
    cache.set("session-a:projection:1", "old", 8);
    cache.set("session-a:projection:1", "new", 3);
    cache.set("session-b:projection:1", "other", 4);
    expect(cache.currentWeight).toBe(7);
    expect(cache.get("session-a:projection:1")).toBe("new");
    expect(cache.get("session-b:projection:1")).toBe("other");
  });

  it("refreshes matched entries and releases all accounting on clear", () => {
    const cache = new SegmentCache<string>({ maxBytes: 8, maxSegments: 2 });
    cache.set("a", "first", 4);
    cache.set("b", "second", 4);
    expect(cache.find(value => value === "first")).toBe("first");
    cache.set("c", "third", 4);
    expect(cache.get("b")).toBeUndefined();
    cache.clear();
    expect(cache.count).toBe(0);
    expect(cache.currentWeight).toBe(0);
    expect(cache.find(() => true)).toBeUndefined();
  });
});
