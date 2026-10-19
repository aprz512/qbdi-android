import type { QtraceApi } from "../api/QtraceApi";
import type { TimelineLocationDto, TimelinePageDto } from "../api/generated";
import { SegmentCache, type SegmentCacheOptions } from "./SegmentCache";

export const TIMELINE_PAGE_SIZE = 2_000;
export interface TimelineSegment { start: number; page: TimelinePageDto }
interface TimelineIdentity { workspaceId: string; projectionId: string; generation: number }
type TimelineApi = Pick<QtraceApi, "queryTimeline" | "locateTimeline" | "locateTimelineOffset">;

export const isTimelineCancelled = (error: unknown): boolean => error instanceof DOMException && error.name === "AbortError";

// One projection owns its requests and bounded cursor metadata. Navigation state
// stays with the consumer; a newer navigation invalidates only older consumers.
export class TimelinePages {
  private readonly cache: SegmentCache<TimelineSegment>;
  private readonly pendingPages = new Map<string, Promise<TimelinePageDto>>();
  private readonly pendingLocations = new Map<string, Promise<TimelineLocationDto | null>>();
  private active = true;
  private navigation = 0;

  constructor(private readonly api: TimelineApi, readonly identity: TimelineIdentity, options: SegmentCacheOptions = {}) {
    this.cache = new SegmentCache(options);
  }

  matches(identity: TimelineIdentity): boolean {
    return this.active && this.identity.workspaceId === identity.workspaceId &&
      this.identity.projectionId === identity.projectionId && this.identity.generation === identity.generation;
  }

  dispose(): void {
    this.active = false;
    this.navigation += 1;
    this.cache.clear();
    this.pendingPages.clear();
    this.pendingLocations.clear();
  }

  first(signal?: AbortSignal): Promise<TimelineSegment[]> {
    return this.navigate(async navigation => [await this.page({ start: 0, cursor: null }, navigation, signal)], signal);
  }

  range(start: number, end: number, signal?: AbortSignal): Promise<TimelineSegment[]> {
    return this.navigate(async navigation => {
      let segment = await this.atOffset(start, navigation, signal);
      const segments: TimelineSegment[] = [];
      if (segment === null) return segments;
      const visited = new Set<string>();
      while (true) {
        segments.push(segment);
        const { page } = segment;
        if (segment.start + page.rows.length >= end || page.next_cursor === null) return segments;
        if (visited.has(page.next_cursor)) throw new Error("Timeline cursor cycle detected");
        visited.add(page.next_cursor);
        segment = await this.page({ start: segment.start + page.rows.length, cursor: page.next_cursor }, navigation, signal);
      }
    }, signal);
  }

  next(segment: TimelineSegment, signal?: AbortSignal): Promise<TimelineSegment[]> {
    return this.navigate(async navigation => segment.page.next_cursor === null ? [segment] : [await this.page({
      start: segment.start + segment.page.rows.length, cursor: segment.page.next_cursor,
    }, navigation, signal)], signal);
  }

  previous(segment: TimelineSegment, signal?: AbortSignal): Promise<TimelineSegment[]> {
    return this.navigate(async navigation => {
      const previous = await this.atOffset(Math.max(0, segment.start - 1), navigation, signal);
      return previous === null ? [] : [previous];
    }, signal);
  }

  locate(sourceRow: number, signal?: AbortSignal): Promise<TimelineSegment[]> {
    return this.navigate(async navigation => {
      const location = await this.location("row", sourceRow, navigation, signal);
      return location === null ? [] : [await this.page(location, navigation, signal)];
    }, signal);
  }

  private check(signal?: AbortSignal, navigation = this.navigation): void {
    if (!this.active || signal?.aborted || navigation !== this.navigation) throw new DOMException("Timeline request cancelled", "AbortError");
  }

  private async navigate(load: (navigation: number) => Promise<TimelineSegment[]>, signal?: AbortSignal): Promise<TimelineSegment[]> {
    this.check(signal);
    const navigation = ++this.navigation;
    try {
      const segments = await load(navigation);
      this.check(signal, navigation);
      return segments;
    } catch (error) {
      // A late failure belongs to its old navigation, even when the transport
      // cannot cancel the underlying IPC call.
      this.check(signal, navigation);
      throw error;
    }
  }

  private async atOffset(offset: number, navigation: number, signal?: AbortSignal): Promise<TimelineSegment | null> {
    this.check(signal, navigation);
    const cached = this.cache.find(segment => segment.start <= offset && offset < segment.start + segment.page.rows.length);
    if (cached !== undefined) return cached;
    const location = await this.location("offset", offset, navigation, signal);
    return location === null ? null : this.page(location, navigation, signal);
  }

  private async location(kind: "row" | "offset", value: number, navigation: number, signal?: AbortSignal): Promise<TimelineLocationDto | null> {
    this.check(signal, navigation);
    const key = `${kind}:${value}`;
    let pending = this.pendingLocations.get(key);
    if (pending === undefined) {
      const { workspaceId, projectionId } = this.identity;
      const locate = kind === "row" ? this.api.locateTimeline.bind(this.api) : this.api.locateTimelineOffset.bind(this.api);
      pending = locate(workspaceId, projectionId, value, TIMELINE_PAGE_SIZE).finally(() => this.pendingLocations.delete(key));
      this.pendingLocations.set(key, pending);
    }
    const location = await pending;
    this.check(signal, navigation);
    return location;
  }

  private async page(location: TimelineLocationDto, navigation: number, signal?: AbortSignal): Promise<TimelineSegment> {
    this.check(signal, navigation);
    const key = location.cursor === null ? "first" : `cursor:${location.cursor}`;
    const cached = this.cache.get(key);
    if (cached !== undefined) return { start: location.start, page: cached.page };
    let pending = this.pendingPages.get(key);
    if (pending === undefined) {
      const { workspaceId, projectionId } = this.identity;
      pending = this.api.queryTimeline(workspaceId, projectionId, location.cursor, TIMELINE_PAGE_SIZE).then(page => {
        if (this.active) this.cache.set(key, { start: location.start, page }, timelinePageWeight(page) + key.length * 2);
        return page;
      }).finally(() => this.pendingPages.delete(key));
      this.pendingPages.set(key, pending);
    }
    const page = await pending;
    this.check(signal, navigation);
    return { start: location.start, page };
  }
}

// Conservative accounting weight, not a browser heap limit: UTF-16 string
// lengths plus fixed object/array overhead. No JSON or temporary encoded copy.
function timelinePageWeight(page: TimelinePageDto): number {
  let weight = 128 + (page.next_cursor?.length ?? 0) * 2;
  for (const row of page.rows) {
    const key = row.key;
    weight += 320 + 2 * (row.kind.length + row.provenance.length + row.location.length +
      (row.symbol?.length ?? 0) + row.summary.length + key.artifact_sha256.length +
      key.timeline_id.length + key.record_ordinal.length + key.source_offset.length + (key.sequence?.length ?? 0));
  }
  return weight;
}
