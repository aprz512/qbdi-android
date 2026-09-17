import type { TimelinePageDto } from "../api/generated";
import type { PageRequest, RowRange, ViewportGeometry } from "./types";

type FetchPage = (request: PageRequest, signal: AbortSignal) => Promise<TimelinePageDto>;
type Schedule = (callback: () => void) => void;

export class ViewportController {
  private pending: PageRequest | null = null;
  private scheduled = false;
  private active: { request: PageRequest; controller: AbortController } | null = null;
  private pages: TimelinePageDto[] = [];

  constructor(private readonly fetchPage: FetchPage, private readonly schedule: Schedule = defaultSchedule) {}

  static rangeForViewport(geometry: ViewportGeometry): RowRange {
    if (geometry.rowHeight <= 0 || geometry.canvasHeight < 0 || geometry.totalRows < 0) throw new RangeError("invalid viewport geometry");
    const visible = Math.ceil(geometry.canvasHeight / geometry.rowHeight);
    const first = Math.floor(Math.max(0, geometry.scrollOffset) / geometry.rowHeight);
    const overscan = Math.ceil(visible * 0.25);
    return { start: Math.max(0, first - overscan), end: Math.min(geometry.totalRows, first + visible + overscan) };
  }

  request(next: PageRequest): void {
    if (next.start < 0 || next.end < next.start) throw new RangeError("invalid request range");
    if (this.active !== null && (!sameIdentity(this.active.request, next) || !overlaps(this.active.request, next))) {
      this.active.controller.abort();
      this.active = null;
    }
    if (this.pending !== null && sameIdentity(this.pending, next) && touches(this.pending, next)) {
      this.pending = { ...next, start: Math.min(this.pending.start, next.start), end: Math.max(this.pending.end, next.end) };
    } else {
      this.pending = next;
    }
    if (!this.scheduled) {
      this.scheduled = true;
      this.schedule(() => this.flush());
    }
  }

  cancel(): void {
    this.pending = null;
    this.active?.controller.abort();
    this.active = null;
  }

  currentPages(): readonly TimelinePageDto[] { return this.pages; }

  private flush(): void {
    this.scheduled = false;
    const request = this.pending;
    this.pending = null;
    if (request === null) return;
    const controller = new AbortController();
    this.active = { request, controller };
    void this.fetchPage(request, controller.signal).then((page) => {
      if (controller.signal.aborted || this.active === null || !exactRequest(this.active.request, request)) return;
      this.pages = [page];
      this.active = null;
    }).catch(() => {
      if (this.active !== null && exactRequest(this.active.request, request)) this.active = null;
    });
  }
}

const sameIdentity = (a: PageRequest, b: PageRequest) => a.workspaceId === b.workspaceId && a.projectionId === b.projectionId && a.generation === b.generation;
const overlaps = (a: RowRange, b: RowRange) => a.start < b.end && b.start < a.end;
const touches = (a: RowRange, b: RowRange) => a.start <= b.end && b.start <= a.end;
const exactRequest = (a: PageRequest, b: PageRequest) => sameIdentity(a, b) && a.start === b.start && a.end === b.end;
const defaultSchedule: Schedule = (callback) => {
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(callback);
  else queueMicrotask(callback);
};
