import type { FoldRange } from "./types";

interface HiddenInterval { start: number; end: number; hiddenBefore: number; visibleEntry: number }

export class TimelineProjection {
  readonly visibleCount: number;
  private readonly intervals: HiddenInterval[];

  constructor(readonly sourceCount: number, folds: FoldRange[] = []) {
    if (!Number.isSafeInteger(sourceCount) || sourceCount < 0) throw new RangeError("invalid source row count");
    const hidden = folds.map(({ startRow, endRow }) => {
      if (!Number.isSafeInteger(startRow) || !Number.isSafeInteger(endRow) || startRow < 0 || startRow >= endRow || endRow > sourceCount) {
        throw new RangeError("invalid fold range");
      }
      return { start: startRow + 1, end: endRow };
    }).filter((range) => range.start < range.end).sort((a, b) => a.start - b.start || a.end - b.end);
    const merged: Array<{ start: number; end: number }> = [];
    for (const range of hidden) {
      const last = merged.at(-1);
      if (last !== undefined && range.start <= last.end) last.end = Math.max(last.end, range.end);
      else merged.push({ ...range });
    }
    let prefix = 0;
    this.intervals = merged.map((range) => {
      const interval = { ...range, hiddenBefore: prefix, visibleEntry: range.start - 1 - prefix };
      prefix += range.end - range.start;
      return interval;
    });
    this.visibleCount = sourceCount - prefix;
  }

  sourceToVisible(sourceRow: number): number {
    this.assertSource(sourceRow);
    const index = this.firstIntervalEndingAfter(sourceRow);
    const interval = this.intervals[index];
    if (interval !== undefined && sourceRow >= interval.start) return interval.visibleEntry;
    const hidden = index === 0 ? 0 : this.hiddenThrough(index - 1);
    return sourceRow - hidden;
  }

  visibleToSource(visibleRow: number): number {
    if (!Number.isSafeInteger(visibleRow) || visibleRow < 0 || visibleRow >= this.visibleCount) throw new RangeError("invalid visible row");
    let low = 0;
    let high = this.intervals.length;
    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      if (this.intervals[mid].visibleEntry < visibleRow) low = mid + 1;
      else high = mid;
    }
    const hidden = low === 0 ? 0 : this.hiddenThrough(low - 1);
    return visibleRow + hidden;
  }

  visibleParentForSource(sourceRow: number): number { return this.sourceToVisible(sourceRow); }
  debugIntervalCount(): number { return this.intervals.length; }

  private firstIntervalEndingAfter(row: number): number {
    let low = 0;
    let high = this.intervals.length;
    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      if (this.intervals[mid].end <= row) low = mid + 1;
      else high = mid;
    }
    return low;
  }
  private hiddenThrough(index: number): number {
    const item = this.intervals[index];
    return item.hiddenBefore + item.end - item.start;
  }
  private assertSource(row: number) {
    if (!Number.isSafeInteger(row) || row < 0 || row >= this.sourceCount) throw new RangeError("invalid source row");
  }
}
