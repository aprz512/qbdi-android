export interface SegmentCacheOptions { maxBytes?: number; maxSegments?: number }
interface Entry<T> { value: T; weight: number }

export class SegmentCache<T> {
  private readonly entries = new Map<string, Entry<T>>();
  private bytes = 0;
  readonly maxBytes: number;
  readonly maxSegments: number;

  constructor(options: SegmentCacheOptions = {}) {
    this.maxBytes = options.maxBytes ?? 32 * 1024 * 1024;
    this.maxSegments = options.maxSegments ?? 128;
    if (this.maxBytes <= 0 || this.maxSegments <= 0) throw new RangeError("cache bounds must be positive");
  }

  set(key: string, value: T, weight = estimateWeight(value)): boolean {
    if (!Number.isSafeInteger(weight) || weight < 0) throw new RangeError("invalid segment weight");
    if (weight > this.maxBytes) return false;
    const previous = this.entries.get(key);
    if (previous !== undefined) { this.bytes -= previous.weight; this.entries.delete(key); }
    this.entries.set(key, { value, weight });
    this.bytes += weight;
    while (this.bytes > this.maxBytes || this.entries.size > this.maxSegments) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      const removed = this.entries.get(oldest)!;
      this.entries.delete(oldest);
      this.bytes -= removed.weight;
    }
    return true;
  }

  get(key: string): T | undefined {
    const entry = this.entries.get(key);
    if (entry === undefined) return undefined;
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }
  get currentWeight(): number { return this.bytes; }
  get count(): number { return this.entries.size; }
}

function estimateWeight(value: unknown): number {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength + 64;
}
