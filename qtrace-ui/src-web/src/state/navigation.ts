import type { EventKeyDto } from "../api/generated";

export interface NavigationEntry { workspaceId: string; projectionId: string; eventKey: EventKeyDto }

export class NavigationHistory {
  private entries: NavigationEntry[] = [];
  private position = -1;
  constructor(private readonly limit = 256) {
    if (limit < 1) throw new RangeError("navigation limit must be positive");
  }
  push(entry: NavigationEntry): void {
    this.entries.splice(this.position + 1);
    this.entries.push(entry);
    if (this.entries.length > this.limit) this.entries.shift();
    this.position = this.entries.length - 1;
  }
  back(): NavigationEntry | null {
    if (this.position <= 0) return null;
    return this.entries[--this.position];
  }
  forward(): NavigationEntry | null {
    if (this.position >= this.entries.length - 1) return null;
    return this.entries[++this.position];
  }
  current(): NavigationEntry | null { return this.entries[this.position] ?? null; }
  get length(): number { return this.entries.length; }
  get canGoBack(): boolean { return this.position > 0; }
  get canGoForward(): boolean { return this.position >= 0 && this.position < this.entries.length - 1; }
}
