export interface RequestGuard {
  readonly revision: number;
  isCurrent(signal?: AbortSignal): boolean;
  accept(update: () => void): void;
}

// Every owner rejects both late successes and late failures. Transport calls may
// finish after cancellation; only the current owner may publish their result.
export class RequestScope {
  private revision = 0;
  private active = true;

  activate(): void { this.active = true; }
  invalidate(): void { this.revision += 1; }
  dispose(): void { this.active = false; this.invalidate(); }
  next(): RequestGuard { this.invalidate(); return this.capture(); }

  capture(): RequestGuard {
    const revision = this.revision;
    const isCurrent = (signal?: AbortSignal) => this.active && revision === this.revision && !signal?.aborted;
    return { revision, isCurrent, accept: update => { if (isCurrent()) update(); } };
  }
}
