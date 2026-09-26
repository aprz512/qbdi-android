import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiProvider } from "../api/ApiContext";
import { E2eQtraceApi } from "../api/E2eQtraceApi";
import type { TimelinePageDto } from "../api/generated";
import { ResultsPane } from "./ResultsPane";

function page(start: number, count: number, total: number, next_cursor: string | null, exact_total = true): TimelinePageDto {
  return {
    total, next_cursor, exact_total,
    rows: Array.from({ length: count }, (_, index) => ({
      source_row: (start + index) * 3,
      key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(start + index), source_offset: "0", sequence: String(start + index), tid: 7 },
      kind: "instruction", provenance: "captured", discontinuity: false,
      location: "lib.so+0x0", symbol: null, summary: "nop",
    })),
  };
}

function visibleOrdinals() {
  return Array.from(screen.getByRole("list").querySelectorAll("button"), (button) => button.textContent);
}

describe("ResultsPane", () => {
  it("reaches every page beyond 2,000 hits and crosses hit boundaries without retaining other pages", async () => {
    const pages = [page(0, 2_000, 4_501, "second"), page(2_000, 2_000, 4_501, "third"), page(4_000, 501, 4_501, null)];
    const api = new E2eQtraceApi();
    api.queryTimeline = vi.fn(async (_workspace, _projection, cursor) => pages[cursor === "third" ? 2 : cursor === "second" ? 1 : 0]);
    api.locateTimelineOffset = vi.fn(async (_workspace, _projection, offset) => ({ start: Math.floor(offset / 2_000) * 2_000, cursor: offset >= 2_000 ? "second" : null }));
    const onJump = vi.fn();
    render(<ApiProvider api={api}><ResultsPane workspaceId="w" projectionId="p" initialPage={pages[0]} onJump={onJump} /></ApiProvider>);
    expect(screen.getByText("4501 results · exact total")).toBeVisible();
    expect(visibleOrdinals()).toEqual(pages[0].rows.map((row) => `instruction · ${row.key.record_ordinal}`));
    fireEvent.click(screen.getByText("instruction · 1999"));
    fireEvent.click(screen.getByText("Next hit"));
    await waitFor(() => expect(onJump).toHaveBeenLastCalledWith(6_000));
    expect(visibleOrdinals()).toEqual(pages[1].rows.map((row) => `instruction · ${row.key.record_ordinal}`));
    fireEvent.click(screen.getByText("Previous hit"));
    await waitFor(() => expect(onJump).toHaveBeenLastCalledWith(5_997));
    expect(api.locateTimelineOffset).toHaveBeenLastCalledWith("w", "p", 1_999, 2_000);
    fireEvent.click(screen.getByText("Next results page"));
    await screen.findByText("Page 2 of 3 · Results 2001–4000");
    fireEvent.click(screen.getByText("Next results page"));
    await screen.findByText("Page 3 of 3 · Results 4001–4501");
    expect(visibleOrdinals()).toEqual(pages[2].rows.map((row) => `instruction · ${row.key.record_ordinal}`));
    expect(screen.getByText("Next results page")).toBeDisabled();
    fireEvent.click(screen.getByText("instruction · 4500"));
    expect(onJump).toHaveBeenLastCalledWith(13_500);
    expect(screen.getByText("Next hit")).toBeDisabled();
    fireEvent.click(screen.getByText("Previous results page"));
    await screen.findByText("Page 2 of 3 · Results 2001–4000");
    expect(visibleOrdinals()).toHaveLength(2_000);
    expect(api.locateTimelineOffset).toHaveBeenLastCalledWith("w", "p", 3_999, 2_000);
  }, 15_000);

  it("retries a pending empty cursor page, exposes errors, and marks the eventual total exact", async () => {
    const api = new E2eQtraceApi();
    api.queryTimeline = vi.fn()
      .mockRejectedValueOnce({ code: "query.failed", stage: "query", source: null, retryable: true, detail: "Try again" })
      .mockResolvedValueOnce(page(0, 0, 0, "watermark", false))
      .mockResolvedValueOnce(page(0, 1, 1, null));
    render(<ApiProvider api={api}><ResultsPane workspaceId="w" projectionId="p" initialPage={page(0, 0, 0, "watermark", false)} onJump={vi.fn()} /></ApiProvider>);
    expect(screen.getByText("At least 0 results · indexing")).toBeVisible();
    fireEvent.click(screen.getByText("Next results page"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Try again");
    fireEvent.click(screen.getByText("Next results page"));
    await waitFor(() => expect(screen.getByText("Next results page")).toBeEnabled());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Next results page"));
    await screen.findByText("1 results · exact total");
    expect(screen.getByText("Page 1 of 1 · Results 1–1")).toBeVisible();
    expect(api.queryTimeline).toHaveBeenCalledTimes(3);
    expect(api.queryTimeline).toHaveBeenLastCalledWith("w", "p", "watermark", 2_000);
  });

  it("ignores a page response and its jump after the projection is replaced", async () => {
    const api = new E2eQtraceApi();
    let resolve: (value: TimelinePageDto) => void = () => {};
    api.queryTimeline = vi.fn(() => new Promise<TimelinePageDto>((done) => { resolve = done; }));
    const onJump = vi.fn();
    const view = render(<ApiProvider api={api}><ResultsPane key="old" workspaceId="w" projectionId="old" initialPage={page(0, 1, 2, "next")} onJump={onJump} /></ApiProvider>);
    fireEvent.click(screen.getByRole("button", { name: "instruction · 0" }));
    fireEvent.click(screen.getByText("Next hit"));
    view.rerender(<ApiProvider api={api}><ResultsPane key="new" workspaceId="w" projectionId="new" initialPage={page(10, 1, 1, null)} onJump={onJump} /></ApiProvider>);
    await act(async () => resolve(page(1, 1, 2, null)));
    expect(screen.getByRole("button", { name: "instruction · 10" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "instruction · 1" })).not.toBeInTheDocument();
    expect(onJump).toHaveBeenCalledTimes(1);
  });
});
