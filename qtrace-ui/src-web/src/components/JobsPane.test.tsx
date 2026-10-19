import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { JobDto } from "../api/generated";
import { JobsPane } from "./JobsPane";

function opening(): JobDto {
  return {
    id: "1", workspace_id: "1", kind: "open", state: "running", error: null,
    progress: { completed: "0", total: "1", detail: {
      stage: "build_index", artifact: "large.trace.bin", processed_bytes: "9007199254740993", processed_events: "8192", processed_rows: "0",
    } },
  };
}

describe("open progress", () => {
  it("shows stage work while a single artifact is still opening, with exact integer counts", () => {
    const job = opening();
    const { rerender } = render(<JobsPane jobs={[job]} onCancel={vi.fn()} />);
    expect(screen.getByText("open · running · 0/1")).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent("Building index · large.trace.bin · 9,007,199,254,740,993 bytes processed · 8,192 events processed");
    rerender(<JobsPane jobs={[{ ...job, progress: { ...job.progress, detail: { ...job.progress.detail!, stage: "reopen_cache", processed_bytes: "1024", processed_events: "0" } } }]} onCancel={vi.fn()} />);
    expect(screen.getByRole("status")).toHaveTextContent("Reopening cache");
    expect(screen.queryByText(/remaining|%/)).not.toBeInTheDocument();
  });

  it("keeps cancellation visible until a terminal state and prevents duplicate cancellation", async () => {
    const cancel = vi.fn().mockResolvedValue(undefined);
    const job = opening();
    const { rerender } = render(<JobsPane jobs={[job]} onCancel={cancel} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Cancelling…" })).toBeDisabled();
    await waitFor(() => expect(cancel).toHaveBeenCalledExactlyOnceWith("1"));
    rerender(<JobsPane jobs={[{ ...job, state: "cancelled" }]} onCancel={cancel} />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByText("open · cancelled · 0/1")).toBeVisible();
  });

  it("allows retrying cancellation when submission fails", async () => {
    render(<JobsPane jobs={[opening()]} onCancel={vi.fn().mockRejectedValue(new Error("offline"))} />);
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Cancel" })).toBeEnabled());
  });
});
