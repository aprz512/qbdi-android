import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AnnotationEditor } from "./AnnotationEditor";
import { FilterBar } from "./FilterBar";
import { ResultsPane } from "./ResultsPane";
import { initialState } from "../state/model";

describe("workspace workflows", () => {
  it("constructs same-field OR filter terms and validates 64-bit inputs", () => {
    const apply = vi.fn();
    render(<FilterBar onApply={apply} />);
    fireEvent.change(screen.getByLabelText("TID"), { target: { value: "7,9" } });
    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "instruction,memory" } });
    fireEvent.change(screen.getByLabelText("Sequence"), { target: { value: "1:18446744073709551615" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    expect(apply).toHaveBeenCalledWith(expect.objectContaining({ tids: [7, 9], kinds: ["instruction", "memory"], sequence: [{ first: "1", last: "18446744073709551615" }] }));
  });

  it("keeps an annotation draft when the committed write fails", async () => {
    const error = { code: "annotation.io", stage: "annotation", source: null, retryable: true, detail: "busy" };
    render(<AnnotationEditor comment="old" onSave={vi.fn().mockRejectedValue(error)} onDelete={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Comment"), { target: { value: "new draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("annotation.io"));
    expect(screen.getByLabelText("Comment")).toHaveValue("new draft");
    expect(screen.getByText("Committed: old")).toBeVisible();
  });

  it("bounds result rendering and state has no full-trace collection", () => {
    const rows = Array.from({ length: 2_001 }, (_, source_row) => ({ source_row, key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(source_row), source_offset: String(source_row), sequence: String(source_row), tid: 1 }, kind: "instruction", provenance: "captured", discontinuity: false }));
    render(<ResultsPane pages={[{ rows, next_cursor: null, total: 2_001, exact_total: false }]} onJump={() => undefined} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(2_000);
    expect(screen.getByText(/indexing/)).toBeVisible();
    expect(Object.keys(initialState).some((key) => /allEvents|eventsById/i.test(key))).toBe(false);
  });
});
