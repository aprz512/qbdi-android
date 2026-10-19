import { act, fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AnnotationEditor } from "./AnnotationEditor";

describe("persistent edit completion", () => {
  it("keeps the latest save when earlier writes finish later", async () => {
    const pending: Array<() => void> = [];
    const save = vi.fn(() => new Promise<void>(resolve => pending.push(resolve)));
    render(<AnnotationEditor comment="" onSave={save} onDelete={async () => undefined} />);
    fireEvent.change(screen.getByLabelText("Comment"), { target: { value: "first" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    fireEvent.change(screen.getByLabelText("Comment"), { target: { value: "latest" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await act(async () => pending[1]());
    await act(async () => pending[0]());
    expect(screen.getByText("Committed: latest")).toBeVisible();
    expect(save.mock.calls).toEqual([["first"], ["latest"]]);
  });

  it("ignores a rejected save after its displayed annotation changes", async () => {
    let reject!: (error: Error) => void;
    const save = () => new Promise<void>((_resolve, fail) => { reject = fail; });
    const props = { onSave: save, onDelete: async () => undefined };
    const { rerender } = render(<AnnotationEditor comment="old" {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    rerender(<AnnotationEditor comment="current" {...props} />);
    await act(async () => reject(new Error("old request failed")));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Comment")).toHaveValue("current");
  });
});
