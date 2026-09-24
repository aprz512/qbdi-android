import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { VirtualTimeline } from "./VirtualTimeline";

describe("VirtualTimeline summaries", () => {
  it("announces the indexed location, attached symbol and instruction summary", () => {
    render(<VirtualTimeline rows={[{
      source_row: 4,
      key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: "4", source_offset: "64", sequence: "4", tid: 7 },
      kind: "instruction", provenance: "captured", discontinuity: false,
      location: "lib.so+0x120", symbol: "function+0x4", summary: "B.EQ x0, #0x4",
    }]} />);
    expect(screen.getByRole("row", { name: /lib\.so\+0x120 function\+0x4 B\.EQ x0, #0x4/ })).toBeVisible();
  });
});
