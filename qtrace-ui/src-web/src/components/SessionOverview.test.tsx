import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { OpenWorkspaceDto } from "../api/generated";
import { SessionOverview } from "./SessionOverview";

describe("SessionOverview", () => {
  it("shows missing context for a single artifact", () => {
    const opened: OpenWorkspaceDto = {
      workspace: { id: "workspace-single", generation: 0, artifact_count: 1 },
      artifacts: [{ index: 0, name: "main.trace.bin", status: "indexed", event_count: 9, tids: [7], completeness: [] }],
      warnings: [], context: null,
      missing_capabilities: ["package", "device", "target", "effective_config"],
    };
    render(<SessionOverview opened={opened} />);
    expect(screen.getByText("Single artifact. Session context is unavailable.")).toBeVisible();
    expect(screen.getByText("Unavailable context: package, device, target, effective_config")).toBeVisible();
    expect(screen.getByRole("button", { name: /main\.trace\.bin — 9 events · indexed/ })).toBeVisible();
  });
});
