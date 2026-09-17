import { describe, expect, it } from "vitest";
import { NavigationHistory, type NavigationEntry } from "./navigation";

const entry = (ordinal: number): NavigationEntry => ({
  workspaceId: "w", projectionId: "p", eventKey: {
    artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(ordinal), source_offset: String(ordinal), sequence: String(ordinal), tid: 1,
  },
});

describe("NavigationHistory", () => {
  it("stores stable keys, truncates branches and navigates back/forward", () => {
    const history = new NavigationHistory();
    history.push(entry(1)); history.push(entry(2)); history.push(entry(3));
    expect(history.back()?.eventKey.record_ordinal).toBe("2");
    history.push(entry(4));
    expect(history.forward()).toBeNull();
    expect(history.back()?.eventKey.record_ordinal).toBe("2");
  });
  it("caps history at 256 entries", () => {
    const history = new NavigationHistory();
    for (let index = 0; index < 300; index += 1) history.push(entry(index));
    expect(history.length).toBe(256);
  });
});
