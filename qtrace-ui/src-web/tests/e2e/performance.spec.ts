import { expect, test } from "@playwright/test";
import { openWorkspace } from "./support";

test("diagnoses a 2,000-row rich timeline render", async ({ page }) => {
  const rows = Array.from({ length: 2_000 }, (_, index) => ({
    source_row: index,
    key: {
      artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(index),
      source_offset: String(index * 56), sequence: String(index + 1), tid: 13,
    },
    kind: index % 5 === 0 ? "memory" : index % 5 === 1 ? "semantic_call" : "instruction",
    provenance: "captured", discontinuity: false,
    location: `libqtrace_rich.so+0x${(0x2000 + index * 4).toString(16)}`,
    symbol: null,
    summary: index % 5 === 0 ? "read/write [0x2000] 4 B" : index % 5 === 1 ? "jni/Lookup: rich-corpus" : "B.EQ x0, #0x4",
  }));
  await page.route(/\/query_timeline$/, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ ok: { rows, next_cursor: null, total: 2_000, exact_total: true } }),
  }));
  await openWorkspace(page);
  const started = await page.evaluate(() => performance.now());
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("row", { name: /^1 thread 13 / })).toBeVisible();
  const elapsed = await page.evaluate((time) => performance.now() - time, started);
  const count = await page.getByRole("row").count();
  expect(count).toBeLessThan(100);
  console.log(`rich_ui_first_visible_ms=${elapsed.toFixed(3)} dom_rows=${count}`);
});
