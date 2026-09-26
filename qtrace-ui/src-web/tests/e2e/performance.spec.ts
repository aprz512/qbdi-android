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

test("records real rich service-to-UI latency", async ({ page }, testInfo) => {
  test.skip(!process.env.QTRACE_E2E_FIXTURE_ROOT, "Requires generated rich fixture root");
  test.setTimeout(120_000);
  await page.goto("/");
  const started = await page.evaluate(() => performance.now());
  await page.getByRole("button", { name: "Open artifact", exact: true }).click();
  await expect(page.getByText(/Workspace /)).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("button", { name: /100006 events/ })).toBeVisible();
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("row", { name: /^1 thread .*B\.EQ/ })).toBeVisible();
  const openMs = await page.evaluate((time) => performance.now() - time, started);
  const samples: number[] = [];
  for (let index = 0; index < 50; index += 1) {
    const before = await page.evaluate(() => performance.now());
    const response = page.waitForResponse(/\/query_timeline$/);
    await page.getByRole("button", { name: "Apply filters" }).click();
    expect((await response).ok()).toBeTruthy();
    await expect(page.getByRole("row", { name: /^1 thread .*B\.EQ/ })).toBeVisible();
    samples.push(await page.evaluate((time) => performance.now() - time, before));
  }
  const domRows = await page.getByRole("row").count();
  expect(domRows).toBeLessThan(100);
  const evidence = { mode: "measurement_only", source: "real_service", events: 100_006,
    open_first_visible_ms: openMs, apply_filter_ms: samples, dom_rows: domRows };
  await testInfo.attach("rich-ui-latency", { body: JSON.stringify(evidence, null, 2), contentType: "application/json" });
  console.log(JSON.stringify(evidence));
});
