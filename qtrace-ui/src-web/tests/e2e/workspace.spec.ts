import { expect, test } from "@playwright/test";
import { openWorkspace } from "./support";

test("opens a real mixed session and queries a bounded timeline", async ({ page }) => {
  await openWorkspace(page);
  await expect(page.getByText(/3 artifacts/)).toBeVisible();
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("grid", { name: "Visible trace rows" })).toBeVisible();
  expect(await page.getByRole("row").count()).toBeLessThanOrEqual(2_000);
});

test("rapid filter changes retain the newest generation", async ({ page }) => {
  await openWorkspace(page);
  await page.getByLabel("TID").fill("1");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.getByLabel("TID").fill("");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("grid", { name: "Visible trace rows" })).toBeVisible();
});

test("opens a degraded session and keeps healthy timelines usable", async ({ page }) => {
  await page.goto("/?fixture=one-invalid-artifact");
  await page.getByRole("button", { name: "Open session" }).click();
  await expect(page.getByRole("complementary", { name: "Workspace warnings" })).toBeVisible();
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("grid", { name: "Visible trace rows" })).toBeVisible();
});

test("opens a degraded single artifact and analyzes it", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Open artifact" }).click();
  await expect(page.getByText(/1 artifacts/)).toBeVisible();
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("grid", { name: "Visible trace rows" })).toBeVisible();
});

test("selection synchronizes detail, completeness, registers, memory, and annotations", async ({ page }) => {
  await openWorkspace(page);
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.getByRole("row").first().click();
  await expect(page.getByRole("region", { name: "Event detail" })).not.toContainText("Select an event");
  await expect(page.getByRole("region", { name: "Completeness" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Registers" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Memory" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Annotation editor" })).toBeVisible();
});

test("search hits and stable-key back/forward navigation stay synchronized", async ({ page }) => {
  await openWorkspace(page);
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.getByRole("button", { name: "Next hit" }).click();
  await page.getByRole("button", { name: "Next hit" }).click();
  await expect(page.getByRole("button", { name: "Back" })).toBeEnabled();
  await page.getByRole("button", { name: "Back" }).click();
  await expect(page.getByRole("button", { name: "Forward" })).toBeEnabled();
  await page.getByRole("button", { name: "Forward" }).click();
});

test("thread selection creates a bounded thread projection", async ({ page }) => {
  await openWorkspace(page);
  await page.getByRole("button", { name: "Apply filters" }).click();
  const thread = page.getByRole("button", { name: /^TID / }).first();
  await expect(thread).toBeVisible();
  await thread.click();
  await expect(page.getByRole("grid", { name: "Visible trace rows" })).toBeVisible();
  expect(await page.getByRole("row").count()).toBeLessThanOrEqual(2_000);
});

test("switches artifacts after entering the timeline and exposes Flight completeness", async ({ page }) => {
  await openWorkspace(page);
  await page.getByRole("button", { name: "Apply filters" }).click();
  const artifacts = page.getByRole("navigation", { name: "Artifacts" });
  await expect(artifacts).toBeVisible();
  await artifacts.getByRole("button", { name: /capture\.flight\.bin/ }).click();
  await expect(artifacts.getByRole("button", { name: /capture\.flight\.bin/ })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("grid", { name: "Visible trace rows" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Completeness" })).toContainText("captured_sequence");
});

test("jumps to a distant viewport and reuses the cached first segment", async ({ page }) => {
  test.setTimeout(60_000);
  const pageSize = 2_000;
  const pageCount = 6;
  const total = pageSize * pageCount;
  let firstPageRequests = 0;
  let pageRequests = 0;
  let locationRequests = 0;
  const cursors: Array<string | null> = [];
  await page.route(/\/locate_timeline_offset$/, async (route) => {
    locationRequests += 1;
    const request = route.request().postDataJSON() as { offset: number };
    const pageIndex = Math.floor(request.offset / pageSize);
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: { start: pageIndex * pageSize, cursor: pageIndex === 0 ? null : String(pageIndex) } }) });
  });
  await page.route(/\/query_timeline$/, async (route) => {
    pageRequests += 1;
    const request = route.request().postDataJSON() as { cursor: string | null };
    cursors.push(request.cursor);
    const pageIndex = request.cursor === null ? 0 : Number(request.cursor);
    if (pageIndex === 0) firstPageRequests += 1;
    const first = pageIndex * pageSize;
    const rows = Array.from({ length: pageSize }, (_, offset) => {
      const sourceRow = first + offset;
      return { source_row: sourceRow, key: { artifact_sha256: "a".repeat(64), timeline_id: "1", record_ordinal: String(sourceRow), source_offset: String(sourceRow * 8), sequence: String(sourceRow + 1), tid: 7 }, kind: "instruction", provenance: "captured", discontinuity: false, location: `lib.so+0x${sourceRow.toString(16)}`, symbol: null, summary: "mov x0, x1" };
    });
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: { rows, next_cursor: pageIndex + 1 < pageCount ? String(pageIndex + 1) : null, total, exact_total: true } }) });
  });
  await openWorkspace(page);
  await page.getByRole("button", { name: "Apply filters" }).click();
  const timeline = page.getByRole("region", { name: "Timeline" });
  await timeline.evaluate((element) => { (element as HTMLElement).style.height = "320px"; });
  const scrollTop = await timeline.evaluate((element, rowCount) => { element.scrollTop = (rowCount - 10) * 24; element.dispatchEvent(new Event("scroll", { bubbles: true })); return element.scrollTop; }, total);
  expect(scrollTop).toBeGreaterThan(250_000);
  await expect.poll(() => pageRequests).toBe(2);
  expect(locationRequests).toBe(1);
  expect(cursors).toEqual([null, "5"]);
  await expect(page.getByRole("row", { name: /11991 thread 7/ })).toBeVisible({ timeout: 30_000 });
  await timeline.evaluate((element) => { element.scrollTop = 0; element.dispatchEvent(new Event("scroll", { bubbles: true })); });
  await expect(page.getByRole("row", { name: /^1 thread 7 / })).toBeVisible({ timeout: 30_000 });
  await expect.poll(() => firstPageRequests).toBe(1);
});

test("call-tree nodes fold and jump through the workspace", async ({ page }) => {
  let childRequests = 0;
  await page.route(/\/get_call_tree$/, (route) => {
    const request = route.request().postDataJSON() as { parent: number | null; expected_identity: string | null };
    const child = request.parent === 1;
    if (child) {
      expect(request.expected_identity).toBe("e2e-tree");
      childRequests += 1;
    }
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: {
      identity: "e2e-tree", artifact_index: 0, timeline_id: "1", tid: 1, parent: child ? 1 : null, offset: 0, total: 1,
      nodes: child
        ? [{ id: 2, parent: 1, child_count: 0, tid: 1, target: "0x1010", display: "child", source_row_start: 1, source_row_end_exclusive: 2, provenance: "derived", state: "incomplete" }]
        : [{ id: 1, parent: null, child_count: 1, tid: 1, target: "0x1000", display: "root", source_row_start: 0, source_row_end_exclusive: 2, provenance: "captured", state: "complete" }],
    } }) });
  });
  await openWorkspace(page);
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.getByRole("row").first().click();
  await page.getByRole("button", { name: "Expand root" }).click();
  await expect(page.getByRole("button", { name: /child · incomplete/ })).toBeVisible();
  await expect.poll(() => childRequests).toBe(1);
  await page.getByRole("button", { name: "Collapse root" }).click();
  await expect(page.getByRole("button", { name: /child · incomplete/ })).toBeHidden();
  await page.getByRole("button", { name: "Expand root" }).click();
  await expect.poll(() => childRequests).toBe(1);
  await page.getByRole("button", { name: /child · incomplete/ }).click();
});

test("reversed projection completion never queries the stale projection", async ({ page }) => {
  let delayedProjection = "";
  const queried = new Set<string>();
  await page.route(/\/create_projection$/, async (route) => {
    const request = route.request().postDataJSON() as { filter: { tids: number[] } };
    const response = await route.fetch();
    const envelope = await response.json() as { ok: { projection_id: string } };
    if (request.filter.tids.length > 0) {
      delayedProjection = envelope.ok.projection_id;
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
    await route.fulfill({ response });
  });
  await page.route(/\/query_timeline$/, async (route) => {
    const request = route.request().postDataJSON() as { projection_id: string };
    queried.add(request.projection_id);
    await route.continue();
  });
  await openWorkspace(page);
  await page.getByLabel("TID").fill("1");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.getByLabel("TID").fill("");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("grid", { name: "Visible trace rows" })).toBeVisible();
  await page.waitForTimeout(400);
  expect(delayedProjection).not.toBe("");
  expect(queried.has(delayedProjection)).toBe(false);
});

test("cancelling a visible long semantic job retains the workspace", async ({ page }) => {
  let cancelled = false;
  await page.route(/\/list_jobs$/, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: cancelled ? [] : [{ id: "semantic-long", workspace_id: "e2e", kind: "projection", state: "running", progress: { completed: "1", total: "1000000" }, error: null }] }) }));
  await page.route(/\/cancel_job$/, async (route) => { cancelled = true; await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: null }) }); });
  await openWorkspace(page);
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("button", { name: "Close" })).toBeEnabled();
  await expect(page.getByText(/Workspace /)).toBeVisible();
});
