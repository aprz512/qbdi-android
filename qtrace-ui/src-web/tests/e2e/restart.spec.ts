import { expect, test } from "@playwright/test";
import { openWorkspace, restartService } from "./support";

test("comment and highlight survive a service restart with the same XDG data root", async ({ page }) => {
  await openWorkspace(page);
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.getByRole("row").first().click();
  await page.getByLabel("Comment").fill("restart comment");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByLabel("Highlight").fill("important");
  await page.getByRole("button", { name: "Save highlight" }).click();
  await expect(page.getByText("Committed: restart comment")).toBeVisible();
  await expect(page.getByText("Committed highlight: important")).toBeVisible();

  await restartService();
  await page.getByRole("button", { name: "Open session" }).click();
  await expect(page.getByText(/Workspace /)).toBeVisible();
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.getByRole("row").first().click();
  await expect(page.getByLabel("Comment")).toHaveValue("restart comment");
  await expect(page.getByLabel("Highlight")).toHaveValue("important");
});

test("local rename survives a service restart with the same XDG data root", async ({ page }) => {
  const digest = "b".repeat(64);
  await page.route(/\/list_symbols$/, (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: [] }) }));
  await openWorkspace(page);
  await page.getByLabel("Module digest").fill(digest);
  await page.getByLabel("Relative PC").fill("0x120");
  await page.getByLabel("Local symbol name").fill("restart_name");
  const [, saved] = await Promise.all([
    page.getByRole("button", { name: "Save rename" }).click(),
    page.waitForResponse((response) => response.url().endsWith("/upsert_local_symbol_name") && response.ok()),
  ]);
  expect((await saved.json()).ok).toBeNull();

  await restartService();
  await page.reload();
  await page.getByRole("button", { name: "Open session" }).click();
  await page.getByLabel("Module digest").fill(digest);
  await page.getByLabel("Relative PC").fill("0x120");
  const [, resolved] = await Promise.all([
    page.getByRole("button", { name: "Resolve symbol" }).click(),
    page.waitForResponse((response) => response.url().endsWith("/get_local_symbol_name") && response.ok()),
  ]);
  expect((await resolved.json()).ok).toMatchObject({ name: "restart_name" });
  await expect(page.getByLabel("Local symbol name")).toHaveValue("restart_name");
});
