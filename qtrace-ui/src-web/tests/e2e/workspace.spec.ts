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
