import { expect, test } from "@playwright/test";
import { openWorkspace } from "./support";
test("workspace remains usable after reopen", async ({ page }) => {
  await openWorkspace(page);
  await page.getByRole("button", { name: "Close" }).click();
  await expect(page.getByText("No workspace open")).toBeVisible();
  await page.getByRole("button", { name: "Open session" }).click();
  await expect(page.getByText(/Workspace /)).toBeVisible();
});
