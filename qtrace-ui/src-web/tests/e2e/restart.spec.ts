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
