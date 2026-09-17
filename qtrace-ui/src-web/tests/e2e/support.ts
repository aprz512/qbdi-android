import { expect, type Page } from "@playwright/test";
export const RUNTIME_FILE = ".e2e-runtime.json";
export async function openWorkspace(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Open session" }).click();
  await expect(page.getByText(/Workspace /)).toBeVisible();
}
