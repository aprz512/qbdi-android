import { expect, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
export const RUNTIME_FILE = ".e2e-runtime.json";
export async function openWorkspace(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Open session" }).click();
  await expect(page.getByText(/Workspace /)).toBeVisible();
}
export async function restartService() {
  const runtime = JSON.parse(await readFile(RUNTIME_FILE, "utf8")) as { url: string; token: string };
  const response = await fetch(`${runtime.url}/restart_service`, { method: "POST", headers: { Authorization: `Bearer ${runtime.token}`, "Content-Type": "application/json" }, body: "{}" });
  expect(response.ok).toBeTruthy();
}
