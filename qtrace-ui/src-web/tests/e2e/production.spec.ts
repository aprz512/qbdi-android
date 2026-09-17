import { expect, test } from "@playwright/test";
test("production selects the Tauri bridge and never calls the E2E loopback adapter", async ({ page }) => {
  const httpCalls: string[] = [];
  page.on("request", (request) => { if (request.resourceType() === "fetch") httpCalls.push(request.url()); });
  await page.goto("/");
  await page.getByRole("button", { name: "Open session" }).click();
  await expect(page.getByRole("alert")).toContainText(/client\.contract_invalid|failed|unavailable/i);
  expect(httpCalls).toEqual([]);
});
