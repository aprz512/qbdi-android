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
