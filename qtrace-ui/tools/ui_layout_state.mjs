#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { once } from "node:events";
import { createRequire } from "node:module";

const root = path.resolve(import.meta.dirname, "../..");
const web = path.join(root, "qtrace-ui/src-web");
const require = createRequire(path.join(web, "package.json"));
const { chromium, expect } = require("@playwright/test");
const output = path.resolve(process.argv[2] ?? path.join(root, "artifacts/ui-layout-state-2026-10-19/baseline"));
fs.mkdirSync(output, { recursive: true });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const report = { method: "Actual Chromium UI with authenticated Rust E2E service. 200% zoom uses half-sized CSS viewport and deviceScaleFactor=2; it does not test WebKit or OS scaling.", scenarios: [], page_errors: [] };
const servicePath = path.resolve(process.env.QTRACE_E2E_SERVER ?? path.join(root, "qtrace-ui/target/release/e2e_server"));
report.service_sha256 = crypto.createHash("sha256").update(fs.readFileSync(servicePath)).digest("hex");
let service, vite, browser;

async function stop(child) {
  if (!child || child.exitCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  await Promise.race([exited, delay(3_000)]);
  if (child.exitCode === null) { child.kill("SIGKILL"); await exited; }
}

try {
  const token = crypto.randomBytes(16).toString("hex");
  const log = fs.openSync(path.join(output, "service.log"), "w");
  service = spawn(servicePath, ["--fixture-root", path.join(root, "qtrace-ui/fixtures"), "--xdg-root", path.join(output, "data"), "--token", token], { cwd: root, stdio: ["ignore", "pipe", log] });
  const ready = await Promise.race([
    new Promise((resolve, reject) => {
      createInterface({ input: service.stdout }).once("line", line => { try { resolve(JSON.parse(line)); } catch (error) { reject(error); } });
      service.once("exit", code => reject(new Error(`Service exited: ${code}`)));
    }),
    delay(15_000).then(() => { throw new Error("Service readiness timeout"); }),
  ]);
  const viteLog = fs.openSync(path.join(output, "vite.log"), "w");
  vite = spawn(path.join(web, "node_modules/.bin/vite"), ["--mode", "e2e", "--port", "1421", "--strictPort"], { cwd: web, stdio: ["ignore", viteLog, viteLog], env: { ...process.env, VITE_E2E_URL: ready.url, VITE_E2E_TOKEN: ready.token } });
  for (let attempt = 0; ; attempt++) {
    if (attempt === 100 || vite.exitCode !== null) throw new Error("Vite readiness failed");
    try { if ((await fetch("http://localhost:1421")).ok) break; } catch { /* Startup only. */ }
    await delay(100);
  }
  browser = await chromium.launch();
  report.chromium = browser.version();
  for (const width of [800, 1024, 1366]) for (const zoom of [1, 2]) {
    const context = await browser.newContext({ viewport: { width: Math.floor(width / zoom), height: Math.floor(900 / zoom) }, deviceScaleFactor: zoom });
    const page = await context.newPage();
    page.on("pageerror", error => report.page_errors.push(error.message));
    await page.goto("http://localhost:1421");
    await page.getByRole("button", { name: "Open session", exact: true }).click();
    await expect(page.getByText(/Workspace /)).toBeVisible();
    await page.getByRole("button", { name: "Apply filters", exact: true }).click();
    await page.getByRole("row").first().click();
    await expect(page.getByLabel("Comment", { exact: true })).toBeVisible();
    await page.getByLabel("Comment", { exact: true }).fill("long_unbroken_comment_".repeat(100));
    const scenario = { width, zoom, css_width: Math.floor(width / zoom), layout: await page.evaluate(() => {
      const panels = [...document.querySelectorAll(".left-dock,.workspace,.right-dock,.bottom-dock")].map(element => {
        const box = element.getBoundingClientRect();
        return { panel: element.className, left: box.left, width: box.width, right: box.right, scroll_width: element.scrollWidth, client_width: element.clientWidth };
      });
      return { viewport: innerWidth, document_width: document.documentElement.scrollWidth, panels };
    }), keyboard: [] };
    const shortcuts = page.getByRole("navigation", { name: "Panel shortcuts", exact: true });
    if (await shortcuts.count()) {
      for (const label of ["Timeline", "Trace", "Details", "Results"]) {
        await page.evaluate(() => { document.body.tabIndex = -1; document.body.focus(); document.body.removeAttribute("tabindex"); window.scrollTo(0, 0); });
        await page.keyboard.press("Control+Home");
        await page.keyboard.press("Tab");
        for (let i = 0; i < ["Timeline", "Trace", "Details", "Results"].indexOf(label); i++) await page.keyboard.press("Tab");
        await expect(shortcuts.getByRole("link", { name: label, exact: true })).toBeFocused();
        await page.keyboard.press("Enter");
        scenario.keyboard.push(await page.evaluate(() => ({ target: document.activeElement?.id, focus_visible: document.activeElement?.matches(":focus-visible"), outline: getComputedStyle(document.activeElement).outlineStyle })));
      }
    }
    scenario.long_text = await page.locator(".right-dock").evaluate(element => ({ scroll_width: element.scrollWidth, client_width: element.clientWidth, raw_wrap: getComputedStyle(element.querySelector("pre")).whiteSpace }));
    await page.evaluate(() => {
      for (const panel of document.querySelectorAll(".left-dock,.right-dock,.workspace,.bottom-dock > section")) panel.scrollTop = 0;
      document.body.tabIndex = -1; document.body.focus(); document.body.removeAttribute("tabindex"); window.scrollTo(0, 0);
    });
    await page.screenshot({ path: path.join(output, `${width}-${zoom}x.png`), fullPage: true });
    report.scenarios.push(scenario);
    await context.close();
  }
  report.passed = report.page_errors.length === 0 && report.scenarios.every(scenario => scenario.layout.document_width <= scenario.css_width && scenario.long_text.scroll_width <= scenario.long_text.client_width && scenario.keyboard.length === 4 && scenario.keyboard.every(item => item.target && item.focus_visible && item.outline !== "none"));
} catch (error) {
  report.error = String(error.stack ?? error);
  report.passed = false;
} finally {
  await browser?.close();
  await stop(vite);
  await stop(service);
  fs.writeFileSync(path.join(output, "layout.json"), JSON.stringify(report, null, 2) + "\n");
}
console.log(JSON.stringify({ passed: report.passed, output, scenarios: report.scenarios.map(item => ({ width: item.width, zoom: item.zoom, document_width: item.layout.document_width, keyboard: item.keyboard })), error: report.error }));
if (!report.passed) process.exitCode = 1;
