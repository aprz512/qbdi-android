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
const output = path.resolve(process.argv[2] ?? path.join(root, "artifacts/ui-layout-state-2026-10-19/elf"));
fs.mkdirSync(output, { recursive: true });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const report = { method: "Actual Chromium Attach ELF, Resolve symbol, and automatic timeline refresh within the existing projection against the authenticated Rust service and a fixed valid AArch64 ELF fixture. No API response mocks.", checks: [], page_errors: [] };
let service, vite, browser;

async function stop(child) {
  if (!child || child.exitCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  await Promise.race([exited, delay(3_000)]);
  if (child.exitCode === null) { child.kill("SIGKILL"); await exited; }
}

const digest = value => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
const elf = JSON.parse(fs.readFileSync(path.join(root, "qtrace-ui/fixtures/manifest.json"), "utf8")).fixtures.find(item => item.path === "elf/lib.so");
if (!elf) throw new Error("Valid ELF fixture is missing");
report.elf = elf;
const servicePath = path.resolve(process.env.QTRACE_E2E_SERVER ?? path.join(root, "qtrace-ui/target/release/e2e_server"));
report.service_sha256 = crypto.createHash("sha256").update(fs.readFileSync(servicePath)).digest("hex");
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
  const context = await browser.newContext({ viewport: { width: 1366, height: 1000 } });
  const page = await context.newPage();
  page.setDefaultTimeout(30_000);
  page.on("pageerror", error => report.page_errors.push(error.message));
  const answer = command => page.waitForResponse(item => item.url().endsWith("/" + command)).then(async http => ({ request: http.request().postDataJSON(), status: http.status(), body: await http.json() }));
  const act = async (command, action) => { const reading = answer(command); await action(); return reading; };
  await page.goto("http://localhost:1421");
  const opened = await act("pick_and_open_session", () => page.getByRole("button", { name: "Open session", exact: true }).click());
  expect(opened.status).toBe(200);
  await page.getByLabel("Kind", { exact: true }).fill("instruction");
  const first = await act("query_timeline", () => page.getByRole("button", { name: "Apply filters", exact: true }).click());
  expect(first.status).toBe(200);
  const row = first.body.ok.rows.find(item => item.location.startsWith("lib.so+") && item.symbol === null);
  expect(row).toBeTruthy();
  await page.getByLabel("Module name", { exact: true }).fill("lib.so");
  await page.getByLabel("Module digest", { exact: true }).fill(elf.sha256);
  await page.getByLabel("Relative PC", { exact: true }).fill("0x2345");
  const refreshing = answer("query_timeline");
  const attached = await act("pick_and_attach_elf", () => page.getByRole("button", { name: "Attach ELF", exact: true }).click());
  expect(attached.status).toBe(200);
  expect(attached.body).toEqual({ ok: null });
  const refreshed = await refreshing;
  expect(refreshed.status).toBe(200);
  expect(refreshed.request.projection_id).toBe(first.request.projection_id);
  const symbols = await act("list_symbols", () => page.getByRole("button", { name: "Resolve symbol", exact: true }).click());
  expect(symbols.status).toBe(200);
  expect(symbols.body.ok.some(item => item.name === "native_work")).toBe(true);
  const pane = page.getByRole("region", { name: "Symbols", exact: true });
  await expect(pane.locator("strong")).toHaveText("native_work");
  await expect(pane).toContainText("ELF native_work");
  report.checks.push("real Attach ELF and Resolve symbol show native_work from the verified fixture");
  const updated = refreshed.body.ok.rows.find(item => digest(item.key) === digest(row.key));
  expect(updated).toBeTruthy();
  expect(updated.symbol).toContain("native_work");
  expect(updated.summary).toBe(row.summary);
  expect(updated.location).toBe(row.location);
  expect((await page.getByRole("row").all()).length).toBeGreaterThan(0);
  await expect(page.getByRole("row").first()).toHaveAttribute("aria-label", /native_work/);
  report.before = row;
  report.after = updated;
  report.projection_id = first.request.projection_id;
  report.checks.push("automatic refresh uses the existing projection and same stable event key without changing captured location or summary");
  await page.getByLabel("Module digest", { exact: true }).fill("0".repeat(64));
  const denied = await act("pick_and_attach_elf", () => page.getByRole("button", { name: "Attach ELF", exact: true }).click());
  expect(denied.status).toBe(400);
  expect(denied.body.error.code).toBe("symbol.module_identity_mismatch");
  await expect(pane.getByRole("alert")).toContainText("symbol.module_identity_mismatch");
  await page.getByLabel("Module digest", { exact: true }).fill(elf.sha256);
  const retained = await act("list_symbols", () => page.getByRole("button", { name: "Resolve symbol", exact: true }).click());
  expect(retained.body.ok).toEqual(symbols.body.ok);
  await expect(pane.getByRole("alert")).toHaveCount(0);
  report.denied = denied;
  report.checks.push("wrong module digest is refused and the previously verified symbols remain usable");
  report.passed = report.page_errors.length === 0;
  await context.close();
} catch (error) { report.error = String(error.stack ?? error); report.passed = false; }
finally {
  await browser?.close(); await stop(vite); await stop(service);
  fs.writeFileSync(path.join(output, "elf.json"), JSON.stringify(report, null, 2) + "\n");
}
console.log(JSON.stringify({ passed: report.passed, output, checks: report.checks, error: report.error }));
if (!report.passed) process.exitCode = 1;
