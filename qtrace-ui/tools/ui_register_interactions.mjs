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
const output = path.resolve(process.argv[2] ?? path.join(root, "artifacts/ui-layout-state-2026-10-19/registers"));
fs.mkdirSync(output, { recursive: true });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const report = { method: "50 actual Chromium result clicks against the retained Xiaomi Flight capture and authenticated release Rust service. Register DOM timing includes transport, concurrent selection requests, React, DOM checks, and browser automation; ui_ms additionally waits for the detail key. No baseline speedup is claimed.", samples: [], page_errors: [], api_errors: [] };
let service, vite, browser;

async function stop(child) {
  if (!child || child.exitCode !== null) return;
  const exited = once(child, "exit");
  child.kill("SIGTERM");
  await Promise.race([exited, delay(3_000)]);
  if (child.exitCode === null) { child.kill("SIGKILL"); await exited; }
}

const fixture = JSON.parse(fs.readFileSync(path.join(root, "artifacts/timeline-pages-2026-10-19/final/capture-scenarios.json"), "utf8")).find(item => item.name === "flight-crash");
const digest = value => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
report.fixture = fixture;
const servicePath = path.resolve(process.env.QTRACE_E2E_SERVER ?? path.join(root, "qtrace-ui/target/release/e2e_server"));
report.service_sha256 = crypto.createHash("sha256").update(fs.readFileSync(servicePath)).digest("hex");
report.frontend_sha256 = Object.fromEntries([
  "src/App.tsx", "src/state/RequestScope.ts", "src/state/useRequestScope.ts", "src/state/useEventDetails.ts",
  "src/state/usePersistentEdits.ts", "src/state/useTimelineNavigation.ts", "src/timeline/TimelinePages.ts",
  "src/timeline/VirtualTimeline.tsx", "src/timeline/TraceCanvasRenderer.ts", "src/components/AnnotationEditor.tsx",
].map(file => [file, crypto.createHash("sha256").update(fs.readFileSync(path.join(web, file))).digest("hex")]));
try {
  const token = crypto.randomBytes(16).toString("hex");
  const log = fs.openSync(path.join(output, "service.log"), "w");
  service = spawn(servicePath, ["--fixture-root", fixture.fixture_root, "--xdg-root", path.join(output, "data"), "--token", token], { cwd: root, stdio: ["ignore", "pipe", log] });
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
  page.setDefaultTimeout(60_000);
  page.on("pageerror", error => report.page_errors.push(error.message));
  page.on("response", async response => {
    if (!response.url().startsWith(ready.url) || response.ok()) return;
    const error = { command: new URL(response.url()).pathname, status: response.status() };
    try { error.body = await response.json(); } catch { /* Record status even if teardown closes the body. */ }
    report.api_errors.push(error);
  });
  const response = command => page.waitForResponse(item => item.url().endsWith("/" + command));
  await page.goto("http://localhost:1421");
  const opening = response("pick_and_open_session");
  await page.getByRole("button", { name: "Open session", exact: true }).click();
  const opened = (await (await opening).json()).ok;
  expect(opened.artifacts[0].event_count).toBe(fixture.expected.event_count);
  report.workspace = opened.workspace;
  await page.getByLabel("Kind", { exact: true }).fill("instruction");
  const firstPage = response("query_timeline");
  await page.getByRole("button", { name: "Apply filters", exact: true }).click();
  const timeline = (await (await firstPage).json()).ok;
  expect(timeline.rows[0].key.artifact_sha256).toBe(fixture.expected.sha256);
  const seen = new Map();
  const results = page.getByRole("region", { name: "Search results", exact: true });
  const registers = page.getByRole("region", { name: "Registers", exact: true });
  for (let index = 0; index < 50; index++) {
    const item = timeline.rows[index % 10];
    const started = await page.evaluate(() => performance.now());
    const reading = response("get_register_state");
    await results.getByRole("listitem").nth(index % 10).getByRole("button").click();
    const http = await reading;
    expect(http.ok()).toBe(true);
    const value = (await http.json()).ok;
    expect(value.key).toEqual(item.key);
    expect(value.before).toHaveLength(34);
    expect(value.after).toHaveLength(34);
    const identity = digest(value.key);
    const fingerprint = digest(value);
    if (seen.has(identity)) expect(fingerprint).toBe(seen.get(identity));
    else seen.set(identity, fingerprint);
    const label = cell => cell.provenance === "damaged" ? "damaged" : cell.value ?? "unknown";
    const cells = value.before.flatMap((cell, slot) => [label(cell), label(value.after[slot])]);
    await expect(registers.locator("tbody tr")).toHaveCount(34);
    await expect(registers.locator("tbody td")).toHaveText(cells);
    const registerDomMs = await page.evaluate(time => performance.now() - time, started);
    await expect(page.getByRole("region", { name: "Event detail", exact: true }).locator("dd").nth(2)).toHaveText(value.key.record_ordinal);
    const elapsed = await page.evaluate(time => performance.now() - time, started);
    report.samples.push({ click: index + 1, source_row: item.source_row, key: value.key, register_sha256: fingerprint, rendered_cells: cells.length, register_dom_ms: registerDomMs, ui_ms: elapsed });
  }
  report.unique_events = seen.size;
  report.p95_ui_ms = report.samples.map(item => item.ui_ms).sort((a, b) => a - b)[47];
  report.p95_register_dom_ms = report.samples.map(item => item.register_dom_ms).sort((a, b) => a - b)[47];
  const closing = response("close_workspace");
  await page.getByRole("button", { name: "Close", exact: true }).click();
  expect((await closing).ok()).toBe(true);
  await expect(registers.locator("tbody tr")).toHaveCount(0);
  const closed = await fetch(ready.url + "/get_register_state", { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ workspace_id: opened.workspace.id, artifact_index: 0, row: timeline.rows[0].source_row }) });
  report.closed_workspace = { status: closed.status, body: await closed.json(), note: "Closed workspace rejects further reads; Arc release is covered separately by the Rust replay lifecycle test." };
  expect(closed.ok).toBe(false);
  report.passed = report.samples.length === 50 && report.unique_events === 10 && report.page_errors.length === 0;
  await context.close();
} catch (error) {
  report.error = String(error.stack ?? error);
  report.passed = false;
} finally {
  await browser?.close();
  await stop(vite);
  await stop(service);
  fs.writeFileSync(path.join(output, "registers.json"), JSON.stringify(report, null, 2) + "\n");
}
console.log(JSON.stringify({ passed: report.passed, output, samples: report.samples.length, p95_ui_ms: report.p95_ui_ms, p95_register_dom_ms: report.p95_register_dom_ms, closed_workspace: report.closed_workspace, error: report.error }));
if (!report.passed) process.exitCode = 1;
