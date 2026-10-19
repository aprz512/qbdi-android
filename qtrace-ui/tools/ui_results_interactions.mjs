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
const output = path.resolve(process.argv[2] ?? path.join(root, "artifacts/ui-layout-state-2026-10-19/interactions"));
fs.mkdirSync(output, { recursive: true });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const report = { method: "Actual Chromium interactions against the retained Xiaomi Flight capture and authenticated release Rust service. Covers summaries, report/single-artifact context, >2,000 real results, cross-page hits, empty results, and a delayed real response across workspace replacement.", checks: [], page_errors: [], summaries: [] };
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
// The fixed E2E single-artifact picker uses main.trace.bin. Give it a copy of
// the retained Flight without changing any original capture or session JSON.
const sourceSession = path.join(fixture.fixture_root, "sessions/valid-mixed");
const diagnosticRoot = path.join(output, "fixture-root");
const sessionCopy = path.join(diagnosticRoot, "sessions/valid-mixed");
fs.mkdirSync(path.join(sessionCopy, "artifacts"), { recursive: true });
for (const name of fs.readdirSync(sourceSession)) {
  if (name.endsWith(".json")) fs.copyFileSync(path.join(sourceSession, name), path.join(sessionCopy, name));
}
const flightName = fs.readdirSync(path.join(sourceSession, "artifacts")).find(name => name.endsWith(".flight.bin"));
fs.copyFileSync(path.join(sourceSession, "artifacts", flightName), path.join(sessionCopy, "artifacts", flightName));
fs.copyFileSync(path.join(sessionCopy, "artifacts", flightName), path.join(sessionCopy, "artifacts/main.trace.bin"));
report.picker_fixture = { root: diagnosticRoot, source_name: flightName, note: "Copied retained Flight at the fixed single-artifact picker path; session JSON is unchanged, and both API artifact digests must match the original." };
try {
  const token = crypto.randomBytes(16).toString("hex");
  const log = fs.openSync(path.join(output, "service.log"), "w");
  service = spawn(servicePath, ["--fixture-root", diagnosticRoot, "--xdg-root", path.join(output, "data"), "--token", token], { cwd: root, stdio: ["ignore", "pipe", log] });
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
  const answer = command => page.waitForResponse(item => item.url().endsWith("/" + command)).then(async http => {
    const body = await http.json();
    if (!http.ok() || !Object.hasOwn(body, "ok")) throw new Error(command + ": " + JSON.stringify(body));
    return body.ok;
  });
  const act = async (command, action) => { const reading = answer(command); await action(); return reading; };
  const apply = kind => act("query_timeline", async () => {
    await page.getByLabel("Kind", { exact: true }).fill(kind);
    await page.getByRole("button", { name: "Apply filters", exact: true }).click();
  });
  const results = () => page.getByRole("region", { name: "Search results", exact: true });
  const detail = () => page.getByRole("region", { name: "Event detail", exact: true });
  const expectSelection = async (expected, action) => {
    const selected = await act("get_event_detail", action);
    expect(selected.row).toBe(expected.source_row);
    expect(selected.key).toEqual(expected.key);
    await expect(detail().locator("dd").nth(2)).toHaveText(expected.key.record_ordinal);
    return selected;
  };
  await page.goto("http://localhost:1421");
  const opened = await act("pick_and_open_session", () => page.getByRole("button", { name: "Open session", exact: true }).click());
  expect(opened.context).toEqual(fixture.expected.context);
  expect(opened.artifacts[0].event_count).toBe(fixture.expected.event_count);
  await expect(page.getByLabel("Session context", { exact: true })).toContainText(fixture.expected.context.package);
  expect(opened.context.profile).toBeNull();
  await expect(page.getByLabel("Session context", { exact: true })).toContainText("unavailable");
  report.checks.push("report context equals retained report; missing profile remains unavailable");
  for (const kind of ["instruction", "memory", "semantic_call", "discontinuity"]) {
    const projection = await apply(kind);
    expect(projection.rows.length).toBeGreaterThan(0);
    const row = projection.rows[0];
    expect(row.key.artifact_sha256).toBe(fixture.expected.sha256);
    expect(row.summary.length).toBeGreaterThan(0);
    expect(Buffer.byteLength(row.summary)).toBeLessThanOrEqual(160);
    const timeline = page.getByRole("region", { name: "Timeline", exact: true });
    await timeline.evaluate(element => { element.scrollTop = 0; element.dispatchEvent(new Event("scroll", { bubbles: true })); });
    const visible = page.getByRole("row").first();
    await expect(visible).toHaveAttribute("title", `${row.symbol ?? ""} ${row.summary}`.trim());
    expect(await visible.getAttribute("aria-label")).toContain(row.summary);
    const selected = await expectSelection(row, () => results().getByRole("listitem").first().getByRole("button").click());
    expect(selected.raw_payload.length).toBeGreaterThan(0);
    if (kind === "discontinuity") expect(await visible.getAttribute("aria-label")).toContain("gap");
    report.summaries.push({ kind, source_row: row.source_row, location: row.location, summary: row.summary, provenance: row.provenance, detail_sha256: digest(selected) });
  }
  report.checks.push("instruction, memory, semantic, and discontinuity summaries match actual rendered accessible rows and typed details");
  const first = await apply("instruction");
  expect(first.total).toBeGreaterThan(2000);
  expect(first.rows).toHaveLength(2000);
  const second = await act("query_timeline", () => results().getByRole("button", { name: "Next results page", exact: true }).click());
  await expect(results()).toContainText("Page 2 of");
  expect(second.rows).toHaveLength(2000);
  await expectSelection(second.rows[0], () => results().getByRole("listitem").first().getByRole("button").click());
  await expectSelection(first.rows.at(-1), () => results().getByRole("button", { name: "Previous hit", exact: true }).click());
  await expect(results()).toContainText("Page 1 of");
  await expectSelection(second.rows[0], () => results().getByRole("button", { name: "Next hit", exact: true }).click());
  await expect(results()).toContainText("Page 2 of");
  await act("query_timeline", () => results().getByRole("button", { name: "Next results page", exact: true }).click());
  await expect(results()).toContainText("Page 3 of");
  await act("query_timeline", () => results().getByRole("button", { name: "Previous results page", exact: true }).click());
  await expect(results()).toContainText("Page 2 of");
  report.results = { total: first.total, page_size: first.rows.length, second_page_first: second.rows[0].key, previous_hit: first.rows.at(-1).key };
  report.checks.push("real >2,000 matches: next/previous pages and hits cross page 1/2 in both directions");
  await page.getByLabel("Sequence", { exact: true }).fill("18446744073709551614:18446744073709551615");
  const empty = await apply("instruction");
  expect(empty.total).toBe(0);
  await expect(results()).toContainText("No rows on this page");
  await expect(results().getByRole("button", { name: "Next hit", exact: true })).toBeDisabled();
  report.checks.push("empty result keeps navigation disabled");
  await page.getByLabel("Sequence", { exact: true }).fill("");
  await apply("instruction");
  let held = false, release;
  const delayed = new Promise(resolve => { release = resolve; });
  await page.route(/\/query_timeline$/, async route => {
    const request = route.request().postDataJSON();
    if (request.workspace_id === opened.workspace.id && request.cursor !== null) {
      const response = await route.fetch();
      held = true;
      await delayed;
      await route.fulfill({ response });
    } else await route.continue();
  });
  await results().getByRole("button", { name: "Next results page", exact: true }).click();
  await expect.poll(() => held, { timeout: 60_000 }).toBe(true);
  await act("close_workspace", () => page.getByRole("button", { name: "Close", exact: true }).click());
  const reopened = await act("pick_and_open_session", () => page.getByRole("button", { name: "Open session", exact: true }).click());
  expect(reopened.workspace.id).not.toBe(opened.workspace.id);
  await apply("instruction");
  release();
  await page.waitForTimeout(100);
  await expect(results()).toContainText("Page 1 of");
  await expect(results()).toHaveAttribute("aria-busy", "false");
  expect(await page.getByRole("alert").allTextContents()).toEqual([]);
  report.checks.push("delayed real results response cannot change replacement workspace or add a stale error");
  await page.unroute(/\/query_timeline$/);
  const artifact = await act("pick_and_open_artifact", () => page.getByRole("button", { name: "Open artifact", exact: true }).click());
  expect(artifact.context).toBeNull();
  expect(artifact.missing_capabilities).toContain("effective_config");
  await expect(page.getByText("Single artifact. Session context is unavailable.")).toBeVisible();
  await expect(page.getByLabel("Session context", { exact: true })).toHaveCount(0);
  const artifactRows = await apply("instruction");
  expect(artifactRows.rows[0].key.artifact_sha256).toBe(fixture.expected.sha256);
  report.checks.push("same retained artifact opens without fabricated session context and remains queryable");
  report.passed = report.page_errors.length === 0;
  await context.close();
} catch (error) {
  report.error = String(error.stack ?? error);
  report.passed = false;
} finally {
  await browser?.close();
  await stop(vite);
  await stop(service);
  fs.writeFileSync(path.join(output, "interactions.json"), JSON.stringify(report, null, 2) + "\n");
}
console.log(JSON.stringify({ passed: report.passed, output, checks: report.checks, error: report.error }));
if (!report.passed) process.exitCode = 1;
