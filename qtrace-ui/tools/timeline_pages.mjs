// Frontend diagnostic: actual App, deterministic synthetic pages, no Rust/device timing.
import { createServer } from "../src-web/node_modules/vite/dist/node/index.js";
import { chromium } from "../src-web/node_modules/playwright/index.mjs";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { arch, cpus, platform, release } from "node:os";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../src-web");
const output = process.argv[2];
if (!output) throw new Error("Usage: node qtrace-ui/tools/timeline_pages.mjs /absolute/evidence.json");
const html = `<!doctype html><html><body><div id="root"></div><script type="module">
import React from "react";
import { createRoot } from "react-dom/client";
import App from "/src/App.tsx";
import { ApiProvider } from "/src/api/ApiContext.tsx";
import { AppStateProvider } from "/src/state/AppStateProvider.tsx";
window.stats = { queries: [], locations: 0, serializations: 0, serialization_ms: 0 };
const stringify = JSON.stringify;
JSON.stringify = function(value, ...args) {
  if (!value || !Array.isArray(value.rows) || !("next_cursor" in value)) return stringify.call(this, value, ...args);
  const started = performance.now();
  try { return stringify.call(this, value, ...args); }
  finally { window.stats.serializations++; window.stats.serialization_ms += performance.now() - started; }
};
const total = 100_000;
const row = source_row => ({ source_row, key: { artifact_sha256: "a".repeat(64), timeline_id: "1",
  record_ordinal: String(source_row), source_offset: String(source_row * 8), sequence: String(source_row + 1), tid: 7 },
  kind: "instruction", provenance: "captured", discontinuity: false, location: "lib.so+0x" + source_row.toString(16),
  symbol: "symbol " + String(source_row).padEnd(64, "x"), summary: "mov x0, x1 " + "x".repeat(120) });
const cursorFor = start => start === 0 ? null : "page-" + start;
const location = offset => { const start = Math.floor(offset / 2_000) * 2_000; return { start, cursor: cursorFor(start) }; };
const api = {
  pickAndOpenSession: async () => ({ workspace: { id: "diagnostic", generation: 0, artifact_count: 1 },
    artifacts: [{ index: 0, name: "synthetic.qtrb", status: "indexed", event_count: total, tids: [7], completeness: [] }],
    warnings: [], context: null, missing_capabilities: [] }),
  createProjection: async () => ({ projection_id: "projection", job_id: "job", generation: 1 }),
  listJobs: async () => [{ id: "job", workspace_id: "diagnostic", kind: "projection", state: "completed",
    progress: { completed: "1", total: "1", detail: null }, error: null }],
  queryTimeline: async (_workspace, _projection, cursor) => {
    window.stats.queries.push(cursor);
    await new Promise(done => setTimeout(done, 60));
    const start = cursor === null ? 0 : Number(cursor.slice(5));
    return { rows: Array.from({ length: Math.min(2_000, total - start) }, (_, index) => row(start + index)),
      next_cursor: start + 2_000 >= total ? null : cursorFor(start + 2_000), total, exact_total: true };
  },
  locateTimelineOffset: async (_workspace, _projection, offset) => { window.stats.locations++; return location(offset); },
};
createRoot(document.getElementById("root")).render(React.createElement(ApiProvider, { api },
  React.createElement(AppStateProvider, null, React.createElement(App))));
</script></body></html>`;
const server = await createServer({
  root, server: { host: "127.0.0.1", port: 0 },
  plugins: [{ name: "timeline-diagnostic", configureServer(vite) {
    vite.middlewares.use("/__timeline_diagnostic", async (_request, response, next) => {
      try {
        response.setHeader("Content-Type", "text/html");
        response.end(await vite.transformIndexHtml("/__timeline_diagnostic", html));
      } catch (error) { next(error); }
    });
  } }],
});
let browser;
const samples = [];
try {
  await server.listen();
  browser = await chromium.launch({ headless: true });
  for (let round = 0; round < 5; round++) {
    const page = await browser.newPage({ viewport: { width: 1366, height: 900 } });
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__timeline_diagnostic`);
    await page.getByRole("button", { name: "Open session" }).click();
    await page.getByRole("button", { name: "Apply filters" }).click();
    await page.getByRole("grid", { name: "Visible trace rows" }).waitFor();
    await page.waitForFunction(() => document.querySelector('[role="row"]'));
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("HeapProfiler.collectGarbage");
    const before = await cdp.send("Runtime.getHeapUsage");
    const workload = await page.evaluate(async () => {
      const frame = () => new Promise(done => requestAnimationFrame(done));
      const timeline = document.querySelector('[aria-label="Timeline"]');
      timeline.style.height = "320px";
      const frameIntervals = [], loads = [], observed = [];
      let previous, handle, maxDom = 0;
      const record = time => {
        if (previous !== undefined) frameIntervals.push(time - previous);
        previous = time;
        handle = requestAnimationFrame(record);
      };
      handle = requestAnimationFrame(record);
      // Three adjacent viewports arrive while one page is still in flight.
      for (const index of [...Array.from({ length: 24 }, (_, i) => i + 1), 24, 23, 22, 21, 24]) {
        const started = performance.now();
        for (const shift of [100, 104, 108]) {
          timeline.scrollTop = (index * 2_000 + shift) * 24;
          timeline.dispatchEvent(new Event("scroll", { bubbles: true }));
          await frame();
        }
        const expected = String(index * 2_000 + 109) + " thread 7 ";
        while (![...timeline.querySelectorAll('[role="row"]')].some(item => item.getAttribute("aria-label").startsWith(expected))) {
          if (performance.now() - started > 5_000) throw new Error("Missing viewport " + index);
          await frame();
        }
        loads.push(performance.now() - started);
        observed.push(index * 2_000 + 108);
        maxDom = Math.max(maxDom, timeline.querySelectorAll('[role="row"]').length);
      }
      cancelAnimationFrame(handle);
      const p95 = values => [...values].sort((a, b) => a - b)[Math.ceil(values.length * 0.95) - 1];
      return { ...window.stats, observed, loads_ms: loads, load_p95_ms: p95(loads),
        frame_intervals_ms: frameIntervals, frame_p95_ms: p95(frameIntervals), max_dom_rows: maxDom };
    });
    await cdp.send("HeapProfiler.collectGarbage");
    const after = await cdp.send("Runtime.getHeapUsage");
    if (errors.length || workload.max_dom_rows > 40) throw new Error(JSON.stringify({ errors, workload }));
    const sample = { round: round + 1, heap_growth_bytes: after.usedSize - before.usedSize, ...workload };
    samples.push(sample);
    console.log(JSON.stringify({ round: sample.round, queries: sample.queries.length,
      serializations: sample.serializations, serialization_ms: sample.serialization_ms,
      load_p95_ms: sample.load_p95_ms, frame_p95_ms: sample.frame_p95_ms }));
    await page.close();
  }
  const sources = {};
  for (const file of ["src/App.tsx", "src/timeline/SegmentCache.ts", "src/timeline/TimelinePages.ts", "package-lock.json"]) {
    const content = await readFile(resolve(root, file)).catch(() => null);
    sources[file] = content === null ? null : createHash("sha256").update(content).digest("hex");
  }
  const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  await writeFile(output, JSON.stringify({ scope: "synthetic frontend diagnostic; actual App; no Rust service/device timing",
    corpus: { events: 100_000, page_size: 2_000, page_delay_ms: 60, unique_pages: 25, viewport_burst: 3 },
    command: "node qtrace-ui/tools/timeline_pages.mjs <evidence.json>",
    commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(), sources,
    host: { platform: platform(), release: release(), arch: arch(), cpu: cpus()[0]?.model, node: process.version },
    browser: browser.version(), samples,
    median_queries: median(samples.map(sample => sample.queries.length)),
    median_serializations: median(samples.map(sample => sample.serializations)),
    median_serialization_ms: median(samples.map(sample => sample.serialization_ms)),
    median_load_p95_ms: median(samples.map(sample => sample.load_p95_ms)),
    median_frame_p95_ms: median(samples.map(sample => sample.frame_p95_ms)),
    median_heap_growth_bytes: median(samples.map(sample => sample.heap_growth_bytes)),
  }, null, 2) + "\n");
} finally {
  await browser?.close();
  await server.close();
}
