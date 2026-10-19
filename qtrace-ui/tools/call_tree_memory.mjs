// Frontend-only diagnostic. Synthetic pages exercise the actual CallTreePane.
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
if (!output) throw new Error("Usage: node qtrace-ui/tools/call_tree_memory.mjs /absolute/evidence.json");
const html = `<!doctype html><html><body><div id="root"></div><script type="module">
import React from "react";
import { createRoot } from "react-dom/client";
import { CallTreePane } from "/src/components/CallTreePane.tsx";
const node = (id, parent, child_count) => ({ id, parent, child_count, tid: 7, target: "0x1000",
  display: "call " + id + " " + String(id).padEnd(256, "x"), source_row_start: id,
  source_row_end_exclusive: id + 1, provenance: "captured", state: "complete" });
const nodes = Array.from({ length: 100 }, (_, id) => node(id, null, 100));
window.requests = 0;
window.jumps = [];
window.ready = false;
const tree = { identity: "memory-diagnostic-v1", artifact_index: 0, timeline_id: "1", tid: 7,
  parent: null, offset: 0, total: nodes.length, nodes };
createRoot(document.getElementById("root")).render(React.createElement(CallTreePane, {
  tree, onJump: row => window.jumps.push(row), loadPage: async (parent, offset, identity) => {
    window.requests++;
    return { ...tree, identity, parent, offset, total: 100,
      nodes: Array.from({ length: 100 }, (_, index) => node(100 + parent * 100 + index, parent, 0)) };
  }
}));
window.ready = true;
</script></body></html>`;
const server = await createServer({
  root, server: { port: 0, host: "127.0.0.1", strictPort: false },
  plugins: [{ name: "call-tree-diagnostic", configureServer(vite) {
    vite.middlewares.use("/__call_tree_diagnostic", async (_request, response, next) => {
      try {
        response.setHeader("Content-Type", "text/html");
        response.end(await vite.transformIndexHtml("/__call_tree_diagnostic", html));
      } catch (error) { next(error); }
    });
  } }],
});
let browser;
const samples = [];
try {
  await server.listen();
  const address = server.httpServer.address();
  browser = await chromium.launch({ headless: true });
  for (let round = 0; round < 5; round++) {
    const page = await browser.newPage({ viewport: { width: 1000, height: 800 } });
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(`http://127.0.0.1:${address.port}/__call_tree_diagnostic`);
    await page.waitForFunction(() => window.ready && document.querySelector('[role="treeitem"]'));
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("HeapProfiler.collectGarbage");
    const before = await cdp.send("Runtime.getHeapUsage");
    const workload = await page.evaluate(async () => {
      const frames = () => new Promise(resolveFrame => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)));
      const tree = document.querySelector('[role="tree"]');
      const samples = [];
      const frameIntervals = [];
      let previousFrame, frameHandle;
      const recordFrame = time => {
        if (previousFrame !== undefined) frameIntervals.push(time - previousFrame);
        previousFrame = time;
        frameHandle = requestAnimationFrame(recordFrame);
      };
      frameHandle = requestAnimationFrame(recordFrame);
      let maxDom = 0;
      for (let id = 0; id < 100; id++) {
        tree.scrollTop = id * 32;
        tree.dispatchEvent(new Event("scroll", { bubbles: true }));
        await frames();
        const button = [...tree.querySelectorAll("button")].find(item => item.getAttribute("aria-label")?.startsWith("Expand call " + id + " "));
        if (!button) throw new Error("Missing root " + id);
        const started = performance.now();
        button.click();
        await frames();
        samples.push(performance.now() - started);
        maxDom = Math.max(maxDom, tree.querySelectorAll('[role="treeitem"]').length);
        if (id === 99) {
          const child = [...tree.querySelectorAll('[role="treeitem"]')].find(item => item.getAttribute("aria-level") === "2");
          child.querySelectorAll("button")[1].click();
        }
        const collapse = [...tree.querySelectorAll("button")].find(item => item.getAttribute("aria-label")?.startsWith("Collapse call " + id + " "));
        if (!collapse) throw new Error("Missing expanded root " + id);
        collapse.click();
        await frames();
      }
      cancelAnimationFrame(frameHandle);
      const percentile = values => [...values].sort((a, b) => a - b)[Math.ceil(values.length * 0.95) - 1];
      return { expand_ms: samples, expand_p95_ms: percentile(samples), frame_intervals_ms: frameIntervals,
        frame_p95_ms: percentile(frameIntervals), max_dom_nodes: maxDom, requests: window.requests, jumps: window.jumps };
    });
    await cdp.send("HeapProfiler.collectGarbage");
    const after = await cdp.send("Runtime.getHeapUsage");
    if (errors.length || workload.requests !== 100 || workload.jumps[0] !== 10000 || workload.max_dom_nodes >= 30) {
      throw new Error(JSON.stringify({ errors, workload }));
    }
    samples.push({ round: round + 1, heap_before_bytes: before.usedSize, heap_after_bytes: after.usedSize,
      heap_growth_bytes: after.usedSize - before.usedSize, ...workload });
    console.log(JSON.stringify({ round: round + 1, heap_growth_bytes: samples.at(-1).heap_growth_bytes,
      expand_p95_ms: workload.expand_p95_ms, frame_p95_ms: workload.frame_p95_ms }));
    await page.close();
  }
  const median = values => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
  const component = await readFile(resolve(root, "src/components/CallTreePane.tsx"));
  const pageCache = await readFile(resolve(root, "src/components/CallTreePages.ts")).catch(() => null);
  await writeFile(output, JSON.stringify({ scope: "synthetic frontend diagnostic; actual CallTreePane; no Rust service or device",
    corpus: { roots: 100, children_per_root: 100, display_padding: 256, id: "memory-diagnostic-v1" },
    command: "node qtrace-ui/tools/call_tree_memory.mjs <evidence.json>",
    commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    component_sha256: createHash("sha256").update(component).digest("hex"),
    page_cache_sha256: pageCache === null ? null : createHash("sha256").update(pageCache).digest("hex"),
    lockfile_sha256: createHash("sha256").update(await readFile(resolve(root, "package-lock.json"))).digest("hex"),
    host: { platform: platform(), release: release(), arch: arch(), cpu: cpus()[0]?.model, node: process.version },
    browser: browser.version(), samples,
    median_heap_growth_bytes: median(samples.map(sample => sample.heap_growth_bytes)),
    median_expand_p95_ms: median(samples.map(sample => sample.expand_p95_ms)),
    median_frame_p95_ms: median(samples.map(sample => sample.frame_p95_ms)),
  }, null, 2) + "\n");
} finally {
  await browser?.close();
  await server.close();
}
