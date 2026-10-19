#!/usr/bin/env node
import { createServer } from "../src-web/node_modules/vite/dist/node/index.js";
import { chromium, expect } from "../src-web/node_modules/@playwright/test/index.mjs";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = path.resolve(import.meta.dirname, "../..");
const output = path.resolve(process.argv[2] ?? path.join(root, "artifacts/ui-layout-state-2026-10-19/call-tree.json"));
fs.mkdirSync(path.dirname(output), { recursive: true });
const html = `<!doctype html><html><body><nav class="left-dock" style="width:220px"><div id="root"></div></nav><script type="module">
import React from "react";
import { createRoot } from "react-dom/client";
import { CallTreePane } from "/src/components/CallTreePane.tsx";
import "/src/styles/global.css";
const root = createRoot(document.getElementById("root"));
window.requests = []; window.jumps = []; window.maxPageNodes = 0; window.maxPageBytes = 0;
window.mismatch = false; window.delayNext = false; window.release = null;
const node = (mode, id, parent) => ({ id, parent, child_count: mode === "deep" && id < 511 ? 1 : 0,
  tid: 7, target: "0x1000", display: mode + " " + id + " " + "long_symbol_".repeat(24),
  source_row_start: id, source_row_end_exclusive: id + 1, provenance: "captured", state: "complete" });
window.mount = mode => {
  const tree = { identity: mode + "-v1", artifact_index: 0, timeline_id: "1", tid: 7, parent: null, offset: 0,
    total: mode === "deep" ? 1 : 10000,
    nodes: mode === "deep" ? [node(mode, 0, null)] : Array.from({ length: 100 }, (_, id) => node(mode, id, null)) };
  root.render(React.createElement(CallTreePane, { tree, onJump: row => window.jumps.push(row),
    loadPage: async (parent, offset, identity) => {
      window.requests.push({ mode, parent, offset, identity });
      const nodes = mode === "deep" ? [node(mode, parent + 1, parent)] : Array.from({ length: 100 }, (_, index) => node(mode, offset + index, parent));
      const page = { ...tree, identity: window.mismatch ? "wrong-v1" : identity, parent, offset, total: mode === "deep" ? 1 : 10000, nodes };
      window.maxPageNodes = Math.max(window.maxPageNodes, nodes.length);
      window.maxPageBytes = Math.max(window.maxPageBytes, new TextEncoder().encode(JSON.stringify(page)).length);
      if (window.delayNext) { window.delayNext = false; await new Promise(resolve => { window.release = resolve; }); }
      return page;
    }
  }));
};
window.mount("deep");
</script></body></html>`;
const server = await createServer({ root: path.join(root, "qtrace-ui/src-web"), server: { port: 0, host: "127.0.0.1" },
  plugins: [{ name: "call-tree-interactions", configureServer(vite) {
    vite.middlewares.use("/__tree_interactions", async (_request, response, next) => {
      try { response.setHeader("Content-Type", "text/html"); response.end(await vite.transformIndexHtml("/__tree_interactions", html)); }
      catch (error) { next(error); }
    });
  } }],
});
let browser;
const report = { method: "Actual CallTreePane in Chromium with synthetic bounded page responses. Deep chain=512; wide roots=10,000. No Rust IPC or backend tree-build cost is claimed.", page_errors: [] };
try {
  await server.listen();
  browser = await chromium.launch();
  report.chromium = browser.version();
  const page = await browser.newPage({ viewport: { width: 800, height: 900 } });
  page.on("pageerror", error => report.page_errors.push(error.message));
  await page.goto(`http://127.0.0.1:${server.httpServer.address().port}/__tree_interactions`);
  await page.getByRole("treeitem").first().waitFor();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("HeapProfiler.collectGarbage");
  const before = await cdp.send("Runtime.getHeapUsage");
  report.deep = await page.evaluate(async () => {
    const frames = () => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    const tree = document.querySelector('[role="tree"]');
    const samples = [];
    let maxDom = 0;
    for (let id = 0; id < 511; id++) {
      tree.scrollTop = id * 32; tree.dispatchEvent(new Event("scroll", { bubbles: true }));
      await frames();
      const button = [...tree.querySelectorAll("button")].find(item => item.getAttribute("aria-label")?.startsWith("Expand deep " + id + " "));
      if (!button) throw new Error("Missing deep frame " + id);
      const start = performance.now(); button.click(); await frames(); samples.push(performance.now() - start);
      maxDom = Math.max(maxDom, tree.querySelectorAll('[role="treeitem"]').length);
    }
    tree.scrollTop = 511 * 32; tree.dispatchEvent(new Event("scroll", { bubbles: true })); await frames();
    const last = [...tree.querySelectorAll('[role="treeitem"]')].find(item => item.getAttribute("aria-level") === "512");
    const jump = last.querySelector(".call-tree-jump"); jump.focus(); jump.click();
    return { depth: 512, max_dom_nodes: maxDom, requests: window.requests.length, expand_ms: samples,
      p95_expand_ms: [...samples].sort((a, b) => a - b)[Math.ceil(samples.length * .95) - 1],
      last_jump: window.jumps.at(-1), last_title_length: jump.title.length, truncated: jump.scrollWidth > jump.clientWidth,
      panel_width: tree.clientWidth, tree_scroll_width: tree.scrollWidth };
  });
  expect(report.deep.requests).toBe(511);
  expect(report.deep.max_dom_nodes).toBeLessThan(25);
  expect(report.deep.last_jump).toBe(511);
  expect(report.deep.truncated).toBe(true);
  expect(report.deep.tree_scroll_width).toBeLessThanOrEqual(report.deep.panel_width);
  await page.evaluate(() => window.mount("wide"));
  await expect(page.getByRole("button", { name: /^wide 0 / })).toBeVisible();
  report.wide = await page.evaluate(async () => {
    const frames = () => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    const tree = document.querySelector('[role="tree"]');
    let maxDom = 0;
    const begin = window.requests.length;
    for (let offset = 100; offset < 10000; offset += 100) {
      tree.scrollTop = 96 * 32; tree.dispatchEvent(new Event("scroll", { bubbles: true })); await frames();
      const button = [...tree.querySelectorAll("button")].find(item => item.textContent === "Load more calls");
      if (!button) throw new Error("Missing wide page " + offset);
      button.click(); await frames();
      maxDom = Math.max(maxDom, tree.querySelectorAll('[role="treeitem"]').length);
    }
    tree.scrollTop = 100 * 32; tree.dispatchEvent(new Event("scroll", { bubbles: true })); await frames();
    const jump = [...tree.querySelectorAll(".call-tree-jump")].find(item => item.textContent.startsWith("wide 9999 "));
    jump.click();
    return { roots: 10000, requests: window.requests.length - begin, max_dom_nodes: maxDom, last_jump: window.jumps.at(-1), scroll_height: tree.scrollHeight };
  });
  expect(report.wide.requests).toBe(99);
  expect(report.wide.max_dom_nodes).toBeLessThan(25);
  expect(report.wide.last_jump).toBe(9999);
  await page.reload();
  await page.getByRole("treeitem").first().waitFor();
  await page.evaluate(() => { window.mismatch = true; });
  await page.getByRole("button", { name: /^Expand deep 0 / }).click();
  await expect(page.getByRole("button", { name: "Load calls", exact: true })).toBeEnabled();
  expect(await page.getByRole("button", { name: /^deep 1 / }).count()).toBe(0);
  await page.evaluate(() => { window.mismatch = false; window.delayNext = true; });
  await page.getByRole("button", { name: "Load calls", exact: true }).click();
  await page.waitForFunction(() => window.release !== null);
  await page.evaluate(() => window.mount("wide"));
  await expect(page.getByRole("button", { name: /^wide 0 / })).toBeVisible();
  await page.evaluate(() => window.release());
  await page.waitForTimeout(50);
  expect(await page.getByRole("button", { name: /^deep / }).count()).toBe(0);
  report.identity = { mismatched_page_ignored: true, unmounted_page_ignored: true };
  report.responses = await page.evaluate(() => ({ max_nodes: window.maxPageNodes, max_bytes: window.maxPageBytes }));
  await cdp.send("HeapProfiler.collectGarbage");
  const after = await cdp.send("Runtime.getHeapUsage");
  report.heap = { before_bytes: before.usedSize, after_bytes: after.usedSize, note: "After includes a page reload and root replacement; it is diagnostic, not a retained-cache limit." };
  report.component_sha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "qtrace-ui/src-web/src/components/CallTreePane.tsx"))).digest("hex");
  report.passed = report.page_errors.length === 0;
} catch (error) { report.error = String(error.stack ?? error); report.passed = false; }
finally { await browser?.close(); await server.close(); fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n"); }
console.log(JSON.stringify({ passed: report.passed, output, deep: report.deep && { ...report.deep, expand_ms: undefined }, wide: report.wide, error: report.error }));
if (!report.passed) process.exitCode = 1;
