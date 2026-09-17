import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { RUNTIME_FILE } from "./support";

export default async function globalSetup() {
  const root = resolve("..");
  const data = await mkdtemp(join(tmpdir(), "qtrace-e2e-"));
  const token = randomBytes(16).toString("hex");
  const server = spawn("cargo", ["run", "-q", "-p", "qtrace-service", "--features", "e2e-fixture", "--bin", "e2e_server", "--", "--fixture-root", join(root, "fixtures"), "--xdg-root", data, "--token", token], { cwd: root, stdio: ["ignore", "pipe", "inherit"] });
  const readiness = await new Promise<{ url: string; token: string }>((resolveReady, reject) => {
    const lines = createInterface({ input: server.stdout! });
    lines.once("line", (line) => { try { resolveReady(JSON.parse(line)); } catch (error) { reject(error); } });
    server.once("exit", (code) => reject(new Error(`e2e server exited ${code}`)));
  });
  const vite = spawn(resolve("node_modules/.bin/vite"), ["--mode", "e2e", "--port", "1421"], {
    cwd: process.cwd(), stdio: "ignore", env: { ...process.env, VITE_E2E_URL: readiness.url, VITE_E2E_TOKEN: readiness.token },
  });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try { const response = await fetch("http://localhost:1421"); if (response.ok) break; } catch { /* retry startup */ }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  await writeFile(RUNTIME_FILE, JSON.stringify({ serverPid: server.pid, vitePid: vite.pid, data, url: readiness.url, token: readiness.token }));
}
