import { readFile, rm } from "node:fs/promises";
import { RUNTIME_FILE } from "./support";
export default async function globalTeardown() {
  const runtime = JSON.parse(await readFile(RUNTIME_FILE, "utf8")) as { serverPid: number; vitePid: number; data: string };
  for (const pid of [runtime.serverPid, runtime.vitePid]) { try { process.kill(pid, "SIGTERM"); } catch { /* already stopped */ } }
  await rm(runtime.data, { recursive: true, force: true });
  await rm(RUNTIME_FILE, { force: true });
}
