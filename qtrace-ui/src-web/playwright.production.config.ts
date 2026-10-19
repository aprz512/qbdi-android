import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "production.spec.ts",
  webServer: { command: "npx vite preview --port 1422 --strictPort", wait: { stdout: /http:\/\/localhost:1422\// }, timeout: 15_000 },
  use: { baseURL: "http://localhost:1422" },
  workers: 1,
});
