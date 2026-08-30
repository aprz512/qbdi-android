import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 1420,
    strictPort: true,
  },
  clearScreen: false,
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
  },
});
