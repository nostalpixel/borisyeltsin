import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    environment: "node",
    // theme.test.ts reads theme.css?raw; Vitest stubs CSS unless told otherwise.
    css: { include: [/theme\.css/] },
    testTimeout: 120000,
    hookTimeout: 120000,
  },
});
