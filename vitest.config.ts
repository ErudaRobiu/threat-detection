import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Phase 1 is the pure analysis core: no DOM, no network, no setup.
    environment: "node",
    include: ["core/**/*.test.ts"],
  },
});
