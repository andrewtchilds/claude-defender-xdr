import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // dist/ is committed for plugin distribution; without this vitest would also collect
    // the compiled copy of every test and run each one twice.
    exclude: ["dist/**", "node_modules/**"],
  },
});
