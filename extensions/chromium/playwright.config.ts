import { defineConfig } from "@playwright/test";

// Driven by tests/e2e/run.sh, which starts the mail server, daemon and
// test site and sets E2E_* variables.
export default defineConfig({
  testDir: "e2e",
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  reporter: [["list"]],
});
