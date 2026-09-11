import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  use: {
    baseURL: "http://localhost:3000",
    // The bounded installer validates the exact PLAYWRIGHT_BROWSERS_PATH cache
    // with Playwright's own chromium.launch() smoke. Do not override
    // executablePath here: recent Playwright releases may select a dedicated
    // headless executable that differs from chromium.executablePath(), and
    // forcing the regular Chrome binary can activate crashpad requirements that
    // are absent from the validated headless path on self-hosted Linux runners.
    trace: "on-first-retry",
  },
  webServer: {
    command: "npm run dev",
    url: "http://localhost:3000",
    reuseExistingServer: true,
    timeout: 120000,
  },
});
