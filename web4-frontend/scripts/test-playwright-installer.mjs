#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");
const installer = fs.readFileSync(path.join(scriptDir, "install-playwright-chromium.mjs"), "utf8");
const workflow = fs.readFileSync(path.join(root, "../.github/workflows/web4-frontend-ci.yml"), "utf8");

function requireCondition(condition, reason) {
  if (!condition) throw new Error(`playwright installer contract failed: ${reason}`);
}

for (const fragment of [
  '["--no-install", "playwright", "install", "chromium"]',
  "timeoutSeconds * 1000",
  "acquireLock",
  "package_lock_sha256",
  "tree_sha256",
  "smokeBrowser",
  "cacheValid",
  "GITHUB_ENV",
  "shell: false",
]) {
  requireCondition(installer.includes(fragment), `installer lost required fragment: ${fragment}`);
}
requireCondition(!workflow.includes("npx playwright install chromium"), "workflow must not use the unbounded direct installer");
requireCondition(workflow.includes("node ./scripts/install-playwright-chromium.mjs"), "workflow must invoke the bounded Node installer");
requireCondition(workflow.includes("node ./scripts/test-playwright-installer.mjs"), "workflow must run the installer contract");
requireCondition(!workflow.includes("PLAYWRIGHT_BROWSERS_PATH: ${{ runner.temp }}/ms-playwright"), "ephemeral browser path defeats verified reuse");
requireCondition(/Install pinned Playwright Chromium[\s\S]{0,500}timeout-minutes:\s*20/.test(workflow),
  "browser installation step must have a workflow timeout");
console.log("playwright_installer_contract=ok");
