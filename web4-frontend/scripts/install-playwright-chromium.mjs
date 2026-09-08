#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");
process.chdir(root);

function fail(message) {
  throw new Error(`playwright-chromium-install: ${message}`);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sha256File(file) {
  const hash = crypto.createHash("sha256");
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

async function treeDigest(directory) {
  const rootDirectory = await fsp.realpath(directory);
  const hash = crypto.createHash("sha256");

  async function visit(current) {
    const entries = await fsp.readdir(current, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      const absolute = path.join(current, entry.name);
      const relative = path.relative(rootDirectory, absolute).split(path.sep).join("/");
      if (relative === ".trnm-playwright-cache-v1.json") continue;
      const stat = await fsp.lstat(absolute);
      hash.update(relative, "utf8");
      hash.update("\0");
      hash.update((stat.mode & 0o7777).toString(8).padStart(4, "0"), "ascii");
      hash.update("\0");
      if (stat.isSymbolicLink()) {
        hash.update("L");
        hash.update(await fsp.readlink(absolute), "utf8");
      } else if (stat.isDirectory()) {
        hash.update("D");
        await visit(absolute);
      } else if (stat.isFile()) {
        hash.update("F");
        for await (const chunk of fs.createReadStream(absolute)) hash.update(chunk);
      } else {
        fail(`unsupported cache entry type: ${relative}`);
      }
      hash.update("\0");
    }
  }

  await visit(rootDirectory);
  return hash.digest("hex");
}

function commandName(base) {
  return process.platform === "win32" ? `${base}.cmd` : base;
}

function runCommand(command, args, { env = process.env, timeoutMs, capture = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: root,
      env,
      shell: false,
      stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
    });
    let stdout = "";
    let stderr = "";
    if (capture) {
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
    }
    let killed = false;
    const timer = timeoutMs
      ? setTimeout(() => {
          killed = true;
          child.kill("SIGTERM");
          setTimeout(() => child.kill("SIGKILL"), 30_000).unref();
        }, timeoutMs)
      : null;
    timer?.unref();
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      resolve({ code, signal, killed, stdout, stderr });
    });
  });
}

async function safeRemove(cacheParent, target) {
  const parent = path.resolve(cacheParent);
  const resolved = path.resolve(target);
  const base = path.basename(resolved);
  requireCondition(
    resolved.startsWith(`${parent}${path.sep}`)
      && (base.startsWith(".install-") || base.startsWith("pw-") || base === ".install.lock"),
    `refusing to remove path outside the cache namespace: ${target}`,
  );
  await fsp.rm(resolved, { recursive: true, force: true });
}

async function acquireLock(cacheParent) {
  const lockDirectory = path.join(cacheParent, ".install.lock");
  const deadline = Date.now() + 600_000;
  while (Date.now() < deadline) {
    try {
      await fsp.mkdir(lockDirectory, { mode: 0o700 });
      await fsp.writeFile(
        path.join(lockDirectory, "owner.json"),
        `${JSON.stringify({ pid: process.pid, host: os.hostname(), started_at: new Date().toISOString() })}\n`,
        { mode: 0o600 },
      );
      return async () => safeRemove(cacheParent, lockDirectory);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      const stat = await fsp.lstat(lockDirectory).catch(() => null);
      if (stat && (stat.isSymbolicLink() || !stat.isDirectory())) {
        fail(`invalid browser cache lock type: ${lockDirectory}`);
      }
      if (stat && Date.now() - stat.mtimeMs > 1_800_000) {
        await safeRemove(cacheParent, lockDirectory);
        continue;
      }
      await sleep(500);
    }
  }
  fail("timed out waiting for the browser cache lock");
}

const smokeSource = String.raw`
const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.setContent("<title>trnm-playwright-cache-smoke</title>");
  const title = await page.title();
  await browser.close();
  if (title !== "trnm-playwright-cache-smoke") throw new Error("unexpected smoke title");
})().catch((error) => { console.error(error); process.exit(1); });
`;

async function smokeBrowser(browserRoot) {
  const result = await runCommand(process.execPath, ["-e", smokeSource], {
    env: { ...process.env, PLAYWRIGHT_BROWSERS_PATH: browserRoot },
    timeoutMs: 120_000,
  });
  return result.code === 0 && !result.killed;
}

async function executablePath(browserRoot) {
  const result = await runCommand(
    process.execPath,
    ["-e", 'const { chromium } = require("playwright"); process.stdout.write(chromium.executablePath());'],
    {
      env: { ...process.env, PLAYWRIGHT_BROWSERS_PATH: browserRoot },
      timeoutMs: 30_000,
      capture: true,
    },
  );
  requireCondition(result.code === 0 && !result.killed, `cannot resolve Chromium executable: ${result.stderr.trim()}`);
  const value = result.stdout.trim();
  requireCondition(value && !value.includes("\n") && path.isAbsolute(value), "resolved Chromium path is invalid");
  const stat = await fsp.stat(value).catch(() => null);
  requireCondition(stat?.isFile() && (stat.mode & 0o111) !== 0, `Chromium executable is unavailable: ${value}`);
  return value;
}

async function main() {
  const lockPath = path.join(root, "package-lock.json");
  const packagePath = path.join(root, "node_modules/playwright-core/package.json");
  const registryPath = path.join(root, "node_modules/playwright-core/browsers.json");
  for (const file of [lockPath, packagePath, registryPath]) {
    requireCondition(fs.existsSync(file), `required input is missing: ${path.relative(root, file)}`);
  }

  const packageMeta = JSON.parse(await fsp.readFile(packagePath, "utf8"));
  const registry = JSON.parse(await fsp.readFile(registryPath, "utf8"));
  const chromium = registry.browsers?.find((item) => item.name === "chromium");
  requireCondition(/^\d+\.\d+\.\d+$/.test(packageMeta.version ?? ""), "invalid Playwright version");
  requireCondition(/^\d+$/.test(chromium?.revision ?? ""), "invalid Chromium revision");

  const packageLockSha256 = await sha256File(lockPath);
  const platform = `${process.platform}-${process.arch}`;
  const defaultCacheBase = process.env.RUNNER_TOOL_CACHE || path.join(os.homedir(), ".cache");
  const cacheParent = path.resolve(process.env.TRNM_PLAYWRIGHT_CACHE_ROOT || path.join(defaultCacheBase, "trnm-playwright"));
  requireCondition(path.isAbsolute(cacheParent), `cache root must be absolute: ${cacheParent}`);
  await fsp.mkdir(cacheParent, { recursive: true, mode: 0o700 });
  await fsp.chmod(cacheParent, 0o700);

  const cacheKey = `pw-${packageMeta.version}-chromium-${chromium.revision}-${platform}-${packageLockSha256}`;
  const cacheDirectory = path.join(cacheParent, cacheKey);
  const markerPath = path.join(cacheDirectory, ".trnm-playwright-cache-v1.json");
  const timeoutSeconds = Number.parseInt(process.env.TRNM_PLAYWRIGHT_INSTALL_TIMEOUT_SECONDS || "900", 10);
  requireCondition(Number.isInteger(timeoutSeconds) && timeoutSeconds >= 60 && timeoutSeconds <= 1800,
    "install timeout must be an integer between 60 and 1800 seconds");

  const expectedMarker = {
    schema: "trnm-playwright-cache-v1",
    package_lock_sha256: packageLockSha256,
    playwright_version: packageMeta.version,
    chromium_revision: chromium.revision,
    platform,
  };

  async function cacheValid() {
    try {
      const marker = JSON.parse(await fsp.readFile(markerPath, "utf8"));
      requireCondition(Object.keys(marker).sort().join("\0") === [...Object.keys(expectedMarker), "tree_sha256"].sort().join("\0"),
        "browser cache marker keys drift");
      for (const [key, value] of Object.entries(expectedMarker)) requireCondition(marker[key] === value, `browser cache marker mismatch: ${key}`);
      requireCondition(/^[0-9a-f]{64}$/.test(marker.tree_sha256), "browser cache tree digest is invalid");
      requireCondition((await treeDigest(cacheDirectory)) === marker.tree_sha256, "browser cache tree digest mismatch");
      return await smokeBrowser(cacheDirectory);
    } catch {
      return false;
    }
  }

  const releaseLock = await acquireLock(cacheParent);
  try {
    if (await cacheValid()) {
      console.log(`playwright_chromium_cache=hit key=${cacheKey}`);
    } else {
      if (fs.existsSync(cacheDirectory)) await safeRemove(cacheParent, cacheDirectory);
      let installed = false;
      for (let attempt = 1; attempt <= 2 && !installed; attempt += 1) {
        const tempDirectory = await fsp.mkdtemp(path.join(cacheParent, `.install-${cacheKey}.`));
        await fsp.chmod(tempDirectory, 0o700);
        console.log(`playwright_chromium_cache=install attempt=${attempt} key=${cacheKey}`);
        const install = await runCommand(commandName("npx"), ["--no-install", "playwright", "install", "chromium"], {
          env: { ...process.env, PLAYWRIGHT_BROWSERS_PATH: tempDirectory },
          timeoutMs: timeoutSeconds * 1000,
        });
        if (install.code === 0 && !install.killed && await smokeBrowser(tempDirectory)) {
          const marker = { ...expectedMarker, tree_sha256: await treeDigest(tempDirectory) };
          await fsp.writeFile(
            path.join(tempDirectory, ".trnm-playwright-cache-v1.json"),
            `${JSON.stringify(marker, null, 2)}\n`,
            { mode: 0o600 },
          );
          await fsp.rename(tempDirectory, cacheDirectory);
          installed = true;
        } else {
          await safeRemove(cacheParent, tempDirectory);
        }
      }
      requireCondition(installed, "Chromium installation or launch smoke failed after two bounded attempts");
      requireCondition(await cacheValid(), "new browser cache failed integrity or launch validation");
      console.log(`playwright_chromium_cache=installed key=${cacheKey}`);
    }

    const executable = await executablePath(cacheDirectory);
    if (process.env.GITHUB_ENV) {
      requireCondition(!cacheDirectory.includes("\n") && !executable.includes("\n"), "environment path contains a newline");
      await fsp.appendFile(process.env.GITHUB_ENV,
        `PLAYWRIGHT_BROWSERS_PATH=${cacheDirectory}\nTRNM_PLAYWRIGHT_EXECUTABLE_PATH=${executable}\n`, "utf8");
    }
    console.log(`PLAYWRIGHT_BROWSERS_PATH=${cacheDirectory}`);
    console.log(`TRNM_PLAYWRIGHT_EXECUTABLE_PATH=${executable}`);
  } finally {
    await releaseLock();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exit(2);
});
