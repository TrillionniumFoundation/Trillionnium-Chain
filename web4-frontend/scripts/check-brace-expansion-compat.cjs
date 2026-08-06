"use strict";

/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const expand = require("brace-expansion");
const minimatch = require("minimatch");
const modernPackage = require("brace-expansion-v5/package.json");

function runIsolated(label, source, timeout) {
  const child = spawnSync(
    process.execPath,
    ["--max-old-space-size=128", "-e", source],
    {
      encoding: "utf8",
      timeout,
    },
  );

  assert.equal(
    child.error,
    undefined,
    `${label} child failed to run: ${child.error?.message ?? "unknown error"}`,
  );
  assert.equal(
    child.signal,
    null,
    `${label} child was terminated by ${child.signal}: ${child.stderr}`,
  );
  assert.equal(
    child.status,
    0,
    `${label} child exited ${child.status}: ${child.stderr}`,
  );

  return JSON.parse(child.stdout);
}

assert.equal(typeof expand, "function");
assert.deepEqual(expand("a{b,c}"), ["ab", "ac"]);
assert.deepEqual(expand("v{1..3}"), ["v1", "v2", "v3"]);
assert.equal(typeof expand.expand, "function");
assert.equal(expand.EXPANSION_MAX, 100_000);
assert.equal(expand.EXPANSION_MAX_LENGTH, 4_000_000);
assert.equal(modernPackage.version, "5.0.9");

assert.equal(minimatch("src/index.ts", "src/*.{js,ts}"), true);
assert.equal(minimatch("src/index.tsx", "src/*.{js,ts}"), false);

const bounded = expand("{a,b}".repeat(50), {
  max: 100_000,
  maxLength: 1_000,
});
assert.ok(
  bounded.reduce((total, value) => total + value.length, 0) <= 1_000,
  "patched expansion must honor maxLength"
);

const resolvedExpansion = JSON.stringify(require.resolve("brace-expansion"));
const commonAssertions = `
  const expand = require(${resolvedExpansion});
  const startedAt = Date.now();
  function finish(values) {
    const totalLength = values.reduce((total, value) => total + value.length, 0);
    if (values.length > expand.EXPANSION_MAX) process.exit(11);
    if (totalLength > expand.EXPANSION_MAX_LENGTH) process.exit(12);
    process.stdout.write(JSON.stringify({
      count: values.length,
      totalLength,
      elapsedMs: Date.now() - startedAt,
    }));
  }
`;

const alternativesResult = runIsolated(
  "comma-alternative memory bound",
  `${commonAssertions}
  const part = "{" + "0".repeat(50) + "1..100000}";
  const input = "{" + Array(400).fill(part).join(",") + "}";
  finish(expand(input));
  `,
  15_000,
);
assert.ok(alternativesResult.count > 0);

const sequenceResult = runIsolated(
  "padded-sequence CPU bound",
  `${commonAssertions}
  const input = "{" + "0".repeat(100_000) + "1..100000}";
  finish(expand(input));
  `,
  8_000,
);
assert.ok(sequenceResult.count > 0);

console.log("brace_expansion_cjs_compat=ok");
