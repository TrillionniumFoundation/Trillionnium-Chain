"use strict";

/* eslint-disable @typescript-eslint/no-require-imports */
const assert = require("node:assert/strict");
const expand = require("brace-expansion");

assert.equal(typeof expand, "function");
assert.deepEqual(expand("a{b,c}"), ["ab", "ac"]);
assert.equal(typeof expand.expand, "function");
assert.equal(expand.EXPANSION_MAX, 100_000);
assert.equal(expand.EXPANSION_MAX_LENGTH, 4_000_000);

const bounded = expand("{a,b}".repeat(50), {
  max: 100_000,
  maxLength: 1_000,
});
assert.ok(
  bounded.reduce((total, value) => total + value.length, 0) <= 1_000,
  "patched expansion must honor maxLength"
);

console.log("brace_expansion_cjs_compat=ok");
