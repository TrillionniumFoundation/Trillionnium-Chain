"use strict";

// minimatch 3 and the current Next ESLint plugins expect
// `require("brace-expansion")` itself to be callable. Patched brace-expansion
// 5 exports `expand` as a named function. Keep the legacy call shape while
// delegating all expansion and resource bounds to the patched implementation.
const modern = require("brace-expansion-v5");

module.exports = modern.expand;
module.exports.expand = modern.expand;
module.exports.EXPANSION_MAX = modern.EXPANSION_MAX;
module.exports.EXPANSION_MAX_LENGTH = modern.EXPANSION_MAX_LENGTH;
