# brace-expansion CommonJS compatibility facade

This private package preserves the callable CommonJS API required by
`minimatch@3` and the current Next ESLint plugins while delegating to patched
`brace-expansion@5.0.9`.

Version 5.0.9 closes `GHSA-rgw5-rvv9-x895`, which bypassed the 5.0.8
`maxLength` mitigation through unbounded comma-alternative and padded-sequence
intermediate arrays. Keep the facade version aligned exactly with the upstream
implementation so dependency audits evaluate the code that actually performs
the expansion.

It exists because the upstream ESLint plugins still depend on `minimatch@3`,
whose transitive brace-expansion API is a callable CommonJS export. Remove this
facade as soon as those plugins no longer require the legacy call shape. It is
production-inert and used only by lint tooling.
