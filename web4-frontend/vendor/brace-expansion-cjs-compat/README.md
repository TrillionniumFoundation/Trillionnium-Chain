# brace-expansion CommonJS compatibility facade

This private package preserves the callable CommonJS API required by
`minimatch@3` and the current Next ESLint plugins while delegating to patched
`brace-expansion@5.0.8`.

It exists because the upstream ESLint plugins still constrain `minimatch` to
the vulnerable 3.x line. Remove this facade as soon as those plugins consume a
patched minimatch/brace-expansion pair. It is production-inert and used only
by lint tooling.
