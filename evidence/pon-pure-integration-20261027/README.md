# Pure PoN integration observations — 2026-10-27

These are observations of identified source commits, not an aggregate release
qualification. The six-item implementation table in the sole development plan
remains authoritative about open blockers.

- `first-ci-failure.json` records the first published source's native/fuzz lock
  mismatch. The failure was retained and the shared dependency versions repaired.
- `local-first-checks/manifest.json` retains the initial checks, including the
  sparse-checkout Markdown failure, missing offline package cache, and the two
  strict Clippy constant-assert errors. The full resolved Cargo graph is retained
  as gzip rather than shortened to a dependency count.
- `repaired-clippy/manifest.json` binds the successful strict all-target,
  all-feature crypto/protocol and node lint runs to source
  `400f034e611073da7259d62b57e2ba3a93904762`. These are lint results, not runtime
  test results and not evidence for an untested later source.

The ingress evidence reader initially could not start in the local sparse
checkout because its tracked gzip fixture was absent. Materializing the existing
tracked evidence directory allowed all eight negative-control tests to execute
and pass; no fixture or rejection predicate was changed to obtain this result.
The focused CI checks the full checkout and executes this reader independently.

For published source `21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59`, the CodeQL
exporter run [40476862879](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40476862879)
failed while waiting for exact-source analyses/checks to stabilize within its
1,200-second deadline. Its 16 exporter unit tests and before/after source checks
passed. The retained artifact is
[12722151935](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40476862879/artifacts/12722151935),
with ZIP SHA-256 `866da7a8c28fdacb48f2239d0fc49e518399afe52579f376ab4a4a584fdac267`.
This timeout is not a completed CodeQL security assessment. The required baseline
workflow for that source was still queued at this observation; the additional
focused workflow does not remove or replace any required gate.
