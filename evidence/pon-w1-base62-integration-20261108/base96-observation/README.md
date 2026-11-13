# Base96 static observation against frozen C6

This bundle records a bounded, read-only source-impact review. It does **not** qualify base96 or the hypothetical merged tree. Existing C6 qualification keeps its frozen source identity. No test, Cargo command, operation, fetch, source edit, branch change, commit or push was performed by this review.

## Exact identities and historical refs

- Old integration base: `62d2d90c9e1f4c8450c89843f1e08360a24283ce`.
- New integration base: `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`, whose only parent is the old base.
- New commit: `ci(history): retain independent stage diagnostics under original limits`, authored/committed at 2026-11-08 06:49:32 UTC.
- Frozen C6: `2bdd252aa6c300b7431b9ee897b254b7953cf562`, tree `ac3cb7171c429fa5e12e29ee16839fa6f49f1b81`.
- The original `git merge-tree --write-tree C6 base96` returned exit 0 without conflicts and produced hypothetical tree `d73e57c9e7a5764a1ab33540c97af587bb6e4a69`. It may write unreferenced Git objects; it did not update a ref, index or worktree. Original HEAD/branch before/after observations remain C6.

The actual remote-ref readback is retained byte-for-byte in [references/mid-qualification-remote-refs.json](references/mid-qualification-remote-refs.json). Its original job is `1a1b9eefb2c-12894-17b0`, with original terminal/witness files under `runtime/`. At `observed_unix_ns=1794120822555997595` the integration branch was base96 and the PR branch was C5 `034aa74358e0a5fa33f33e83cb63669e9738da4b`. The qualifying local source was C6. This is a historical observation; a subsequent PR push does not rewrite it. We did not query current remote refs during this review.

## Six-path delta

`62 -> 96` has 1120 insertions and no deletions:

| Path | Added lines | Effect |
| --- | ---: | --- |
| `.github/workflows/pon-history-stage-diagnostic.yml` | 74 | Independent diagnostic workflow, two retained replicas |
| `config/pon/pq-cross-branch-corpus-v1.json` | 10 | Five additional exact blob pins and required paths |
| `scripts/ci/run_from_zero_host.py` | 6 | Shared Host import, exact command route and two adapter dispatches |
| `scripts/ci/run_history_diagnostic.py` | 457 | Independent preparation/execution/binding adapter |
| `scripts/ci/test_history_stage_diagnostic.py` | 85 | Six local control methods in source, not run here |
| `trillionnium/crates/trnm-pon-node/tests/history_stage_diagnostic.rs` | 488 | Separately named ignored native history diagnostic |

No production Rust `src`, M12 source, or W1 generation/collector source changed in this delta. It is nevertheless an executable CI/diagnostic change, not solely documentation or pins. Complete source copies, original diffs, command outputs and selected source blob identities are retained.

## Shared Host: exact meaning of the six additions

The [retained Host hunk](static-followup/shared-host-six-lines.patch) adds:

1. `import run_history_diagnostic as diagnostic`.
2. The exact `python3`, `diagnostic.SCRIPT`, `--out`, output-path form to the existing four-argument allowlist.
3. A two-line preparation branch calling `diagnostic.validate_preparation(output)`.
4. A two-line binding branch calling `diagnostic.bind_execution(prepared, output)`.

The existing resource, deadline and native/history/fixture dispatch code is textually unchanged. The new module is now an import dependency and accepts its own diagnostic route through the same Host. Its main function is guarded by `if __name__ == '__main__'`; importing it does not launch a native experiment. This static reading does not substitute for checking import/dispatch behavior on the newly merged source.

## Diagnostic behavior and limits visible in source

The new adapter has a separate target (`history_stage_diagnostic`), output directory (`history-diagnostic`) and preparation/execution schemas. It binds the event-selected source receipt, exact release test binary, prepared build and retained native process outcome. The copied Rust test still uses 4105 blocks, the 1800-second native service lifetime and the 30-second import-call budget. It records attempted History RPC/import outcomes before propagating an error and adds per-call observer snapshots. Partial activation, final State, reopen and corrupt-index checks remain present in this new test.

The new workflow runs only on the named integration branch's matching diagnostic path changes. It declares two replicas, `fail-fast: false`, `cancel-in-progress: false`, a 180-minute job limit and `always()` artifact retention, with no `continue-on-error`. These are source declarations; **the workflow and new tests were not executed in this review**.

The instrumentation consumes time within its diagnostic execution. Nested phase and Host CPU observations are not additive. The source explicitly keeps `resource_qualification`, `production_activation`, `public_network_ready`, `hardness_accepted` and `independent_accepted` false. A successful diagnostic would not establish the original resource qualification, WAN deployment or independent measurement.

## Static merge scope

The only overlapping path between `62 -> C6` and `62 -> 96` is the PQ corpus JSON. The merged-minus-C6 path list is exactly the same six paths as the base96 delta. The other five selected merged blobs exactly equal the new-base blobs.

A bounded comparison of the two corpus Git objects confirms that the merge keeps every C6 pin value and required path, adds only the five new pins/required paths, and does not change other corpus fields. Raw object reads and selected blob inventories are under `static-followup/`. This is a narrow static check, **not** a full sourceguard, full manifest qualification, test run or qualification of the hypothetical merged tree.

## Provenance, failed retrieval and publication bounds

`command-manifest.json` retains the original Git commands, times, exits and raw-output hashes. `static-followup/command-manifest.json` adds only bounded object reads. Original runtime terminal JSON/witnesses are under `runtime/`.

The first multi-file retrieval returned `INVALID_ARGUMENT`; its full tool result is retained. A selected diff was approximately 66 KiB, beyond that call's 64 KiB per-file ceiling. Subsequent bounded file/hunk reads supplied the retained data. A local orchestration string then had a JavaScript syntax error before any tool execution; that error is also retained. The first remote archive attempt `1a1ba06baac-12894-1810` then stopped with exit 1 because it expected the raw `exit.json` to contain the API-derived `state` field. The raw record actually had exit 0 and complete/durable output. That archive failure and stderr are retained; no publication directory had been created. A corrected archive-only continuation preserves every existing byte and reads the raw terminal schema without inventing a missing state field. A second archive helper assembly (`1a1ba07be6b-12894-1817`, exit 1) omitted the OUT binding and stopped before file access; its complete terminal/stderr are retained as well. None of these failures is a business experiment, and no missing retrieval was converted into a positive result.

`manifest.json` lists every published regular UTF-8 file, byte count, SHA-256 and origin, excluding the manifest itself. The publication copy was create-only into the assigned `base96-observation/` directory and was rehashed against this external bundle. No environment mapping, credentials, SQLite database, executable binary, Cargo cache or unrelated task material is included. No other D4 subtree was modified by this audit.
