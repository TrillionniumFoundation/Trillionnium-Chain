# Recovered historical native regression: original production to repaired files

[Recovery summary](recovery-summary.json) binds all original files by size, SHA-256 and Git blob. The original driver actually finished at 2026-11-11 01:06:20 UTC. Its terminal record became readable after the desktop transport recovered. Earlier records saying the outcome was UNKNOWN reflect the information available at that time; this directory adds the original completed evidence without rewriting those snapshots.

## Observed negative baseline

The driver started from base `e4abb172147e941b62483652b0ceabaae4317624` and inserted the new regression while retaining the old production Growth and store bytes. Compilation completed.

The [baseline raw log](03-baseline-new-regression.log) reports **0 passed / 1 failed**, with command exit **101**. In the first fresh-request loop iteration (`existing=false`), assertions had already established a refusal with `TIME_DEFERRED`. The subsequent work counter assertion failed: `work_started=1`, expected `0`.

This demonstrates late eligibility rejection after W1 had begun. It does not demonstrate invalid activation. The assertion stopped the test before the stored-duplicate baseline iteration, so no separate negative result for that iteration is claimed.

## Observed repaired behavior

The [original driver record](02-native-run.json) and raw logs show:

- [New regression](06-after-new-regression.log): one test passed, including both fresh and stored-duplicate iterations.
- [Independent retained postcommit regression](07-after-retained-postcommit.log): one test passed.
- [Public Growth library selection](08-after-public-growth-v1-subtree.log): all six tests passed.
- Three-file formatting and whitespace checks returned zero.

This is a **three-file working-tree red-to-green observation**, not complete committed-source validation. Other agents could change unrelated files during the old run. The two repaired production blobs match candidate `a0cf721c`; the final test file differs only in one formatter line wrap. The original Cargo manifest and lockfile were unchanged.

Current-candidate validation is recorded independently in the [final focused Actions record](../actions-a0cf721c0a3f/README.md) and the [desktop native record](../local-native-a0cf721c/README.md).

No test here directly injects a wall-clock rollback during unlocked W1 and owner reacquisition. Concurrent races, long-chain resource bounds and hostile-load liveness remain outside these regression results. All quantum and production qualification remains **HOLD / NO-GO**.
