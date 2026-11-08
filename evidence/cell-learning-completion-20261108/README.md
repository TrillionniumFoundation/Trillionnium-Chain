# Original completed-learning checkpoint and next-use evidence

Result: **five original native actor controls passed; thirteen Chain continuation
controls passed. Complete real learning/adoption qualification remains
HOLD_NO_GO.** The positive corpus contains actual native actor exports, with
synthetic learning and worker outputs. It does not contain neural training or
independent evaluator evidence.

## Frozen source and execution

| Field | Exact observation |
| --- | --- |
| Chain dependency | PR #809, `5f7eccf86e252cce67bf5dd6f614c1c7a1824e53` |
| Hepta source | `34eacaec1c94032f4980807e4a6f7c3516a7dafc` |
| Hepta tree | `fdfed48155d664ef3f56c84a6972f2d746e46587` |
| Hepta code base | `ed1ea5691798a2dbffbbcc8216f2929e67724af7` from PR #5357 |
| Configured host | `rog`, isolated checkout and independent empty Cargo target |
| Runtime test job | `1a1bc339416-138b0-d6` |
| Source verification | 11,190 tracked entries verified before and after; exact head/tree and clean index/worktree |
| Native command | Original `just test -p codex-hepta-agentd --lib --locked --offline --no-capture -E` with five fixed selectors |
| Resource envelope | 200% CPU quota, 8 GiB MemoryMax, two Cargo build jobs, original nextest profile/retries/timeouts |
| Native outcome | Command exit 0; 5 passed, 0 selected skipped, 0 retries observed; 748 unrelated cases filtered |
| Native execution | 455.949 seconds including fresh compilation; native nextest interval 15.011 seconds |
| Native log SHA256 | `dd87a08e99c8fd1f9d4aa3fff7032d71f8b429574cc8e590098af22245f4003e` |
| Original JUnit SHA256 | `f72ae088f976646bbe6fc53b4ef10ed59ab61475e12e1be1dda82946a237b5ee` |

The five original selectors are:

- `ordinary_actor_reads_actual_use_and_cold_recovery_without_reexecution`
- `updated_candidate_uses_original_actor_and_recovers_without_another_reset`
- `running_actor_refuses_current_withdrawal_and_revocation`
- `updated_actor_rechecks_current_withdrawal_and_revocation`
- `unpublished_actor_refuses_learning_readback_and_keeps_transport_errors`

The frozen Hepta source adds a test-only export of the actual completed native
checkpoint after its original use/recovery checks. The complete native codec,
actor journal, publication, current authorization, nonce, recovery and negative
controls remain responsible for execution. No production API or stored checkpoint
domain changes.

## Retained collector failure and reconciliation

The native command succeeded. Its outer run script then looked for JUnit under
`CARGO_TARGET_DIR/nextest/local/junit.xml` and failed with FileNotFoundError.
Nextest actually emitted the configured report under the isolated workspace's
`codex-rs/target/nextest/local/junit.xml`.

[native-run/result.json](native-run/result.json) preserves that original outer
**FAIL**. [native-run/run_native_original.py](native-run/run_native_original.py)
is the exact executed runner. [native-run/verification.json](native-run/verification.json)
is a later, separate reconciliation: it verifies all five original JUnit names,
absence of failures/skips/retries, report modification time within the original
run interval, the retained log hash, original native exit code, and unchanged
source. It does not rewrite the failed attempt or rerun the tests.
The reproducible [runner](run_native.py) now checks the actual workspace report
path and its run interval.

The first Chain test attempt expected an alternate native iteration refusal for
the retained checkpoint supplied to the adopted fixture. Those original fixtures
share a request/owner map and correctly differ at their receipt prefix, so the
reader refused `COMPLETION_EXACT_RECEIPT_PREFIX`. Only that assertion's expected
code was corrected; the reader gate was not changed. The retained first run is
[failures/completion-suite-v1.log](failures/completion-suite-v1.log).
The initial sparse baseline checkout also omitted an original historical
real-model fixture; its failing run is retained in
[failures/baseline-native-reader.log](failures/baseline-native-reader.log), and the
original file was restored before the unchanged baseline suite passed.

## Original byte capture and validation

The collector produces the [fixture manifest](native-readbacks/fixture-manifest.json),
retained original stdout, four native readbacks, four Selection checkpoints and
two completed checkpoints. The manifest pins every material and locates the exact
original JSON slices. Expected contexts and freeze records are fixture-derived;
source strings and SHA256 consistency do not independently authenticate them.

Reproduce the capture into a new directory:

```sh
python scripts/capture_cell_learning_completion.py \
  --log evidence/cell-learning-completion-20261108/native-run/native.log \
  --native-source 34eacaec1c94032f4980807e4a6f7c3516a7dafc \
  --output /absolute/new-native-readbacks
```

Run the preserved original readers and the additive suite:

```sh
python scripts/test_cell_adoption_readback.py -v
python scripts/test_cell_learning_iteration_join.py -v
python scripts/test_cell_learning_completion_join.py -v
```

The completed-chain reviewer binds the original final receipt to the exact
original use, rejects rehashed prior/final evidence substitution, foreign task
runs, wrong owners/predecessors/times, unacknowledged output, incorrect pins,
codec truncation/extension and duplicate completion. ACK, model STOP and learning
completion remain distinct. All production, independent-control, real-training,
settlement and FinalUse acceptance flags remain false.
