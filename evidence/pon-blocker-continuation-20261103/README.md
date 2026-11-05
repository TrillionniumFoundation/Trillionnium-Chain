# Remaining-blocker continuation, 2026-11-03

This increment fixes the Cell retirement deadline boundary, improves failure
diagnosis without changing acceptance, and aligns the existing Draft review with
the original CodeQL producer's target coverage. It does **not** close all PoN
blockers. Original work-cost, public-service, independent-review and activation
gates remain HOLD.

The work started at `1b0d60d574c4b3e2172f314cd2655644373b0a27` and preserves the
concurrent parent `469c4d4bb36efb37045d968f35f83cb2c1771933`, tree
`383a3cbc8a4a71f27e4f18d7df089b860f302439`. The [integration receipt](concurrent-integration.json)
verifies the remote tree and commit and retains all twenty incoming files.
No concurrent account-graph, workflow, source-pin or evidence change was discarded.

## 1. Retirement keeps the original deadline and irreversible outcome

The prior retirement path checked its deadline before an uncontrolled metadata
write. The retained implementation keeps the public `retire` entry point and
routes it through `retire_controlled`, using the existing `OperationControl`.
The same original deadline now surrounds successor verification, writer
acquisition, the status update, transaction readback, commit and final readback.

The retirement-specific Immediate transaction acquires the writer before changing
status and rechecks the exact prior obligation. Writer and commit busy timeouts
are capped by the smaller of the previous timeout and remaining original time.
All normal Result paths restore the previous timeout. Cancellation or expiry
observed before commit rolls back this metadata update. Cancellation after commit
returns an error while retaining the retired fact for an exact-identity retry;
it does not claim a rollback or refund previously committed byte charges.

The original status contract remains: pending duties cannot retire, acknowledged
duties must satisfy height and successor coverage, and an already retired
identity is read back. Successor bytes, manifest, store identity and retention
window are still verified. The shared write helper retains the previous complete
row/checksum readback for acknowledgement and repair callers.

The 27 release retention controls include normal local writer contention and an
independent reader that cancels only after observing a real committed retirement.
They verify preserved duty/capacity before commit, restored timeout, cold reopen,
and exact reconciliation after commit. No old-version reproducer or network
pressure run was executed for this increment. These are cooperative checkpoints,
not a claim that a running filesystem or SQLite call can be forcibly preempted.

## 2. W1 failure diagnosis remains separate from acceptance

The existing W1 service manifest can report `FRESH_NATIVE_PROCESS_REQUIRED` for
a native test that actually ran and failed its business assertion. The new
`failure_diagnostic` field records only the actual child return code, a strictly
typed `finite_target_met`, and the last bounded History replay result from the
declared final phase. Missing or malformed information stays `unknown`.

The diagnostic reuses the existing regular-file and strict JSON reader. It
retains no proof or request fields, permits at most sixteen replay entries and
only short error identifiers, and cannot fall back to an earlier successful
entry or the baseline. It adds no process call or retry. Original validation,
selectors, budgets, failure strings, source/binary checks, final exit and
qualification flags are unchanged. Thirteen static/mock controls cover these
boundaries, including a nonzero native exit paired with a positive-looking
summary: the original failure still wins.

Read-only inspection of existing W1 run
[41635095283](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41635095283)
found actual four-second business failures in the head and old prospective-merge
fresh-service jobs. Their four small no-pressure baselines completed one
confirmation each; their four pressure phases completed none. This is a different
workload from the large F0 baseline below. Neither result remeasures the historical
approximately 20.73 primitive rejection-CPU ratio.

## 3. Two additional performance candidates were rejected

The [plan](experiment-plan.json) was recorded before measurement. The local rule
required every planned call to complete, a median per-round thread-CPU ratio at
most 0.95, and an empirical nearest-rank p95 ratio at most 1.05. With sixteen
rounds, that empirical p95 is the largest observed round ratio; it is not a
population-tail or confidence claim.

| Candidate | Observed or reviewed result | Decision |
| --- | --- | --- |
| Prepared immutable Host path bytes and exact current-limit text comparison | 16 ABBA rounds, 64 samples, 16,384 complete calls; median CPU ratio **0.902946**, empirical p95 **1.417139** | Reject: p95 failed the predeclared condition. Restore the original Host source exactly. |
| One ordered UNION query for both account children | Pinned SQLite initializes both arms before delivering the first Row; a left SQL execution error can precede the original right missing/decode/edge verdict | Reject before runtime qualification or timing. Restore the original three source/test files exactly. |

The [Host result](host-component-decision.json), [decisions and source hashes](component-negative-decisions.json),
[validation archive](raw-validation.tar.gz.base64) retain both attempts. The exact
patches are archive members `rejected-host-prepared-paths.patch` and
`rejected-sibling-order-by.patch`; their original hashes and unified-diff context
bytes are preserved. Keeping them inside the lossless archive resolves the
staged whitespace check on the context-only blank lines of raw patch files. The combined candidate was compiled, and only the named
Host component observer was executed from that binary. The rejected sibling
candidate's planned runtime comparisons were not executed. A possible no-order
sentinel query received only a partial static analysis and was not substituted
as a qualified implementation.

The Host observer compares seven fresh complete reads per call: two real procfs
texts and five ordinary temporary files. The derived 114,688 file opens exclude
fixture setup. It omits parent metadata and the complete Host authority decision.
It is a local same-executable component comparison under the recorded
[hardware](hardware.json), not an independently built whole-node comparison or
the original quarter-CPU public Host. The median improvement cannot erase the
failed p95, and neither metric qualifies public service.

## 4. Preserve the complete failed F0 denominator

The [baseline readback](baseline-readback.json) comes from the exact existing
`1b0d60...` run
[41635095044](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41635095044).
Its raw baseline is retained losslessly in [the compressed record](baseline.json.gz.base64),
with [digests](baseline-raw-manifest.json) and the unchanged
[outer result](original-f0-result.json). The reader never runs the downloaded binary.

| Original large baseline observation | Result |
| --- | ---: |
| Extra request processes | 0 |
| Planned business packets | 21 |
| Timely receiver acknowledgements | 7 |
| Planned confirmation rounds | 3 |
| Observed rounds / missed rounds | 1 / 2 |
| Confirmations within the original window | 0 / 3 |
| Successful / failed local imports | 6 / 1 |
| Actual checkpoint calls | 91,462 |
| Checkpoint thread CPU sum | 5.022116584 s |
| Outer importer calling-thread CPU sum | 5.833386418 s |
| Account-graph stage CPU delta | 4.595563093 s |

The failed last import ends with `PUBLIC_REQUEST_DEADLINE` and remains in the
totals. Its completed-work amount is censored. Host, importer and account-graph
intervals overlap and must not be added. Host spans cover each actual invoking
thread, while importer CPU excludes scoped-worker CPU. No exact CPU percentage,
cross-source speedup or missing-round latency is inferred from these totals.

Recompute the retained readback with:

```sh
python3 -B evidence/pon-blocker-continuation-20261103/read_baseline.py
```

## 5. CodeQL needs a producer for the actual review target

The [coverage investigation](codeql-coverage-readback.json) records why the old
exact-source export timed out: all 38 selections were empty, all 76 check API
pages reported no check, and all 38 analysis pages were empty. All 198 artifact
file digests matched. This is missing analysis evidence, never a zero-finding
security result.

At inspection, the old target feature branch
`fix/chain-pon-work-safety-20261103` was unprotected. This matches the missing
producer observations and GitHub's [default-setup trigger rules](https://docs.github.com/en/code-security/concepts/code-scanning/setup-types):
PR scans target the default or protected branches. The [normal Draft retarget](codeql-retarget.json)
aligns #688 with the original `main` review target. It changes no branch
protection, token permission or CodeQL configuration, and performs no merge or
activation. Main's only exclusive content change, the empty README, is retained.
The detailed-contract check now requires those exact zero bytes. Its previous
single-newline expectation rejected the main-aligned tree; that failed check is
retained alongside the earlier incomplete-packaging link failure. The check
continues to reject any content in the owner-cleared README.
The normal subsequent source push supplies the synchronize event for producer
coverage. Actual new source/merge checks and analyses must still be observed.

This expands the visible review difference to the already retained ancestry.
Old feature-base and prospective-merge receipts keep their original identities;
they cannot qualify the new main comparison. The action does not supply a
CodeQL verdict or independent security acceptance by itself.

## 6. What remains blocked

| Boundary | Current disposition and required evidence |
| --- | --- |
| Retirement's late-success path | Component repair and regression controls retained; no permanent-custody claim. |
| Misleading W1 process-failure diagnosis | Bounded metadata added; the original failure still determines the result. |
| Exact-source CodeQL | Normal producer target aligned; fresh completed analyses and the original authenticated gate still required. |
| W1 cheapest legal cost and effective production share | HOLD: relation verification and cache correctness do not establish a cheapest-algorithm bound, comparable tasks, hardware competitiveness or preprocessing/reuse limits. |
| Primitive rejection cost | HOLD: the historical local approximately 20.73 ratio is not remeasured here and is not a public-network amplification estimate. |
| Original public confirmation service | HOLD: retain failed original workloads and all missed/failed outcomes; the concurrent account-graph component does not automatically qualify the combined source. |
| Difficulty and confirmation parameters | HOLD: original development parameters unchanged; the prior fluid model is not stochastic, heterogeneous-hardware, partition or quantum qualification. |
| Independent participation and evaluator control | HOLD: independent operators, discovery and governance require independent operational evidence. |
| Effects and model use | Preserve existing irreversible local history; real external-effect recovery, loader/FinalUse integration and model behavior need their own evidence. |
| Availability and economics | Local retention correctness does not prove future retrieval, independent custody, sustainable resources or fair attribution of real model gain. |
| Whole-chain PQ and release | Existing exact-source, witness and activation gates remain separate and false. |

The [validation manifest](validation.json) and [raw archive inventory](raw-manifest.json)
bind executed commands, outcomes, source-file identities and logs. The lossless
[validation archive](raw-validation.tar.gz.base64) can be restored with
`python3 -B evidence/pon-blocker-continuation-20261103/restore.py NEW_DIRECTORY`. The separate
final clean-commit identity check verifies bytes; it does not execute tests.
Local runtime checks in this package use normal component/regression workloads.
The initial retention receipt records two unrelated Node SQL files changing
concurrently; the integrated retention controls repeat all 27 selected tests on
stable source. No original receipt is relabeled as a complete-tree snapshot.
Original hosted campaigns keep their own source-bound outcomes. No broader
qualification or activation flag is promoted.
