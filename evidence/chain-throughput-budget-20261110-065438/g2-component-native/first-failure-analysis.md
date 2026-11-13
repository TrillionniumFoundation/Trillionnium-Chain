# G2 hosted component control failure readback

Run 42938943118, attempt 1, head `7d6567b92575d1d84766afd49d0720b6f197b0e0`, tree `ea0f6792497d72cbad92cffdeeedbcba7b6f9a06`, completed **failure** at 2026-11-11 01:52:45 UTC. This is a component experiment, not a service campaign or TPS measurement.

## Custody and execution

Both official artifact ZIP digests, sizes, CRCs and all 55 unique safe member paths were verified. The extracted binary digest, every recorded stdout/stderr digest, compiler artifact JSON, actual release profile, exact Rust 1.95.0 and before/after source receipts were independently checked. Each libtest lists 1,338 tests; all seven required names occur exactly once. Both builds exited 0 and all seven native control processes started. No compiler or source guard failure explains the result.

| Arm | Artifact | ZIP SHA256 | Native results | Reader accepts |
|---|---:|---|---|---|
| fixed | 13820743494 | f14479eb27957c6f5bd45fe5602137544db7597d74bcece3e9fbc6df1d0638b0 | 6 pass, 1 fail | 5/7 |
| before | 13820199912 | cc7b922af95c21fb295173e771118b224f2557e2927bd38ea9949d79f7353aef | 1 pass, 6 fail | 4/7 |

The four mining controls meet their exact expectations: fixed four passes; old production three specific assertion failures and one packet/error/cold-commit equivalence pass. This does not qualify the History controls.

## Observed History failure

All six History invocations reached actual M06 injection: 321–326 complete native W1 replays, approximately 165 ms measured caller-thread CPU, versus approximately 140 ms projected paid credit. They did not fail before the intended injection point.

For fixed Continue, detached Execution completed and was accepted. The subsequent held Commit started but refused with `PUBLIC_MUTATION_CPU_BUDGET`; the last History epoch close then refused `PUBLIC_MUTATION_CPU_UNAVAILABLE`. The native test panicked at its successful-import unwrap (original line 145). Forty-two resource checks during refill were observed. The ownership fix therefore enables the detached continuation in this experiment, while the fixture's stronger complete-import assertion is not established.

For fixed Cancel, Execution preserved `PUBLIC_REQUEST_CANCELLED`, Commit did not start, and the native test passed its local cancellation assertions. The final outward result was nevertheless `PUBLIC_MUTATION_CPU_UNAVAILABLE` because epoch close failed. Final flow was null; the runner rejected that missing accounting evidence.

For fixed Expire, the same original five-second deadline expired during the first refill callback. Execution retained `PUBLIC_REQUEST_DEADLINE`, Commit did not start, epoch close succeeded, and final exact CPU flow remained available. Both native and reader checks passed.

All three old-production History invocations refused at Execution with `PUBLIC_MUTATION_CPU_BUDGET`, performed zero refill callbacks and panicked at the intended original line 133. Their last epoch close also failed, and final flow was null. The reader correctly refused to count those as qualified negative controls without the required flow object.

## Source-derived causal boundary

`ServiceMutationCpuOperation::finish` has successful CPU-settle phases in all six records. No observed evidence establishes an arithmetic identity defect. `finish_remote_history_cpu_epoch` separately requires the last listener's settled stored credit to be nonnegative. A failed close leaves `EpochGuard.closed` false; its Drop calls `abandon_history_epoch`, marking the original account unavailable. `observe_actual_flow` intentionally returns None once unavailable. Thus final null does not by itself show lost CPU samples or a false balance equation.

The sampler may resume a verified detached continuation once its original allowance permits the next step. It does not promise sufficient CPU for a subsequent indivisible held commit. Held boundaries must continue refusing rather than sleeping with the Node writer.

These are source-derived explanations consistent with the raw phases, not an observation of the pre-close balance. A new cfg(test)-only, read-only before-epoch-close hook has been added to capture the original settled flow and balance before any crash fence. It has not yet been compiled or executed. No production budget, refill, deadline, admission or cleanup predicate was changed, and the original G2 artifacts and verdicts are preserved.

## Files

`independent-readback.json` contains all fourteen actual native summaries, exact panics, source identities, compiler profile, binary digests and the minimal raw History phases. Original reports and full process files remain under `fixed/native/` and `before/native/`; original archives remain at their artifact-ID ZIP paths. Complete official job logs and terminal run metadata are retained alongside them. Signed download receipts are local scratch metadata and are not intended for repository evidence.
