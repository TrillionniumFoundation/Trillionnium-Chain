# Six-axis measurement continuation — 2026-11-03

**Decision: HOLD.** The descriptor candidate passed the allocation rule in all eight cohorts, but passed the ordinary-allocator wall nonregression rule in only six. The two failing cohorts remain failures. The earlier filtered candidate and its instrumented observations are also retained. No campaign was rerun to obtain a passing result.

The runtime candidate is **not selected**. The default M06 arithmetic function and Node integration were restored; four Node candidate helpers are fenced by `cfg(test)`. The M06 borrowed primitive remains available to explicit example/test callers. [Production isolation identity](production-isolation-identity.json) records 11 function bodies and the complete cache integration file as byte-identical to the original base. No wall measurements were taken after this isolation. Final integration validation is separate and is not certified by this historical measurement package.

## Revisions and scope

Both experiments start at `bebb1f3289cd7050fefde89ea8f2cf33c6c37588` and use Rust 1.95.0, the existing **test profile**, and M06 default features. Existing package optimization overrides remain unchanged. [Reproduction metadata](reproduction.json) binds the commands, rules, source patches, binary identities, and raw files.

- [Filtered v1 patch](filtered-v1-reproduction.patch) restores the original rejected filtered prototype and its original instrumented observer. Its six recorded source inputs match [the original manifest](filtered-v1-source.json); only the M06 source and new example differ from the base.
- [Descriptor v2 patch](descriptor-v2-reproduction.patch) restores the exact measured seven core files and three observer files, including the experimental Node wiring. All 1,107 recorded source files are reconstructable from the base plus this patch: 1,097 match the base and ten match the patch. [Reconstruction checks](reconstruction-check.json) include successful cached-index application checks for both patches.
- The v2 wall executable uses the standard Rust allocator. Allocation counting lives in a separate executable sharing the exact fixtures and arm implementations. The wall executable and shared support install no custom allocator. Counter overflow invalidates an allocation sample without panicking in the allocator.
- The independent `pon_executor::root` oracle remained byte-identical to the base. **The measured owned arm's `root_with_arithmetic` used the candidate's shared iterator adapter**, so it is not a byte-identical execution of that base function. Historical reproduction requires the archived patch; running the unchanged examples against the subsequently restored library is a different source revision.

The component includes non-account partition construction, grammar validation, and its root calculation. It excludes account-root construction, liability checks, Host processing, I/O, and service paths. Requested allocation bytes are cumulative allocator requests, not retained memory, peak RSS, or process memory savings. Neither run establishes service CPU, host qualification, p99, TPS, or an end-to-end speedup.

## Fixed descriptor campaign

The four fixed `(payload cells, account rows)` pairs were `(64,64)`, `(1024,64)`, `(2100,64)`, and `(64,2100)`, each cold and warm. Each payload cell contains 4,080 ASCII bytes. Both arms use the same source state and original 2 MiB retained-payload cap. Cold caches reset outside each timed interval; warm caches receive one untimed preparation per arm.

Wall measurement used 16 ABBA rounds per cohort: 32 samples per arm, 512 samples overall. The paired median is the median of the 16 ratios of each round's two borrowed durations to its two owned durations. The empirical p95 is nearest-rank over the 32 samples of each arm; the reported ratio is borrowed p95 divided by owned p95. Allocation measurement used one separate ABBA sequence per cohort, 32 samples overall. Both processes completed once with exit 0 and empty stderr; exit 0 records completion, not performance acceptance. Every planned cohort and raw sample is retained.

The preregistered rule required at least 5% fewer requested allocation bytes in **every** cohort, and wall paired median B/A ≤ 1.00 with p95 B/A ≤ 1.10 in **every** cohort. The separate 5% wall-improvement rule required median B/A ≤ 0.95 and the same p95 bound.

| Payload / accounts | Cache | Requested bytes removed per call | Wall paired median B/A | Wall p95 B/A | Nonregression | 5% wall improvement |
| --- | --- | ---: | ---: | ---: | --- | --- |
| 64 / 64 | Cold | 277,408 | 0.987654 | **1.319470** | **FAIL** | FAIL |
| 64 / 64 | Warm | 277,408 | 0.856948 | 0.862005 | PASS | PASS |
| 1024 / 64 | Cold | 4,485,648 | **1.007682** | 0.997328 | **FAIL** | FAIL |
| 1024 / 64 | Warm | 4,485,648 | 0.950543 | 1.017122 | PASS | FAIL |
| 2100 / 64 | Cold | 9,190,156 | 0.974642 | 0.989496 | PASS | FAIL |
| 2100 / 64 | Warm | 9,190,156 | 0.919510 | 0.868267 | PASS | PASS |
| 64 / 2100 | Cold | 277,408 | 0.975681 | 1.085623 | PASS | FAIL |
| 64 / 2100 | Warm | 277,408 | 0.926702 | 0.881957 | PASS | PASS |

Allocation reduction passed 8/8; ordinary-wall nonregression passed 6/8; the separate wall-improvement rule passed 3/8. At 2,100 payload cells, the requested-byte reduction is 23.97% cold and 29.95% warm. These allocation results do not override the all-eight wall failure.

[Wall JSONL](descriptor-v2-wall.jsonl), [allocation JSONL](descriptor-v2-allocations.jsonl), and the [independent audit](descriptor-v2-independent-audit.json) retain the unrounded values. The audit checked exact ordering and completeness, reference roots, arithmetic observations, retention limits, deterministic allocation counts, and all thresholds. [Campaign metadata](descriptor-v2-campaign.json) retains process receipts and host observations; its identical before/after source inventories are stored once as compact `[path, sha256, bytes]` rows in [the source inventory](descriptor-v2-source-inventory.json).

## Earlier rejected filtered candidate

The [first raw result](filtered-v1-raw.json) retains all eight cohorts, 512 instrumented wall samples, and 32 allocation samples. The [first summary](filtered-v1-summary.json) reports all outcomes. Its original all-eight wall rule was median B/A ≤ 0.95 and p95 B/A ≤ 1.10; only one cohort passed. The mostly-account warm cohort regressed to median 1.569046 and p95 1.116157. Requested bytes at 2,100 payload cells fell by 9,321,164 per call, a different candidate and count from v2.

That binary still installed a custom allocator wrapper with a TLS lookup while counters were disabled. **Its wall timings cannot establish an ordinary-binary improvement.** The exact observer source is retained in its replay patch, not silently replaced by the corrected observer. Results from the two different revisions are not pooled.

## Native controls and setup history

The pre-isolation descriptor Node binary `68d9d1ba7ad5b3eb657a020a46ebd2aee576468934bdc77a011ac94faacef098` produced **119 passed, 2 failed, and 1 explicitly ignored** tests across seven selectors. Both original CPU selectors failed with `PUBLIC_MUTATION_CPU_BUDGET`. [Selector results](native-descriptor-control-results.json), [the first failure log](native-descriptor-large-parent.log), [the supplementary failure log](native-descriptor-large-parent-auth.log), and [log hashes/counts](native-control-observations.json) preserve those outcomes. The baseline's first CPU failure and supplementary pass remain in [its summary](native-baseline-cpu-summary.json) and [verbatim CPU receipts](native-baseline-cpu-receipts.jsonl). These single CPU observations support no strict speed ratio. The M06 component source manifest does not certify the complete Node binary source closure.

[Setup observations](setup-observations.json) preserve verified log excerpts and hashes for the offline dependency failure, the cached 10-test M06 result, the initial zero-match Node selector, its corrected one-test selector, the initial unused-import warning, unused release preparation, and subsequent test-profile example build, overflow control, and narrow Clippy completion. Missing standalone exit receipts remain explicitly null. The zero-test run and unused release build are not accepted as validation or measurement evidence.

This directory contains no binaries, hosted ZIPs, or complete source snapshots. [File checksums](SHA256SUMS) cover the package files; [copy provenance](retained-file-provenance.json) links retained raw bytes to their original observation files. The integration results below remain separate from these frozen experimental receipts.

## Isolated integration validation

[Final validation](final-validation.json) binds the isolated code to commit
`751e75b8f11fecad612bb95c33ea3a2567dc131b`, tree
`24e310522368f3816b333fc0b80e4f67a8ecb669`. An independent clean checkout verified
all 7,348 tracked entries. All 1,156 native source/config inputs remained identical
through the final runs; subsequent evidence-only additions must preserve that hash.

| Local check | Observed result |
| --- | --- |
| Selected Node controls after clean package build | 120 passed, 1 failed, 1 explicitly release-only ignored |
| Remaining Node failure | Original supplementary large-parent `PUBLIC_MUTATION_CPU_BUDGET` |
| M06 library after clean package build | 101 passed, 0 failed, 6 original explicit cost experiments ignored |
| DA library | 173 passed, 0 failed, 0 ignored |
| Workspace/all-target/all-feature Clippy | PASS with `-D warnings` |
| Formatting and offline locked graph | PASS; 26 packages, 138 all-feature Linux resolve nodes |
| CI contract / execution / PQ source / project boundary checks | 98 / 67 / 34 / 16 executions passed respectively |

The first final Node build failed to link: its M06 archive still held the old
filtered constructor symbols while the consumer expected descriptor symbols.
The receipt retains that failure and symbol evidence. Cleaning only the task's
M06 and Node package caches and rebuilding the same source/profile resolved the
link error. The original CPU refusal remained; the controls were not retried to
obtain an all-pass result. The default path's first large-parent control passed
in this final run, without erasing the earlier baseline or experimental failures.

[Direct binary inspection](descriptor-v2-binary-forensics.json) separately
confirmed that both actual v2 measurement executables contain the one-pass Vec
descriptor constructor, its 16-byte pointer-pair elements and the matching arm
calls. They do not contain the stale filtered constructor found in the unrelated
root build artifact. This inspection did not execute the binaries or change HOLD.

[Parent hosted outcomes](parent-hosted-outcomes.json) retain their exact `bebb1f3`
head/merge scope: pressure four-second confirmation 0/1, F0 1/6 in thirty seconds,
and the three original native campaigns 3/27. The prior 43 PQ selectors passed
each of the four matrices, while original ARM CPU and test-only lint failures
remained. Those results are not relabelled as this continuation's hosted results.
Final HEAD/prospective-merge hosting, public-service acceptance, whole-chain PQ
qualification and activation remain separate unclosed gates.
