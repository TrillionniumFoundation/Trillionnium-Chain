# Responsive PoN continuation: CI observations and a bounded test repair

This supplement retains observations of GitHub head `a490d3b971997e927de3aece19864497d65d5984` and repairs one test assumption. The scientific implementation and its 62-command validation remain bound to `bab83768b7c794b0127dc63d633f3e37a1be025a`; the [frozen scientific report](../pon-quantum-responsive-gates-20261107/README.md) is unchanged. All four general quantum security gates remain **HOLD**.

## What changed

The only modification to existing test or implementation code in this follow-up is [the staged-observer test module](../../scripts/ci/test_w1_staged_observer.py). In the retained transparent-candidate CI failure, the test indexed stage zero after the coordinator returned an empty stage list. Its real 0.2-second cumulative budget can legally expire during initialization, before preparation is launched. The original test deleted its temporary result and suppressed the coordinator's output: the console proves empty stages, while the exact inner error receipt was unavailable. Prelaunch budget expiry is a supported explanation, not a recovered observation of that missing receipt.

The repair checks two explicit failed paths using a coordinator-local test clock. One spends 0.05 seconds in initialization and requires preparation to receive the original absolute deadline of 100.2, leaving 0.15 seconds. The other expires exactly at or after the deadline and requires no subprocess-supervisor call, stage event, manifest verification or proof credit. The failed lifecycle control produces no successful cryptographic backend or scientific execution.

The new evidence verifier checks archive identity and extraction completeness only. The real subprocess timeout, absolute-deadline, cancellation, descendant cleanup and ownership controls remain in the same module. The production coordinator, its supervisor, workflow deadlines, CPU/memory limits and acceptance predicates are unchanged.

## Repair validation

The complete module passed **31 tests**. Two in-memory negative controls were rejected: removing the prelaunch budget guard fails both boundary cases, and renewing the deadline at preparation fails the original-deadline assertion. The mutation controls do not edit production files.

- [Full test command and source binding](repair/staged-observer-tests.json)
- [Complete test output](repair/staged-observer-tests.stderr)
- [Negative-control results](repair/negative-mutations.json)
- [Exact source diff](repair/staged-observer-repair.diff.gz)

The original diff and one negative-control log are stored as lossless gzip to preserve their raw whitespace. [Decoded and compressed hash bindings](repair/lossless-receipt-bindings.json) identify both byte sequences.

The tested repaired file has SHA-256 `763acbdb380da2784038aaceaa579571305e57b2919375a21b9a1688db28e5b6`. The coordinator remains `704349676bfd812c9788440f9d41d866de9305d9283c34b4e5342ba57bcf52ab` and the supervisor remains `ec8bf817620d3d4166c03b86693657ae9b4a59ceeed9d147aecc1126bc62f3df`. Independent review checked the unchanged real process controls and read both negative-control logs.

Reproduce the module from the follow-up checkout:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s scripts/ci -p test_w1_staged_observer.py -v
```

This local result does not relabel the earlier GitHub failure or establish that a later GitHub run passed.

## Current-source CI failures remain visible

The complete paginated snapshot at **2026-11-08 02:21:16 UTC** contained 100 checks: **71 success, 14 failure, one skipped and 14 in progress**. Both pages and their total counts were retained. This is a live observation, not a closed final cohort; pending checks are not passes. See the readable snapshot audit and the original responses inside the archive.

| Failure group | Observed evidence | Scope of the conclusion |
| --- | --- | --- |
| Cross-architecture cost, x64 and ARM64 | All five named native tests and service/sustained acceptance pass. Confirmation acceptance rejects `CONFIRMATION_TARGET`. Seven honest submissions succeed, while paid native history replay misses the original four-second confirmation deadline. | A real finite business-target failure. Successful submission and safety/accounting checks do not satisfy independent confirmation. |
| Protocol contract, head and prospective merge | Both fail `CONFIRMATION_TARGET`; baseline confirms one transaction, the four-second/16-worker pressure phase confirms zero. | The existing lane stops at its first command. Its later commands are not claimed executed. |
| Fresh challenge service, head and prospective merge | Fresh native test exits 101 at the original four-second/six-depth assertion. The original native report also fails independent confirmation acceptance. All four baseline variants confirm one transaction; all four pressure variants confirm zero. | This failure is separate from the repaired transparent-candidate unit test. |
| Four native-priority service-model jobs | Original release from-zero step rejects `CONFIRMATION_TARGET`; five named tests and service/sustained validation pass. Baseline confirms one transaction and pressure confirms zero. | Three reports retain `PUBLIC_REQUEST_DEADLINE`; ARM/head has an empty verification-error list despite missing the confirmation target. Do not assign one unobserved error to every job. |
| Original native campaign, x64/head/release | All three predeclared runs exit 101 and retain `finite_experiment_criteria_met=false`. All nine phases, including the three attack-free baselines, fail complete signed-round confirmation. | Failed baselines prevent an inference that an attacker caused the failure. The original workload and criteria remain in the reports. |
| Historical retained-pressure artifact | Run `37730166589`, artifact `11531476198`: zero artifacts found; independent artifact GET returns 404. | The historical evidence prerequisite is missing. Expiration versus deletion is unknown. |
| CodeQL export | All 39 retained snapshots expose no matching CodeQL analyses/check runs for the frozen head/merge. The existing 1200-second/30-second polling contract fails before another poll. | No CodeQL verdict was obtained. This is neither a reported vulnerability result nor a passing security gate. |
| Transparent candidate, prospective merge/x64 | Empty stage list triggered the old test's `IndexError`. | The scoped repair above covers both valid budget-failure paths; production behavior is unchanged. |

The compared workflows, drivers and original native fixtures are byte-identical to `bef17d6` for the inspected failing paths. This establishes direct source identity, not a complete counterfactual latency or environment analysis. No original deadline, quota, confirmation criterion or historical-evidence requirement was relaxed.

Complete original console logs and the compact per-group audits are retained. The readable audits preserve exact job/artifact IDs and source comparisons.

## Evidence verification and limits

[The raw manifest](raw-manifest.json) pins [the archive](raw.tar.gz), every selected member, and each original allowlist. [The verifier](verify_raw.py) checks the archive and every unique regular member before optional extraction.

```bash
python3 -B verify_raw.py
python3 -B verify_raw.py --extract /tmp/pon-responsive-ci
```

Extraction requires an absent destination. The archive contains selected complete console logs, acceptance manifests/reports, source comparisons, test-repair context and polling observations. It excludes authentication state, private profiles, signed download URLs, native binaries and databases.

For cost, protocol, fresh-service and CodeQL artifacts, complete downloaded ZIPs were checked against the original GitHub upload digests before the selected public files were packaged. The original 61 MB native campaign archive and the four priority archives were read selectively. Their full ZIP digests are **not** claimed verified. Each selected native campaign report and stderr file independently matches its SHA printed in the complete original job console. Priority member reads retain ZIP size/CRC and per-file SHA checks with their immutable artifact IDs. Lossless gzip copies retain the complete original report bytes and decoded hash bindings.

These integrity records establish the identity of the selected evidence. They do not calibrate physical hardware or turn failed service observations into quantum-security results.

## Later allocation observation

The frozen scientific record correctly retains two guarded release refusals and an incomplete allocation lifetime. The later read-only assignment inventory at **2026-11-08 02:04:13 UTC** no longer lists the owned endpoint. This proves absence at that observation, not the release mechanism, exact release time or complete billing interval. The earlier frozen receipts are unchanged; no forced cleanup or ownership change was performed.

## Publication scope

This follow-up is a test repair plus evidence and a development-plan update. It preserves the earlier source/evidence commits and the four **HOLD** outcomes. Publication uses the authorized HeptaRuntime local Mac GitHub channel and the existing draft PR 781. Its exact new head and subsequent live CI state require their own readback; the frozen 02:21 snapshot above is not reassigned to the repair commit.
