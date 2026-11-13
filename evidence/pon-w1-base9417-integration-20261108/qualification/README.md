# C8 qualification history and independent audit

Frozen executed source: `4e007a87ceecbec8d265f6a70cfd71d512a514b5`, tree `19a4f1a6e1cec5c27e595fa555b97cddc4717a3c`. Source parents are C7 and the fixed base9417 commit. These records qualify the frozen head source within the stated tests; they do not qualify a later prospective-merge event or the post-hoc evidence commit.

**The first campaign was not all green.** Its 73 commands produced 665 ordinary method executions: 664 passed and 1 failed, with 4 Rust methods ignored. One additional complete staged suite was declared in advance and run with the same source, plan, driver, argv and original parameters. It passed all 32 methods. Across every declared qualification attempt, the retained total is **77 commands, 697 ordinary method executions, 696 passed, 1 failed and 4 ignored**. The backend also has one deliberately expected source-probe exit 1, which is not a test method.

The selected successful coverage set contains 73 commands and 665 passed ordinary methods, plus 4 ignored. It uses the one repeat for staged coverage. That selected set must never replace the all-attempt totals or turn the original `qualification_complete=false` into true.

| Component or attempt | Commands | Ordinary executions | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: | ---: | ---: |
| backend | 7 | 0 | 0 | 0 | 0 |
| native | 10 | 4 | 4 | 0 | 0 |
| core | 20 | 571 | 571 | 0 | 0 |
| owner | 19 | 37 | 37 | 0 | 4 |
| receiver | 4 | 11 | 11 | 0 | 0 |
| historical-regressions | 4 | 10 | 10 | 0 | 0 |
| history-local | 5 | 0 | 0 | 0 | 0 |
| staged-original | 4 | 32 | 31 | 1 | 0 |
| staged-repeat | 4 | 32 | 32 | 0 | 0 |

## Original staged failure and bounded repeat

The original staged job `1a1ba8f182e-12894-1b97` has 31 passed methods and one failure in `test_ignored_sigterm_escalates_and_output_overflow_remains_failure`. Its original 0.2-second allowance expired before Popen, producing `DEADLINE_EXHAUSTED_BEFORE_SPAWN`; the SIGKILL cleanup assertion was not satisfied and the later OUTPUT_LIMIT subcase was not entered. The production observer starts this allowance before declaration persistence and output-file setup. No per-phase measurement establishes which activity caused the exhaustion, and no I/O, CPU or whole-host-idle explanation is claimed.

The test patches a module constant to 0.15, but `measure` already captured the default argument when it was defined. Because the test passes no explicit cleanup-grace keyword, the actual omitted default remains 5 seconds. Neither this fixture nor production deadline logic was changed. The successful job `1a1ba97e353-12894-1bcf` is the single predeclared complete-suite repeat, not an extension of the first trial's deadline. It adds actual SIGKILL/OUTPUT_LIMIT branch coverage; it does not explain the first failure or establish stable short-budget timing. The launcher observations concern the seven known qualification units and the original failed unit at bounded times, not all host workloads, zombie reaping or historical resource ownership.

## Evidence and counting

Each component directory contains its original manifest and every original stdout/stderr byte in a read-back-verified `raw-logs.tar.gz`, a per-member hash index, an independent review and a file manifest. `command-output-index.json` maps all 154 command streams to those archives. Raw Python and Rust outcomes, including the failure and ignored counts, were parsed independently; the aggregate also rechecked every archived stream and recomputed the totals. Source-before and source-after are the original strict head-identity records, not newly run checks.

The History group compiled its release test binary with `--no-run` and listed one exact ignored entry using `--ignored --list`. It executed zero test methods and no 4105-block workload. The 10 historical/cache regression methods are separate from the owner's legacy-admission and reorganization filters. Counts describe executions, not global unique tests across previous sources or repeated attempts. Precommit 160 Python methods, prerequisite imports, audits, copy/preparation receipts and listed-only entries are not added to the qualification totals.

The owner, backend and native targets were independent copies of qualified C7 caches, with `fresh=false`; registry and toolchain caches were reused. Original C7 empty-target creation is historical provenance, not an empty C8 target or clean-room claim. Actual Cargo/source and ELF pins are retained. Backend/native ELFs were rehashed by the independent component audit; owner ELF hashing is bound to the original strict import, and History ELF hashing to its original compile/list helper. This aggregate does not reread or publish those executables.

## Preserved preparation and audit failures

The initial owner launcher failed its wording assertion before invoking any qualifier, Cargo or Node, and executed zero qualification commands or methods. Its original failure and the exact three-line external launcher correction are retained. Two independent audit-only failures are also retained: an incorrect inherited source-hash constant and an incorrect traceback substring. They executed no tests or source guards and did not change original qualification outcomes; corrected audits used new output directories. Audit-driver inputs preserve raw terminal text where available and do not use a rounded request-fingerprint number as an identity authority.

## Limits and publication

This package generates zero complete proofs. The 11 receiver controls use the original November 5 complete receipt with the C8 verifier. It establishes no winning W1 Node admission, C8-bound full-generation ABBA benefit, positive provider payment, complete historical process accounting, original business-budget pass, deployment qualification or full cryptographic/protocol security. All four engineering gates remain **HOLD**. Lifecycle observations belong to a separate package and are not counted here.

Only allowlisted logs, JSON, source helpers and review documents are copied. ELF binaries, SQLite databases, private process environments and credentials are excluded. The package manifest proves filesystem bytes, including every component archive and provenance member. The publishing owner must still verify all listed files in the Git index and the published commit; this package makes no circular claim about its own eventual publication.
