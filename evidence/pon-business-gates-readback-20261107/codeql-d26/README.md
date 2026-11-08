# d26 CodeQL read-only review — 2026-11-07

## Observed result

The two automatic CodeQL runs for `d26e047dedfcdb17a1ac2c47cc26e6f1185f6b89` completed successfully. All six jobs and all 69 recorded job steps succeeded; no job/step was skipped in these two final snapshots. This is successful scan execution and source verification, **not zero findings, complete Rust extraction, native acceptance, prospective-merge coverage, or production qualification**.

| Producer | Run | Event / source | Jobs / steps | Actual scan results |
| --- | --- | --- | --- | --- |
| Repository exact-source local SARIF | 42383368491, attempt 1 | push; head d26 | 3 / 39, all success | Rust 568; Python 2; Actions 0 |
| GitHub default Code Scanning | 42383373868, attempt 1 | dynamic; refs/pull/688/head, d26 | 3 / 30, all success | Rust 568; Python 2; Actions 0 |

The exact-source producer uses CodeQL 2.27.4 for all three languages and `upload: never`; its complete local SARIF files are retained in the original artifact ZIPs. The default producer uploaded server analyses; its Rust/Actions metadata says 2.27.4 and Python says **2.27.3**. The server SARIF responses are explicitly retained as GitHub API subsets. These are separate producers, not independent sets of 1,140 vulnerabilities.

Every API operation in this review was GET-only through HeptaRuntime Desktop `/usr/bin/gh`, after a successful login check for **ProfHepta**. No dispatch, rerun, account change, source mutation or native build was performed.

## Original source-after proof

All three exact-source artifact ZIPs match their GitHub-reported SHA256 digests. Each includes byte-identical `source-before.json` / `source-after.json`:

- candidate / tested commit: `d26e047dedfcdb17a1ac2c47cc26e6f1185f6b89`
- tested tree: `cef3563653b982a8043326ad4b53a4b93ab63906`
- kind: `head`; base / prospective_merge: null
- tracked_worktree_verified: true
- tracked entries: 11,017; tracked bytes: 1,031,001,045
- tests_executed_by_identity_check: false

For each language, all six original post-analysis status/diff/index files are present and empty. The original complete run log is retained. This closes the previously observed Cargo.lock worktree-mutation failure **for this actual head scan**; no old failure is relabelled.

The default run's full logs independently show checkout of d26 and `CODE_SCANNING_REF: refs/pull/688/head`. Its three server analyses bind that same commit/ref. It does not emit the repository's source-after receipt, and no such receipt is fabricated for it.

**No prospective-merge CodeQL scan was observed in these two runs.** The push workflow has only the head matrix; the dynamic producer also uses the PR head ref. Native priority/W1 canonical-merge coverage cannot be inherited by CodeQL.

## Findings and extraction limits

The complete exact-source Rust SARIF has 568 results: 562 `rust/hard-coded-cryptographic-value` and 6 `rust/cleartext-logging`. Many locations are tests or examples, but some are production source paths; no blanket false-positive, dismissal or remediation conclusion is made. The rule metadata gives warning-level security severities 9.8 and 7.5 respectively; those are rule defaults, not independently established exploitability assessments.

Rust has `executionSuccessful: true`, yet its original notifications include one error (`rust/diagnostics/type-inference-consistency-counts`, “Ill-formed type mention”), 19 `rust/diagnostics/extraction-warnings` with no explicit level, 66 notes and 7,733 none-level notifications. Successful jobs and empty server metadata `error` / `warning` fields do not erase these extraction diagnostics.

The complete Python SARIF has two `py/redos` results, default rule level error / security-severity 7.5:

- `evidence/pon-throughput-continuation-20261104/parent-and-tail/ci/workflow_wiring_static.original.py`, line 60
- `evidence/pon-throughput-continuation-20261104/parent-and-tail/ci/workflow_wiring_static.py`, line 79

Both concern the same nested repeated regular expression in `test_names`. The files are byte-identical at e70, 96e1 and d26; see `python-source-comparison.json`. They are historical evidence/static-replay helpers, not the public request path. The original file retains hard-coded historical scratch paths; the derivative accepts a repository argument. Its six fixed Rust input paths are read without a hard byte ceiling. The current workflow/scripts/sole-plan search found no automatic invocation; three old Rust inputs are absent from d26. This bounds current exposure, but does not make the regex safe on arbitrary repository input.

A future reviewed fix should replace the ambiguous repeated regex in a maintained replay helper with a deterministic scanner, preserve duplicate-name checks and the original accepted attribute/function forms, and compare with the original on the six historical source inputs plus bounded hostile repetition controls. A simple `[^\\n]*` to `[^\\n\\]]*` change or indiscriminate atomic grouping can alter attributes containing `]` and same-line attribute/function behavior. Do not rewrite the frozen original as if it had generated past evidence with the new algorithm; any successor/archival change needs its own declared identity. No repair was applied here.

Actions SARIF contains zero results and no error/warning extraction notification. Python has five telemetry notes and no error/warning extraction notification. Those narrower observations do not promote the other lanes.

## Evidence locations

All paths below are relative to this directory. Original snapshots remain unchanged; incomplete early snapshots retain their then-current running statuses.

- `20261107T145343Z-d26-d8573e1b/`: first targeted snapshot; Actions/Python artifacts, both Rust jobs then in progress.
- `20261107T145847Z-d26-artifact-review-61d4b79b/`: offline inspection of those original artifacts.
- `20261107T145955Z-d26-9d0facd5/`: exact-source run completed; all three original artifacts and complete run-log ZIP; default Rust was still in progress at capture.
- `20261107T150052Z-d26-python-findings-0cdd73db/`: complete Python finding objects/rule lookup attempt and telemetry notes.
- `20261107T150558Z-d26-exact-final-review-5839ccbe/`: complete exact-source artifact, job/step, source-after, finding, extraction-diagnostic and log-highlight review. Rule lookup includes SARIF extensions.
- `20261107T150558Z-d26-d5db65e2/`: final default run metadata, all jobs and original complete run logs.
- `20261107T150805Z-d26-compact-review-d8f19a9f/`: full counts/locations and an explicitly compact diagnostic projection.
- `20261107T151137Z-d26-default-analysis-review-1e1a63dd/`: four complete metadata pages (345 PR688 CodeQL analyses), the three exact-d26 metadata readbacks and API SARIF subsets, plus default log source binding.

The final default analysis IDs are Rust **2118459507**, Python **2118438476**, Actions **2118432667**. Their list/readback metadata agrees and all three bind `refs/pull/688/head` at d26. No prospective merge or inaccessible PR metadata is inferred from these head-only records.

The acceptance owner separately paginated all automatic Actions for this exact head and observed four runs total; priority/W1 results belong to that owner's original artifacts and are not certified by this CodeQL package.

## Retained operational interruption

The first Hepta `process_read` of completed collector job `1a1b6801bd4-12894-4a7` returned a non-JSON tool error after a long delay, causing the local summary parser to fail. The collector itself had already completed exit 0 with durable output. A read-only retry of that **same job** retrieved the original output; no collector replay, new run, omitted native result or source repair followed.

Top-level `SHA256SUMS.json` covers every retained regular file, including all child checksum manifests, and excludes only itself. GitHub artifact digest checks are recorded separately from local manifest hashing.
