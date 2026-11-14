# Model owner final integration verification — 2026-11-05

The actual model campaign remains **aborted, spent 1/1; all six final
acceptance gates remain open**. This directory retains source integration
checks and native component observations. It does not add a model attempt,
independent evaluation, deployment authorization or release qualification.

## Exact executed source

Commit `7d347fa80e2cd3fd19d0010c3465581143b8d2e1`, tree
`30309765887b6d2f54a5e37d58f8608dc60a2518`, combines original PR head
`23a56123e3112de06d7c684ef2057578759176ff` with frozen model source
`f388f46d9df150a3599b9d961b48918b3ff1fb48`.

| Check | Actual result | Scope |
| --- | --- | --- |
| Native M06 all-targets/all-features | 236 passed, 7 existing ignored, 0 failed/filtered/measured | 25 targets; all 243 prior target/test identities and all 236 prior passing outcomes retained |
| Strict Clippy | Exit 0, 15.825 seconds | M06 all-targets/all-features with `-D warnings` |
| Cargo metadata | Exit 0; 26 workspace / 175 resolved packages | Locked graph; original Rust 1.95 and provider |
| Cargo fmt | Exit 0 | Whole native workspace |
| CI contract | 98 passed, 0 failed/errors/skipped; 9.443 seconds | One execution on clean committed source |
| Source integrity | 43 passed; 3.471 seconds | Printed negative-control FAIL receipts are expected; suite exit 0 |
| Repository check | PASS; 2,829 local links | 1,135 Rust files, 26 workspace packages, 25 normal edges |
| Exact source corpus | 468 pinned blobs | HOLD_NO_GO; qualification flags remain false |

The [native verification](native-integrated-7d347fa80e2c/verification.json),
[per-target roster](native-integrated-7d347fa80e2c/actual-test-roster.json),
[CI contract report](ci-contract/verification.json), and
[source-check snapshot](source-integration/integration-source-validation.json)
bind actual commands, logs, identities and source before/after. The source-check
snapshot was written while native verification was pending; the separate
completed native report supplies the later result without rewriting that history.

The controller rejects target substitution, formerly passing tests becoming
ignored, and contradictions between individual outcomes and summary totals.
Its [seven negative controls](integrated-controller-transcript-controls-v2.json)
and earlier controller observations are retained. Controllers are original
execution records with original absolute paths, not a portable reexecution API.

Cargo metadata returned zero while its stderr contained a global cache
last-use database ENOSPC warning; those original bytes remain in
[cargo-metadata.stderr.log.gz](native-integrated-7d347fa80e2c/cargo-metadata.stderr.log.gz).
Earlier native build/cache failures remain in
[the frozen-source case](../native-f388-verification/README.md).
These M06 observations do not execute or certify Node admission/TCP/CPU,
Growth cold replay, the whole Torch release, or an installed Hepta consumer.

## Concurrent PR changes and input binding

While verification ran, the original PR advanced from `23a56123` to
`67097f5add069c49788fc5ba21c35d1db07167c4`. The exact delta consists of
two modified documentation/evidence files and 114 new evidence files.
The [read-only input binding](docs-only-followup/native-input-continuation.json)
and [exact upstream comparison](docs-only-followup/upstream-path-binding.json)
record no intersection with 149 observed repository compiler inputs,
42 literal includes, the fixed runtime fixture or six Python oracle modules.
The native, config, scripts and formal subtrees are unchanged in that delta.

The [prepared final input binding](source-integration/final-prepared-input-binding.json)
verifies all H runtime/build/config/workflow inputs remain identical in the composition. H's native
execution remains identified as H's execution; a documentation/evidence-only
successor is not described as another native run. Final committed-source
repository/corpus readback is reported on the original PR.

The first no-lazy-fetch checkout attempt encountered missing blobs in the
existing partial clone and exited before worktree changes. The retained
[source observation](source-integration/final-concurrent-checkout-observation.json)
and [normal Git transport result](source-integration/final-concurrent-blob-fetch.json)
record the failure and retrieval of 112 missing immutable blobs. Permanent
Git configuration and the partial-clone boundary were not changed.

The initial whitespace check against H also listed four original concurrent
raw-log files already present in the current PR head. The
[scope observation](source-integration/whitespace-scope-observations.json)
proves their staged blob identities exactly match the actual first parent
`67097f5`. The new diff against that parent passes without changing their
bytes, trimming original logs, or disabling whitespace rules.

## Retention and full acceptance

[retained-files.json](retained-files.json) records each listed copied observation's
original size/SHA-256 and retained size/SHA-256. Gzip records are lossless, with
fixed metadata; decompression reproduces the original bytes including blank
lines and diagnostics. Later integration receipts and cleanup observations are
also retained in this directory and bound by their containing commit. No raw
test output was trimmed to satisfy whitespace checks.

The [actual hosted case](../hosted-run-41951536925/README.md) retains the only
pretrained attempt, its original SQLite, all 26 artifact files and the exact ZIP.
The [full gate record](../full-acceptance-gates.json) keeps independent custody,
unseen tasks, whole-release measurements, lifecycle economics, behavioral
exercises and real CURRENT/generation/FinalUse execution unclosed. No source
or native pass changes the failed model outcome or grants another allowance.
