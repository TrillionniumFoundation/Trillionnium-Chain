# C6 first CI failure diagnosis: frozen 07:19:50 UTC snapshot

This bundle preserves the original C6 CI observation and a read-only diagnosis. It does not replace failed jobs, change their declarations, rerun workflows or assign outcomes to checks that were still running.

## Snapshot and exact source

- Observation: 2026-11-08 07:19:50 UTC, `observed_unix_ns=1794122390975428400`.
- C6 head: `2bdd252aa6c300b7431b9ee897b254b7953cf562`.
- Actual target branch ref: `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`.
- Actual PR merge: `7b4a63b6f08687e93270407772951aa71087ca3d`, tree `d73e57c9e7a5764a1ab33540c97af587bb6e4a69`.
- Actual ordered parents: `[96a241bf43f6a46d35dfb3d4ced9594ed8ceca75, 2bdd252aa6c300b7431b9ee897b254b7953cf562]`.
- The contemporaneous PR API retained `base.sha=62d2d90c9e1f4c8450c89843f1e08360a24283ce`. This original field is preserved, not corrected after the fact.

The original snapshot contained **85 checks: 40 failure, 10 success, 3 skipped and 32 still running**. This is not an all-terminal snapshot and is not a claim that all CI passed. Raw PR metadata, checks API response, actual merge object, live refs, source commands and original snapshot are under `root-observation/`.

## The 40 failures, classified by observed stopping point

| Count | Observed stopping point | Evidence and limit |
| ---: | --- | --- |
| 38 | Prospective-merge source/ordered-identity preconditions | All 38 original job metadata records identify their first failed source-binding/preflight step and skipped downstream work. Seven representative full logs confirm the ordered base/head mismatch. This is not a claim to have read the precise exception in all 38 logs. |
| 1 | CodeQL exporter source binding | The original export log explicitly rejects prospective-merge ordered parents. Its separate 16 offline exporter tests passed before that refusal. |
| 1 | Historical artifact retrieval | The retained-pressure job found zero artifacts for historical run `37730166589`; its diagnostic execution step was skipped. |

Thus this snapshot has **39 source-bound pre-execution blockers (38 prospective lanes plus export), and one missing historical artifact**. It does not show 40 business/resource regressions. It also does not demonstrate that the blocked business controls would pass if allowed to run.

The 16 exporter helper tests are reported separately; they are not added to local C6 qualification totals or counted as business execution. The independently observed C6 heavy/cold lifecycle results are outside this CI bundle.

## Common refusal observed in original logs

CodeQL Python (`128660701001`), PQ x64 (`128660701244`), W1 fresh service (`128660701933`), native history (`128660701592`), native service-model (`128660701543`) and native boundary (`128660701420`) report:

> ValueError: merge parents differ from the event base and candidate

Their original expected base is `62d2d90...`, expected head is C6 and expected merge is `7b4a63...`. The checkout/actual merge instead has base96 as its first parent. Cleanup x64 (`128660701243`) fails its equivalent shell test requiring ordered parents `BASE_SHA SOURCE_SHA` with `BASE_SHA=62d2d90...`.

The exporter (`128660701162`) reports:

> CodeQL analysis export failed: Prospective merge does not have the exact ordered base/head parents

The strict source guards correctly reject these mismatched identities. They must not be weakened to accept a different base, reversed parents or a source tree selected after observing the result. Empty-artifact upload failures are retained as downstream consequences of source-stage refusal, rather than presented as the primary cause. Node.js deprecation warnings are retained but are not the observed first failure.

## All failed checks grouped by original run

| Run ID | Failed checks | Prospective role | Other role | Names represented |
| --- | ---: | ---: | ---: | --- |
| 42457886518 | 10 | 10 | 0 | W1 false trace reuse; W1 complete legal strategies; W1 paid rank and batch v5; W1 fresh challenge service; W1 factorial legal strategies v3 |
| 42457886584 | 2 | 2 | 0 | reference |
| 42457886555 | 7 | 6 | 1 | native priorities; retained-pressure-failure |
| 42457886583 | 2 | 2 | 0 | original state and exit |
| 42457886547 | 2 | 2 | 0 | native boundary |
| 42457886520 | 2 | 2 | 0 | original workspace test CPU |
| 42457886526 | 2 | 2 | 0 | recent batch |
| 42457886533 | 2 | 2 | 0 | parent evidence |
| 42457886519 | 2 | 2 | 0 | PQ network and witness |
| 42457886523 | 4 | 4 | 0 | cleanup; aggregate-owner-controls |
| 42457886542 | 1 | 0 | 1 | export |
| 42457886506 | 3 | 3 | 0 | CodeQL local SARIF |
| 42457886532 | 1 | 1 | 0 | W1 transparent candidate |

`failed-check-groups.json` retains every original name, role, job ID and run ID. `all-failed-job-steps.json` retains all first/secondary failed steps and skipped/successful steps from 13 original run-jobs API responses. All 40 original failed job IDs were found, and all returned head SHAs match C6. The compact JSON is a derivative for review; the unabridged API responses remain in `run-jobs/`.

## Expected-base upstream

Read-only Git searches against exact C6 are retained in `source-context/`. They show the following original expressions:

- `codeql-real-exact-source.yml`: `EXPECTED_BASE_SHA` takes `github.event.pull_request.base.sha`.
- `pon-owned-process-cleanup.yml`: `BASE_SHA` takes that same event field.
- `pon-pq-system-continuation.yml` and the other PR matrix workflows likewise use the event base field.
- W1 and native-priority workflows select `needs.push-source-context.outputs.base` only for push events; their pull-request route uses `github.event.pull_request.base.sha`.

Those are declarations of the original event-bound expected source, not an instruction to infer expected parents from the merge being tested. The C6 guard/context code was not changed. `source-context/PROPOSAL.md` records the paused code-change proposal and the separate possible C7 integration route; neither rewrites this C6 event.

## Collection and publication

The configured read-only GitHub identity was confirmed as ProfHepta. This collector performed 15 representative metadata/log/annotation GETs, 13 run-jobs GETs and one identity GET, all successful. No workflow was rerun, no artifact was downloaded, and no source or CI configuration was mutated. Nine full representative logs are retained: five fetched here and four byte-copied from the independent native/W1 collector after SHA-256 verification. That second collector's separate GET count is retained in its own diagnosis and is not counted again as a new fetch.

The one 64 KiB file-read limit failure is retained in `bounded-read-failure-01.json`; the complete 83,438-byte steps record already existed and was subsequently read through a compact derivative. It is a retrieval limitation, not a missing job or a test failure.

`manifest.json` covers the exact allowlisted publication bytes, excluding itself. Source Git objects, runtime terminal records, initial failures, raw APIs and logs are retained without rewriting them. The destination was created exclusively at `ci-c6/`; no other D4 subtree, C5/C6 source, qualification result or lifecycle operation was altered.
