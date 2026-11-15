# PR847 required CI queue and protected legacy deletion review

Observed 2026-11-14 04:26:26 UTC. This report performed only read-only GitHub queries and immutable local source reads.

## Required CI is already triggered and waiting

Exact e40d7071c4724e6600deef8a2820bf35c1982289 run 43551533528 was created at 03:25:09 UTC as a pull_request run and is pending. Its jobs endpoint returned zero jobs at 04:24:08 UTC. The workflow has no draft condition or path filter. Its concurrency group is portable-trnm-required-baseline-refs/pull/847/merge and cancel-in-progress is false.

The same workflow/PR has an older in-progress run 43540659883 at e35cfb3cd85183a3b5beb47ad1287389cc4d1cd5. It was created at 01:27:04 UTC, but its three remaining jobs began at 02:21:31 UTC. All three are executing the retained Rust shard step; the pinned OpenSSL provider preparation already succeeded.

| Job | Job ID | Actual start | Current step and start | Original timeout (min) | Nominal timeout |
| --- | --- | --- | --- | ---: | --- |
| prospective Rust shard (runtime) | 132296835371 | 2026-11-14T02:21:31Z | Run retained Rust shard (2026-11-14T02:26:58Z) | 180 | 05:21:31 UTC |
| rust-baseline shard (quality) | 132296835378 | 2026-11-14T02:21:31Z | Run retained Rust shard (2026-11-14T02:26:50Z) | 180 | 05:21:31 UTC |
| rust-baseline shard (runtime) | 132296835492 | 2026-11-14T02:21:31Z | Run retained Rust shard (2026-11-14T02:26:56Z) | 180 | 05:21:31 UTC |

The unchanged timeout is per job, so 05:21:31 UTC is the nominal start-plus-180-minute boundary, about 55 minutes after the observation. It is not a guaranteed whole-run completion time: final artifact/cleanup processing and downstream aggregate jobs may follow. Completed head and prospective protocol-contract and repository-truth jobs already report failure; no conclusion was discarded or rewritten. This review did not reanalyze those failure logs.

Normal final-candidate path: root can update the existing PR head by a normal authenticated fast-forward push after its source review. That produces pull_request:synchronize and the existing head plus prospective-merge gates. A new pending candidate can automatically replace the previous pending run under the existing default single-slot queue, while the running predecessor remains preserved. No manual cancellation or concurrency edit is needed. Marking ready is not one of this unfiltered pull_request trigger default activities, and workflow_dispatch cannot replace the PR-only prospective-merge verification.

The five required contexts are actual head jobs (repository-truth, protocol-contract, fuzz-smoke, external-evidence-contract, rust-baseline). The workflow also has prospective merge paths; their existence does not explain absent head jobs. Exact-head and prospective evidence must both be evaluated after the candidate synchronizes.

## Existing legacy deletion policy blocks this viewer

The read-only GraphQL query authenticated as ProfHepta, whose repository viewerPermission is ADMIN. For fix/chain-bulk-state-tree-20261017 at 57c1ed545d067937cbd7aaa7570d5f22123265e6 both branchProtectionRule.allowsDeletions and viewer-specific refUpdateRule.allowsDeletions are false. viewerCanPush is true and allowsForcePushes is false. REST enforce_admins false therefore does not establish deletion permission.

GitHub defines RefUpdateRule as the protection enforced on the viewer and exposes delete permission separately from push permission. Existing policy prevents ordinary deletion by this viewer. No deletion attempt, protection change or bypass was made. The one-branch goal remains policy-blocked until the user or repository governance legitimately changes that policy; this review does not authorize such a change.

## Official references and raw evidence

- https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency — Same group allows one running workflow; a successor stays pending; default single pending may be replaced, running is retained with cancel-in-progress false.
- https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows — Default pull_request activities are opened, synchronize, reopened; ref is refs/pull/NUMBER/merge.
- https://docs.github.com/en/graphql/reference/git#refupdaterule — RefUpdateRule describes protection enforced on the viewer; allowsDeletions and viewerCanPush are distinct fields.
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule — Allow deletions belongs to rules applied to everyone including administrators.

Machine-readable report: /private/tmp/chain-ci-required-pr-trigger-review-20261114/required-trigger-and-legacy-delete-review-v1.json
Raw evidence paths and SHA256 values are recorded there. All observations are timestamp-bounded and do not grant production, performance or merge qualification.
