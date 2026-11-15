# PR 784 retained historical artifact read failure

The job remains **failure**. It failed while retrieving pinned historical
artifact `11531476198` from run `37730166589`. The diagnostic step after
download was skipped. This job did not rerun a pressure test and did not
execute the candidate native or risk code.

The workflow at final head `b5c655ebe9611b3d62cf739e61e6867decc053e3`
is byte-identical to base `cb314bb4656e5da4844325cd83994ab4764fe8e9`.
Its purpose is to expose an immutable historical failure without treating
that historical result as current acceptance. The missing-artifact error is
a current retrieval blocker, not a passing negative-control result.

At 2026-11-08 00:54:58 UTC the original October 8 run remained readable and
reported failure. Its current artifact list was empty, and the pinned
artifact metadata endpoint returned HTTP 404. The evidence does not determine
whether the artifact expired, was deleted, or became unavailable through
another retention mechanism.

[Diagnosis](diagnosis.json), [current historical availability](historical-availability.json),
[short log](failure-excerpt.txt), [annotations](annotations.json), and the
[exact retained-job source excerpt](workflow-retained-job-excerpt.txt) are
included with raw API responses, complete job log, and both workflow versions.

- [Failed hosted job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42431209882/job/128580281336)
- [Committed workflow](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/b5c655ebe9611b3d62cf739e61e6867decc053e3/.github/workflows/pon-priority-acceptance.yml#L60-L97)
- [Historical run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/37730166589)

Only REST GET and git inspection were performed. No source edit, CI rerun,
cancellation, comment or GitHub write was performed. Other hosted jobs are
outside this diagnosis.
