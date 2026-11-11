# Exact-source observations at 2582a6d15a14

These files preserve the original successful and unsuccessful observations for
commit `2582a6d15a14d3929d3238d844e710f5a291b422`, tree
`472706bce99c94b47141ca5dd4c22e458e1deb4c`. They must not be relabelled as
execution of a later commit.

## What actually ran

The focused quantum job ran 58 network, 12 adversarial and 18 resource-clock
tests, all passing. The 34 joint qualification tests and 28 dynamic
participation tests passed. The qualification request actually returned 3
with `REFUSED_UNPROVED_JOINT_CONSENSUS`. All 72 cases completed their declared
horizons, all 72 traces replayed, and the source identity matched before and
after. There were 1844 latched tip-measurement requests. Requests are not
completed physical measurements. The per-case archive has not been unpacked
in this review, so no adoption-gain estimate is invented here.

The focused native job actually passed all six selected library
`public_growth_v1` tests, including both named current-clock regressions.
Other compiled test targets had zero matches for this filter. Compile time
was reported as 10m 40s; the six tests ran in 3.67s. This is distinct from the
old desktop negative-baseline process, whose final state remains UNKNOWN.

## Failures retained and narrowly corrected

- The CI contract rejected the old whole-file `store.rs` pin in
  `pon-recent-batch-acceptance.yml`. The 180-test CI mutation run reported
  10 failures and 3 errors, with that rejection blocking expected later
  checks. All 32 workflows and 26 inline guards were inspected; only this
  guard intersects a changed current-candidate path. The correction updates
  that one reviewed pin without changing any check.
- Native tests passed, but rustfmt rejected two call layouts in
  `growth/tests.rs`. The correction follows the two actual formatter hunks.
  It does not change a condition, parameter or production implementation.
- Repository-truth ran 58 lifetime-budget controls and reported one error:
  the declared source lock did not match `consensus.rs`. The complete
  fifteen-path review found an inherited test-only consensus change and this
  continuation's helper visibility change. The correction rebinds those two
  digests and the declaration revision, preserving all unknown bounds,
  false claims and historical source records.

The focused successor lane also runs the 58 lifetime controls. Its native
command explicitly selects `--lib`: the same six tests live in the library,
and the original full-workspace baseline gates remain unchanged. The original
source3 command and its results remain in the raw log.

## Existing host gate remains separately unresolved

The arm64 cross-architecture job completed its earlier cost steps but its
from-zero service controller returned failure. Build preparation passed.
The service includes a formatting gate, but the console summary does not
show whether formatting was its only failure. The child artifact members
needed for attribution are listed in `arm64-host-observation.json`.
No resource limits, service acceptance criteria or permissions were changed.

## Evidence and scope

The JSON files summarize the adjacent original raw logs. Full paired traces
and command receipts are retained in the linked GitHub artifacts, with their
reported archive digests. Artifact retention is finite; the original head
quantum/native failure logs and repository-truth failure log are retained
here as exact UTF-8 bytes.

All experiment, native-regression and source-check results remain development
observations. Native W1 quantum hardness, an all-legal-algorithm resource lower
bound, CP/CG/CQ, lifetime failure and production activation remain unqualified.
