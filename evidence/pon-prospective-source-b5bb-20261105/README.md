# Frozen candidate b5bb: actual GitHub prospective-merge source check

Status: **PASS for source identity only**.

The actual GitHub prospective merge for Draft PR #688 was fetched as
`f135eb867d10ead2058073f78d9d82af2e174f29`. Its ordered parents are:

1. Base: `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`.
2. Candidate: `b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c`.

The merge and candidate tree are both
`8be28a72673ce318d60a464898ab610d9ba39216`.
The API observation and the fetched Git commit agree.

## Execution

An independent Git repository fetched complete commit history using the
server-advertised tree filter. Native `git merge-base --is-ancestor` returned
0 for the exact base and candidate; `git rev-list --count` traversed 12,771
candidate-reachable commits. No shallow file, graft file, or replacement ref
was created. The initial treeless preparation lacked the base tree required
by `git show -s`; a normal blobless fetch of that exact tree resolved the
preparation error. No checker change or fabricated history was used.

The independent repository retained about 3.12 MB of its own object files and
read existing candidate objects through an alternates path. A preflight with
lazy fetching disabled confirmed every selected blob was local. The complete
checkout contains **9,587 tracked entries / 954,728,186 raw bytes**.
The integration and native-test workspaces were not modified.

The unmodified repository checker, Git blob
`c775290c138c3b41a32e654f56ed5cbe9acec3ee`, ran with:

```text
python3 scripts/ci/verify_ci_source.py --kind prospective-merge
  --expected-head b5bb7bc8d7ffe79d46c6a58fd5189e2bb9e4550c
  --expected-base dd6e1c3cbeacbdc532b0679297835b3a0aac78f0
  --expected-merge f135eb867d10ead2058073f78d9d82af2e174f29
  --output <outside-checkout>/prospective-source.json
```

It returned exit 0. Before and after checks found the exact merge HEAD/tree
and a clean complete worktree. The raw checker receipt and stdout are
preserved unchanged; stderr is empty. Setup, object-history checks, the API
observation and execution details are included alongside them.

## Scope

This checks the actual GitHub merge object's parents, the canonical
base/candidate combination, and every tracked filesystem byte. It executes
no native tests and supplies no native prospective-merge acceptance, PQ
qualification, independent physical witness acceptance, W1 proof, or QROM
security result. Those gates require their own recorded execution.
