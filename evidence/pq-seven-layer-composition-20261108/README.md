# Seven-layer PQ composition evidence — 2026-11-08

Status: **HOLD / NO-GO**. This packet is a continuation of PQ128 accounting
candidate `88568e2511fcf166e6824947ac97b06b72104385` (PR #790). It adds source
binding, a seven-route source/effect register, and a pure root/recovery policy
model. It grants no execution authority and supplies no complete lifetime bound.

## Source and regression records

- [Lifetime lock generation](pq-source-lock-generation.json) records the 15
  declared owner paths checked against the original `12e510b...` Git blobs.
- [Original failing controls](pq-source-lock-red.txt.gz) precede the repair. Their
  failures and errors are retained; the subtest counts are not distinct tests.
- [Source-lock validation](pq-source-lock-green.txt) retains 58 lifetime tests,
  49 claim tests and separate HOLD reports. It predates the final composition.
- [Root policy validation](root-policy-validation.txt) retains 26 model tests,
  preflight and the unknown-evidence example. It is not signature verification.
- [Reviewed corpus pin changes](source-pin-update.json) list changed and newly
  required paths. Existing historical pins are not discarded to pass checks.
- [Initial environment observations](initial-environment-observations.json)
  preserve the failed local partial clone and missing sparse-checkout evidence.
  They are setup observations, not successful or failed native campaigns.
- [Exact-source validation runner](run_validation.py) writes separate command
  receipts outside the checkout, checks raw tracked bytes before and after, and
  preserves command failures. A run must supply its own expected full commit.

The four targeted Python suites contain 58 + 49 + 18 + 26 = **151 tests**.
The source/effect register locks 44 source files. These counts are scoped to
their named suites; no full Node, WAN, physical rollback or independent custody
acceptance is implied. Subsequent committed-source records, when added, remain
separate observations rather than edits to these earlier records.

## Independent branch observations

[Candidate metadata](remote-candidate-observation.json) is a non-atomic read-only
snapshot. It does not combine separate PRs into one tested candidate.

The three records below were read from #796 delivery
`01e2c4c010c3cf65d1cf094368961efc1abab445`. Their exact Git blob identities were
checked on import. The original source and evidence paths remain in the JSON.

| Retained original | Original Git blob | Interpretation |
| --- | --- | --- |
| [32-command summary](upstream-796-inventory-summary.json) | `865712b48843c04403b1c93e2f8f06896e4cc1aa` | Tested `ca3c4f88...`; 31 passes, one failed command; aggregate FAIL |
| [Inventory readback](upstream-796-inventory-readback.json) | `1d71a3cc2ce8d3ae7a0f8dd317de57826ed946ad` | Node module: 38 passed, 2 failed, 1 ignored; original names retained |
| [Dual-family experiment](upstream-796-root-quorum-result.json) | `71a32122e6d58c3c89082dcce57523dee5945e88` | Separate real signature experiment, no installed root effect or independent custody |

No #796 failure was rerun, reclassified as expected success, or repaired by
this continuation. Its native results cannot qualify this PR, and this PR's
Python/source controls cannot qualify #796.

The [seven-layer review](../../docs/security/PQ_SEVEN_LAYER_REVIEW_20261108.md)
and [root policy contract](../../docs/security/PQ_ROOT_RECOVERY_POLICY_V1.md)
describe the remaining proof, state, custody, content and execution obligations.

## Embedded source inventory repair

The [inventory repair record](distributed-inventory-repair.json) preserves a
failed generation-consistency check at `d8280daa8651ca387813b25e2a712f3fd1c82a1d`.
The native embedded source inventory omitted the two new composition configs
and two lifetime configs already present in #790. The canonical generator adds
all four entries; its one existing corpus pin changes while the 727-path set
stays fixed. This changes the generated native source inventory, with no new
authorization rule or production permission. The repaired committed source
requires its own command receipts; earlier results do not automatically apply.

The record also retains a separate local full-diff failure caused by an absent
historical Git object. Scoped repair checks do not substitute for the complete
desktop checkout's source and diff checks.


## Exact committed-source campaigns

| Tested source | Command gates | Aggregate result | Receipt |
| --- | --- | --- | --- |
| `d8280daa8651ca387813b25e2a712f3fd1c82a1d` | 28 passed / 1 failed | FAIL: generated inventory omitted four config entries | [Original campaign](committed-source-d828/README.md) |
| `1d29818ad927f549f43d74a06f51e91771feac70` | 29 passed / 0 failed | PASS for the named scoped checks; whole-chain HOLD remains | [Repaired-source campaign](committed-source-1d29818/README.md) |

Both campaigns completed all 29 commands, including raw tracked-source checks
before and after, exact Cargo graphs with locked offline dependencies, strict
workspace Clippy, formatting, 165 default crypto tests, and 6 Hepta PQ comparator
tests. Each keeps its original summary and stdout/stderr byte identities. The
[separate inventory refusal](inventory-negative-d828/summary.json) is also
retained. Results from one source never replace results from another source.

The [repair delta](source-repair-delta.json) and
[environment observation](validation-environment-observation.json) expose the
actual source and toolchain scope. These are operator observations and do not
establish independent custody, deployed-root identity, or whole-chain acceptance.

The [local materialization summary](local-materialization-summary.json) and
[lossless complete record](local-materialization.json.gz) resolve the earlier
local missing-pin and Markdown-target observations. That earlier local sparse
checkout still had 142 explicitly missing objects and did not qualify as a
complete source checkout. Both recorded campaigns used the separate, complete
desktop worktree and preserved full source verification before and after.
