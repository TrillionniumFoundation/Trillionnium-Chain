# Independent package review protocol v1

Status: **A00 control-plane candidate; no package, Gate, merge, release or activation decision is included**

The machine decision template is `INDEPENDENT_PACKAGE_REVIEW_DECISION_V1.json`. A reviewer creates a new decision envelope for one exact package commit/tree. The checked-in template is empty and has no authority.

## Required separation

The independent reviewer must not be the package author. Conflicts, employer/organization relationships, campaign-operation duties, signer custody and prior authorship are disclosed. A conflicted reviewer may contribute analysis but cannot be the sole acceptance authority.

## Exact package identity

A review binds all of:

```text
agent and package ID
PR and branch
head commit and tree
base commit and tree
handoff path, Git blob and SHA-256
source-manifest path, Git blob and SHA-256
```

Mutable branch names and PR merge refs are navigation aids only. Any identity change requires a successor review.

## Exact replay evidence

The reviewer verifies a completed/success run on the exact package head. The decision records workflow name, run ID, workflow head SHA, runner identity, toolchain identity, command-manifest root and raw-log digest. Skipped, stale, queued, in-progress, cancelled, failed or synthetic-merge runs cannot satisfy the replay field.

A successful workflow is necessary but not sufficient: the reviewer must also inspect scope, authority boundaries, retained mutants, source-binding assertions and known omissions.

## Mutant replay

The reviewer content-addresses the complete retained mutant corpus and independently executes every P0 mutant. The decision separately records rejected and unexpectedly accepted mutants. One accepted safety, root, durability, cryptography, economic, custody or truth mutant produces `STOP_CONDITION`; it cannot be waived by changing the expected output or deleting the case.

## Interfaces

Requested interfaces are reviewed against exact source digests. Accepted and rejected interfaces are explicit. An accepted interface bundle root is computed over sorted, domain-separated interface records. Package-local models, fixtures and caller-supplied digests are not silently promoted to cross-package or production authority.

## Findings

The decision binds a finding ledger and counts open Critical, High, Medium and Low findings. Open Critical or High findings block candidate acceptance. A reopened finding invalidates affected downstream evidence.

## Decision layers

The following decisions are independent fields and must never be collapsed:

```text
package_candidate_accepted
interface_candidate_accepted
gate_exit_authorized
merge_authorized
release_authorized
production_activation_authorized
```

Accepting a bounded candidate does not authorize any later layer. Merge, Gate, release and production decisions require their own authorized process and evidence.

## Invalidation

A review reopens when source/base identities, handoff, manifest, mutant corpus, workflow, runner, toolchain, interface set, finding state, evidence root or signature changes. Old envelopes are immutable; publish a successor with predecessor and invalidation links.

## Empty-template truth

The repository template remains:

```text
status=NOT_REVIEWED
exact_head_completed_success=false
all_p0_replayed=false
package_candidate_accepted=false
interface_candidate_accepted=false
gate_exit_authorized=false
merge_authorized=false
release_authorized=false
production_activation_authorized=false
```

No tooling may infer acceptance from the presence of the template itself.
