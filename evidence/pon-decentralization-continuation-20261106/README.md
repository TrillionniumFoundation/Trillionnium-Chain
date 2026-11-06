# Five-axis evidence continuation — 2026-11-06

This continuation of Draft PR #742 fixes two missing-evidence diagnostics and a
repeated-scan cost defect, adds real local evidence-byte materialization, and
introduces explicitly selected WAN V4 joint-domain accounting. The actual
source-only assessment still has **23 findings and HOLD**. No independently
administered network, custody appointment, funding population or 72-hour WAN
campaign was supplied or executed.

The [machine summary](summary.json) retains original counts and all final
command receipts. The governing contracts are the existing
[five-axis audit](../../docs/protocol/pon-nakamoto-v1/details/DECENTRALIZATION_AUDIT_V1.md)
and [WAN evidence accounting](../../docs/protocol/pon-nakamoto-v1/details/WAN_EVIDENCE_ACCOUNTING_V1.md).

## Exact source and publication

| Identity | Value |
| --- | --- |
| Original #742 head | `73ed42284b7c0ac53e95dd1ed4bf0f058edb8ffa` |
| Locally measured implementation | `e7e6af3c53ac9c111bd210fedaf3f181e1bf8e6d` |
| Published implementation | `22a1fe67c247072eface8625a93e23ed01974a51` |
| Identical implementation tree | `eb93b36df0da51816a05cd4cc1a113e679bcfbdd` |
| Source before/after validation | 10,765 tracked entries; 1,027,152,925 bytes; equal reports |

The ordinary Git push dry run returned 128 because no Git HTTPS credential was
available. Publication used the authorized GitHub connector with a non-force
compare-and-swap from the original branch head. The created/fetched tree is
identical to the measured tree. The
[publication proof](validation/source-publication-equivalence.json),
[fetched Git object](validation/published-implementation-git-object.json), and
both [measured](validation/measured-implementation-commit.txt) and
[published](validation/published-implementation-commit.txt) commit preimages
preserve the two distinct commit identities. Original execution receipts still
name the actual measured commit; publication metadata is not relabeled as a
different execution.

This evidence package is an evidence-only child. It does not change the tested
Python/Rust implementation or reinterpret earlier failed observations.

## What changed and why

### Missing producer control and unknown resource units

A nonempty producer roster whose owners were all unknown could previously have
an empty work-axis findings list when its four access declarations and inventory
reference were current. It now retains `PRODUCER_CONTROL_UNRESOLVED` separately
from the four access facets. This does not turn a missing custody declaration
into a fabricated network-access failure.

An unknown resource unit could likewise disappear from the findings when a
current reference and a complete zero or positive denominator were supplied.
Both cases now retain the funding/hardware unresolved finding. A complete
known-unit zero-activity observation remains valid zero data, with no invented
percentage.

The [before observations](counterexamples/before/summary.json),
[frozen-source reproductions](validation/core-reproduction/summary.json) and
[reproduction script](counterexamples/reproduce.py.txt) retain the exact inputs
and outputs. The selected real source-only input was already missing these
inventories, so its original 23 findings remain unchanged.

### Repeated evidence scans

Every `ControlMap` now owns a read-only snapshot of its registry, context and
window. It computes usable component/subject groups once. Author exclusion uses
the same subject, declared-group and fingerprint relations in sets; stale or
revoked known relations continue to exclude forbidden aliases. No cache is
shared across maps, windows or contexts, and no cached declaration is a live
authorization decision.

For the retained 512-subject synthetic case, one quorum query previously made
1,050,624 `reference()` calls and now makes zero additional calls after map
construction. All three 128/256/512 input and quorum-output hashes match their
predecessors. This is a component-query observation; it excludes construction
cost and does not establish consensus throughput, WAN latency or a stable
whole-system speedup.

The final independent implementation review ran 750 fixed-seed registry cases,
233,440 relation/group/window comparisons and 7,500 quorum comparisons against
the old implementation. All 4,064 returned results and 3,436 refusals agreed.
The [review receipt](wan/final-readonly-review.json) and
[complete review script](wan/final-readonly-review.py.txt) retain the exact
frozen source, raw before/after guards and direct file hashes. This internal
code review does not count as an independently administered evaluator.

### WAN V4: count simultaneous independence

Three control-group labels and three failure-domain labels can still provide
only two simultaneously distinct replicas. The retained five-operator trap has
edges A-X, A-Y, A-Z, B-X and C-X. V4 calculates an exact maximum bipartite
matching; its result is two. Both the global operator roster and each claimed
repair's actual replica subset must satisfy the new joint requirement.

V1/V2/V3 preserve their historical meanings. On the identical 80 scheduled and
80 recorded synthetic observations, the
[V3 CLI result](validation/trap-v3.log) retains arithmetic success; the
[V4 CLI result](validation/trap-v4-refusal.log) returns exit 2 and arithmetic
failure. That exit 2 is the expected negative result, not a failed unit suite.
The original [V3 manifest](wan/trap-v3-manifest.json), explicit
[V4 manifest](wan/trap-v4-manifest.json), and
[JSONL observations](validation/trap-observations.jsonl) are retained.

The regression suite checks all 512 three-by-three graphs against a separate
exhaustive oracle, an augmenting-path case that defeats greedy selection,
unknown/stale/revoked control, order changes, duplicate edges, and separate
global/per-repair requirements. The additional frozen-source review exercises
64 operators, 1,024 original slots/records and 256 repair diagnostics, retaining
the V3 costs, outcomes, timely counts and denominators. A 65th operator rejects.
Matching subsets explain declared arithmetic; physical independence and every
PN5/public/production acceptance flag remain false.

### Material references are now actually read

The new read-only materializer requires a fixed digest of the raw audit input
and hashes the referenced files under a SHA-256-named local directory. It
separates absent bytes, wrong bytes, revoked/unknown declarations and window
gaps. The reader rejects symlinks, hard links, special files, path traversal,
unstable files/directories and byte-limit violations. Its installed policy must
exactly equal the same frozen policy used by the original audit CLI.

Limits are 4 MiB input, 16 MiB per artifact and 64 MiB total artifact bytes.
Output is create-only. Matching bytes does not authenticate signatures, claim
contents, context contents, appointment, custody or independent administration.
The 20 controls include real isolated CLI policy-drift refusal and actual
filesystem mutation/race cases.

The [actual materialization report](validation/current-materialization-output.json)
uses the retained source-only input, raw SHA-256
`dfa8436a646626def5468f391d2fcfabe79b167fb5b150f61d8992fb3190f473`.
It reports `empty`, zero declared artifacts, zero bytes read,
`DEPLOYMENT_EVIDENCE_MISSING`, and all 23 original accounting findings. It
does not award completion for an empty set of materials. The
[actual audit output](validation/current-assessment-output.json) exactly matches
the prior [current assessment](../pon-decentralization-20261106/current-assessment.json).

## Validation on the frozen implementation

| Scope | Actual result |
| --- | --- |
| Core control/five-axis suite | 69 passed |
| Evidence materialization suite | 20 passed |
| WAN V3/V4 control suite | 31 passed |
| Retained WAN V1/V2 suite | 25 passed |
| Complete CI contract suite | 104 passed |
| Negative raw-source integrity suite | 43 passed |
| Project-boundary suite | 16 passed |
| Public evaluation lifecycle reference | 17 passed |
| Native-quorum reference implemented in Python | 4 passed |
| Total Python tests above | **329 passed** |
| Repository/Markdown contract | Passed: 3,475 links; 1,165 Rust files; 26 packages |
| Raw full-source verification | Before/after reports identical |
| Source-only assessment | Exact retained output; 23 findings and HOLD |
| Current materialization | Empty/HOLD; no deployment artifacts |

Each command retains argv, exact source commit/tree, clean source checks,
timestamps, exit status, original log size and SHA-256 under `validation/`.
The source-integrity suite deliberately prints synthetic `FAIL` records for
its refusal controls; its real unittest outcome is 43 passes and exit 0.
The [command runner](validation/command-runner.py.txt) and all original logs are
included. The 512 graph cases and extra differential review are separately
described checks, not extra independent deployments or added unit-test counts.

## Retained incomplete gates

**Native Rust qualification remains incomplete.** This executor lacks Cargo.
The current locked/offline Cargo graph, format and strict all-workspace,
all-targets, all-features Clippy attempts each returned 127 before execution.
Their three receipts and raw errors are retained. The complete Rust subtree
and toolchain input are byte-identical to the original #742 head; that equality
does not turn a missing current run into a pass. The earlier two Clippy
SIGKILL observations and incomplete/127 native-quorum observations remain in
the [original evidence package](../pon-decentralization-20261106/README.md).

A read-only Mac path-discovery request timed out. Its one reconciliation cycle
could not recover the original idempotency-key/command binding from the
available job metadata. It remains UNKNOWN and was not reissued. An unbound
nearby job with exit 0 and `rg: command not found` is not native-validation or
project-discovery evidence. The limited
[discovery accounting](native-discovery-accounting.json) preserves this boundary.
No build, service activation or credential modification was launched there.

The [development observations](development-observations.json) separately retain
the initial hardlink-refusal test error and a truncated publication-preparation
read. Neither caused a successful stub, weakened check or fabricated result.
The original first hardlink test's full raw log was not retained; the final
20-test frozen-source log is complete. The development and final observations
retain their separate scopes.

The five actual deployment gates remain:

| Gate | Missing actual evidence |
| --- | --- |
| Work access | New producer obtains material/task, reaches service and completes accepted work under the original hostile-load budgets; attributed complete valid-work denominator |
| Data distribution | Independent full-release copies and shared-infrastructure inventory; publisher loss, authenticated retrieval, repair, renewal, retention and funded payment |
| Evaluation | Appointed evaluators, actual key custody/control, author aliases, frozen datasets and independent prospective evaluation |
| Root/release/upgrade/recovery/witness | Complete deployed public rosters, all alternative authorities and credentials, their actual custodians and original-owner rotation/recovery tests |
| Funding and hardware | Time-bounded complete populations, units, original denominators, unknown shares, ownership/control and shared infrastructure |

At least three real independent administrators/failure domains and 72 real WAN
hours remain required under the original PN5 contract. Hosted CI, prospective
merge qualification, original attacked-service goals, full PQ authority,
ordinary Cell adoption and model-benefit gates are not closed by this package.
