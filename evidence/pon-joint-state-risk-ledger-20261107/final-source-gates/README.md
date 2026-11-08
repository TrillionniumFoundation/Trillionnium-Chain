# Exact merged-source certificate validation

Status: research implementation and source/native component validation. Both actual security certificates remain HOLD; the native six-successor failure probability is unknown.

## Tested source and preserved history

All final component execution below is bound to commit 2d46d8682201bc0619f5b156af50e77fb399322e, tree 5ae5317304588cca8295a19dd512c8e853f1ef5b. Its ordered parents are b66e66d2465258d808c0f56ff851123306d4bdb4 and cb314bb4656e5da4844325cd83994ab4764fe8e9. The review destination is the existing fix/chain-six-axis-performance-20261103 integration branch.

The ordinary merge retains all 32 incoming integration commits. The committed-tree audit preserves every blob and mode in 1,328 ours-only paths, 4,331 integration-only paths and 10,644 paths on which both parents agree. Ten overlapping paths were combined; four needed explicit conflict resolution. CI retains the complete lifecycle, journal, risk, score-bridge and composition controls together with the incoming Cell controls. The final CI contract suite passes 108 tests.

This directory is an evidence addition. Final publication must verify that every non-evidence path has the same type, mode and blob as the tested merge. A later evidence-only commit is not a new execution of changed native code.

## Exact merged-source results

| Gate | Observed result and scope |
| --- | --- |
| Cargo graph and lockfile | Locked, offline metadata passed on the exact merge. |
| Rust formatting | The complete workspace formatting check passed. |
| Strict Clippy | Library, four retained targets and the two native examples passed with warnings denied. |
| Cell native integration | 12 tests passed. |
| Persistent native owner journal | 10 tests passed. |
| Native owner observation | 10 tests passed. |
| Native confirmation risk ledger | 11 tests passed. |
| New owner and risk standalone scenarios | Both were built from the merge and executed in new output directories, exit 0. |
| Independent raw owner reader | 21 tests passed. |
| Independent raw risk reader | 25 tests passed. |
| Exact CC1 packet composition | Real ML-DSA-65 signatures and six raw journals were checked; all 16 composition tests passed. |
| Finite complete joint initial state | 34 tests passed. |
| Complete finite-law confirmation events | 21 tests passed. |
| Shared lifecycle query accounting | 26 tests passed. |
| CI source integrity | 43 tests passed. |
| CI execution controls | 77 tests passed. |
| CI command-contract controls | 108 tests passed. |
| Inventory, invariants, detailed contracts, applicability and current implementation | Original validators passed; missing small fixtures were fetched as real commit-bound Git blobs. |

The two child-helper entry points marked ignored by ordinary Rust discovery are actually invoked by their parent tests. Test-suite totals overlap: CI execution imports source-integrity tests. No deduplicated grand total is claimed.

The new risk scenario retains eight registered starts, seven native confirmation intents, six bank outcomes and two still-charged pending starts. Expenditure is 36 of a capacity of 40, with denominator 1,000. These units are declared accounting, not a proved native failure probability. The genuine pre-dispatch and post-native child exits are 31 and 32. No old pending result is inferred or replayed. CC1's 58 packet-artifact observations are across six journals, not a distinct-work count.

## Raw evidence

- [Merged native execution](merged-native/README.md), including the original bank and native files, packet bytes, SQLite stores, child plans, binary hashes, fresh run records, independent reads and exact signature joins.
- [Merged Python and source gates](merged-python/README.md), including all suite logs, 2,415 non-evidence source hashes at the execution endpoints and the original missing-fixture refusals.
- [Merge and commit-tree Markdown review](merge-review/README.md), including the actual full tree, real Markdown input archive, verifier, twelve negative controls and path-preservation audit.
- [Earlier b66 complete local repository gate](b66-local/README.md).
- [Earlier b66 remote source, native and publication gates](b66-remote/README.md).
- [Machine-readable result](summary.json) and [copy-integrity records](copy-integrity.json).

Source files, compilation inputs and raw artifact bytes retain their individual identities. The wrapper documentation distinguishes the two earlier standalone risk runs from the new merged-source run.

## Full-lane coverage remains explicit

The complete local check_repository gate passed on b66, with a clean committed tree and 3,868 local links. That result belongs to b66.

For the exact merge, the independent tracked-commit Markdown verifier read all 605 actual Markdown blobs and checked 4,133 local links with zero errors. It checks the original repository checker's reviewed inline-link syntax, directory and case rules, URL-path decoding, escaping and committed symlinks. It is not an execution of check_repository and does not check fragment anchors or reference-style links.

The whole repository-truth lane was not run in the sparse Hepta checkout. At its recorded audit, 12,646 historical evidence paths were unmaterialized and the original worktree source guard would refuse those skip-worktree entries. No placeholders were created and no guard was relaxed. Thirteen genuine small fixture blobs, 965,044 bytes, were fetched and checked against their Git object IDs to run the original detailed-contract and applicability validators successfully. The retained static list of lane fixtures is not a complete dynamic dependency closure.

The final published head's required GitHub baseline must be read separately. This evidence asserts no complete hosted-CI, whole-workspace, production-host, release or production qualification.

## Preserved failures and the last semantic correction

All earlier unsuccessful observations remain. The first risk Python harness failed before running test cases because a fixture dictionary shadowed TestCase.run. Later source corrected that fixture and executed the complete suite. The original optional SQLite loader refusal remains beside the later run using the unchanged fence's required absolute compiler and canonical library paths.

A concrete impossible-start history was reproduced with real run bytes: a coherent extra pending start at an already ended native lease was formerly accepted as nine starts and expenditure 37. The hardened Python and Rust replay require an idle, non-stopped prefix in the same native epoch. The identical forged bank is rejected, and tests cover ended, incomplete, cross-epoch and stopping prefixes. A separate pre-dispatch bank-only rollback counterexample remains valid without an externally retained newer checkpoint; that limit was not hidden by this correction.

The first merged-native harness unnecessarily required AGENTS to equal its first-parent version. It stopped before compilation when the legitimate incoming ProfHepta/HeptaRuntime rule changed those bytes. The next harness binds the exact current merge's AGENTS object. Repository instructions and guards were unchanged. Initial missing fixtures, the first promisor-probe failure, the cancelled large auxiliary checkout and subsequent successful read-only checks are also retained.

## Scientific obligations still open

FJS1 certifies the supplied complete finite oracle/advice state and exact domination loss. It does not attest a physical adversary state, complete future helper channels, all-path actual resource budgets or an all-algorithm physical-cost reduction. Its global-state bound is not automatically a bound after an adaptively selected start.

EC1 derives the full event population inside one explicit finite execution law. PNRL1 checks source-mediated registration and integer expenditure for the supplied native owner history. Neither authenticates world-wide view coverage, physical time and adoptability, hidden in-flight inventory, the actual joint inventory/honest-progress law, or the required conditional failure bounds.

Their separate passes do not supply a final native security probability. Actual work-security, native six-successor security and production qualifications remain unproved; global_failure_probability remains null.
