## Why

The repository has 908 branch names pointing to 892 distinct tips. This PR brings the reviewed current implementation and its controls together, records a disposition for every branch, and preserves the original history before branch cleanup.

## Changes

- Integrates the selected ownership, lifecycle, fresh Host observation, receiver scheduling, worker accounting and original mining-time controls. Historical alternatives that conflict with current owners remain preserved with explicit dispositions.
- Updates four current source contracts covering 232 distinct inputs and repairs current CI fixtures while retaining the original acceptance limits and historical evidence.
- Adds the [complete audit report](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md), 296 terminal dispositions covering all 908 names, and an [index of 527 evidence artifacts](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dc42ce4df5cff79cc61c5addbaf01074b56b06ca/evidence/branch-consolidation-20261114/ARTIFACT_INDEX.json) totaling 49,605,430 bytes. The report identifies the limits of historical source-body review.
- Preserves a failed empty network response as raw bytes with its original source identity; the evidence index records its corrected `.json.raw` destination.

## Exact candidate and validation

Candidate: `dc42ce4df5cff79cc61c5addbaf01074b56b06ca`  
Tree: `9fda17fed2542b2baccaa34585bb00afd699e12b`

All seven original local prepublication source gates passed on this exact clean commit: project preflight, source verification before and after, repository check, generated inventory check, CI contract and PQ corpus checks. Their original outputs are included in the history archive.

The full Linux repository-truth lane and the required exact-head/prospective-merge hosted checks are separate acceptance evidence. Their final results remain required; the revision-specific native controls in the audit report do not substitute for them.

## History preservation

Verified remote tag: `archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2`  
Annotated tag object: `9dafd9192e4040fab530958ef71598aaec9265b9`  
[Archive commit and recorded manifests](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b): `5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b`

The archive commit directly retains all 892 original tips plus this candidate. It preserves their reachable history and exact name-to-SHA manifests. This history archive does not assert semantic equivalence between historical alternatives or that every tip becomes an ancestor of the repository's linear main branch.

## Remaining acceptance conditions

- The original four-second confirmation target with sixteen pressure workers must pass on the new candidate. Retained e40d failures are diagnosed separately; no deadline, worker count or acceptance assertion was relaxed.
- Main integration must use the protected linear merge route. Branch cleanup follows a verified merge and a fresh reference inventory.
- Observed protection on `fix/chain-bulk-state-tree-20261017` disallows deletion. That rule remains a distinct blocker to a one-branch result.
- The report also retains the unresolved macOS physical-retention observation and 27 historical dependency registry/yank-query timeouts.

This update records candidate publication and audit evidence. Main integration and final branch cleanup are still pending.
