# Exact-head package replay policy v1

Status: **A00 control-plane candidate; no Gate or release promotion**

The repository freezes the GitHub Actions surface at thirteen workflow files and twenty jobs. Package owners therefore must not create one workflow per package merely to obtain exact-head evidence.

The existing trusted `TRNM payload replay recovery v1 gate` is the shared replay entry point. Its Cargo guard retains the frozen order: verify the pre-provisioned toolchain, verify the offline cache, then assert the exact checked-out PR head and dispatch the package-owned gate by registered branch name. Package-specific Cargo commands stay inside package scripts rather than the workflow.

Invariants:

1. Workflow and job counts do not increase.
2. The trusted runner remains `[self-hosted, Linux, X64, x230, trillionnium-chain]`.
3. Cargo remains offline, pre-provisioned, and protected by the unchanged-input check.
4. A package script remains owned by its package Agent; A00 only routes execution.
5. A completed success is eligible only when checkout and asserted `HEAD` equal the exact PR head.
6. Synthetic merge refs, stale heads, skipped, queued, cancelled, in-progress and failed runs are not green evidence.
7. This policy does not authorize merge, Gate exit, production, activation, release, node support or normative freeze.

Temporary per-package workflow files are invalid under the frozen workflow policy and must not be present in package trees.
