# Exact-head package replay policy v1

Status: **A00 control-plane candidate; no Gate or release promotion**

The repository freezes the GitHub Actions surface at thirteen workflow files and twenty jobs. Package owners therefore must not create one workflow per package merely to obtain exact-head evidence.

The existing trusted `TRNM payload replay recovery v1 gate` remains the sole shared replay entry point. For pull requests it checks out `github.event.pull_request.head.sha`, asserts the resulting `HEAD`, and dispatches the package-owned gate by the exact registered branch name. For non-package branches it retains the canonical agent-documentation, payload-replay and G1-R4A checks.

This control-plane policy has these invariants:

1. Workflow and job counts do not increase.
2. The trusted runner remains `[self-hosted, Linux, X64, x230, trillionnium-chain]`.
3. Cargo remains offline, pre-provisioned, and protected by the unchanged-input check.
4. A package script remains owned by its package Agent; A00 only routes execution.
5. A completed success is eligible only when the checked-out commit equals the exact PR head.
6. Synthetic merge refs, stale heads, skipped, queued, cancelled, in-progress and failed runs are not green evidence.
7. This policy does not authorize merge, Gate exit, production, activation, release, node support or normative freeze.

The temporary per-package `*-exact-head-v3.yml` files are invalid under the frozen workflow policy and must be removed from their package branches when this control-plane commit is imported.
