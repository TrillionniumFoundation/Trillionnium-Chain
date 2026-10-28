# Finite-nonce stopping research: local execution evidence

This archive belongs to the incremental source based on
`5d16aafee014fe7a06a0ed76b9aaa06b6058c5d0`, on development branch
`test/chain-finite-nonce-stopping-20261027`. The
[model document](../../docs/security/PON_FINITE_NONCE_STOPPING_MODEL_V1.md)
defines the assumptions, equations, costs, comparisons and remaining limits.

## Observed controls

The retained baseline execution ran the original eleven reversible gate/adjoint
controls and seven DAA controls. The latter compiled the actual pinned Rust
consensus source, then compared 1,079 requests. Neither suite was skipped. The
two original generated JSON reports match the original #510 CI artifact exactly;
the old ZIP's SHA-256 is
`cc9740c63fa5c8a503036705be0ea5ada4b96f7712fc3622e9f5e5a6eaa1ed22`.

The incremental model has eighteen controls: 1,139 small-domain state-vector
comparisons, 5,000 independent geometric-completion enumerations, 120 independent
2–4-worker tuple enumerations, endpoint/competitor/partial-tail checks and
explicit invalid-input/resource rejection. The final run, command exits and
input hashes are recorded in [validation.json](validation.json); the baseline
commands and old artifact member hashes are in [baseline-receipt.json](baseline-receipt.json).

| File | Role |
| --- | --- |
| [finite-stopping.json](finite-stopping.json) | 45 fully costed conditional scenarios, stopping and finite-budget results, fixed-policy races and omitted-cost negative control |
| [finite-stopping-controls.log](finite-stopping-controls.log) | Actual eighteen-test execution |
| [gate-controls.log](gate-controls.log) | Actual original eleven controls |
| [native-daa-controls.log](native-daa-controls.log) | Actual seven controls with real Rust compilation/parity |
| [logical-circuit-upper-bound.json](logical-circuit-upper-bound.json) | Reproduced original complete-W1 logical upper-bound report |
| [conditional-daa.json](conditional-daa.json) | Reproduced original native-rule conditional DAA report |
| [negative-controls.json](negative-controls.json) | Actual floating-point and omitted-cost counterexamples; corrections remain scope-limited |
| [tracked-worktree-guard.log](tracked-worktree-guard.log) | The actual full identity guard outcome on this sparse checkout |
| [repository-check.log](repository-check.log) | The actual full repository guard outcome, including sparse historical evidence |

## Preserved limitations and failures

The first proposed local branch used the unsupported `research/` prefix and
preflight rejected it. Renaming it to the permitted `test/chain-...` form made
preflight pass. No policy was weakened.

Three numerical limitations were exposed and retained: nearly-full 64-bit
marked sets require the complementary angle; tiny geometric probabilities
require `log1p`/`expm1`; arbitrarily large accumulated phases are rejected for
every marked fraction. The last came from an independent root review, with
`N=2,M=1,j=2**52-1` producing the naive wrong value `0.0741385878` instead of
`0.5`. The supported minority-angle phase is at most 64 radians. It remains
ordinary binary64 numerical evaluation, not interval-certified arithmetic.

An earlier oracle-only work-cost sensitivity left checking/setup/winning-tail
costs fixed and selected `j=0` at multiplier 256. The main comparison now charges
those mandatory stages explicitly; the misleading omitted-cost scenario is
retained and marked invalid for a work-scaling conclusion.

The checkout inherits 4,114 sparse tracked paths, including 3,806 blobs absent
from its local object store. Its full tracked-worktree identity guard cannot
qualify this checkout; no skip flags were removed to conceal missing bytes.
Full repository checks may also fail on the historical evidence omissions. The
recorded outcomes must not be relabelled as passing full-tree CI. Selected input
hashes only bind the source actually executed. Existing whole-workspace Rust
tests and strict Clippy were not re-executed for this Python-only model; Rust
production files and their lockfile remain unchanged. Native DAA parity and
the read-only format/inventory/source-integrity controls have separate outcomes.

The workflow change schedules these controls for a future full exact-source CI
checkout. No new remote CI execution, upload, merge, deployment or production
activation occurred. The model does not qualify physical quantum costs,
`r=0.25`, unknown-marked-count policies, strategic equilibria, native network tie
settlement, actual W1 marked distributions or whole-chain quantum security.
