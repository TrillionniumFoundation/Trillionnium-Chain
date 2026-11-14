# PQ Root raw state-tip and depletion-meter claim controls (2026-11-12 UTC)

**HOLD_NO_GO / DENY_ALL.** This is a necessary-conditions hardening of the original native evidence reader, not a successful native campaign, actual independent external verification, custody evidence, proof of unforgeability, or a lifetime failure bound.

## Exact source and retained inputs

- Parent audited reader: PR #922 head `bc411aa4a81970d822c073f3ab4ce24ff8c9bc22`.
- Parent reader blob: `7e29bd608aafa49b93e6463a660058e72b5a756d`.
- Parent reader test blob: `e72925ae8dd2e3a2bf64cea910824db7a31bb66c`.
- New reader blob: `73b8e61ab87d11063fd6bf68f9c65b2a120a86fd`.
- New test blob: `58cd328dc05ad2995ac1f046b9a4c4eb8272b44b`.
- Historical V4 qualification record blob on #844: `0ea59b3c80d852e8395db9b845ebe7c4fc872062`, source commit `0d99924005b70b1308bf3e62c53e9300fbb4aac4`. It cannot certify this branch.
- #890 original native Actions [43104547221](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43104547221); retained local ZIP SHA-256 `9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e`.
- #914 original native Actions [43077271521](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43077271521); retained ZIP SHA-256 `8edd9a303fc7ac3de0e97f6dbfa40b734df5a49489a9bce783769b6240f5f982`.

## Narrow change

The prior evidence reader only required the self-declared `receiver_client_state_equal` and `genuine_budget_depletion_observed` booleans when validating successful phase claims. A report with a changed final client tip, or with `depletion_at_ns=None` and `depletion_meter=None`, could therefore falsely corroborate those individual prerequisites if the other flags were forged too.

The new reader requires, as **necessary conditions**:

1. A true equal-state claim must carry two matching canonical 32-byte hex final-tip digests; this does not establish entire state equality or finality.
2. A true depletion claim must carry an in-window integer time, an actual `Ok` depletion meter with `depleted=true`, available accounting, and a balance-identity-verified flow object.
3. Both claim fields must be native JSON booleans, never integers, strings, or null.

The controls do **not** authenticate the reporter or infer a physical budget from a counter. External proof of independent operator, paid CPU, anti-rollback freshness, and whole-chain cryptographic security remain independently outstanding.

## Local preliminary negative controls (not CI)

A separate 6-test Python guard harness was executed against all 18 phases of two unmodified retained original native ZIPs; its SHA-256 is `19bb8a8344d50029042e1065d00228b577c16c0190f1ae574e29d8e798d0806e`. The six tests passed. All 18 original phase reports remained failed with no true equal-state or depletion claims. This is a narrow pre-commit regression check only. The repository's exact post-edit full test/CI results must be inspected independently after this PR is created.

## Original gates unchanged

Three complete native campaigns, nine phases, 27 in-window signed confirmations, 0/24/24 hostile actors, 30 s per phase, 21 business blocks, 0.25 CPU, 2 GiB memory, zero swap, 256 PID, parent cgroup, real paid depletion, and independent receiver/client consistency are **not** weakened. There is no production activation or permission grant. The latest reviewed original native acceptance remains **0/3 complete**, **0/9 phases**, **3/27 confirmations**, and **0/6 hostile phases with depletion**. Neither this reader nor its tests support a real `2^-128` bad-event bound.
