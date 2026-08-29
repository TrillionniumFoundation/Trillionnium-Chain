# TRNM Agent Prompts A15-A17 v1

Status: **copy-ready per-Agent messages; subordinate to the canonical Plan**

Published source baseline: `feature/chain-g1-r4c-full-gap-closure-20260829@6e0189e351015ef3230f217ca7ff86149baedcf0` (`efea864cb2fbc4835a59a089b3dbab8934e71231`).

## Universal first sentence

For each Agent, prepend this sentence to the module block:

```text
Read and obey docs/development/agents/AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md,
docs/development/agents/AGENT_REGISTRY_V1.yaml and the canonical Plan/evidence/
machine/release truth. Work only in TrillionniumFoundation/Trillionnium-Chain, revalidate the exact GitHub
ref/commit/tree on every run, use one isolated package branch/PR, never merge
your own PR, and never change production/activation/release/normative-freeze
truth. Continue the package gap loop until MODULE_CLOSED_CANDIDATE or a valid
BASE_DRIFT, BLOCKED_UPSTREAM, STOP_CONDITION or RESUME_REQUIRED outcome.
```

The blocks below are the per-Agent messages to send after that universal
sentence. Each Agent must keep iterating across repeated cloud/scheduled runs,
but cannot bypass prerequisites, permissions, independent review or tool/runtime
limits.

## A15 — G2E Settlement and Economic Conservation

```text
Start and own package G2E_SETTLEMENT_ECONOMICS_V1 for Gate G2E.
Mission: Close canonical SettlementIntent/Receipt, multi-asset conservation, challenge maturity and exactly-once crash/retry semantics.
Upstream dependencies: A12, A13, A14.
Owned surfaces: trillionnium/crates/trnm-poco-consumption-settlement-v1/**; settlement/economics contracts; economic simulations and vectors.
Forbidden surfaces: validator or PoCO weight activation; verification authority; governance activation.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: multi-asset registry and fee schedule root; escrow/bond/reward/slash/refund/treasury/burn/dust accounting; insolvency and stale price behavior; related-party/Sybil/MEV/griefing simulations; JMT proof interface; PoCO-weight ineligibility.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: At most one terminal receipt exists per intent.; All assets conserve in every terminal path.; No settlement occurs before exact result/challenge maturity.; PoCO weight remains ineligible..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A16 — G2F Whole-Node Authority, State Sync and Light Client

```text
Start and own package G2F_WHOLE_NODE_LIGHT_CLIENT_V1 for Gate G2F.
Mission: Close authenticated cross-plane atomicity, canonical application JMT binding, external anti-rollback, staged state sync and independent W3-W7 light clients.
Upstream dependencies: A11, A12, A13, A14, A15.
Owned surfaces: cross-plane readback/global execution/order-application/finality-verifier candidates; whole-node authority/state-sync/light-client contracts; light-client conformance.
Forbidden surfaces: editing source-plane transition semantics; substituting composite root for application JMT; production signer or activation.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: one authenticated snapshot or explicit atomic multi-store protocol; canonical JMT membership in Order header; external monotonic anchor; descriptor/openat namespace identity; staged state-sync swap; two independent light clients; complete W0-W7 real trace.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Copied, renamed, stale, torn, sidecar, WAL and full-store rollback fail before authority use.; Two independent clients verify Order, DA, execution, result, settlement and upgrade.; No private-alpha claim exists before complete W0-W7 evidence..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```

## A17 — G3-G5 Benchmark, Security, Operations and Activation Preparation

```text
Start and own package G3_G5_BENCH_SECURITY_OPS_V1 for Gate G3-G5.
Mission: Prepare reproducible G3 benchmarks, G4 adversarial/public-testnet campaigns and G5 economics/governance/migration/activation evidence.
Upstream dependencies: A01, A06, A07, A16.
Owned surfaces: benchmark/topology/workload/fault schemas; chaos/security/operations runbooks; RPC/SDK/indexer conformance plans; G3-G5 evidence and ceremony preparation.
Forbidden surfaces: consensus or protocol semantic changes; superiority claims without accepted evidence; production credentials or activation decisions.

On the first run: fetch the current candidate source, open PRs and all
owned code/docs/tests; create or refresh a typed gap-ledger; avoid
duplicating existing PR work; freeze missing public interfaces before
code; then close the highest-severity unblocked gap with the smallest
reviewable implementation, negative mutants, fault/replay evidence and
a Draft PR. Continue to the next unblocked local gap in the same run.

Initial gap themes: benchmark-manifest-v1 and no-orphan-metric binding; 7/31/100 process/host/operator/region topology; AI-specific threat-to-invariant register; 72h/7d/30d chaos and soak; RPC/WS/indexer/SDK SLO and conformance; incident/DR/key-rotation runbooks; MIG-COMET-POCO and activation ceremony packages.

If an upstream interface is missing, emit a typed interface-change
request and BLOCKED_UPSTREAM rather than editing another owner. If the
base moved, emit BASE_DRIFT and compute the invalidation set. If a
safety/root/durability/economic/profile/light-client/custody/truth
invariant fails, retain the mutant and emit STOP_CONDITION.

Module closure assertions: Submitted TPS is never substituted for committed goodput.; Every metric binds one workload, denominator and evidence root.; All Critical/High findings block the applicable promotion.; No activation flag changes without the signed governance/release record..

Before every run ends, publish the exact base/head SHA and tree, changed
paths, closed/open gaps, commands/results, failed tests and mutants,
scope/authority/classification, interface requests, known gaps,
downstream invalidation and the next deterministic action. A local
module closure is still candidate-only and requires independent review.
```
