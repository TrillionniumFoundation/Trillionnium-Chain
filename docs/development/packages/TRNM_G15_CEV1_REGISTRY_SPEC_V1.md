# G1.5 CEV1 registry specification package v1

Status: **MODULE_CLOSED_CANDIDATE / candidate-non-normative / promotion blocked by G1**

Package ID: `G15_CEV1_REGISTRY_SPEC_V1`
Agent: `A08`
Base: `docs/chain-agent-fleet-plan-v1-20260829@8fb9ad6ea27dd3026f0188df6a3b728545751027`

This package closes the repository-shape gap for one machine-readable CEV1 registry set. It does not freeze protocol v1, enable a wire kind, implement a node, or change any production/activation truth.

## Deliverables

- closed operation slot registry for kinds `0..29`;
- object, digest-domain, error, limit, and verification-profile registries;
- exact 53-object catalog projection (IDs/order/planning planes) with a
  standard-library checker that rejects duplicate IDs, missing slots,
  unsupported activation, unknown cross references, catalog drift, and silent
  profile fallback;
- retained 10-case negative-mutant harness for object/catalog drift,
  duplicate JSON keys, activation, operation, and profile enablement;
- exact candidate/non-claim boundary for A09/A10 and G2 plane consumers.

## Authority hierarchy

The numbered protocol documents and their exact schemas remain the semantic source. These JSON files are generated-review surfaces and integration contracts. A disagreement is `STOP_CONDITION: registry_semantic_drift`; the checker cannot resolve it by choosing the registry over the protocol text.

## Registry invariants

1. Every operation slot `0..29` exists exactly once.
2. An operation is either `candidate-assigned` or `disabled`; no implicit/reserved success path exists.
3. `enabled=false` for every operation until G1.5 and G2.0 accepted evidence authorizes a separate truth update.
4. Every object names exactly one plane and one lifecycle authority class.
5. Every digest/signature/root meaning has a distinct ASCII domain.
6. Error codes are stable, scoped, and never collapsed across malformed/invalid/unavailable/backend/internal classes.
7. Every verification profile is independently versioned and globally disabled. There is no fallback graph.
8. Limits are positive, conservative candidate ceilings and never inferred from host memory.
9. V0 bytes/domains are not aliases for v1.
10. Registry success is not normative freeze.

## Operation assignment rule

The operation names in this package are candidate slot assignments for conformance and gap tracking. Existing local candidate kernels may expose different private operation IDs. A09/A10 must record any mismatch and must not rewrite local history or silently call it wire-compatible.

## Exit evidence

Run:

```bash
python3 scripts/ci/check_cev1_registry_spec_v1.py
scripts/ci/check_cev1_registry_mutants_v1.sh
```

Candidate closure requires both checkers to pass from a clean checkout,
independent review of slot/domain/error meaning, and an immutable source/tree
binding. Promotion remains `BLOCKED_UPSTREAM` until accepted G1 evidence and
complete G1.5 independent conformance exist.

## Non-claims

```text
normative_freeze=false
implementation_complete=false
node_support=false
protocol_activation=false
production_candidate=false
production_consensus_activation=false
release_ready=false
```

## Downstream invalidation

Any change to an operation number, object identifier, domain, error code, limit key, or profile hash input invalidates A09, A10, every G2A-G2F wire/vector result, all SDK/light-client fixtures, and every benchmark manifest consuming it.
