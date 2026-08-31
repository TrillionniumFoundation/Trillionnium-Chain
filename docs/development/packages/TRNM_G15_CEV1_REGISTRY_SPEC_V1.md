# G1.5 CEV1 registry specification package v1

Status: **MODULE_CLOSED_CANDIDATE / candidate-non-normative / BLOCKED_UPSTREAM (semantic review pending)**

Package ID: `G15_CEV1_REGISTRY_SPEC_V1`
Agent: `A08`
Control base: `docs/chain-agent-fleet-plan-v1-20260829@7d9a17abb727950f278235dce817df29e97fea19` (tree `00a9de9534860abdccc2aeb31307810897330c4c`)
Replay base: `feature/chain-a08-g15-registry-parity-v4-20260829@8fb9ad6ea27dd3026f0188df6a3b728545751027` (replay pending onto the exact control tip)
Candidate source: `feature/chain-a08-g15-registry-parity-v4-20260829@HEAD` (exact commit/tree in closing evidence)

This package closes the repository-shape gap for one machine-readable CEV1 registry set. It does not freeze protocol v1, enable a wire kind, implement a node, or change any production/activation truth.

## Deliverables

- closed operation slot registry for kinds `0..29`;
- object, digest-domain, error, limit, and verification-profile registries;
- exact 53-object catalog projection (IDs/order/planning planes) with a
  standard-library checker that rejects duplicate IDs, missing slots,
  unsupported activation, unknown cross references, catalog drift, and silent
  profile fallback;
- retained 17-case negative-mutant harness for object/catalog and operation
  semantic drift,
  duplicate JSON keys, activation, operation, and profile enablement;
- exact candidate/non-claim boundary for A09/A10 and G2 plane consumers.

## Authority hierarchy

The numbered protocol documents and their exact schemas remain the semantic source. These JSON files are generated-review surfaces and integration contracts. A disagreement is `STOP_CONDITION: registry_semantic_drift`; the checker cannot resolve it by choosing the registry over the protocol text.

## Registry invariants

1. Every operation slot `0..29` exists exactly once and carries the exact
   `body_type` from document 08's `OperationPayloadV1` table.  The short
   `name` is display-only and cannot redefine a body.
2. An operation is either `candidate-assigned` or `disabled`; no implicit or
   reserved success path exists.  Kinds 20 and 27 retain their canonical slots
   but are explicitly profile-disabled with `ERR_OPERATION_DISABLED`.
3. `enabled=false` for every operation until G1.5 and G2.0 accepted evidence
   authorizes a separate truth update.  This candidate activation bit is
   intentionally distinct from document 08's reference `OperationLimitV1`
   profile eligibility (which enables 0..19, 21..26, 28, and 29).
4. Every object names exactly one plane and one lifecycle authority class.
5. Every digest/signature/root meaning has a distinct ASCII domain.
6. Error codes are stable, scoped, and never collapsed across malformed/invalid/unavailable/backend/internal classes.
7. Every verification profile is independently versioned and globally disabled. There is no fallback graph.
8. Limits are positive, conservative candidate ceilings and never inferred from host memory.
9. V0 bytes/domains are not aliases for v1.
10. Registry success is not normative freeze.

## Operation assignment and authority rule

The operation registry is a candidate projection of the exact kind/body table in
`docs/protocol/poco-ai-native-v1/08-coordination-settlement-execution-and-fees.md`
(kinds `0..29`). `body_type` is the exact canonical body/object identifier;
`name` is a stable short display label only.  Existing local candidate kernels
may expose different private operation IDs. A09/A10 must record any mismatch
and must not rewrite local history or silently call it wire-compatible.

The `authority` slug is the canonical `outer_authority_mode` mapping:

| Mode | Slug | Kinds |
|---:|---|---|
| 0 | `existing-agent` | 1–17, 19–20, 22, 29 |
| 1 | `existing-or-self-origin` | 0 |
| 2 | `permissionless-trigger` | 18, 26 |
| 3 | `externally-signed-object-submitted-by-agent` | 21, 24–25, 27 |
| 4 | `action-dependent` | 23, 28 |

Kinds 18, 23 action `CloseExpired`, 26, and 28 action `GarbageCollect`
consume the outer sender nonce but acquire no lifecycle authority.  Inner
verifier/bilateral/evidence signatures for kinds 21, 24, 25, and 27 never
replace the outer submitter authorization.  `nonce_lane` records the role of
the outer authorization lane (or `outer-sender` where the body has no
role-specific lane); it is descriptive and does not assign a numeric lane.

The semantic correction is captured in the typed handoff
[`TRNM_G15_CEV1_REGISTRY_OPERATION_ICR_V1.md`](TRNM_G15_CEV1_REGISTRY_OPERATION_ICR_V1.md).
Until the protocol owner and an independent A09 replay accept the proposed
mapping, downstream conformance remains `BLOCKED_UPSTREAM`; no normative or
activation truth is changed.

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

The correction candidate source/tree is recorded at handoff time after the
local commit; the final immutable tuple is emitted by the closing evidence
entry and must be revalidated after any control-branch replay.

Proposed operation-registry interface digest (SHA-256 of committed JSON
bytes): `ec856f6c02b26137200c9353cadaeac9cb3c4c417f2b8f9844baa81041efecf7`.

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
