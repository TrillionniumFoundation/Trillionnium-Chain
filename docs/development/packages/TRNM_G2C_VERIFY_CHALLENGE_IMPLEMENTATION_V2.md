# G2C verification profile and challenge implementation v2

Status: **MODULE_CLOSED_CANDIDATE for the A14-owned registry/verification/challenge slice; BLOCKED_UPSTREAM for accepted DA, Agent, execution, Order and settlement authority**

Package: `G2C_VERIFY_CHALLENGE_V1`  
Owner: `A14`  
Branch: `agent/a14-g2c-verify-challenge-v1-20260829`  
Original stacked base: `agent/a13-g2d-execution-mvcc-fee-v1-20260829@38993b0893f9fe3fa7ba6995d45f7dff5c870ee7`

## Implemented candidate

The package now includes real Rust code, not only a reference model:

```text
trillionnium/crates/trnm-poco-verify-challenge-v1/
  src/profile_registry_v1.rs
  tests/profile_registry_v1.rs
```

The closed registry requires exactly one row for each candidate profile kind:

1. deterministic re-execution;
2. reproducible machine learning;
3. zero knowledge;
4. trusted execution environment;
5. stake quorum;
6. optimistic;
7. subjective.

Resolution is exact by profile ID, version and hash. Disabled, unknown,
not-yet-valid, expired and revoked profiles fail before backend invocation. No
fallback is possible. Subjective profiles cannot acquire objective settlement
or PoCO-weight authority.

The verification path freezes this order:

```text
statement shape and digest
→ exact profile resolution
→ profile height/expiry/revocation
→ Task/Lease/ExecutionReceipt binding
→ ArtifactEvidence and AvailabilityCertificate binding
→ evidence-window validation
→ backend invocation
```

`Verified`, `Rejected` and `Unavailable` are separate results. None moves
assets, reorgs Order, or becomes PoCO weight.

## Challenge lifecycle

The candidate challenge book provides one challenge per result and a forward
state machine:

```text
Opened
→ EvidencePeriod
→ ResponsePeriod
→ DecisionPending
→ Upheld | Rejected
→ optional single AppealPending
→ Upheld | Rejected
→ Final
```

Withdrawal and deadline expiry close explicitly. Duplicate challenges, phase
skips, late evidence/response/decision and second appeals fail closed. Every
record keeps `economic_authority=false` and `order_reorg=false`.

## Exact replay

```bash
bash scripts/ci/check_g2c_profile_registry_v1.sh
```

The gate runs the existing independent deterministic-reexecution model, the
new Rust integration test, strict Clippy, targeted rustfmt and static
non-authority checks. The trusted-runner workflow is
`.github/workflows/trnm-g2c-profile-registry-v1.yml`.

## Typed upstream blockers

| Blocker | Required owner |
|---|---|
| canonical ArtifactEvidence and AvailabilityCertificate authority | A11 |
| Task, Lease and verification-profile policy authority | A12 |
| accepted execution receipt and canonical application JMT proof | A13 + A16 |
| accepted Order finality and rollback coordinate | accepted G1 + A16 |
| bond, payment, refund and slash movement | A15 |
| appeal governance and concurrent-challenge policy | A17 / G5 |

A14 does not edit those owners and does not treat caller-supplied digests,
local SQLite rows or subjective evidence as objective finality.

## Explicit non-claims

```text
g2c_exit=false
profiles_globally_enabled=false
profile_fallback=false
artifact_availability_authority=false
execution_receipt_authority=false
order_finality_authority=false
settlement_movement=false
poco_weight_eligible=false
production_candidate=false
production_consensus_activation=false
release_ready=false
```

Independent exact-head replay and owner-accepted upstream interfaces are
required before any Gate or release claim.
