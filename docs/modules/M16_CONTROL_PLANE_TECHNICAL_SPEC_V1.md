# M16 Global Control Plane technical specification v1

Status: **implementation contract; observer-first and non-authoritative**

## Authority

M16 observes declared telemetry, validates module descriptors, proposes bounded
operational changes and records rollout/rollback receipts. It cannot sign, vote,
finalize, create roots, alter SafetyRules, bypass admission, rewrite history,
delete evidence or activate production. Consensus continues when M16 is absent.

## Interfaces

- `ModuleDescriptorV1`: identity, version, capabilities, dependencies and limits;
- `MeasurementWindowV1`: source/config/workload identities and bounded metrics;
- `OptimizationPlanV1`: objective ordering, validity region, finite changes,
  expiry, rollout stages and rollback;
- `GuardDecisionV1`: exact accepted/rejected fields and invariant results;
- `ActionReceiptV1`: generation, applied digest, resulting configuration,
  measured effect and rollback status.

The node-local guard independently validates every plan. It accepts only
`OperationalLocal` changes such as bounded worker, queue or batch limits.
Consensus, economic, protocol, signer, validator-set and activation parameters
require their native governance paths and are unrepresentable as local plans.

## State machine

```text
Observed -> Proposed -> Guarded -> Shadowed -> Canaried -> Applied
                                     \-> Rejected
Applied -> Stable | RolledBack | Frozen
```

Every transition binds source graph, plan digest, generation and expiry. A
stale, broadened or partially applied plan is rejected. Loss of telemetry or
controller freezes the last accepted safe configuration; it never triggers an
automatic consensus change.

## Persistence and recovery

Plans and receipts are append-only, signed and idempotent. Recovery recomputes
the currently applied digest from node configuration and compares it with the
last receipt. Ambiguity invokes rollback or freeze according to the exact plan.
Control-plane storage is not a consensus authority and may be rebuilt from
signed records without changing chain state.

## Resource bounds

Telemetry cardinality, label length, sampling rate, window count, plan size,
actions, concurrent rollouts, retained history and controller CPU/memory/network
are bounded. Plans contain finite numeric ranges and cannot encode programs,
shell commands, arbitrary paths or opaque executable payloads.

## Security

Threats include telemetry poisoning, forged plans, compromised controller,
confused deputy, stale replay, capability escalation and rollout correlation.
Controls include mutual authentication, signed descriptors/plans, separation of
planner and node guard, least privilege, monotonic generation, expiry,
multi-party approval for broad changes and fail-safe rollback. Private prompts,
model weights and raw user data are not telemetry.

## Observability and SLO

The `non-authoritative-service-v1` profile reports ingest lag, rejected samples,
plan feasibility, guard rejection reasons, shadow/canary duration, rollback
latency and configuration drift. Optimization is lexicographic: safety,
determinism, durability and compatibility violations must remain zero before
latency, cost or goodput improvement is considered.

## Verification and evidence

Tests cover forged, stale, over-broad and infeasible plans; poisoned telemetry;
guard/controller disagreement; node restart; partial rollout; controller loss;
rollback; and correlated canary failure. Mutants prove the node guard, scope,
generation, expiry and rollback checks cannot be removed silently.

## Activation boundary

Initial deployment is read-only observation. Plan application remains disabled
until the networked service, independent guard, authentication, canary/rollback
campaign and security review pass. M16 can never become consensus or activation
authority without a new architecture and protocol decision.
