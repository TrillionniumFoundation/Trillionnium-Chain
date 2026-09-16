# M01 Crypto Identity Technical Specification v1

Status: implementation contract; acceptance and production activation remain false.

## Scope

This specification binds the M01 boundary to its primary crates in `config/module-coverage-v1.toml`. It defines inputs, deterministic outputs, failure behavior, resource limits, and evidence required before promotion.

## Contract

- Inputs are versioned, canonically encoded, length-bounded, and chain/epoch bound.
- State transitions are deterministic across supported worker counts and replay.
- Invalid signatures, stale generations, conflicting roots, budget exhaustion, and malformed frames fail closed.
- No adapter, control-plane process, migration fixture, or laboratory binary may create consensus authority or bypass SafetyRules.
- Every durable mutation requires identity fencing, crash-safe ordering, and post-operation readback where applicable.

## Operational SLOs

The SLO profile is the one registered for M01 in `config/module-coverage-v1.toml`; measurements must report p50/p95/p99 latency, throughput, queue depth, memory, CPU, and error classes under bounded and adversarial workloads. No benchmark result alone establishes production readiness.

## Required tests and evidence

1. Canonical encode/decode vectors and negative parser cases.
2. Deterministic replay and cross-worker equivalence.
3. Crash, restart, timeout, duplication, reordering, and resource-exhaustion matrix.
4. Independent second implementation or differential oracle for protocol-critical behavior.
5. Exact-source, multi-host, and (where relevant) HSM, power-loss, or long-running evidence named by the canonical development plan.

## Non-claims

Presence of this document does not claim implementation completeness, liveness, Byzantine safety, public-testnet readiness, production readiness, or consensus activation.
