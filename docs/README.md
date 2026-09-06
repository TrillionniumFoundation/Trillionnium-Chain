# Trillionnium Chain Documentation

## Current truth sources

1. `../RELEASE_READINESS.md` — release posture.
2. `architecture/TRNM_SELF_DEVELOPED_CONSENSUS_CANONICAL_2026-09-07.md` — binding consensus architecture.
3. `../OPERATIONS.md` — build, test, operation, recovery, and evidence rules.
4. `../SECURITY.md` — security scope and reporting policy.

## Documentation areas

- `architecture/` — binding architecture decisions and component boundaries.
- `protocol/` — wire formats, state machines, proof payloads, and compatibility rules.
- `runbooks/` — operational procedures and incident response.
- `performance/`, `perf/`, and `reports/` — benchmark methodology and commit-bound evidence.
- `release/` — launch criteria and handoff records.
- `schemas/` — machine-readable contracts.
- `archive/` — historical material only; never use it as current release truth.

## Consensus policy

The native Rust consensus implementation is the only supported route. Documentation must not describe an external consensus engine or adapter as current, fallback, reference, migration, test, or release authority.

## Evidence discipline

Every date-stamped result is valid only for its recorded commit, configuration, workload, host profile, and topology. A local or simulated PASS must not be generalized into public-network readiness.
