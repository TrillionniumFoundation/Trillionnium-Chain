# Trillionnium Chain release readiness

This file is the **human-readable release projection and stable navigation entrypoint**.
It is deliberately not a second mutable status database. The machine-readable authority is
`config/consensus-mainline.json`; repository merge/release policy is
`config/repository-policy-v1.json`; the implementation and promotion contract is
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`.

## Current conclusion

**NO-GO: not public-testnet-ready, not production-ready, and not release-ready.**

The conservative release boundary remains:

| Claim | Value |
|---|---:|
| Public-testnet ready | `false` |
| Production candidate | `false` |
| Production consensus activation | `false` |
| Release ready | `false` |

A source commit, pull request, document edit, fixture, simulation, local/hosted workflow,
candidate process run, benchmark, or generated report cannot independently promote these
claims. The default `trnm-poco-node` production startup remains fail-closed until the
machine authority and protected release procedure explicitly change it.

## Exact current status

Do **not** copy a mutable branch SHA, pull-request number, blocker list, or observed check
result into this document. Generate the exact commit/tree-bound projection instead:

```bash
python3 scripts/ci/generate_release_status_v1.py --check-deterministic \
  --output /tmp/trnm-release-status.json
```

That report derives the current Git commit/tree/branch at execution time and joins the
machine truth, repository policy, Cargo workspace, repository blockers, external blockers,
required checks and release flags. CI verifies the same generator. A new source or merge
candidate therefore gets a new report without editing this navigation file.

For live pull-request check state, use the hosting provider's check records for that exact
head/merge candidate. Historical PR numbers and observed SHAs belong in Git/evidence
history, not in current readiness truth.

## Evidence boundaries

Repository-owned work can prove implementation, deterministic replay, exact-source tests,
crash recovery and candidate composition. It cannot self-create independent operator,
custody, hardware or audit facts. External evidence requirements are registered in
`config/repository-policy-v1.json` and validated under `docs/evidence/external/`; their
current status is emitted by the release-status generator rather than duplicated here.

SIGKILL tests are process-crash evidence, not physical power-loss evidence. Local
watermarks/sidecars are not independent rollback anchors. Submission or micro-benchmark
throughput is not finalized user goodput. Candidate and laboratory paths do not become
production authority because they are wired or green.

## Promotion rule

Promotion requires the protected branch, protocol/schema/formal inputs, implementation
closures, exact release artifact, required checks, reproducible build/provenance,
independent reviews and required external evidence to bind the same accepted release.
Governance/activation must then update the authoritative machine state through the
protected procedure. If any relevant source, dependency, compiler, feature, configuration,
validator/key policy, migration input or security invariant changes, downstream evidence
is replayed according to the canonical development plan.
