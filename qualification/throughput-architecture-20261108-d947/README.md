# Throughput architecture continuation — 2026-11-08

## Scope and source

This continuation starts from unified PR #812 at
7e044b65454f4c9ea505591727332acffb33e7e5. It does not presume that the
separate throughput, witness or later qualification drafts are ancestors.
The candidate remains **HOLD / NO-GO**. No production, FinalUse, quantum-work,
WAN or original-host acceptance flag is promoted.

The sole plan is
[the development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The measured architecture decision contract is
[the comparison](../../docs/protocol/pon-nakamoto-v1/details/ARCHITECTURE_COMPARISON_V1.md#2026-11-08-implementation-order-and-decision-gates).

## Changes with narrow claims

1. Native PQ configuration material is checked completely and borrowed only
   within an entry call. No state authority, signature result or durable cache
   is introduced. Actual cryptographic attempts still consume the same atomic
   budget before verification. Current-state authority, parent grammar,
   canonical application, worker joins and the single durable writer remain.
2. The original fullpath collector now audits actual tracked bytes before
   context execution and after owned processes settle. Separate raw-source
   audit/binding v1 sidecars do not alter historical context/process schemas.
   Initial failure cannot launch native context; closing failure retains the
   frozen attempt denominator. Source snapshots do not attest execution or
   reproducible binary provenance.
3. The finite Bellman model query captures an immutable construction-time
   snapshot. The caller must keep the model stable while constructing a query.
   Later changes require a fresh query. This fixes caller mutation mixing old
   cached and new uncached laws; it is not a native W1 security result.
4. The architecture comparison keeps data/order separation, bounded batching
   and deterministic execution before a consensus replacement. NG, Prism and
   GHOSTDAG remain conditional candidates. Committee DAG and paid useful-work
   service alternatives require an explicit new security model.

### Native operation counts

The AccountsV2 instrumented fixture establishes these complete configuration
digest counts, with genuinely signed transactions. It does not time whole-node
execution, generalize to every profile or qualify fixed-resource goodput.

| Operation | Previous count | Candidate count |
| --- | ---: | ---: |
| Validate N-transaction block | 2N + 3 | 1 |
| Prepare one signature | 4 | 2 |
| Prepare dual signatures | 6 | 3 |
| Apply prepared command | 3 | 1 |
| Validate current authority | 4 | 1 |

New controls include batches of 0/1/8/16 transactions, fresh configuration
checks, stale/rotated authority, repeated invalid-signature debits, late invalid
input and first-error ordering, complete parent grammar, authority-change
exclusion in both transaction orders, full state/receipt/root equality with
1/2/4/8 workers, and cancellation that joins all entered preparation work.

### Model report identity

The original static report remains unchanged: 6,156 dynamic-program cases and
324 independent binomial comparisons, with canonical SHA-256
9fd4114587446ce8a2d39aa11b06b7c37d866d436f15cc5d1deb79e03281453c.
Its status remains ABSTRACT_CERTIFICATE_ONLY_HOLD_FOR_W1, with all seven
qualification claims false. Seven snapshot regression controls cover changed
mappings/state sets, mutable action/outcome sequences, record aliases, invalid
laws and that complete historical report.

## Validation provenance and limits

Component source commits are recorded in component-provenance.json.
The component runs are distinct from checks on the combined committed tree.
Precommit controls and their original whitespace failure are retained in
precommit-controls/; the raw streams are losslessly base64-wrapped with byte
counts and SHA-256 values, and those runs do not claim an immutable combined source.
Combined command logs and actual before/after raw-source receipts are added
as separate records after execution, without relabeling component results.

The readiness observation in host-readiness.json found the required
/sys/fs/cgroup/trnmponpublic.slice absent. No original-budget native campaign
ran in that environment. The original 0.25 CPU / 2 GiB / zero swap / 256 PID /
four-second / sixteen-hostile contract remains unchanged. Successful source
checks, Rust/Python controls and fewer configuration digests do not establish
that contract, honest confirmation, rejection cost, WAN tails or useful-model
efficacy. Completed-only latency must retain its cohort; overlapping stages
cannot be added as disjoint costs.

PoN work lower bounds, legal preparation reuse, DAA/credit correctness and
whole-chain PQ composition remain independent proof/qualification obligations.
No implicit consensus or hash-only fallback is introduced.
