# M14 RPC / Indexer / SDK / CLI technical specification v1

Status: **implementation contract; non-authoritative service**

## Authority

M14 owns query and submission APIs, index projections, transaction builders,
SDKs, CLI behavior and Web4 adapters. It owns usability and compatibility, not
consensus, state-root, execution, signer or finality authority. Every response
states its freshness and proof class.

## Interfaces

The API surface is versioned and generated from M00 schemas. Common response
metadata contains `chain_id`, protocol/schema version, serving node,
committed/finalized height, state root, finality class, proof reference,
indexer height and lag. Query consistency classes are:

- `local`: explicitly non-authoritative and potentially stale;
- `committed`: bound to a committed node root;
- `finalized`: accompanied by or referenceable to an M13-verifiable proof;
- `historical`: bound to a retained checkpoint and pruning policy.

Submission routes only to M05. Simulation invokes M06 semantics against an
immutable view and discards all writes. Builders never sign implicitly and
never normalize an invalid canonical object into a different transaction.

## State machine

Indexer ingestion follows:

```text
Absent -> Received -> RootVerified -> Applied -> Published
```

Rollback is permitted only for an unfinalized local projection and is explicit
to clients. Finalized projection conflicts stop publication and trigger rebuild
from a trusted checkpoint. SDK compatibility follows `supported`,
`deprecated`, `read-only` and `rejected` states with published version windows.

## Persistence and recovery

Index records bind source block/finality proof, state/receipt/event roots,
schema version and previous applied height. Recovery resumes from the last
verified contiguous height. Gaps, duplicate conflicting events or root mismatch
halt the affected index. Rebuild occurs into a new namespace and swaps only
after full verification; it does not rewrite the node authority store.

## Resource bounds

Every method declares maximum request bytes, decoded work, pagination size,
proof work, response bytes, timeout and concurrency. Pagination tokens bind
query, root, order and expiry and cannot be reused across chains or filters.
WebSockets/streams have bounded subscriptions, buffers and lifetimes. Expensive
historical/proof queries use separate quotas from transaction submission.

## Security

Mutating methods require authenticated authorization and cannot bypass M01/M05.
Controls include TLS, origin policy, CSRF protection where applicable, credential
separation, rate limits, cancellation, cache key isolation, error redaction and
proof verification. Mock mode is unmistakable in protocol metadata and user
interfaces. An indexer compromise cannot mint a finalized response.

## Observability and SLO

The `non-authoritative-service-v1` profile reports method p50/p95/p99, error and
rate-limit classes, index lag, proof availability, stream drops, cache age,
rebuild time and stale-read signalling accuracy. Availability SLOs are separate
from chain-finality SLOs.

## Verification and evidence

Contract tests compare generated clients in every supported language, stable
error codes, pagination, cancellation, stale and proof-bearing reads. End-to-end
tests submit a signed transaction, observe admission, wait for finality, verify
the M13 proof, query the index and repeat after restart/rebuild. Browser tests
cover credential boundaries and mock-mode separation.

## Activation boundary

M14 may be deployed before production consensus only as a labelled candidate.
A public API claim requires versioned schemas, real-node finality/readback,
rate-limit and abuse tests, proof-aware clients, index rebuild evidence and an
operator runbook. Its deployment never promotes the chain.
