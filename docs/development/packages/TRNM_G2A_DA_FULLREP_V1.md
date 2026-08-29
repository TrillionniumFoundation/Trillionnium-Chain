# G2A DA-FULLREP-V1 package

Status: **MODULE_CLOSED_CANDIDATE for the independent full-replication model / Node and network authority blocked**

Package ID: `G2A_DA_FULLREP_V1`
Agent: `A11`
Upstream trace commit: `56f274410dcb624c59ae45a0272bacfb60cbad59`.

## Closed candidate surface

- distinct `TransactionBatch` and `ArtifactEvidence` namespaces;
- content-addressed durable manifest;
- durable-before-attest and per-provider monotonic attestation journal;
- strict threshold certificate construction;
- exact complete retrieval and digest verification;
- repair from independently matching replicas;
- withholding evidence for a certified provider that does not return promised bytes;
- retention and challenge/sync/evidence holds;
- Node permit required for GC;
- explicit rejection of sampling-only/DAS certificates.

## Authority boundary

The Python model is an independent executable assurance model. The existing Rust SQLite crate remains the candidate implementation. Neither one supplies authenticated P2P, a production signer, Order vote eligibility, whole-node CAS, anti-rollback, or GC authority.

## Invariants

1. A provider cannot attest before exact bytes and manifest are durable.
2. Namespace is part of every object identifier and proof statement.
3. A certificate means threshold durable storage only; it does not prove correctness, privacy, result validity, payment, or perpetual availability.
4. Retrieval must return the complete digest-matching value.
5. Repair cannot accept one matching chunk or a mismatched namespace.
6. A retention or challenge/sync/evidence hold forbids deletion.
7. GC requires an explicit Node-owned permit that this package cannot issue in production.
8. `DA-DAS-V1` remains disabled.

## Command

```bash
bash scripts/ci/check_da_fullrep_model_v1.sh
```

## Remaining upstream gaps

- authenticated peer envelopes, quotas and anti-amplification;
- production author/attestor signer journals;
- `AgentTransactionV1` batch bytes;
- exact `BatchRef` proposal and complete retrieval-before-vote integration;
- multi-host fault evidence;
- Node-owned retention/GC and external anti-rollback authority.

## Non-claims

```text
g2a_exit=false
da_network=false
order_vote_authority=false
node_gc_authority=false
data_availability_sampling_active=false
production_candidate=false
```
