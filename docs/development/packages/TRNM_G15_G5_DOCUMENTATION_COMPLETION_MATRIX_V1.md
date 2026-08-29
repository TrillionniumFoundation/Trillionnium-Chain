# TRNM G1.5-G5 Documentation Completion Matrix v1

Status: **candidate preparation; all promotions remain prerequisite-gated**

## 1. G1-R5 Native 4/7-Node Campaign

### 1.1 Identity

Every run reports separately:

```text
process_count
host_count
operator_count
region_count
validator_id/key proof-of-possession
binary/container/SBOM digest
genesis/validator-set/parameter digest
```

Multiple processes on one host are not multiple host/operator failure domains.

### 1.2 Required campaigns

Four validators:

- normal non-empty finality;
- one offline and rejoin;
- leader crash and timeout certificate;
- 3-1 progress;
- 2-2 safe stall and heal;
- restart and authenticated catch-up;
- shortened epoch/key rotation;
- signer unavailable/uncertain;
- disk full and application restart.

Seven validators repeat the matrix with equal and unequal voting power and add:

- one-third-minus-one offline;
- selective omission/censorship;
- slow/bandwidth-constrained leader;
- validator state sync from a trusted finalized checkpoint;
- staggered restart;
- epoch transition during faults.

### 1.3 Safety and evidence

- zero conflicting finality;
- zero double-sign;
- zero unauthorized validator set;
- zero state/JMT/AppHash divergence;
- no certified body unavailable inside its promise;
- restart cannot lower Safety/checkpoint/watermark;
- exact roots and receipts agree across all honest nodes.

Raw process logs, network captures, fault timeline, finality samples, state
roots, resource metrics and recovery traces are content addressed. A transport
mesh smoke, port check or signed health report does not satisfy this campaign.

R5 evidence may support G1 only after R4 has accepted exact single-node
authority. It does not create a production candidate, public testnet or
AI-native v1 result.

## 2. G1.5 Normative Inventory

Machine-generated registries:

```text
cev1-object-registry-v1
cev1-domain-registry-v1
cev1-error-registry-v1
cev1-operation-registry-v1
cev1-limit-registry-v1
cev1-verification-profile-registry-v1
```

Each entry includes owner, schema hash, domain, max bytes/depth/items/signature
work/CPU, version negotiation, parser pair, vectors, status and evidence ID.

Required independent reviews cover consensus/order, canonical encoding,
application/state, DA, cryptography, economics and light client/upgrade.

`normative_freeze` remains false until accepted G1 and all
reviews/vectors/models agree.

## 3. G2.0 W0-W7 Traceability

Thirty generated operation rows (`0..29`) contain:

```text
kind
enabled/disabled
schema_hash
domain
authority
nonce lane
access set
DA binding
Order binding
ExecutionReceipt
Result/Challenge binding
Settlement binding
RPC/SDK/indexer/light-client projection
positive/negative vectors
implementation owner
evidence ID
```

An enabled operation must reach every applicable link. A disabled operation
ends in a canonical rejection.

## 4. G2 Plane Documentation

### 4.1 G2A DA-FULLREP-V1

- TransactionBatch and ArtifactEvidence separate namespaces.
- Author/responder journals and durable-before-attest.
- Authenticated range request/response, quota and anti-amplification.
- Full retrieval, repair, withholding/non-response, retention and GC.
- BatchRef complete-retrieval-before-vote interface.
- DA-DAS remains a separate disabled profile.

### 4.2 G2B Agent/Market/Task

- root/controller/session key lifecycle;
- capability attenuation/revocation/budget/expiry;
- parallel nonce lanes and payer nonce;
- Task/Bid/Lease/Escrow/Bond/Checkpoint;
- pause/resume/migrate/cancel/timeout/refund;
- model/tool/endpoint/privacy/profile scope and immutability;
- AgentTransactionV1 admission.

### 4.3 G2D Execution/MVCC/Fees

- exact access/version sets;
- deterministic speculative execution and canonical retry;
- serial oracle;
- success/reverted/out-of-resource receipts;
- order/state/transaction-DA/artifact-DA/proof/priority metering;
- block-end fee deltas;
- JMT inclusion proof;
- explicit prohibition on settlement authority.

### 4.4 G2C Verify/Challenge

The first objective candidate is deterministic re-execution. Its assurance case
includes model/runtime/container/compiler/kernel/tokenizer/precision/seed/input/
output digests, hardware matrix, equality rule, cost/time bounds, DA evidence,
challenge, expiry, revocation and appeal.

Every other profile remains separately versioned and disabled until its own
evidence exists. No fallback is allowed.

### 4.5 G2E Settlement

- immutable SettlementIntent;
- unique terminal SettlementReceipt;
- multi-asset fee schedule and registry;
- escrow/bond/payment/refund/reward/slash/treasury/burn/dust conservation;
- insolvency/stale price/related-party/Sybil/MEV/griefing;
- exactly-once crash/retry;
- result/challenge maturity;
- PoCO weight ineligibility.

### 4.6 G2F Whole-node/Sync/Light Client

- one authenticated snapshot or explicit atomic multi-store protocol;
- canonical application JMT, not a composite substitute;
- membership in finalized Order proof;
- external monotonic anti-rollback;
- descriptor/openat namespace identity;
- staged state sync and atomic swap;
- independent Order/DA/Execution/Result/Settlement/Upgrade proof families;
- two independent light clients;
- complete real W0-W7 trace.

### 4.7 Cross-plane invalidation

A schema/domain/profile change invalidates parser, vector, DA, execution,
result, settlement, light-client, SDK and benchmark records that consumed it.
The earliest changed interface is the mandatory rerun start.

Local candidate completion is always qualified by:

```text
scope = crate|fixture|process
authority = candidate
classification = candidate-non-normative
```

No local store, composite root, signed claim or candidate process can set
`node_support`, `implementation_status`, `release_ready` or activation.

## 5. G3-G5 Evidence, Security and Operations

### 5.1 Benchmark manifest

Every run binds:

- source/tree, plan/protocol/parameter hashes;
- binary/container/SBOM/builder;
- exact process/host/operator/region mapping;
- genesis, validator keys and proof of possession;
- workload grammar and exact bytes;
- seed, warm-up, duration, replicates and percentile denominator;
- RTT/loss/jitter/bandwidth and fault schedule;
- raw traces and analysis version;
- comparator artifact;
- signatures and evidence expiry.

Submitted or ingress TPS is forbidden as committed goodput.

### 5.2 No orphan metrics

Every published number maps to:

```text
metric_id
gate
workload/profile
event definition
denominator
raw trace root
manifest ID
command
reviewer
```

A changed workload, topology, denominator or comparator creates a new manifest
and invalidates the old claim.

### 5.3 G3 campaigns

Run 7/31/100 processes with process, host, operator and region counts reported
separately. Cover normal, slow/crashed/censoring leader, partition/heal,
restart/sync, epoch/key rotation, DA withholding/repair, signer failure and
storage pressure.

Order retain/amend/replace is an evidence-backed ADR. Protocol novelty is not a
goal.

### 5.4 G4 adversarial and AI-specific campaigns

Required:

- 72-hour chaos, then 7-day and 30-day soak;
- power, disk, OOM, corruption, rollback, clock, network, HSM/KMS and sync faults;
- model/data/license/runtime substitution;
- private-input leakage and low-entropy commitment inference;
- malicious tool/evaluator behavior;
- TEE freshness/TCB/rollback and ZK setup/VK/cost failures;
- verifier collusion/Sybil and challenge griefing;
- duplicate settlement, insolvency and governance abuse.

Each threat maps
`threat -> invariant -> mutant -> owner -> evidence root -> severity`.

### 5.5 Developer and operator surfaces

- versioned JSON-RPC/WS limits and errors;
- typed AgentTransaction builder;
- at least two language SDKs;
- indexer replay schema;
- independent light client;
- validator onboarding and key rotation;
- metrics, alerts, incident, backup/restore and disaster recovery;
- bug bounty and disclosure route.

### 5.6 G5 economics/governance/activation

Freeze parameter roots for staking, validator weight, fees/resources, assets,
escrow/bonds, rewards/slashes/refunds/treasury, privacy and upgrades.

Governance requires versioned Proposal/Vote/Decision objects, membership proof,
threshold, notice/timelock, emergency limits, veto/appeal, upgrade/cutover proof
and independent client verification.

`UP-V0-V1` and `MIG-COMET-POCO` are separate source/target/quorum/evidence
domains. Neither substitutes for the other.

No Critical or High finding may remain open at C0 or G5. No benchmark,
schedule or manually edited flag activates mainnet.
