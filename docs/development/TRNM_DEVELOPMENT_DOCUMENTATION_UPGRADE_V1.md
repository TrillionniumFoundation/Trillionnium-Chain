# TRNM Development Documentation Upgrade v1

Status: **subordinate documentation program; no gate promotion**

Authority baseline:

```text
repository = TrillionniumFoundation/Trillionnium-Chain
latest_candidate_ref = feature/chain-g1-r4c-full-gap-closure-20260829
latest_candidate_commit = 6e0189e351015ef3230f217ca7ff86149baedcf0
latest_candidate_tree = efea864cb2fbc4835a59a089b3dbab8934e71231
assessed_plan_ref = docs/chain-poco-bft-mainline-20260825
assessed_commit = 8198fea0307eb368df34ff77ffc272a6b0e655ec
assessed_tree = a1be71bba1b54c428493d186fafb656d081b31a9
```

## 1. Purpose

Convert the canonical Plan from one large narrative into machine-checkable,
review-sized package contracts that 18 independent Workspace Agents can execute
without creating parallel roadmaps or overlapping authority.

## 2. Documentation closure tiers

### D0 — truth and agent control plane

Required:

- `CURRENT_SNAPSHOT_V1.json` plus schema/generator/checker;
- agent registry, ownership matrix, dependency DAG and merge train;
- work-package and interface-change templates;
- per-run handoff schema;
- package index tied to exact source/tree;
- stale-pointer and unscoped-positive CI checks.

### D1 — current G1 promotion-critical closure

Required package contracts:

1. G1 authority/capability interface freeze.
2. External recovery/status protocol.
3. R2 replay/Core acknowledgement atomicity.
4. R3 ordinary proposal/execution/AuthorityVote.
5. R4B application commit process matrix.
6. R4C Safety/checkpoint/signature process matrix.
7. R4D multi-block/fork/anti-rollback.
8. Durability and physical power-loss evidence taxonomy.
9. R4 exit evidence index.
10. R5 native 4/7-node campaign.

Detailed minimums are in
[`packages/TRNM_G1_R4_FULL_CLOSURE_DOCUMENTATION_V1.md`](packages/TRNM_G1_R4_FULL_CLOSURE_DOCUMENTATION_V1.md).

### D2 — G1.5/G2 candidate preparation

Required:

- generated CEV1 object/domain/error/operation/limit/profile registries;
- independent parser and corpus contract;
- 30 W0-W7 operation rows;
- DA-FULLREP transaction/artifact namespaces;
- Agent/capability/task lifecycle;
- deterministic execution/MVCC/resources;
- profile-specific verification assurance cases;
- settlement conservation;
- whole-node JMT/CAS/anti-rollback/sync/light client.

### D3 — G3-G5 evidence and operations

Required:

- signed benchmark/topology/workload/fault manifests;
- no-orphan-metric binding;
- adversarial/AI-specific threat register;
- chaos/soak/SLO/incident/DR/key-rotation runbooks;
- independent RPC/SDK/indexer/light-client conformance;
- separate `UP-V0-V1` and `MIG-COMET-POCO` ceremonies;
- economics/governance/activation evidence.

The D2/D3 matrix is in
[`packages/TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md`](packages/TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md).

## 3. Documentation acceptance

A document is not complete because it is long. It is complete only when it has:

- exact authority tuple;
- normative/candidate classification;
- owner and forbidden owner;
- state machine and invariants;
- byte/resource/time bounds;
- positive vectors and retained negative mutants;
- crash/fault/replay semantics;
- exact commands and evidence artifacts;
- exit and non-claim language;
- rollback and downstream invalidation;
- independent review owner.

## 4. Relationship to agents

The documentation matrix maps one-to-one into
[`agents/AGENT_REGISTRY_V1.yaml`](agents/AGENT_REGISTRY_V1.yaml). An agent may add
missing subordinate contracts, but it may not silently edit the canonical Plan
or machine truth to make its module appear closed.
