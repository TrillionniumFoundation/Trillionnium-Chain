# TRNM Workspace Agent Control and Operating Contract v1

Status: **subordinate execution contract; no gate promotion**

## 1. Exact baseline

- Repository: `TrillionniumFoundation/Trillionnium-Chain`
- Latest candidate source: `feature/chain-g1-r4c-full-gap-closure-20260829@6e0189e351015ef3230f217ca7ff86149baedcf0`
- Candidate tree: `efea864cb2fbc4835a59a089b3dbab8934e71231`
- Assessed Plan source: `docs/chain-poco-bft-mainline-20260825@8198fea0307eb368df34ff77ffc272a6b0e655ec`
- Stage: `G1-native-host-incomplete`
- `production_candidate=false`
- `production_consensus_activation=false`

## 2. Fleet

The fleet contains 18 agents, A00–A17. The structured source is
[`AGENT_REGISTRY_V1.yaml`](AGENT_REGISTRY_V1.yaml). Copy-ready instructions are
in [`AGENT_PROMPT_PACK_V1.md`](AGENT_PROMPT_PACK_V1.md).

`MODULE_CLOSED_CANDIDATE` means only package-local evidence completeness. It is
not accepted, merged, gate-exit, release-ready or production.

## 3. Non-overlap and dependency

```text
A00 -> A01
A01 -> A02 -> A03 -> A04 -> A05 -> A06 -> A07
A08 -> A09 -> A10
A10 -> A11
A10 -> A12 -> A13
A11 + A12 + A13 -> A14 -> A15
A11 + A12 + A13 + A14 + A15 -> A16
A01 + A06 + A07 + A16 -> A17
```

Promotion remains:

```text
G0 -> G1 -> G1.5 -> G2.0 -> G2A -> G2B -> G2D -> G2C -> G2E -> G2F -> G3 -> G4 -> G5
```

Preparation may be parallel. Authority and promotion are not.

## 4. Merge waves

```text
M0 A00/A01 control plane + source truth
M1 capability/interface freeze
M2 A02 recovery/Core acknowledgement
M3 A03 ordinary proposal/Vote
M4 A04 application/finality
M5 A05 Safety/checkpoint/anti-rollback
M6 A06 fault/independent replay
M7 independent G1 exit review
M8 A07 4/7-node campaign
M9 A08/A09 normative inventory + independent conformance
M10 A10 W0-W7
M11 A11/A12/A13 candidate interfaces
M12 A14 verification
M13 A15 settlement
M14 A16 whole-node/sync/light client
M15 A17 benchmark/security/operations
```

## 5. Package template

Every agent package contains, in order:

1. authority and exact source/tree tuple;
2. objective;
3. explicit non-claims;
4. owned and forbidden paths/surfaces;
5. upstream immutable inputs;
6. public interface/capability freeze;
7. state machine;
8. safety/liveness/durability/economic invariants;
9. byte/count/depth/signature/CPU/storage/time/retry bounds;
10. positive vectors;
11. retained negative mutants;
12. fault/crash/replay matrix;
13. exact commands/artifact hashes;
14. gap ledger;
15. evidence envelope with scope/authority/classification;
16. module-local exit criteria;
17. rollback/recovery;
18. downstream invalidation;
19. independent reviewer and second replay.

## 6. Interface change request

```text
request_id
requester_agent
owner_agent
current_interface_digest
proposed_interface
safety rationale
version impact
required vectors
downstream invalidation
status
reviewer
```

No requester edits another owner's surface before acceptance.

## 7. Autonomous loop

```text
VALIDATE BASE
 -> LOAD GAP LEDGER
 -> SELECT HIGHEST-SEVERITY UNBLOCKED GAP
 -> FREEZE INTERFACE
 -> IMPLEMENT MINIMAL SLICE
 -> RUN POSITIVE/NEGATIVE/FAULT TESTS
 -> RECORD EVIDENCE
 -> UPDATE DRAFT PR/HANDOFF
 -> REPEAT
```

Valid terminal statuses:

- `MODULE_CLOSED_CANDIDATE`
- `BLOCKED_UPSTREAM`
- `BASE_DRIFT`
- `STOP_CONDITION`
- `RESUME_REQUIRED`

Memory is advisory and never a source of commit/status truth. A new run always
re-reads GitHub.

## 8. Stop conditions

Stop on conflicting finality, double-sign, unauthorized validator set,
JMT/root divergence, lost durable obligation, unavailable certified data,
nondeterministic replay/execution/migration, asset imbalance, profile downgrade,
unauthorized light-client acceptance, checkpoint/anti-rollback failure, unsafe
custody or truth drift.

## 9. Per-run handoff

```json
{
  "schema": "trnm-agent-handoff-v1",
  "agent_id": "A00",
  "package_id": "PACKAGE",
  "status": "WORKING",
  "base_commit": "6e0189e351015ef3230f217ca7ff86149baedcf0",
  "base_tree": "efea864cb2fbc4835a59a089b3dbab8934e71231",
  "head_commit": null,
  "changed_paths": [],
  "gaps_closed": [],
  "gaps_open": [],
  "commands": [],
  "failed_tests": [],
  "retained_mutants": [],
  "evidence_scope": "crate",
  "authority": "candidate",
  "classification": "candidate-non-normative",
  "known_gaps": [],
  "interface_requests": [],
  "downstream_invalidation": [],
  "next_action": ""
}
```

## 10. Scheduling

- A00: every 2 hours, read-only by default.
- A01: daily and on candidate updates.
- A02–A06: every 6 hours, isolated branch, write confirmation, no auto-merge.
- A07/A16: every 12 hours.
- A08–A15: every 8 hours.
- A17: daily.

A scheduled writer first acquires a package generation lease. A concurrent run
exits without writing.
