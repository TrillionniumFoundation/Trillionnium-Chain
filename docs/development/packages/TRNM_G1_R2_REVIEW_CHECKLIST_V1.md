# G1-R2A review checklist v1

This checklist is evidence input only. It cannot promote machine truth.

## Parent dependency

- [ ] G1-R1 source/tree is accepted and independently replayed.
- [ ] G1-R2 is rebased on the accepted G1-R1 parent.
- [ ] Parent and stack manifests contain exact source/tree tuples.

## Pending-before-Core invariant

- [ ] Exact pending bytes are fsynced before the authority call.
- [ ] Input, target, namespace, predecessor and idempotency digests are bound.
- [ ] A conflicting pending record is rejected.
- [ ] A second target is rejected while an earlier target is pending.

## Core authority boundary

- [ ] No public or public-crate constructor can mint a durable Core receipt.
- [ ] The authority trait remains sealed.
- [ ] R2-A contains no live production authority implementation.
- [ ] R2-B receipt construction follows real Core persistence/readback.

## Replay acknowledgement and completion

- [ ] An exact existing G1-R1 ack completes without Core redelivery.
- [ ] A new sealed Core receipt is acknowledged through G1-R1.
- [ ] Completion publication cannot overwrite an existing final record.
- [ ] Final-plus-pending residue reconciles only after exact authentication.
- [ ] Retained completion temporary evidence is an ambiguous stop.

## Negative evidence

- [ ] Pending mutation and truncation fail closed.
- [ ] Completion mutation and truncation fail closed.
- [ ] Wrong namespace/input/predecessor/target fails closed.
- [ ] Symlink, hardlink and broad-mode paths fail closed.
- [ ] Live-lock contention fails closed.
- [ ] Response-loss retries are byte-identical.

## Required commands

```bash
bash scripts/ci/check_replay_to_core_coordinator_v1.sh
bash scripts/ci/check_payload_replay_recovery_v1.sh
bash scripts/ci/check_canonical_development_plan.sh
bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover
```

## Truth check

- [ ] `live_core_adapter=false`
- [ ] `core_ack_generated_by_core=false`
- [ ] `core_ack_atomic_with_core=false`
- [ ] `node_process_integration=false`
- [ ] `production_candidate=false`
- [ ] `production_consensus_activation=false`
