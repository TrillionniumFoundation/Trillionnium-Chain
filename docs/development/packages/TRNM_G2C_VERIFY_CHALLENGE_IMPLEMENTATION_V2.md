# G2C verification profile, challenge and outbox implementation v2 replay

Status: **MODULE_CLOSED_CANDIDATE for A14-owned registry/verification/challenge/outbox surfaces; BLOCKED_UPSTREAM for accepted DA, Agent, Order, JMT and settlement authority**

Package: `G2C_VERIFY_CHALLENGE_V1`  
Owner: `A14`  
Exact base: PR #34, `feature/chain-a13-g2d-execution-mvcc-fee-v2-20260830@ad633bf7557052c02bf214b683a18bd72bb4bec5`, tree `b430c899be1b5c17815bdaf01a957f5565e105e9`.

## Candidate implementation

The package carries a closed seven-profile Rust registry and challenge lifecycle. Resolution is exact by profile ID, version and hash. Disabled, unknown, not-yet-valid, expired and revoked profiles reject before backend invocation. No fallback is possible. Subjective profiles cannot obtain objective settlement or PoCO-weight authority.

The replay also adds a deterministic outbox/recovery model:

```text
Enqueued -> Sent -> Acked
Sent --response loss/retry delay--> Pending -> Sent
```

Event IDs bind result and event kind; payload conflicts quarantine the outbox. Delivery tokens bind sequence, payload and attempt. Exact duplicate ack is idempotent, while conflicting ack quarantines. Ordered commitments reject sequence gaps/reuse.

Challenge finality remains forward-only and permits one candidate appeal for state-machine testing. It never reorgs Order or moves assets.

## Commands

```bash
bash scripts/ci/check_g2c_source_binding_v2.sh
bash scripts/ci/check_g2c_replay_v2.sh
```

## Typed blockers

- canonical ArtifactEvidence/AvailabilityCertificate authority: A11;
- Task/Lease/profile policy authority: A12;
- accepted execution receipt plus canonical JMT proof: A13 + A16;
- accepted Order finality: G1 + A16;
- bond/payment/refund/slash movement: A15;
- production appeal/concurrent-challenge governance: A17/G5.

## Non-claims

```text
g2c_exit=false
profiles_globally_enabled=false
profile_fallback=false
artifact_availability_authority=false
order_finality_authority=false
settlement_movement=false
poco_weight_eligible=false
production_candidate=false
production_consensus_activation=false
```
