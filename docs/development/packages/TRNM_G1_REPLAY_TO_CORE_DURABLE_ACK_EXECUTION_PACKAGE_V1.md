# TRNM G1-R2 replay-to-Core durable acknowledgement package v1

Package ID: `trnm-g1-r2-replay-to-core-durable-ack-v1`

Status: **stacked candidate implementation; G1-R1 dependency remains unverified; not a G1 exit or activation record**

Parent authority:

- [`../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
- [`../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md)
- [`TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md`](TRNM_G1_REPLAY_RECOVERY_AND_CORE_ACK_EXECUTION_PACKAGE_V1.md)
- [`../TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md)
- [`../../../config/consensus-mainline.json`](../../../config/consensus-mainline.json)

## 1. Purpose

G1-R1 makes payload-WAL publication externally observable and repairable, and
adds an immutable Core-acknowledgement ledger. Its acknowledgement fact is
still supplied by a caller and is explicitly not atomic with Core.

G1-R2 removes that caller-shaped transition in two ordered tranches:

1. **R2-A — Node-owned recoverable delivery coordinator**: persist the exact
   replay target and predecessor checkpoint before Core delivery; admit only a
   sealed durable-Core receipt; persist the G1-R1 replay acknowledgement; then
   atomically publish completion and clear the pending breadcrumb.
2. **R2-B — real Core adapter and process integration**: construct the sealed
   receipt only inside the existing Core/process authority after the exact
   SafetyState/Core persistence barrier and whole-node predecessor check.

This package lands R2-A. It intentionally has no public constructor for a
Core-durable receipt and no live Core adapter. That prevents a generic callback
or CLI argument from silently recreating the G1-R1 caller-supplied authority.
The package therefore remains incomplete until R2-B is implemented and proven.

## 2. Required state machine

```text
AuthenticatedFrame
 -> PayloadWalAdmitted
 -> DeliveryPendingDurable
 -> CoreInputAccepted
 -> CoreSafetyRevisionDurable
 -> ReplayCoreAckDurable
 -> DeliveryCompletedDurable
```

Recoverable restart states:

```text
pending + no replay ack
  -> redeliver the same idempotency key to Core

pending + exact replay ack
  -> publish completion without redelivery

completed + no pending
  -> return the exact prior receipt

completed + exact pending residue
  -> verify both records, clear the residue, return the prior receipt
```

Forbidden states/transitions:

- no durable pending record -> Core delivery;
- caller-constructed Core receipt -> replay acknowledgement;
- different target/input/predecessor -> reuse an existing pending record;
- unresolved earlier target -> start a fresh target;
- conflicting completion -> overwrite or normalize;
- retained completion temporary -> silently delete or choose a side;
- Core acknowledgement without exact payload target -> complete;
- crate-local coordinator -> production/Node/Core authority claim.

## 3. Exact durable bindings

The pending record binds:

```text
schema/version
payload namespace digest
complete payload target digest
payload record index/hash
frame fingerprint
Core input digest
whole-node predecessor checkpoint
Core idempotency key
record checksum
```

The completed record additionally binds:

```text
positive Core safety revision
Core acknowledgement digest
G1-R1 replay acknowledgement hash
completion checksum
```

The idempotency key is derived from the exact namespace, target, input and
predecessor checkpoint. A restart must present the same key to Core; it cannot
mint a new request identity.

## 4. Authority boundary

`ReplayToCoreAuthorityV1` is sealed. Code outside the coordinator compilation
unit cannot implement it, and `CoreDurableReplayReceiptV1` has no public
constructor. The only implementation in R2-A is test-only.

R2-B must add one concrete implementation inside the trusted
`trnm-poco-node`/Core process boundary. That implementation must:

1. consume the exact pending request and idempotency key;
2. call the real private Core ingress;
3. cross the exact Core/SafetyState persistence and readback barrier;
4. verify the whole-node predecessor checkpoint did not move;
5. derive the acknowledgement digest from the durable Core result;
6. construct the sealed receipt;
7. return no receipt for an uncertain or partially persisted Core outcome.

Until R2-B exists:

```text
core_adapter_present=false
core_ack_generated_by_core=false
core_ack_atomic_with_core=false
node_process_integration=false
production_activation=false
```

## 5. Persistence and crash contract

The coordinator root is a canonical private directory with one exclusive lock.
Pending and completed paths are keyed by exact payload record index/hash.

Writes use:

```text
create_new private temporary/file
 -> write complete fixed-size record
 -> fsync file
 -> publish without overwrite
 -> fsync directory
 -> remove exact predecessor residue when safe
 -> fsync directory
```

Any retained completion temporary is an explicit ambiguous stop. A final file
and pending residue may be reconciled only when both independently authenticate
and bind the same request.

Only one unresolved pending target is allowed per coordinator root. This is the
bounded G1 rule that prevents a later peer generation or frame from overtaking
an uncertain earlier Core delivery.

## 6. R2-A deliverables

- `trnm-poco-replay-to-core-coordinator-v1` candidate binary compilation unit;
- sealed Core-authority trait and non-public durable receipt construction;
- exact target/input/predecessor/idempotency binding;
- private pending and completed fixed-size records;
- exclusive root lock;
- G1-R1 payload publication recovery before delivery;
- G1-R1 replay acknowledgement after sealed Core receipt;
- restart completion when the replay acknowledgement already exists;
- idempotent completed-record replay;
- unresolved-earlier-target exclusion;
- tamper, conflict, symlink/mode, lock and retained-temp negatives;
- dedicated package gate and trusted-runner workflow;
- no machine-truth or production promotion.

## 7. R2-B remaining work

- integrate with the actual `trnm-poco-node` private Core ingress;
- construct the sealed receipt after real durable Core readback;
- bind the real whole-node checkpoint/CAS predecessor;
- make pending creation, Core transition and replay acknowledgement one
  recoverably coordinated process contract;
- add process/SIGKILL cuts at every state transition;
- prove exact response-loss replay against a real Core process;
- prove no fresh generation can overtake an unresolved target;
- add clean-clone independent evidence and review;
- only then consider changing candidate machine truth.

## 8. Failure matrix

| ID | Cut/fault | Required outcome |
|---|---|---|
| R2A-01 | before pending file sync | no Core call |
| R2A-02 | after pending sync | exact restart redelivery key |
| R2A-03 | Core returns no sealed receipt | pending retained; no replay ack |
| R2A-04 | Core durable, before replay ack | restart uses same Core idempotency key |
| R2A-05 | replay ack durable, before completion | restart completes without Core redelivery |
| R2A-06 | completion temp durable | ambiguous stop; no guessed completion |
| R2A-07 | final completion published, pending remains | exact reconciliation only |
| R2A-08 | response lost after completion | exact idempotent receipt |
| R2A-09 | different input/predecessor for same target | conflict |
| R2A-10 | second target while first pending | rejected |
| R2A-11 | pending/completed byte mutation | corruption stop |
| R2A-12 | symlink, hardlink or broad mode | invalid-path stop |

R2-B extends this matrix with real Core/SafetyState/checkpoint process cuts.

## 9. Required verification

```bash
bash scripts/ci/check_replay_to_core_coordinator_v1.sh
bash scripts/ci/check_payload_replay_recovery_v1.sh
bash scripts/ci/check_canonical_development_plan.sh
bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover
```

The package remains stacked on an unverified G1-R1 branch. A passing R2-A gate
cannot promote G1-R1, cannot satisfy R2-B, and cannot change G1 or production
truth.

## 10. Acceptance criteria for R2-A

1. no Core call is possible before exact pending durability;
2. no public API can construct a Core durable receipt;
3. the exact request/idempotency key survives restart;
4. an existing exact replay acknowledgement completes without redelivery;
5. an existing exact completion is byte-identical and idempotent;
6. an earlier unresolved target blocks a later target;
7. all conflicting/tampered/ambiguous states fail closed;
8. all package gates pass from an authorized clean clone;
9. G1-R1 dependency status is explicitly recorded;
10. production, activation, live-Core-adapter and Core-atomic flags stay false.

## 11. Non-claims

R2-A does not prove:

- a real Core input was accepted;
- a real SafetyState revision was persisted;
- Core and replay acknowledgement are atomic;
- the default node owns the coordinator;
- process crash recovery is complete;
- G1 is complete;
- validator, public-testnet or production readiness.
