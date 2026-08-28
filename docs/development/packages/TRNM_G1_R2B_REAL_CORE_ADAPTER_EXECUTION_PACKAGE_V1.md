# TRNM G1-R2B real Core adapter and process contract v1

Package ID: `trnm-g1-r2b-real-core-adapter-v1`

Status: **candidate-only contract; implementation and evidence are not
authorized or promoted**

This document is subordinate to the single canonical development plan. It is
an implementation contract for the next tranche after G1-R2A; it is not a
second roadmap, a release note, or a G1 exit record.

Authoritative inputs:

- [`../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
- [`../TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md)
- [`TRNM_G1_R2B_NEXT_IMPLEMENTATION_TARGET_V1.md`](TRNM_G1_R2B_NEXT_IMPLEMENTATION_TARGET_V1.md)
- [`TRNM_G1_REPLAY_TO_CORE_DURABLE_ACK_EXECUTION_PACKAGE_V1.md`](TRNM_G1_REPLAY_TO_CORE_DURABLE_ACK_EXECUTION_PACKAGE_V1.md)
- [`trnm-g1-r2b-manifest-v1.toml`](trnm-g1-r2b-manifest-v1.toml)

## 1. Scope and current status

R2-A owns a recoverable pending/ack/completion coordinator. R2-B is the
smallest trusted process-boundary slice that may turn a pending
`CoreReplayRequestV1` into a sealed `CoreDurableReplayReceiptV1`.

The assessed g1-r2b worktree has a candidate probe named
`CandidateCoreIngressV1`. That probe is deliberately **not a source-bound
implementation**: it uses synthetic fixture proposal material and candidate
files, has no authorized clean-commit tuple, and has no process/SIGKILL or
independent-review evidence. A call into the Core library, a unit test, or a
candidate journal therefore cannot be described as a live production Core
adapter. The probe must remain unbound until its source, API boundary,
durability owner and evidence are reviewed and committed together.

The R2-B manifest records this state with `source_commit` and `source_tree`
set to `UNBOUND_UNTIL_NORMALIZED_SOURCE_*`. Those placeholders are a safety
fence, not missing release metadata.

The candidate probe now exercises a real in-process Core transition, rejects
non-contiguous phase residue, reconstructs the deterministic fixture
transition on reopen, and compares the complete revision-one/revision-two
SafetyState values before returning its sealed test receipt. These checks are
candidate instrumentation only: the journal uses unkeyed integrity digests,
the body is synthetic, and no durable Core/SafetyStore or process-restart
authority is implied.

## 2. Required ordered transition

The private adapter must consume the exact request emitted by R2-A and perform
the following sequence without changing any identity field:

```text
authenticated replay record
 -> exact CoreReplayRequestV1 and idempotency key
 -> authenticated proposal/body resolution
 -> private Core ingress
 -> Core accepts input
 -> SafetyState/Core transition persisted
 -> durable state reopened and read back
 -> whole-node predecessor checkpoint compared-and-swapped
 -> acknowledgement digest derived from the durable Core result
 -> sealed CoreDurableReplayReceiptV1
 -> R2-A replay acknowledgement and completion
```

The receipt constructor remains private to the trusted compilation boundary.
It may be called only after every barrier above has succeeded. A caller, CLI,
generic callback, test carrier, or deserialized response must never be able to
supply the revision or acknowledgement digest.

The adapter must bind the request's namespace, target, input digest,
predecessor checkpoint and idempotency key to the Core input and to the
durable read-back facts. It must resolve an authenticated body from the
node-owned replay source; deriving a proposal body from a digest-only fixture
is candidate instrumentation, not the R2-B authority.

## 3. Ownership and persistence contract

R2-B is a private `trnm-poco-node` process-boundary owner. It must not add a
default-feature binary, public receipt constructor, or independently callable
Core acknowledgement API.

The implementation must use the existing Core/SafetyState types and a real
durable owner. In particular, the design review must account for the
transition binding between Core's `SafetyStatePersistenceV0` and the
whole-node checkpoint CAS; an unbound generic `Ordinary` context or an ad-hoc
text WAL is insufficient. If the current `SqliteSafetyStateStoreV0` API
cannot carry the exact transition digest, the adapter must add a private,
request-bound binding rather than silently dropping that fact.

The following are hard requirements:

- one non-cloneable owner for Core, SafetyState persistence/read-back and the
  predecessor checkpoint;
- no receipt on an uncertain, partially persisted or response-lost Core
  outcome;
- exact retry by the same idempotency key, never a fresh generation;
- no later target while an earlier pending target is unresolved;
- all path, mode, inode, checksum and namespace checks fail closed;
- no production/activation flag changes in this tranche.

## 4. Required fault cuts

Each cut must be exercised against a real process and a reopened durable
directory. A unit-level error return is useful negative evidence but does not
close a process cut.

| ID | Cut | Required durable result |
| --- | --- | --- |
| `R2B-01` | before Core input | pending request remains; Core is not called; no receipt or replay acknowledgement |
| `R2B-02` | Core accepted, before SafetyState persistence | outcome is uncertain; pending remains; retry uses the exact idempotency key |
| `R2B-03` | persistence completed, before durable read-back | no receipt; reopen either proves the exact state or remains pending; no guessed revision |
| `R2B-04` | read-back completed, before replay acknowledgement | durable Core facts are recoverable; retry cannot mint a second Core transition |
| `R2B-05` | replay acknowledgement, before completion publication | exact acknowledgement completes without Core redelivery; conflicting bytes fail closed |
| `R2B-06` | completion publication, before response | exact completed receipt is returned on retry; retained temporary/residue is reconciled only after independent authentication |

The matrix must additionally cover SIGKILL, disk-full/I/O failure, stale or
forged response, symlink/hardlink/path substitution, namespace rollback and a
second target racing the unresolved first target.

## 5. Evidence and gate semantics

Before any promotion claim, the implementation owner must publish:

1. a clean committed source/tree tuple and exact Cargo.lock hash;
2. Rust format, focused tests and strict Clippy output from an authorized
   clean clone;
3. process-level traces for `R2B-01` through `R2B-06`, including response loss
   and restart/reopen facts;
4. independent verification that the Core revision and acknowledgement digest
   came from the durable Core result and bind the predecessor checkpoint; and
5. an independent review decision that accepts the private ownership boundary.

The contract gate
[`check_replay_to_core_r2b_contract_v1.sh`](../../../scripts/ci/check_replay_to_core_r2b_contract_v1.sh)
checks only the documentation, manifest and negative truth boundary. Its
`PASS` output means **contract-only**; it is not a real-Core, process, G1 or
production result. The existing R2-A code gate and parent R1 gate remain
separate dependencies.

For the 2026-08-28 worktree snapshot, the canonical-plan and pre-cutover
mainline truth checks pass. `project-preflight.sh --audit` still reports the
known frozen-workflow policy mismatch for the two R2 workflows; that baseline
CI failure is recorded as a blocker and is not waived by this contract.

## 6. Explicit non-claims

Until the source tuple and all evidence above are accepted, this package does
not claim:

- a live or production Core adapter;
- Core-generated or Core-atomic replay acknowledgement;
- default-node or process integration;
- whole-node anti-rollback or checkpoint CAS closure;
- crash/restart completion, arbitrary execution, finality, signer ownership,
  testnet readiness or production readiness;
- G1-R2, G1 or any downstream gate exit.

The machine truth must remain:

```text
production_candidate=false
production_consensus_activation=false
live_core_adapter=false
core_ack_generated_by_core=false
core_ack_atomic_with_core=false
node_process_integration=false
process_kill_matrix_complete=false
whole_node_anti_rollback=false
```
