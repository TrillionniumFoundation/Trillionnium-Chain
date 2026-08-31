# TRNM G1-R1 payload replay recovery and Core acknowledgement package v1

Package ID: `trnm-g1-r1-payload-replay-recovery-core-ack-v1`

Status: **candidate implementation package; not a G1 exit, production authority,
or activation record**

Parent authority:

- [`../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
- [`../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_EXECUTION_PACKAGES_V1.md)
- [`../TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md`](../TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md)
- [`../../../config/consensus-mainline.json`](../../../config/consensus-mainline.json)

This package implements the first item in the canonical plan's current safe
execution order: add an externally callable recovery/status owner for the
authenticated payload replay WAL. It also introduces an immutable Core
acknowledgement ledger so the next package can replace a caller-supplied Core
fact with a Node/Core-owned atomic transition.

## 1. Source identity

Development base:

```text
canonical_ref=refs/heads/docs/chain-poco-bft-mainline-20260825
branch_tip_at_package_start=92449b8e101642f39d644d863db7bb60dea488f7
latest_code_ancestor=3e6bdf1938ca409b8a32db922548bf6232391a7a
plan_assessed_commit=8198fea0307eb368df34ff77ffc272a6b0e655ec
plan_assessed_tree=a1be71bba1b54c428493d186fafb656d081b31a9
```

The package must record its own final source commit/tree after implementation.
The older plan assessment is not upgraded automatically. No central machine
flag is changed by this package.

## 2. Problem statement

The candidate P2P path currently performs:

```text
authenticated session/frame
 -> external peer lease revalidation
 -> append-only payload replay WAL admission
 -> private Core ingress attempt
```

The payload WAL and its exact head sidecar are durable before the frame is
reported admitted. A crash can nevertheless occur in two important windows:

1. the frame record has reached the WAL, but the exact head sidecar publication
   did not complete;
2. the WAL admission is durable, but no independently queryable record says
   whether the exact frame reached a durable Core revision.

The existing store deliberately rejects retained publication temporaries and
head disagreement. That is correct for the normal runtime owner, but without an
external recovery owner it leaves an operator unable to distinguish a safe
one-record publication lag from corruption or a different prefix.

## 3. Scope

### 3.1 In scope

- read-only independent verification of the complete replay WAL hash chain;
- exact namespace, epoch, validator-set, run and network-context binding;
- exact target record binding using record index/hash and complete frame facts;
- exclusive payload lock and live-owner exclusion;
- classification of:
  - exact durable publication;
  - exact one-record head lag;
  - exact durable publication with retained temporary evidence;
  - admitted but Core-unacknowledged;
  - Core-acknowledged;
- repair of only the exact one-record head lag;
- quarantine, not deletion, of retained head-publication evidence;
- immutable target-bound Core acknowledgement files;
- stable command-line `status`, `recover` and `ack` operations;
- unit and negative tests;
- truthful package/Cargo metadata.

### 3.2 Explicitly out of scope

- invoking `Core::step`;
- constructing a Core acknowledgement digest;
- claiming that a caller-provided Core revision is genuine;
- atomicity between payload WAL, Core SafetyState and the acknowledgement file;
- replay-to-Core automatic recovery;
- production P2P listener or persistent daemon ownership;
- pacemaker, Vote, Timeout, finality or application apply;
- whole-namespace anti-rollback;
- HSM/KMS or remote-signer authority;
- public testnet, performance or activation claims.

The global truth fields therefore remain:

```text
stage=G1-native-host-incomplete
production_candidate=false
production_consensus_activation=false
external_status_or_recovery_owner=false  # global/accepted authority
replay_core_ack_atomic=false
```

The crate-level candidate metadata may truthfully state that the bounded API is
present while the central production flags remain false.

## 4. Authority model

The package creates two cooperating local authorities.

### 4.1 Payload recovery owner

The recovery owner opens the exact existing WAL and lock sidecars. It never
creates a missing payload journal, lock or head. It obtains the same exclusive
lock class used by the runtime store, so a live store and a recovery owner
cannot operate concurrently.

Before returning a status, it independently verifies:

- private canonical parent path;
- regular, single-link, owner-only files;
- exact fixed record size;
- complete record checksum chain;
- record index continuity;
- namespace and context equality;
- genesis shape;
- peer/direction session-generation monotonicity;
- contiguous sequence numbers;
- payload and fingerprint limits;
- exact target record facts;
- head checksum and namespace.

### 4.2 Core acknowledgement ledger

The acknowledgement ledger has a private root directory and an exclusive lock.
One file is keyed by exact payload record index and record hash. Its body binds:

```text
schema/version
payload namespace digest
payload record index
payload record hash
frame fingerprint
positive Core safety revision
Core acknowledgement digest
record checksum
```

The file is immutable. Exact replay returns the same receipt. A different
revision or digest for the same payload target fails closed.

This ledger is evidence supplied by a caller after Core is claimed to be
durable. It is not Core authority by itself.

## 5. State machine

```text
Unknown
  -> WalVerified
  -> TargetVerified
  -> PublicationDurable
       |-> AdmittedUnacknowledged
       |-> CoreAcknowledged

TargetVerified
  -> ExactOneRecordHeadLag
  -> HeadRepaired
  -> TemporariesQuarantined
  -> PublicationDurable

PublicationDurable + exact caller Core fact
  -> AckTempDurable
  -> AckPublished
  -> AckDirectoryDurable
  -> CoreAcknowledged
```

Forbidden transitions:

- missing WAL -> create new WAL;
- arbitrary prefix -> repair;
- two-or-more-record lag -> repair;
- wrong target -> repair or acknowledge;
- retained temp -> silently delete;
- head divergence -> choose WAL or head heuristically;
- unacknowledged -> acknowledged without a positive revision and digest;
- existing acknowledgement -> overwrite;
- conflicting acknowledgement -> normalize or choose one;
- recovery state -> production activation.

## 6. Exact recovery rule

A head may advance only when all conditions hold:

```text
head.namespace_digest == expected_namespace_digest
head.record_count + 1 == wal.record_count
head.record_count == target.record_index
head.record_hash == target.predecessor_hash
target.record_index + 1 == wal.record_count
target.record_hash == wal.last_record_hash
target complete frame facts == decoded last WAL record
```

Any other relation is `PayloadHeadDiverged` and requires forensic/operator
recovery outside this package.

## 7. Temporary evidence handling

A normal payload-store open rejects files matching the retained head temporary
prefix. The recovery owner:

1. verifies each temporary is a private regular single-link file;
2. keeps the payload and acknowledgement locks held;
3. renames it to a non-active `payload-head-recovery-evidence-*` name;
4. syncs the parent directory;
5. verifies that no active temporary prefix remains.

It never interprets temporary bytes as authority and never deletes them.

## 8. Core acknowledgement write contract

The `ack` operation requires publication state `Durable`. It creates a private
unique temporary, writes the complete fixed-size record, syncs the file, moves
it to the immutable target path and syncs the directory.

Possible results:

- `written`: a new exact acknowledgement exists;
- `idempotent_replay`: the same exact acknowledgement already exists;
- `AckConflict`: the target has a different valid acknowledgement;
- `AckLedgerCorrupt`: bytes, size, checksum or binding are invalid;
- `AckCommitAmbiguous`: I/O failed after the temporary may have become durable.

A future package must add explicit acknowledgement-temp recovery and bind this
publication to the real Core transition. Until then, ambiguous acknowledgement
publication is a stop condition.

## 9. Stable CLI contract

Binary:

```text
trnm-payload-replay-recovery-v1
```

Operations:

```text
status
recover
ack
```

Common input binds the complete namespace and target:

```text
payload-wal
ack-root
local-id
active epoch
validator-set ID
run ID hash
network-context hash
record index/hash
remote ID and direction
session ID
generation and sequence
frame kind and payload length
frame fingerprint
```

`ack` additionally requires:

```text
Core safety revision
Core acknowledgement digest
```

Output is one line of stable `key=value` facts and always includes:

```text
candidate_only=true
production=false
```

Acknowledgement output also includes:

```text
atomic_with_core=false
```

The CLI never derives missing values from filenames or latest state.

## 10. Work breakdown

### R1.1 — package and truth freeze

- add this package contract and manifest;
- link it from the single plan entry point;
- record base branch/code/plan identities;
- preserve central false flags.

### R1.2 — independent WAL reader

- fixed-size bounded read;
- full chain verification;
- namespace/context checks;
- generation/session/sequence replay checks;
- exact target lookup.

### R1.3 — publication status

- exact head decode/checksum;
- durable/head-lag/residual classification;
- stable public status enum.

### R1.4 — bounded repair

- exact one-record rule;
- fsynced head replacement;
- temporary evidence quarantine;
- post-repair readback.

### R1.5 — Core acknowledgement ledger

- private root/lock;
- fixed canonical body and checksum;
- immutable target path;
- exact replay and conflict handling;
- ambiguous-write classification.

### R1.6 — CLI

- strict lowercase 32-byte hex parser;
- exact numeric parsing;
- stable status schema;
- no implicit defaults.

### R1.7 — tests and gates

- normal admitted/unacknowledged status;
- acknowledgement and restart/idempotent replay;
- conflicting acknowledgement;
- exact one-record repair;
- acknowledgement-before-repair rejection;
- live payload-owner exclusion;
- target mismatch;
- WAL/head/ack tamper and truncation;
- path/symlink/mode/hardlink negatives;
- formatting and strict Clippy.

### R1.8 — review and evidence

- clean source/tree;
- exact command log and exit codes;
- test counts and raw output hash;
- independent reviewer replay;
- no central flag promotion.

## 11. Crash matrix

The process must eventually be killed immediately after each boundary:

| ID | Cut | Expected recovery |
|---|---|---|
| C01 | payload WAL write begins | normal WAL parser rejects torn record |
| C02 | payload WAL file sync | exact one-record lag may be recoverable |
| C03 | payload parent sync | same as C02, exact target required |
| C04 | payload head temp sync | retained temp is evidence, not authority |
| C05 | payload head rename | reopen decides exact head equality |
| C06 | payload head directory sync | reopen decides; no duplicate admission |
| C07 | Core input accepted, no ack ledger | `AdmittedUnacknowledged` only |
| C08 | ack temp write | ambiguous/retained evidence; no false ack |
| C09 | ack temp sync | ambiguous until exact final publication is observed |
| C10 | ack rename | reopen either finds exact final or no final |
| C11 | ack directory sync | exact final is idempotent if present |
| C12 | response emitted | exact retry returns the same acknowledgement hash |

This package lands unit-level boundaries. A later process/SIGKILL package must
execute and sign the complete matrix.

## 12. Required commands

From the repository root:

```bash
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo test --manifest-path trillionnium/Cargo.toml \
  --locked -p trnm-consensus-peer-lease -- --test-threads=1
cargo clippy --manifest-path trillionnium/Cargo.toml \
  --locked -p trnm-consensus-peer-lease --all-targets -- -D warnings
bash scripts/ci/check_payload_replay_recovery_v1.sh
bash scripts/ci/check_canonical_development_plan.sh
bash scripts/ci/check_poco_bft_mainline_truth.sh --pre-cutover
```

A passing local command is candidate evidence only. Package promotion requires
captured exit codes, exact source/tree, toolchain, lock hash and independent
replay.

## 13. Acceptance criteria

The package is review-complete only when:

1. every source/schema/doc change is committed in one clean package branch;
2. all listed tests and strict Clippy pass from a clean clone;
3. a live `PayloadReplayStoreV1` excludes the recovery owner;
4. every WAL byte and transition is reverified independently;
5. only an exact one-record lag is repaired;
6. wrong target, longer lag and divergent head fail closed;
7. retained temporaries remain preserved and no longer block the normal store;
8. acknowledgement replay is byte-identical and conflicting facts fail;
9. no acknowledgement is accepted before publication recovery;
10. central production/activation/Core-atomic flags remain false;
11. an independent reviewer reproduces the package evidence.

## 14. Non-claims after acceptance

Even after this package is accepted, the project must not claim:

- payload replay is atomically acknowledged by Core;
- automatic Core recovery exists;
- ordinary Proposal execution is production-ready;
- the default node is deployable;
- G1 is complete;
- a validator run has completed;
- state sync, finality or signer custody is production-ready;
- public testnet or mainnet readiness.

## 15. Immediate successor package

`G1-R2 replay-to-Core acknowledgement owner` must consume this API and remove
the caller-supplied authority. Its first deliverable is a non-cloneable Node
owner that holds:

```text
exact authenticated frame
payload admission receipt
pending replay breadcrumb
Core input authority
Core durable result/revision
whole-node predecessor checkpoint
```

It must produce the acknowledgement digest internally, cross the exact Core
persistence barrier, write the replay acknowledgement, and clear the pending
breadcrumb under one recoverable contract. Only G1-R2 may consider changing
the central `external_status_or_recovery_owner` candidate wording or
`replay_core_ack_atomic` truth, and only after signed process evidence.
