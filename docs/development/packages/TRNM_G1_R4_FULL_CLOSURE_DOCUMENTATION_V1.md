# G1-R4 Full Closure Documentation Contract v1

Status: **candidate-only documentation contract; G1-R4 exit remains open**

## 1. Frozen end-to-end boundary

```text
Core finalization queue front
 -> finalization intent durable
 -> exact body/overlay/JMT lineage revalidated
 -> native application BEGIN
 -> application rows/JMT durable
 -> application commit
 -> fresh application readback
 -> Core application-finalization receipt
 -> tag-3 Safety intent
 -> Safety persist and fresh readback
 -> successor whole-node checkpoint CAS
 -> checkpoint readback
 -> Ready/reopen
 -> queue acknowledgement and fork reclamation
```

No earlier step may be inferred from a later receipt.

## 2. Required subordinate packages

### R4B — application commit owner

Must define:

- finalization queue/front/proof/body/overlay identity;
- application transaction and commit-uncertainty semantics;
- JMT promotion and committed root;
- exact retry and duplicate rejection;
- fresh readback before Core receipt;
- losing-fork retention/reclamation;
- source/target/quarantine outcomes.

### R4C — Safety and checkpoint owner

Must define:

- exact Core receipt consumed;
- tag-3 Safety record and predecessor;
- Safety readback before checkpoint;
- Application/Safety/Signer checkpoint tuple;
- successor-only CAS;
- external monotonic anchor;
- signature release prohibition until checkpoint proof;
- mixed-cut and coherent rollback behavior.

### R4D — multi-block, fork and anti-rollback

Must define:

- contiguous ascending finalization for 3/10/100/1000 ancestors;
- no skipped ancestor and no out-of-order apply;
- queue/head/checkpoint relationship;
- fork overlay retention and safe GC;
- App-only, Safety-only, Signer-only and coherent namespace rollback;
- copied/renamed/path-swapped stores;
- restart from every block in a batch.

### R4E — independent fault evidence

Every durable edge is tested under:

```text
SIGKILL
response loss before and after commit
disk full
short/torn write
fsync and directory-fsync failure
SQLite busy/hot journal/WAL/SHM residue
process restart
host reboot classification
database rollback
full namespace rollback
signer/Safety/Application skew
```

## 3. Capability table

| Capability | Sole issuer | Consumer | Forbidden substitute |
|---|---|---|---|
| FinalizationQueueFrontPermit | Core | application owner | raw block/proof |
| ApplicationFinalizationPermit | Core/Safety-bound seam | application store | height/hash tuple |
| ApplicationCommitReadback | fresh store reopen | Core receipt issuer | transaction return |
| CoreApplicationReceipt | Core | Safety tag-3 owner | app receipt alone |
| SafetyTag3Readback | SafetyStore reopen | checkpoint owner | in-memory Safety state |
| WholeNodeCheckpointReceipt | external checkpoint authority | Ready/sign/recovery | path checksum |
| SignatureReleasePermit | Core-owned Safety authority | remote signer | raw sign bytes |
| RecoveryReadyReceipt | recovery owner | process startup | absence of marker |

All capability serialization/reconstruction rules must be explicit.
Non-forgeable in-process carriers cannot be replaced with caller-supplied JSON
merely to make testing easier.

## 4. Matrix IDs

```text
R4-M01 intent publication
R4-M02 app begin
R4-M03 app durable rows
R4-M04 JMT promotion
R4-M05 app commit response loss
R4-M06 app readback/Core receipt
R4-M07 Safety intent
R4-M08 Safety persist/readback
R4-M09 checkpoint intent/CAS
R4-M10 checkpoint response loss/readback
R4-M11 queue acknowledgement
R4-M12 multi-block ancestor order
R4-M13 losing-fork reclamation
R4-M14 store skew
R4-M15 coherent rollback
R4-M16 independent process replay
```

Each ID requires source SHA/tree, binary hash, command, cut, residue, expected
outcome, actual result, raw trace root and independent reviewer.

## 5. Exit

R4 remains open until every matrix ID is accepted and:

- zero lost/skipped ancestor;
- zero duplicate apply;
- zero root/receipt drift;
- zero double-sign;
- no ambiguous third state;
- exact retry is idempotent;
- coherent rollback is rejected before authority use;
- independent clean-clone replay agrees.

Passing R4 does not itself create production candidacy or a public-testnet
claim.
