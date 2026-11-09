# Same-operation learning and business readback V1

This is a bounded, read-only composition over the original Hepta completion
reader and the original Node paid-Task V3 export. It keeps **DENY_ALL / HOLD_NO_GO**.
It has no signing, dispatch, installation, payment, redispatch or recovery-write
path. Structural agreement does not authenticate a source, customer, evaluator,
consumer, payment provider or Hepta FinalUse issuer.

The authoritative development plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Inputs and version identity

[The business reader](../../scripts/cell_learning_business_join.py) takes the
original selection checkpoint, completed checkpoint, native use readback,
freeze and first-use expectations. Its separately pinned bindings document
contains one operation, one invocation identifier and one declared pair of
Chain/Hepta source commits and trees. Every material has its own original-byte
SHA-256, operation and source pair. Declared mismatches are refused.

The original completion reader replays the actual binary checkpoint and the
original owner bytes. There is no import path for a precomputed positive summary.
The request must contain the HEPLCP02 pre-frozen evaluation profile. Root outer
schema metadata cannot turn HEPLCP01 into HEPLCP02. The optional outer schema is
reported as `declared_root_envelope_schema`, with `root_envelope_verified=false`.

Even a consistent declared source pair is not authenticated execution provenance.
`source_execution_authenticated` remains false. In particular, the latest Root
scope work and the older real-model experiment cannot be combined merely because
their individual branch tests pass.

Selection exports the complete original trained candidate descriptor. NoUpdate
exports the complete original incumbent descriptor, including all component,
lineage and rollback bindings. This is not proof that independent providers
possess every byte or that a device loaded those bytes.

## Original native economic owner

[The economic reader](../../scripts/cell_learning_business_economics.py) consumes
the existing `pon-native-task-operation-current-v3` export from
[Node reconciliation](../../trillionnium/crates/trnm-pon-node/src/store/task_operation_v2/reconciliation.rs).
It does not introduce a second settlement ledger or payment implementation.

The reader checks the exact claim, task, operation, target scope/receipt,
original payer/provider, frozen contract terms, output, original delivery and
payment transactions, measurement unit/receipt and observed owner checkpoints.
It recomputes the existing native contract/task digests using the original
[funded-task encoding](../../trillionnium/crates/trnm-protocol/src/funded_service_task_v1.rs)
and [hash framing](../../trillionnium/crates/trnm-protocol/src/pon_wire.rs).
It does not reconstruct unexported V2 binding bytes or authenticate native
signatures, chain membership or the exporting process.

The accepted monetary profile is explicitly `funded-service-contract-dev-v1`;
its unit is `native-development-ledger-unit`. It is not independently sourced
customer money. Original historical and current payment observations are kept
separately and never added together. The native Task beneficiary credit is a
service-fee observation, not evidence of Sybil-resistant consensus credit.

| Category | Required independent evidence | What this reader authorizes |
| --- | --- | --- |
| Contract service fee | Original client contract, fulfilled service and original settlement owner | Nothing; correct NoUpdate does not force the contractual fee to zero |
| Improvement reward | Independent pre-frozen evaluation with complete cost and demonstrated useful improvement | Zero reward authority; NoUpdate is not eligible for a fabricated improvement reward |
| Consensus credit | The separate security relation covering all allowed work strategies | Zero credit authority; useful computation and a paid task do not supply that argument |

Unknown external amounts remain `null`. A reader-authorized amount of zero is
not an observation that no external transfer occurred. Native `Positive` or
`NoGain` service outcomes are not equated with model Selection or NoUpdate.

## Explicit funded request and result mapping

Two new application-level SHA-256 domains define an opt-in contract mapping:

- `trnm.cell.learning.business-request.v1\0` commits to canonical JSON containing
  the original learning operation, invocation, source pair, initial checkpoint
  head, source-task receipt, pre-frozen evaluation profile and incumbent bundle.
- `trnm.cell.learning.business-result.v1\0` commits to that request digest, the
  completed learning head, Selection/NoUpdate, selected complete bundle, next
  task/input, original committed-step receipt and cost-source digest.

Canonical JSON is ASCII, sorted by key, uses compact separators and rejects
non-finite values. These are new application mapping namespaces; no existing
signed native domain, stored schema, authority or owner is changed.

For a joined economic observation, the original contract `terms.request` must
already equal the request digest and the original native output must equal the
result digest. Both original contract and original output are separately pinned.
An unrelated valid native payment is refused. A historical contract that never
contained this mapping cannot be retrofitted by changing metadata.

The two retained research examples have no original funded mapping. Their
business bindings therefore contain `economics: []`. The mapping digests computed
now describe retrospective readback only, not an existing paid contract, a
pre-dispatch freeze or a real external payment.

## Missing observations, restart and reorganization

At most 16 ordered economic observation positions are accepted. Each populated
position contains a complete original paid-v3 export and independent expected
bindings. A `null` position means that no complete export is available. The
paid-v3 schema does not admit a partially paid or fabricated UNKNOWN record.

Across known positions the reader requires the original service/context/decision
to remain identical. Original declared costs, historical payment and historical
delivery anchor must remain unchanged. They are write-once M12 facts. Current
branch rows and current anchors may change under the original generation rules;
they are not confused with the retained historical facts.

The reconciliation epoch, sequence and anchor generation cannot decrease. Equal
sequence or generation cannot carry different corresponding state. The M12
capacity stays fixed, its sequence cannot decrease, and the same sequence has the
same checkpoint root. These comparisons do not prove a journal prefix or that
all owner and external-anchor snapshots cannot be jointly restored.

Known observations on either side of a missing position remain comparable, but
the gap remains explicitly unverified. When the latest position is missing,
current payment status is `UNKNOWN`; the earlier observation is retained without
being relabelled current. No observation authorizes duplicate service execution,
repayment or compensation. Complete failure/reorg recovery remains unqualified.

## Retained real-model records and test scope

The [retrospective bindings](../../evidence/cell-learning-business-readback-20261109/bindings/)
use the unchanged original materials under
`evidence/hepta-real-native-adoption-20261108/chain-reader/`:

| Original case | Actual historical Hepta code | Original Chain reader code | Original structural outcome |
| --- | --- | --- | --- |
| `adopt-v1` | `edf03ecb8a814a0f5e86b1d6a752aeac80b1a978` | `9129e65b3255439593e44a0ba39578f220c27087` | Selection, seven receipts, acknowledged next task |
| `no-update-v9` | Same Hepta source | Same original Chain source | NoUpdate, six receipts, acknowledged retained-model next task |

NoUpdate can skip the proposal stage after the original evaluator rejects the
candidate. Six original receipts are not padded to manufacture seven.
The original experiment's evaluation was exposed and not independently controlled.
The selected candidate's next answer was wrong. This change reruns readers only.

The unchanged original reader suites cover 64 named methods. New economics
controls use explicitly synthetic paid-schema samples and a fixed native Rust
digest vector. Business controls join the real archived learning bytes to
explicitly synthetic funding mappings for parser checks. They are not new
training, payment, reorg or independent-customer experiments.

Both new test commands run once in the existing repository-truth lane, with
omission, duplication, wrong-lane and failure-policy controls. The dedicated
readback workflow also executes these scoped checks and preserves command exits,
source identities and raw output. It does not replace any required gate or
qualify the whole native workspace.

## Remaining original-owner obligations

The report preserves unresolved requirements for authenticated same-version
execution; real client authorization, data rights and budget; original training
and all attempts; independent frozen evaluation and decision; complete custody
and cold retrieval; loaded bytes and current Hepta FinalUse; an independent
consumer's real next task; complete physical costs and original financial owners;
and failure/reorg/full-state recovery. Independent improvement reward and
consensus-cost qualification remain separate obligations.

All source-execution, independence, physical-installation, complete-cost,
settlement, FinalUse and production qualification flags remain false.
