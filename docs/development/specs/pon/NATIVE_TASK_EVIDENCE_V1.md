# Native Task evidence and reconciliation V1

## Scope and authority

This development adapter exports evidence from the actual Node funding,
delivery-commitment and payment owners, together with the checked M12 resource
and operation journal. It records what those owners observed. It does not pay,
issue currency, dispatch an effect, accept a model, or install a release.

The native integration has two layers:

1. `trnm-service-settlement::native_budget::evidence` replays the existing M12
   journal into a sealed `NativeBudgetClaimEvidenceV1`. This does not add events
   or change the existing budget database schema. The export preserves the
   original Open, Reserve and Intent funding observations, policy, claim,
   outcome, resources, effect, receipt and historical payment.
2. `Node::reconcile_native_task_evidence_v1` re-reads those funding observations
   from the Node's own retained historical states, checks the complete contract
   when present, and replays the exact native payment transition. It then writes
   a bounded observation to the Node's metadata namespace.

An M12 owner callback is a trusted integration boundary. A caller can implement
that trait with arbitrary statements and still create a structurally valid M12
journal. Consequently, journal validity alone is never accepted as native
funding or payment proof. The Node adapter checks the actual native histories
before promoting any such statement to a verified native observation.

There is no JSON import endpoint for native evidence. JSON produced by `report`
or the history reader is an export, not a capability that can be supplied back
to the native owner. The sealed M12 and Node evidence objects have no public
constructors or deserializers.

For a TSC1 Task, V1 reconciliation also requires the actual Node's retained V1
protocol pin. The trusted V1 budget-owner funding callback creates that pin;
the ordinary public funding reader remains read-only. A generic callback that
quotes real funding facts does not acquire the Node's V1 authorization. A V2 pin
or a missing pin is refused when promoting TSC1 V1 operation evidence. This is a
local native-owner rule, not a claim that arbitrary M12 trait implementations
are unforgeable global capabilities.

## Evidence meanings

| Fact | Authoritative owner and check | Limit |
| --- | --- | --- |
| Escrow source | Actual historical `task:` row, block, root and height; exact M12 funding snapshot comparison | Does not prove that payer and provider are independently controlled |
| Contract | `funded_service_v1::read_contract` over the actual native row | Binds commitments; does not fetch or inspect all referenced business material |
| Delivery commitment | Actual provider receipt and native task output | Does not prove that output bytes were made available or met the specification |
| Payment | Exact transaction identity, executed M06 transition, receipt, escrow debit and beneficiary credit | Current membership is scoped to the observed branch and generation |
| Resources, outcome and completion | Retained checked M12 operation journal | These remain local operation-owner statements; export does not measure physical cost |
| Independent evaluation or model gain | No authority supplied by this adapter | Neither a successful payment nor `NoGain` is an evaluation certificate |

The report therefore keeps `physical_costs_verified`,
`independent_customer_verified`, `independent_evaluator_verified`,
`external_demand_verified`, `learning_bonus_authorized`, `execution_authority`
and `production_activation` false. A frozen contract's presence is reported as
`complete_contract_bound`, separately from actual delivery and actual payment.

`current_delivery_matches_claim` compares the actual current output commitment
with the M12 claim's output subject. It is not a check of output bytes or quality.
An absent historical payment in M12 is not proof that no transaction ever paid
the task. A negative current-branch payment observation concerns the exact
operation recorded by that claim, not every possible business payment.

## Public integration surface

The caller supplies a real opened `NativeBudgetStoreV1` and a
`NativeTaskEvidenceRequestV1` containing:

- `claim`: the retained M12 claim identity;
- `consumer_epoch`: a caller-controlled monotonic fence;
- `expected_contract_digest`: an optional exact expected full-contract digest.

The request contains no funding amount, payment receipt, task row, measured
resource value or evaluator verdict. Those values come from the real owners.
When an expected contract digest is present, absence or mismatch is a refusal.
Omitting the expectation does not erase a real contract: the adapter always
reads and pins the actual digest when one exists.

`NativeTaskEvidenceV1::report()` returns the native observation together with
the M12 display report. `sequence()` and `root()` identify the immutable retained
observation. Repeating an identical observation returns that same record;
these identifiers need not be the newest record for some other task.

`Node::native_task_evidence_history_v1()` checks the retained native history and
exports the records. It expressly reports `m12_current_journal_rechecked=false`:
the external M12 store is supplied only to reconciliation. A history read alone
cannot authorize reuse of an old journal or start a new effect.

## One Node namespace, one M12 journal history

The first successful observation pins the M12 configuration and a checked
sequence/root. Subsequent observations, including observations for another
task, must extend that same M12 journal history. This namespace is not a merger
of independent journal files. A different journal is acceptable only when it
contains the exact retained prefix and its valid continuation.

`claim_evidence_after_v1` checks the consumer's retained prefix and reads the
claim in one SQLite read transaction. A separate prefix preflight followed by
an unrelated snapshot would not establish this relation. The adapter checks the
exported prefix again before a replay response or metadata write. Concurrent
valid appends may extend that prefix; a rollback, substituted history or fork at
the retained sequence is refused.

The Node records bind each Task identity to the same M12 claim, budget, subject,
beneficiary, monetary reservation, immutable binding digest and contract digest.
A later epoch cannot assign that Task a different claim or beneficiary. Once a
historical payment is present, later observations cannot remove or replace it.

The adapter is not a transaction across two databases and is not a grant for
external execution. Its output is an observation of checked prefixes and native
anchors. The next reconciliation checks the retained fences again.

## Durable metadata and bounds

The new namespace is `pon-native-demand-evidence-v1`. Events use ordered
`event:` keys and a canonical head record. Each record binds its sequence,
previous root and canonical observation under
`pon-native-demand-evidence-record-v1`.

The fixed local limits are **128 records and 32 KiB per record**, across all
tasks and epochs in this namespace. An unchanged replay consumes no new record.
A changed observation or increased consumer epoch adds a record. At capacity,
the writer refuses the new observation; it does not silently drop, overwrite,
prune, roll over or reset history. Supporting larger retained histories or an
archive migration requires a separately specified owner and retention policy.

The reader bounds SQL key/value materialization before decoding, rejects
unexpected keys and types, checks canonical bytes, verifies the entire ordered
root chain and head, and checks immutable task bindings and monotonic progress.
The writer compares the complete prior record set in its write transaction and
checks exact event/head readback before commit. A missing or corrupt record is
an owner-stopping local-integrity failure, not an empty history.

`consumer_epoch` is a caller-supplied local fence. It is not a wall clock,
network epoch attestation, proof of restart, or proof of independent control.
It can increase but cannot decrease or erase an operation's prior identity.
Native anchor generations are separately checked against the actual Node.

Restoring an old M12 file while keeping the Node's newer fence fails. Restoring
both databases and every external fence together is outside this local
anti-rollback guarantee. Target-side global effect deduplication and external
anti-rollback witnesses remain responsibilities of their actual owners.

## Reorganization and historical payment replay

`native_payment_observation_at_anchor_v1` verifies the retained anchor's
network, parameters, genesis, block, root and height against the actual Node,
requires its generation not to exceed the current generation, and checks the
original durable activation events. The final attached block in that generation
must be the anchor's exact block; generation zero can identify only genesis.
A valid side branch that was never active cannot be relabeled as a historical
active funding or payment snapshot. The reader then runs the original bounded
ancestry scan and full native transition replay from that retained block. It
does not activate the historical branch or rewrite balances.

An orphaned but retained payment can therefore remain historically verified
while `payment_current_on_observed_branch` becomes false. Only the precise
`NativePaymentNotConfirmed` result is treated as absence of that exact payment
on the observed branch. Scan exhaustion, malformed history and other owner
failures propagate as errors; they are not downgraded to nonpayment.

The adapter checks current funding again after payment lookup so a negative
lookup cannot be attached to a different generation. Reopen validation replays
historical payments and both positive and negative recorded membership facts.
Resource charges, completion receipts and historical payment identities are not
rewound when current branch membership changes.

## Backend qualification boundary

The integration tests cover complete TSC1 contracts and TSD1 provider-payment
arbitration on the Legacy and Authenticated Node backends. A TSD1 refund is not a
provider payment. The full-contract development profile has its own network and
parameter context; its Growth and native-PQ combinations are explicitly refused
by their profile admission rules.

The ordinary pre-existing Task path is separately exercised on the permanent
account Growth backend. Such evidence reports `complete_contract_bound=false`.
Its metadata writer retains the cold-audited Growth owner, opens one Immediate
transaction, reads the checked bounded working state and permanent-account root
before and after the exact metadata writes, verifies unchanged active selection
and slot, and rechecks the owner epoch before and after commit. It does not pass
Growth state through the complete-State slot checker or enumerate all permanent
accounts.

## Known-output V1 and prospective training

The original M12 V1 claim fixes `subject` before effect intent. For a Task, that
subject must match the actual output when delivery is present. A known fixed
output in a development fixture does not establish admission of an unknown
training result before the work is performed. This V1 report therefore always
sets `prospective_training_admission=false`.

The separately namespaced [Native Task operation V2](NATIVE_TASK_OPERATION_V2.md)
authorizes a Task operation from the frozen output specification and binds the
actual output later through the real provider-receipt owner. It has a fresh
journal and claim domain, explicit pending/delivered states, native version and
once-begin fences, an immutable first-delivery pin, and a Node-retained M12
prefix floor. It does not repurpose V1's subject, convert JSON into delivery
authority, or interpret an owner resource statement as independent physical
metering. Qualification of that separate version does not change this V1
report's meaning.

## Executable checks

The Node target is `native_demand_evidence`:

- `complete_contract_real_arbitration_reconciles_after_restart_reorg_and_epoch`;
- `ordinary_growth_task_keeps_native_evidence_without_claiming_full_contract`.

The scenarios use real signed native reservations, provider receipts and
customer/arbitrator payments. They reject fabricated M12 funding and payment
owners, changed expected contracts, old consumer epochs, rolled-back journals,
forked journals and missing durable records. They check exact replays, native
historical payment retention, current-branch membership after reorganization,
and reopening across consumer epochs. Their controlled development keys and
resource/output fixtures are explicitly not external-customer evidence.

M12 unit checks additionally cover immutable binding versus changing evidence
digests, exact prefix acceptance and refusal, funding-snapshot mismatch, and
live journal corruption after a previous successful export:

- `evidence_snapshot_preserves_binding_and_checks_exact_prefix`;
- `evidence_export_rechecks_live_journal_instead_of_trusting_a_cached_report`.

Run the normal locked Cargo test profiles with the required qualified native
toolchain environment. Do not relax the SQLite qualification owner or change
optimization/debug settings to make a failing gate appear passed. The retained
test results and exact source identity are recorded in the sole development
plan and its acceptance evidence.
