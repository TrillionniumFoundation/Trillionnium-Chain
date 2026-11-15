# Funded service task contract v1

## Status and ownership

`funded-service-contract-dev-v1` is an explicit classical development context.
It extends the actual native Task owner in M06, with durable execution and payment
readback through Node. Selecting it changes both network and parameters before
genesis and task bootstrap. It does not activate an existing network, authorize a
production migration, or add a monetary ledger.

The original Task escrow, account balances, transaction fees, issuance checks,
mandatory expiry, canonical replay, and branch selection remain the owners of
money. The extension only makes the task terms and settlement authority explicit.
Existing profiles reject the new payloads. Existing PQ account profiles retain
their original grammar; this extension requires a separately designed PQ migration
before it can be used there. The initial development integration supports the
ordinary and authenticated state backends; permanent account growth is not a
selected combination for this profile.

## Frozen terms and real output

A payer signs a native tag 2 reservation containing these ten 32-byte commitments:

| Field | Frozen meaning |
| --- | --- |
| `request` | The commissioned request and its scope |
| `provider` | The native account that may submit the result and receive the fee |
| `model` | The selected model identity |
| `input` | The selected input identity |
| `output_spec` | The required output format and acceptance specification |
| `qualified_work` | A committed reference to the agreed work qualification material |
| `evaluation_protocol` | The evaluation rules agreed before the result |
| `fee_schedule` | The service pricing terms |
| `dispute_policy` | The agreed dispute rules and evidence requirements |
| `arbitrator` | The native account allowed to issue a binding disposition |

The exact native escrow amount, inclusive delivery deadline, and exclusive final
dispute deadline follow as three little-endian u64 integers. All commitments are
nonzero, the amount is positive, and delivery precedes final expiry. The original
native maximum lifetime and pending-task/expiry capacity limits also apply.

These are commitments to frozen materials. The chain does not infer business
usefulness from a hash, verify the off-chain contents without their appropriate
owner, or certify that the payer and provider are independently controlled.
In particular, `qualified_work` is not a lookup or membership proof in the native
qualified-task registry. An arbitrary nonzero reference can be committed; it
cannot be reported as an admitted qualified computation. This version enforces
the commissioned contract and its monetary owner, not a new computational
qualification rule. The existing matrix qualification owner remains separate.
The frozen arbitrator cannot use the payer's or provider's exact account key.
Different keys alone are not evidence of independent control.

The output digest is deliberately absent from reservation. A later tag 4 receipt
from the original provider binds the actual nonzero output digest and receipt
height, and the actual `task:` row retains both. Changing the model, input,
specification, evaluator protocol, price, arbitrator or deadlines changes the
contract digest and task instance.

M12's existing V1 `begin_effect` interface requires its output subject in advance
and keeps that published meaning. The separate
[native Task operation v2](NATIVE_TASK_OPERATION_V2.md) now records a prospective
unknown-output operation, pins V1/V2 ownership in the actual Node, and binds the
actual provider receipt after completion. It has a fresh journal namespace and a
one-time Node begin marker. The physical target still owns its execution grant,
receipt validation and final dispatch deduplication; this local protocol does not
certify independent physical metering or a global target permission.

## Exact wire and namespace

| Native tag | Selected payload | Bytes |
| --- | --- | ---: |
| 2 | `TSC1`, task id, ten commitments, amount, delivery deadline, dispute deadline | 380 |
| 3 | Original task id; a non-delivery refund request from its payer | 32 |
| 4 | Original task id and actual output digest | 64 |
| 5 | Original task id and output digest; ordinary payer acceptance | 64 |
| 5 | `TSD1`, task id, contract digest, output digest, evidence digest, verdict | 133 |

`TSD1` verdict 1 pays the original provider; verdict 2 refunds the original payer.
Other values, trailing bytes, zero evidence, and zero output for a pay verdict are
rejected. This version has no partial amount or arbitrary-recipient field.
An arbitration refund uses a zero output digest only when no provider receipt
exists. After delivery, every disposition must match the actual receipt digest.
All payload bytes are covered by the ordinary authenticated native envelope.

The contract digest uses the fresh `funded-service-contract-v1` domain over
network, parameters, payer and the exact ordered terms bytes. The task instance
uses the fresh `funded-service-task-instance-v1` domain over network, parameters,
payer, native reservation nonce and contract digest. Exact hash and wire vectors
are retained with the protocol tests.

The native task row contains a new `service_contract_v1` object with schema
`funded-service-task-record-v1`. It retains complete terms and context, payer,
reservation nonce, contract digest, reservation height, optional actual output and
receipt height, and optional resolution. Its typed reader also checks agreement
with the original native owner, provider, remaining escrow, deadline, status and
output fields. Parsing caller-supplied JSON does not establish native provenance;
an evidence consumer must read through the actual Node state owner.

## Ordering, dispute execution and refunds

1. **Reserve:** the payer funds the complete original escrow. The selected profile
   refuses the old unbound 80-byte reservation. A reservation must precede delivery
   deadline; no provider payment occurs at reservation.
2. **Deliver:** only the frozen provider may submit the output, through delivery
   deadline inclusive. Only the first receipt is accepted.
3. **Accept:** after delivery and before final expiry, the payer can accept the
   exact output. The original native escrow credits the complete amount to the
   original provider once.
4. **Arbitrate:** the frozen arbitrator signs the actual contract digest, output,
   evidence and verdict. It may pay only after a provider receipt. It may refund
   after receipt, or after missed delivery when no receipt exists. It cannot
   cancel a still timely undelivered task before the provider's deadline.
5. **Non-delivery refund:** after delivery deadline, the payer may use tag 3 only
   if no receipt exists. It credits the original payer from the same escrow.
6. **Unresolved final expiry:** at the exclusive dispute deadline, the original
   mandatory expiry owner returns unresolved escrow to the payer. Neither payer
   acceptance nor arbitration can race this mandatory transition at that height.

Successful customer acceptance and arbitration pay use status `settled`.
Arbitration refund and non-delivery refund use status `refunded` and distinct
resolution kinds. All set the original remaining escrow to zero. A second
resolution, customer acceptance after arbitration, or arbitration after customer
acceptance fails even with a new account nonce. Conflicting transactions in the
same block use the same canonical MVCC owner and cannot both spend the escrow.

Final expiry uses the original `expired` status and leaves resolution absent.
If the provider already delivered, its actual output remains in that record.
Returning the deposit without a decision does not establish that the service had
no value, that the provider was paid, or that every off-chain debt is extinguished.
The distinction between a monetary refund and an adjudication remains visible.

## Restart, reorganization and evidence

All contract and disposition data live in the actual canonical native Task row.
The existing authenticated roots, durable storage and branch replay therefore
apply to them. There is no external dict that can authorize a payment.

The payment observer reexecutes the exact accepted native transaction and checks
the admitted header. A frozen arbitrator's pay verdict is recognized as provider
payment; a refund is never converted into provider service revenue by changing
the queried recipient. A branch change can remove current payment membership and
restore an unpaid task. It cannot retroactively erase local work already done;
the separate evidence journal must retain historical observations and local
operation identity when reconciling the new branch.

Targeted tests exercise real signatures, monetary execution, strict profile and
PQ grammar rejection, exact term binding, delivery/cancellation boundaries,
customer acceptance, unauthorized arbitration, conflicting resolutions, refunds,
expiry, and real Node reopen/reorg/payment readback. Their public development keys,
output digests and evidence digests are test fixtures. They do not establish real
customer independence, prospective physical cost measurement, evaluation quality,
product adoption, model improvement, or production qualification.
