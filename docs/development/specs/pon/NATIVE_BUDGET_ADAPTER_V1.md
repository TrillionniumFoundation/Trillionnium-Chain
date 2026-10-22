# Native owner resource budget adapter V1

Owner: M12. Namespace: `pon-native-owner-six-lane-budget-v1`. The implementation
is [native_budget.rs](../../../../trillionnium/crates/trnm-service-settlement/src/native_budget.rs).
It is separate from the portable one-asset, one-result, one-rollup settlement
store. Existing native transaction bytes, state rows, fee rules, issuance and
reward allocation are unchanged.

## Funding boundary

There is no `register_funding(amount)` entrypoint. Every new budget, claim and
external intent calls `NativeFundingOwnerV1::observe_funding`. The actual Node
implementation must obtain the current active block, generation, height, state
commitment and requested monetary row from one authenticated owner snapshot.
The adapter derives amounts, owner, payee, maturity, deadline and allocation
root from that row. An absent, expired, spent, incompatible or repinned source
refuses. Equal owner generations must identify exactly the same anchor; a new
generation may switch branches, including to a lower height.

The owner trait is a trusted local integration boundary. Arbitrary JSON rows or
an external implementation of that trait do not authenticate a native chain.
The adapter's unit tests use an explicitly synthetic owner to test accounting
counterexamples. Native integration must test the real Node reader and ordinary
escrow transactions separately. The permanent-account growth backend must read
its complete authenticated bounded working partition; a partial account witness
is not an old-format complete State root.

| Lane | Existing original funding | Separate resource cap |
| --- | --- | --- |
| Mining | One native `reward:` row, already issued by M06 | Verified work units, CPU ns |
| Contribution | Sponsor-debited `release:` escrow | Training CPU ns, parameter bytes |
| Evaluation | Explicit sponsor-debited `task:` escrow | Evaluation CPU ns, evaluated examples |
| Storage | Explicit sponsor-debited `task:` escrow | Retained bytes, retained byte-blocks |
| Repair | A distinct sponsor-debited `task:` escrow | CPU ns, downloaded bytes, uploaded bytes, attempts |
| Serving | Sponsor/consumer-debited `quota:` escrow | Inference CPU ns, output tokens |

Each source is pinned to one lane and an immutable contract identity. All budgets
under a source share its original observed funding ceiling. A source cannot be
renamed, reassigned from storage to repair or allocated afresh after a reorg.
Existing task settlement and reward maturation pay the whole obligation; this
adapter therefore requires both a budget and claim to reserve that whole original
amount. It does not invent fractional task or mining-reward payments. A reward
ID binds parent, height and miner while its amount also includes the block fees;
a sibling branch with different fees cannot authorize work under an old whole
amount. Release and quota claims retain
their ordinary native allocation and consumer-consent checks. A task already in
`receipt` status must bind its nonzero native `output` to the claim subject both
at reservation and before the first external intent. The native release claim
map is also rechecked before that intent, not merely at initial reservation.
A quota source ID commits its original units, parties, deadline and parameter
context; that context commits `quota_unit_price`. Remaining units and escrow are
dynamic native state, not replaceable local price assertions.

These resources are independently typed. Repair has its own monetary source,
attempt cap, byte caps, CPU cap and in-flight limit. Resource reservations and
known physical costs accumulate even for failed or orphaned work. An unknown
measurement charges the whole original reservation. A completed job cannot
change its recorded cost on retry. Resource numbers do not themselves prove a
GPU lease, allocated storage extent, packet transfer or model improvement; those
facts belong to the corresponding worker or storage owner.

## Actual payments and native cancellation

The adapter has no issuance, account-credit, transfer or refund API.
`record_native_payment` records an already executed ordinary native fact through
`observe_payment`; its default is the explicit refusal
`NATIVE_PAYMENT_PROOF_UNAVAILABLE`. The real owner must authenticate the exact
ordinary transaction or original reward maturation, its branch membership,
source, subject, beneficiary and gross/net amounts. The subject is the task
output, release contribution ID, quota result or original reward ID. A payment
operation is the exact ordinary transaction ID, or that original reward ID for
maturation. A decreasing escrow balance, an RPC ACK or an arbitrary supplied funding field is insufficient.

For native task settlement, release claims and mining maturity, the beneficiary
credit equals the gross escrow debit. A sender's separately debited fee is not
subtracted from that credit instruction. Quota use takes its native fee from the
gross quota cost, so its beneficiary credit is gross minus that actual fee;
a valid native zero-credit transfer when cost equals fee still records its
positive gross debit. The local journal preserves both amounts and binds each payment operation once.
It does not claim that an observed historical payment remains on the current
branch after a reorganization or has attained irreversible finality.

Local reservation does not change native escrow cancellation or expiry rights.
For example, a task owner may still cancel a native `reserved` task. New physical
effects therefore re-read the current funding row before intent creation. A
failed or unknown local job retains its monetary hold conservatively until the
original native source expires; an assertion of no gain cannot recreate funds.
Only existing native execution returns unused escrow to the original owner.
There is no atomic commit between this local database, a chain reorganization
and an external machine. Those facts remain separate and require reconciliation.

## Durable local ordering

Use a fresh database path. The SQLite application ID, exact schema, immutable
context/configuration and bounded chained event log are checked on reopen.
Each update uses one immediate transaction with synchronous durability; standalone
readers pin one read transaction across the metadata and event stream too. The
bounded journal allocates room for every permitted lifecycle transition of
every admitted budget and claim; exact replay appends no event.

Before physical dispatch, `begin_effect` durably binds the global operation ID,
lane, subject, claim, budget, beneficiary and effect identity. The original call
returns `New`. Time-scoped physical services use `begin_effect_in_window`: the
immutable `[from, until)` interval and native funding are validated against the
same owner snapshot before any intent is appended. The exact optional window
is retained in the intent and revalidated against its recorded anchor on reload.
A retry cannot add, remove or shorten that original window. An exact unfinished
retry returns `Pending`, which requires a
target-side check and grants no redispatch. A target receipt finishes the same
operation; exact completed retry returns `Done`. Conflicting operation reuse,
changed effect identity or changed receipt refuses without altering any index.
M09 retention and repair should bind their actual obligation IDs and materialized
readbacks to these subjects/effects; a disposable CellStore cache is insufficient.

Chain rollback never restores this database. Pending effects survive source
removal, expiry and restart, and unknown resource work keeps its original charge.
This is monotonic behavior with the retained local journal, not protection against
an operator restoring the entire database from an old copy. Node epoch fences,
target idempotency and independent crash/recovery qualification are still needed.

## Verification

Run `cargo test --locked -p trnm-service-settlement native_budget` from
`trillionnium`. Controls cover all six lanes, native source shape/type failures,
source and lane repinning, provider and task-output changes, already claimed
release subjects, indivisible native rewards, absent or spent sources, exact
resource types, independent repair caps, unknown cost, pending/completed replay
through reorg and restart, expiry, exact native-payment bindings, quota fee
separation including zero credit, stale owner generations, concurrent overspend
and coherent read snapshots, immutable effect windows and in-window source
cancellation, operation reuse,
foreign databases, corrupt journal entries and the exact fresh hash namespace.
Passing these controls is not a claim of independent evaluator quality,
public reward eligibility, physical backing or production activation.
