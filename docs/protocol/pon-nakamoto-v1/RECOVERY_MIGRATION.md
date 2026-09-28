# PoN reorganization, external effects and PoCO retirement

Status: development contract; no live database conversion or activation is performed.
Owners M07/M08/M13/M15. M03 guards local authority; M05/M10-M12/M14 are consumers.

## R1. Two histories with different rollback laws

The active chain is reorganizable. Account state, tasks, adopted release pointers,
reward maturities and branch-derived replay/nullifier state follow the active branch.
The local operation journal, effect-entry facts, external provider receipts, local
revocation frontier and independent anti-rollback anchor are NOT rewound with it.

This is the major change from the old append-only finalized-ancestor application
assumption. Node Commit Ledger and PinnedSqliteNamespace ideas remain useful, but
existing PoCO finality stores cannot be renamed into PoN undo stores. Introduce a new
versioned branch/undo schema and prove its crash behavior before ordinary operation.

## R2. Reorg transaction

M02 issues a context-bound preferred-branch decision after full validation. M08 plans
fork_point, old/new tip, source generation, ordered detach list (tip-to-fork), attach
list (fork-to-tip), all roots and bounded resource requirements. Before mutation it
persists ReorgIntent. M07 stages reversible deltas/undo under one writer. M06 reexecutes
new branch effects and checks exact roots. M08 atomically publishes the new active head,
index/reward generation and reorg event only after verified readback. M14 consumes an
idempotent remove/add event sequence; caches and confirmation receipts become stale.

Crash cuts at intent, detach, attach, root publication, index acknowledgement and outbox
publication recover the same transition, not an arbitrary convenient tip. The old/new
intermediate state is not exposed as one coherent RPC snapshot. Insufficient undo
history requires authenticated replay/state sync; it is not permission to reject a
valid heavier chain forever or turn a local prune depth into consensus finality.

## R3. External task effects

Included and confirmed leases remain subject to reorg. Before an irreversible call,
Hepta verifies current inclusion/confirmation, exact task/lease/attempt, local authority,
payload and generation, then records independent durable effect entry and consumes the
local final-use capability. Final-use tokens never cross the chain as bearer proofs.

After reorg, a prior execution fact is retained as an orphaned authorization/economic
obligation for reconciliation. Stop new effects, inspect the same remote operation and
settle/compensate under an explicitly accepted policy; never execute it again because
the chain nonce disappeared. A compensation is a newly authorized action, not a rewind
of the world. Confirmation depth cannot guarantee zero exposure. For risks that cannot
be compensated or collateralized, the consumer must refuse this probabilistic settlement
profile rather than claim BFT finality. Even local-only revocations cannot roll backward.

## R4. Model release reorg

Reorg can remove a GlobalModelRelease pointer or contribution entitlement. A host that
already used the release retains which parameters produced each recorded decision.
It does not rewrite historical outputs with a different model. Pause new adoption/use
as required, quarantine problematic artifacts and create a new admitted local generation
when switching. Active tasks drain/reconcile; old grants do not revive. Public bytes
already downloaded cannot be recalled cryptographically by deleting a chain row.

## R5. Historical proof boundary

Old consensus source, protocol trees, QC/TC/finality decoders and signer journals are
absent from the active tree. Git alone retains their history. A future historical export
requires an explicitly isolated version-bound utility. No historical signature or proof
is currently accepted as PoN work or implicit new-chain authority.

## R6. Initial migration is a fresh instance

Retire PoCO as development direction now; retire an actual old deployment only after
its operator-controlled drain/export. Stop new legacy admission, reconcile incomplete
external effects and task liabilities, export balances/escrow/replay floors/profiles/
retention/model lineage, classify proof strength and independently check conservation.
Create a new chain id, genesis, PoN parameters, fresh authority/storage namespace and
keys. Stage all imported obligations, reopen and verify before network entry.

A legacy snapshot accepted by explicit import governance is a trusted allocation input,
not proof that old history was secured by PoN. Old and new assets are not automatically
bridged or protected against spending on two independent networks. Either retire/lock
old claims under its accepted policy or make the distinct asset/instance semantics clear.
No same-path WAL rewrite, reset of vote/nonce history or reinterpretation of an old
signature is allowed. After new effects escape, recovery preserves that identity;
restoring a pre-migration image is not safe rollback.

## R7. Current source and required tests

The portability inventory binds every retained package and concise source dispositions.
No old active consensus dependency remains. Retained CAS, strict crypto, bounded worker
control, escrow conservation and serial/parallel execution are candidates only. Local
application stores need a new branch/undo adapter, not renamed monotonic finality.

Future tests must cover shorter-higher-work chains, deep reorg across maturity/model
adoption/nonce reuse, every crash cut, orphaned external effects, wrong-genesis import,
omitted escrow/retention and rejection of historical proof substitution.

## Executed reference storage protocol

[S1](details/STATE_RECOVERY.md) now gives exact tables, owner locks, before/after values,
shadow generations, publication transaction and eight actual child-process crash cuts.
The Python ledger is an executable design oracle; existing native local task stores are
not claimed to have become a qualified native chain/reorganization implementation.
