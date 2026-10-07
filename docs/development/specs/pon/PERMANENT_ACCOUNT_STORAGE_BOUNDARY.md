# Permanent accounts, available witnesses, and bounded validation

Status: implementation decision for continuation; not an installed consensus
profile, a migration authorization, or public-service acceptance evidence.
Source baseline: `c4f7f04e7a814952a438fc343ad92a5cf4885f4f`.

## Decision

Continue the existing authenticated account archive and original-parent witness
execution. Separate permanent account history from a bounded validator working
set. Do not delete zero-balance accounts, reset nonces, raise the existing global
key limit silently, or treat an archive experiment as native ledger admission.
The existing complete-state path remains the comparison implementation throughout
this change.

There are three independent resource contracts:

1. Consensus preserves each account's existence, balance, and nonce, with a
   checked permanent-account count and monetary aggregates.
2. Each block has bounded touched-account proofs and complete mandatory-action
   coverage. Non-account working state and obligations retain explicit bounds.
3. Actual archive bytes, historical roots, retrieval capacity, and recovery have
   an operator-owned storage budget and availability responsibility.

A compact commitment is not possession of the committed data. A storage budget
is not an execution proof. Passing one of these contracts cannot imply either of
the others. Sustained growth requires sustained provision of storage; the design
does not promise infinitely many accounts under a fixed physical storage budget.

## Why the existing backend alone does not remove the bound

`store/native_authenticated.rs` verifies the complete state and account tree,
compares actual deltas with the complete before/after difference, and checks the
retained history. Its integrated account archive changes storage representation,
not the full-state consensus limit or the need to reconstruct complete State.

`account_archive_execution/state_witness.rs` already binds account root, count,
balance, non-account root/count, escrow, rewards, and issued supply to the actual
parent. Its private bound state still requires the complete native parent. The
existing commitment's `state_root` is therefore not a new independently activated
split-state consensus root. Removing the full-parent check while keeping the old
root interpretation would not implement this decision.

## Protocol transition boundary

A separately identified consensus revision is required before native admission
can use a bounded account witness instead of reconstructing every account.
It must bind the new state-root relation into the existing header's parameters
and challenge. Old profiles, signature domains, genesis identities, storage
namespaces, and historical validation remain unchanged.

The proposed relation authenticates the account tree and its global aggregates,
plus the complete bounded non-account partition and its monetary liabilities.
Its encoding and domain must be versioned explicitly. Global totals come from the
verified parent commitment and exact checked deltas, never from summing only the
accounts supplied by a caller. Any conversion to a new commitment verifies every
source account, nonce, balance, non-account record, and retained branch against
its original source root before atomic destination publication.

Use the existing AAM1 compact query/update relation and original-parent witnesses
where their checks apply; do not reinterpret AAW1, AAM1, or the v1 checked-state
record as a new consensus certificate. Missing or extra proof nodes, nonmaximal
frontiers, wrong roots, noncanonical counts, account deletion, nonce regression,
and overflow remain rejection conditions. Preserve absent data, authenticated
nonmembership, and a present zero-balance account as different states.

For execution, obtain the complete mandatory recipient set before authorizing
user transactions. It includes maturity, funded expiry/refunds, release and quota
obligations, and the miner where applicable. Existing monetary range checks must
cover all due/future/zero-valued rows required by their relation; a valid subset
membership proof does not establish range completeness. Shared original-parent
proofs merge once, and both mandatory and successor transitions are checked in
canonical order. No partial result gains admission authority.

The old 65,536-key profile remains old. A new growth profile must distinguish its
permanent-account count from its bounded working-key count; changing a label or
moving rows to SQLite without changing and proving this relation is insufficient.
The new count and monetary fields require explicit finite numeric limits and
checked overflow behavior, not an implicit claim of mathematical infinity.

## Witness and storage responsibility

The producer supplies the block's complete required witness with its exact parent
and context. A validator may retrieve bytes from an archive, but authenticates
them against that parent before use. An archive provider supplies and retains
bytes; it does not select the chain, authorize a transaction, certify model value,
or manufacture authenticated absence.

Before acknowledging an obligation-bearing state transition, the responsible
storage owner reserves the bounded mandatory successor writes and the required
retained roots in the same durable ownership model as ordinary writes. Optional
admission is backpressured before it can consume those reservations. A full local
archive must not erase nonce history or retroactively revoke already accepted
maturity/refund duties. Disk-full after partial writes must roll back every
uncommitted component and retain the original recoverable state.

Witness retrieval is an explicit operation with context, parent root, ordered
query, byte bound, absolute deadline, and a declared retention endpoint. Retrying
must keep that original identity and deadline. A timeout or unavailable provider
is data unavailability, not authenticated nonmembership and not proof that an
otherwise valid block is consensus-invalid. Bad authentication and corrupted
local structure remain distinct from transient unavailability.

Retention covers roots still needed by active/inactive retained branches,
mandatory obligations, pending reorganization, recovery anchors, and any explicit
operator hold. Archive garbage collection requires authenticated reachability
and a separately justified retirement decision. Confirmation depth alone must
not be relabeled as an irreversible external fact. An expired storage payment or
lease cannot turn an existing account into a new account with nonce zero.

Recovery uses one consistent storage snapshot and rechecks root, count, monetary
aggregates, namespace, and branch selection before service. Missing required
nodes stop availability claims. Exact authenticated repair may restore service;
recovery must not synthesize missing records. Budget or history uncertainty does
not refund consumed resources on restart.

## Measurement before hot-path replacement

Instrument the existing operation boundaries, retaining one enclosing operation
interval and nested stage intervals rather than adding them twice. Measure
parent acquisition/reconstruction, non-account scan, history seals, account proof
collection/verification, complete reference-root construction, M06 execution,
delta publication, final integrity fences, commit, and recovery separately.
Measure owner-lock wait and SQLite wait as wall time; do not charge them as CPU.
Account for every actual scoped worker and join before reporting aggregate CPU.
Unavailable clocks and unfinished operations remain unknown, not zero.

In particular, `native_authenticated::publish` currently verifies the parent,
publishes and verifies the child, and traverses retained history. A measurement
must distinguish those passes and their final-write protection before attempting
to reuse a result. A progress callback, intervening writer, or trigger can make
apparently redundant reads an integrity boundary. Do not remove the final fence
based only on repeated function names or a microbenchmark.

A semantics-preserving optimization requires complete byte/root/receipt parity,
the same first error and cancellation behavior, atomic rollback, and real
operation measurements at increasing state and history sizes. A count of hashes,
SQL statements, or logical payload bytes alone is not end-to-end cost evidence.

## Required native acceptance

The growth revision is not accepted until actual signed native transitions cross
65,536 permanent accounts while the declared working-state/witness budgets stay
within bounds. A synthetic archive with 65,537 leaves does not satisfy that test.
Exercise zero balance, nonce reuse refusal, later re-entry, different branches,
mandatory reward/expiry/refund at the boundary, cleanup followed by new admission,
pending reorganization, abrupt process loss, and cold recovery. Compare complete
small-state execution and independently reconstruct the resulting commitments.

Availability acceptance additionally needs actual provider loss, truncated or
stale/wrong-parent witnesses, full storage, retrieval deadlines, retained-root
repair, and operator handoff without losing acknowledged obligations. Record the
real storage owner, paid/available retention, required bytes, requested and
completed retrievals, rejected/unknown outcomes, and oldest unresolved duty.
Declare the tested availability assumptions and resource limits explicitly.

Independent long-duration WAN service and future-sample model efficacy are
separate campaigns. Neither the above native tests, a source-bound CI pass, nor a
storage-provider signature supplies those results. Existing model source,
evaluation, challenge, and reward admission rules remain in force.

## Current delivery boundary

The current stacked growth increment now adds two research-only pieces without
changing the installed profile:

1. `AccountArchive::aggregate_observation` recomputes permanent-account root,
   count and balance from every authenticated retained leaf and binds the archive
   network/parameters/genesis context. Raw aggregate claims are not accepted.
2. `GrowthStateCommitmentV2` binds that verified permanent-account aggregate to
   the complete bounded non-account working partition, explicit finite account
   and working-key ceilings, and checked monetary conservation under a new hash
   domain.

The ordinary regression checks context, partition and conservation. A separate
release-only test constructs 65,537 retained permanent accounts and the v2
relation while keeping the working partition bounded. That test is deliberately
not native ledger admission: it does not install new header parameters, migrate
an existing Node, submit signed transactions above the old cap, reserve a real
storage service, or change the old 65,536-key profile.

The next activation increment must therefore use this relation from an explicitly
new profile and migration namespace, then satisfy the native acceptance and
availability campaigns above. An archive-only or synthetic relation still cannot
be reported as closure of permanent-account growth.
