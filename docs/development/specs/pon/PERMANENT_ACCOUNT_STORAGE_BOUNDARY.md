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

## Candidate profile identity after the v2 relation

The executable v2 relation is still not a native ledger profile.  Before any migration
or signed admission can select it, the implementation must have a distinct parameter,
genesis and storage identity.  The current research owner now exposes
`growth_profile_binding_v2` for that anti-aliasing step.

The binding consumes an already verified `GrowthStateCommitmentV2`, the exact source
development context and a bounded non-traversing storage namespace.  It derives a fresh
candidate parameter digest, candidate genesis digest and namespace digest.  Changing the
namespace changes the complete binding; a forged commitment id, cross-context relation or
path-like alias such as `..` is refused.

This value has **no activation authority**.  It does not mutate `Settings`, does not
change the legacy header `state_root`, does not open/migrate a database and does not
permit a 65,537th native ledger key.  The remaining activation work is therefore concrete:
install the new commitment in a separately versioned profile, migrate one actual source
Node into its own namespace, execute signed transactions across the old cap with complete
mandatory witnesses/ranges, reserve real storage and demonstrate full-disk/provider-loss/
process-loss/cold-recovery behavior.

## PN2 implementation work order and interfaces

This is the storage delivery for I03–I05 in the
[sole plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md), amended
against PR #323 source `9bd8b20da68f0dc199aab78c27644ed004af7411`.
The following contracts remain targets until implemented and source-bound.
Neither the existing authenticated backend nor the research v2 relation has
completed the native growth gate.

| Step / owners | Deliverable | Acceptance before the next step |
| --- | --- | --- |
| 1 / M07/M15/M17 | Enclosing-operation timing and counters for full parent/state encoding, account graph, history, proof/range collection, execution, lock/SQL wait, commit, client import and recovery | Reproduce the original failure with nested costs charged once; missing worker CPU stays unknown. Keep the current source's actual root/SQL/final reorg fences. |
| 2 / M00/M01/M06 | Explicit growth-profile dispatch, commitment encoding, finite limits, independent byte/arithmetic vectors and old/new rejection matrix | Parameter/genesis/namespace anti-aliasing and header/challenge binding; old profiles retain byte/root/error parity and the 65,536 total-key cap. |
| 3 / M06/M07/M09 | Original-parent account multiproof plus complete bounded non-account/mandatory range input | Reject wrong parent/context, omitted/extra/noncanonical witnesses, counterfeit absence, stale aggregates, overflow and incomplete mandatory coverage; independent small-state execution agrees. |
| 4 / M07/M08 | One atomic publication of block/deltas, COW roots/nodes, aggregate changes, root references, reservations and branch/active generation | Fault injection at every persistence cut leaves the complete old state or recoverable complete new intent; no orphan partial acknowledgement or local-effect rewind. |
| 5 / M09/M13 | Reserved retention, authenticated retrieval/repair, source-preserving migration and cold recovery | Exact provider loss/full-disk/GC/deep-fork schedules preserve nonce history and acknowledged duties. Missing bytes stop availability, never synthesize a record. |
| 6 / M05/M06/M07/M15/M17 | Real signed ordinary-Node workload beyond the old cap, plus scaling and fault reports | More than 65,536 permanent accounts actually admitted under the new context; fixed touched-account and working-state bounds, independent root/conservation readback, all failure cohorts retained. |

I03's parent commitment contains profile/context, account root/count/balance,
complete bounded non-account root/count, issued supply and every monetary
liability aggregate required by the profile. I04's block witness identifies the
exact original parent and canonical ordered account query/update set; mandatory
actions are collected before optional transactions. The verified result contains
child commitment, exact reversible delta, required retained roots and storage
reservation changes. Construct it privately only after authentication,
completeness and conservation, not from caller-supplied summary fields.

The profile must freeze finite numeric ceilings for permanent accounts, working
keys, all touched accounts, mandatory rows, account/range witness bytes, complete
block bytes and sync-page bytes. These are proposed parameter responsibilities,
not existing `Settings` field names. Validate at genesis and at every admission.
The complete packet includes transactions, header, the 49,188-byte W1 proof and
all required witnesses; a compact account proof does not excuse overflow of
the complete packet budget. Expiry/maturity scheduling reserves the maximum
future mandatory fanout and writes before accepting the originating obligation.
Optional load cannot consume those reservations. If the maximum due set would
exceed a block's execution/proof budget, reject the originating optional admission
under an explicit rule rather than later omit refunds or postpone them silently.

At fixed touched-account count W, target O(W log A + bounded non-account/range
input) validation for A permanent accounts. Increasing retained history must not
add a complete history walk to each new block, Head request or confirmation.
Persist verified root/context/generation and authenticated branch indexes;
check every accessed path/page against its pinned root and retain transactional
publication/readback fences. Cold integrity audit and verified replay remain
explicit operations. State the changed storage trust/detection model: a hot
path proof checks accessed data, not immediate detection of every untouched
corrupt disk byte. Do not claim the old backend's full-database check has merely
become cheaper while deleting it. New-profile tests must cover corruption of
accessed and untouched nodes, delayed detection, fail-stop recovery and repair;
old-profile checks are unchanged.

I05's reservation identifies required roots/obligations, reserved and actually
used bytes, storage owner, retention/renewal endpoint, deadline, funding and
release conditions. Keep the state archive and disposable Cell cache in distinct
namespaces and eviction classes. Reserve disk/WAL/headroom before acknowledgement,
backpressure optional intake, and settle failures without refunding resources
already consumed. GC is an authenticated reachability operation across active
and retained inactive branches, undo/recovery anchors, pending duties and holds.
Recovery or verified backfill must support a valid deep fork outside local undo;
retention or an operator checkpoint does not create consensus finality.

Freeze a scaling matrix with the old boundary, actual signed admission of at
least 65,537 permanent accounts, and a larger preregistered target. At each A,
vary W, working keys, proof sizes and retained history separately; report actual
CPU/wall/RSS, disk/WAL, read/write amplification, confirmation and cold-sync cost.
Pass requires declared bounds and fixed-W growth behavior, not just a faster
single sample. Include present-zero versus absent versus unavailable, stale
nonces/re-entry, mandatory miner/refund/reward recipients, expiry/cleanup,
reorg after pruning, reservation exhaustion, provider failure, process cuts and
cold reopen. Keep physical power-loss qualification separate from process loss.

Migration is explicit and source-preserving: verify all source accounts,
balances/nonces, non-account records, retained branches and local obligation
identities; create an isolated destination; independently recompute aggregates;
read back roots and recovery references; then publish through the existing owner.
Abort leaves the source usable and the incomplete destination unselected.
Local revocation/effect history is carried as monotonic facts, not imported as
rewindable branch state. Production migration still requires PN6 authorization.

## Verified v2 relation interface

The candidate-binding input now distinguishes a serializable
`GrowthStateCommitmentV2` observation from a private
`VerifiedGrowthStateCommitmentV2` capability. The public archive relation obtains
the latter only from authenticated account bytes and the complete bounded
working partition; the internal migration/reference relation obtains it from
the complete actual source State. Candidate binding and retained-binding
verification accept only this capability. A JSON observation with a recomputed
digest cannot enter either API, and the read-only projection cannot replace a
verified root. Serialization retains the exact existing observation grammar and
all commitment/profile hash domains.

This closes an interface-hardening subitem, not native growth acceptance. The
old API could bind a caller-constructed self-consistent observation as a
candidate identity; it already granted no admission or activation, and the
actual Node migration owner independently reconstructed its source relation.
The private type makes that provenance requirement executable before a future
profile owner is connected. Compile-fail controls cover raw-observation binding,
deserialization and mutation; a separately encoded digest vector and the real
archive/reference comparison check that the byte relation is unchanged.

No installed profile selects the v2 state root, and no 65,537th native key is
admitted by this increment. Signed growth, atomic migration, complete mandatory
witnesses, storage sufficiency, fault recovery and independent availability
remain the required PN2 acceptance above.


## Native complete-State growth reference, revision 17

The explicitly selected development task profile
`consensus-maintenance-growth-reference-dev-v2` is a native reference increment.
It keeps the ordinary Node, W1 validation, cumulative-work fork choice, single
SQLite writer, branch deltas, monotonic local facts and recovery machinery. Its
GSC2 state relation separates at most 1,000,000 permanent accounts from at most
65,536 non-account working rows. Future missing mandatory recipients reserve
permanent-account capacity; evaluation archives and the unfilled mining-reward
queue reserve working capacity. Every balance and nonce, including a present
zero-balance account, remains committed. Monetary conservation is checked from
all actual account, escrow and reward rows.

GSC2 is exactly 196 bytes: four magic bytes; network, parameters and account
root; account count, account balance and permanent-account ceiling; working
root; working count, working ceiling, escrow balance, reward balance and issued
supply. Hashes occupy 32 bytes and all counts/amounts use little-endian u64.
`H("native-permanent-account-state-v2", GSC2)` is a fresh native root domain.
It reuses the existing account-archive sparse key/leaf/branch relation and the
old root grammar for the complete bounded working partition. This is not the
research observation's commitment id: that observation includes genesis, which
cannot be used to recursively construct its own new genesis state root. The
native network and parameters are frozen first, genesis commits the initial
GSC2 root, and subsequent headers bind the genesis ancestry and selected
parameters into W1's challenge. The old state-root function and every historical
profile retain their original bytes, errors and 65,536-total-key ceiling.

The new development context has a separate chain label, parameter digest,
genesis and `native-growth-reference-branch-schema-v2` namespace identity.
`config/pon/growth-reference-v2.json` freezes revision 17, the two finite
capacity dimensions, the root/schema domains and the unqualified acceptance
flags. Its canonical JSON hash under `native-growth-reference-policy-v2` is
included in the parameters and checked when the native root is constructed.
Header checks, preparation, admission, actual SQL reads, snapshots, reorganization,
final publication, stats and cold reopen all select the same root relation.
Complete actual State is checked against the owner's stored parent root before
M06 execution; a caller-provided commitment or serialized observation is not
accepted as that parent. Legacy tree capabilities are not reinterpreted, and
legacy optional root caches return no snapshot for this profile. This reference
retains full scans and complete-State root reconstruction: it has not met the
bounded-witness hot-path objective.

Every admitted reference block receives a complete canonical snapshot under the
existing 64-retained-snapshot policy plus the genesis anchor. Snapshots remain
comparison material, with exact deltas and final transactional readback fences;
pruned/inactive paths still replay retained deltas. This changes the new context's
storage cadence, not historical contexts or consensus finality.

Authenticated-v1 storage, operator-owned task/mining/continuous modes, the legacy
M05 prefix pool, legacy ExecutionSession, the research public reader and the old
single-total-key capacity observation explicitly refuse this profile where their
legacy-root contracts do not apply. `growth_reference_observation` instead reads
and checks the actual active State, root, tip and generation, reports separate
permanent/working obligations, and retains `complete_state_required=true`,
`bounded_witness_qualified=false` and `production_activation=false`.

Fresh development namespaces are supported by this increment. Cross-profile
live migration remains unimplemented: old signed work/evaluation records and
acknowledged obligations cannot be relabeled under new network parameters, and
the old authenticated migration entry refuses the reference profile. A future
source-preserving migration must explicitly account for those facts rather than
copy rows and claim authorization.

Native tests cover signed transfers, zero-balance nonce retention and re-entry,
old/new namespace rejection, unsupported-backend refusal before creation,
reorganization interruption/cold recovery, independent account-root readback and
corruption refusal. The separately selected release gate starts at the ordinary
four-account genesis and submits genuinely signed transfers until the active
native ledger has 65,537 permanent accounts, then cold reopens it. No synthetic
archive, preallocated account genesis or mathematical vector substitutes for
that execution. Until the actual selected run finishes, this is an implemented
acceptance selector, not a passed native-growth campaign. Even a successful run
leaves bounded witnesses, source-preserving migration, storage sufficiency,
provider/full-disk/physical-loss coverage and independent WAN acceptance open.

The required release gate can retain its original SQLite store and `native.json`
by selecting an absent absolute `TRNM_NATIVE_GROWTH_EXPORT_DIRECTORY`. The
independent Python current-state reader checks actual SQL schema objects against
the selected literal DDL, canonical actual KV bytes, both complete sparse roots,
monetary conservation, GSC2 encoding and the active header/context. Its output
hashes the retained database files and receipt, and marks full-history
signature/W1 replay, compiler identity, mandatory liability recomputation and
fault causality as unproved. The small reader controls use an explicitly
synthetic SQLite fixture with dummy proof bytes; they are parser/math negative
controls, never a substitute for the signed native campaign.
