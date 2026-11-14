# Asynchronous proof and settlement boundary V1

Status: **proposed research interface; no new proof transaction, queue worker,
consensus profile, payment authority or production activation is implemented by
this document**. Reviewed against integration candidate
`3d1b6507671ec694ce58e86d4063a125c8deeb66`. The sole implementation plan remains
[the AI native blockchain development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
This contract locates a future asynchronous worker within the existing owners;
it does not introduce a second ledger or a second model registry.

## 1. Two clocks, five separate decisions

Moving proof generation out of the mining critical path can remove its generation
latency from block publication. It does not remove its resource cost or the
cost of verifying a proof when that proof eventually affects canonical state.
An asynchronous job may finish minutes later while blocks continue to carry
complete current native W1 work. A block must never acquire active-chain status
on a promise to supply its required W1 proof later.

[CONSENSUS C2--C4](../../../protocol/pon-nakamoto-v1/CONSENSUS.md) binds the entire
candidate template and requires complete work, bodies, execution and ancestry.
The present [WorkCheckedPacket verification](../../../../trillionnium/crates/trnm-pon-node/src/store.rs)
calls the complete `pon_work::verify` or its controlled full-verification entry.
The separate RISC Zero W1 v2 research receipt is not an admitted alternative in
that entry. A later artifact reward cannot retroactively give a withheld,
invalid or unverified block chainwork.

| Decision | Necessary evidence | What it does not establish |
| --- | --- | --- |
| Native block work is valid | Complete current W1 relation and actual parent/context checks | A useful training update, independent model quality or reward eligibility |
| A job's computation is correct | The exact versioned relation, fixed verifier and independently expected statement | Data rights, evaluator independence, future quality or consumption |
| A candidate improves the declared task | Frozen evaluation policy, complete parent and controls, qualified evidence | General improvement outside that task or permission to activate code |
| A model may be adopted | Actual current parent, valid evaluation closure and original adoption policy | Extra chainwork or an irreversible effect on another host |
| A party may be paid | Funded native source, actual entitlement/owner authorization, current branch and deduplication | Proof of the other four decisions solely from payment or an RPC ACK |

W1 v2 proves the complete W1 relation for its header and externally bound
materials. It does not thereby prove the derivation of those materials from raw
text, a whole training run, a transformer, a Cell state transition or an
independent quality gain. A training-proof backend must first specify that
larger relation. Calling an existing W1 receipt a training certificate would
leave the principal computation unproved.

## 2. Existing owners that can be reused

The following are source-level capabilities, not new execution results from this
review. The version numbers of model evolution and qualified task authority name
different contracts and must not be treated as interchangeable profiles.

| Existing owner and entry | Implemented behavior relevant here | Missing asynchronous integration |
| --- | --- | --- |
| M06 [`pon_executor::apply_task_command`](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs) | Ordinary task creation debits the sponsor; provider receipt binds a nonzero output; owner settlement requires the exact output before expiry; cancellation and mandatory expiry follow existing state rules | The output hash is not automatically a verified succinct proof. These commands do not install a proof verifier or authorize an unattended prover |
| M06 [`tasks_v5::eligible_task_metered`, `admit_material_metered`, `consume_output`](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v5.rs) | The PQ task profile resolves current requester/source authority, verifies the manifest/material under the selected profile and meters verification. Output consumption uses the independently verified W1 product; repeated identical output returns no additional credit, while a conflict refuses | This exact task-material/output relation does not prove an arbitrary training trace. `consume_output` explicitly mints no rewards |
| M06 [`model_evolution_v5::admit`](../../../../trillionnium/crates/trnm-mvcc-fee/src/model_evolution_v5.rs) | Loads the actual complete parent and derives the bounded integer candidate; normalized update identity rejects alternate factor encodings of the same complete update in the current parent/round window | No proof of arbitrary optimizer steps or general function-equivalence normalization |
| M06 [`public_evaluation`](../../../../trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs) and ordinary adoption/claim entries | Frozen commit/reveal/closure, selected profile checks, actual positive native score, current model parent, funded release, allocation and maturity checks remain canonical | A new proof's mathematical validity cannot replace empirical evaluation, independent administration or adoption. A compute worker must not invent new evaluator authority |
| M12 [`NativeBudgetStoreV1`](../../../../trillionnium/crates/trnm-service-settlement/src/native_budget.rs) | Current native funding observations, typed resource lanes, reservations, durable effect intents, exact replay, resource records and observation of already executed payments | No issuance or escrow-lock API. The six lanes are not six complete physical worker or payout pipelines |
| Node [`NativeFundingOwnerV1 for Node`](../../../../trillionnium/crates/trnm-pon-node/src/store/funding.rs) | Actual native owner bridge for funding and payment observations | A remote JSON row or a prover's own owner implementation is not an authenticated chain observation |
| M09/Node [`storage_service`](../../../../trillionnium/crates/trnm-pon-node/src/store/storage_service.rs) | Actual task-funded retention/repair entry, current-owner effect check and retained operation handling | Storage service completion does not establish a complete proof service, independent custody or future availability |

In particular, the portable
[`ConsumptionSettlementStoreV1`](../../../../trillionnium/crates/trnm-service-settlement/README.md)
is a local monotonic commit/replay kernel and explicitly is not a
branch-reorganization backend. It must not be adopted as the canonical PoN
settlement ledger merely because its name includes settlement. Canonical
balances and rewards remain in M06 and the Node branch owner. The existing
[native budget adapter contract](NATIVE_BUDGET_ADAPTER_V1.md) is the integration
boundary for local resource/effect records.

## 3. Proposed job statement and independent binding

Before admitting expensive work, the requesting owner retains a canonical job
contract independently of the proof envelope. The future decoder compares the
received envelope to that retained contract; agreeing with its own downloaded
manifest is insufficient. The contract must commit these groups:

| Group | Required binding |
| --- | --- |
| Protocol and ownership | Schema/domain version, network, parameters, genesis, job/request identity, requesting account, provider, current authority generation, policy and signature profile |
| Computation | Relation identifier, verifier/image identifier and dependency/profile identity, numeric rules, input/model/data roots, complete starting model/state, ordered operations, output/state commitment, resource envelope |
| Application context | Family, actual model parent reference and artifact, task/evaluation plan and round, expected source context, use/output meter and any candidate/contribution identity |
| Funding and effects | Exact native funding source, beneficiary, authorized maximum debit, allocation entitlement or consumer consent where required, globally stable operation identity |
| Deadlines and availability | Admission/expiry heights, local absolute monotonic deadline policy, cancellation policy, DA manifest/root, retained bytes and retention obligation, complete witness/payload size limits |

A locally measured timestamp cannot become a consensus height or a universal
clock. Height-based funding/evaluation windows remain checked by native state;
wall-time limits belong to the specific process/host contract. A proof finishing
after its job window can remain a mathematical fact about an old statement and
still be ineligible for payment or current adoption.

The logical job/result identity excludes randomized proof encodings, retry
numbers and the prover identity when these do not change the authorized result.
Exact replay is idempotent. A different proof of the same task/result is not a
second useful output. Existing model normalized-update and task output-meter
identities remain the comparison points; a new hash namespace must not erase
their original deduplication rules. Scope must be explicit: the current model
normalization covers one actual parent/round window, not arbitrary equivalence
across all future models and networks.

The v2 independent expected-artifacts binding is retained. Any extension that
adds raw-data provenance or training semantics requires a new relation and
fresh signed/storage namespaces, test vectors and backend-equivalence review.
A new envelope must not reinterpret historical v2 bytes.

## 4. Worker lifecycle and resource ownership

The future worker should represent these states under existing operation owners.
They are **design states**, not currently implemented enum variants or on-chain
tags.

| Transition | Required action and refusal |
| --- | --- |
| Declared to admitted | Decode bounded bytes; authenticate owner and exact statement; observe original native funding; reserve global and per-source resources; fix the whole attempt set/limits |
| Admitted to running | Reobserve the current funding/authority snapshot and cancellation state; durably create the exact effect intent before dispatch; `Pending` requires target reconciliation and never authorizes redispatch |
| Running to proof available | Retain every worker outcome and paid resource interval; bind proof, journal/output and expected statement; reject oversized or incomplete packages |
| Proof available to checked | Run the fixed independent verifier under its original absolute deadline and reserved verifier budget; keep both successful and rejected costs |
| Checked to evaluated | Use the existing qualified task/evaluation owner. Computational correctness supplies only the computation fact; frozen score, controls and evaluator requirements still apply |
| Evaluated to settlement pending | Recheck current native parent, authority, funding, entitlement, result deduplication and availability; submit the ordinary supported settlement/adoption action, or a separately specified future proof-bearing action |
| Settlement pending to paid on current branch | Observe the actual native transaction/reward through the owner, including source, subject, beneficiary, gross/net amounts and required confirmation policy |
| Any unfinished state to failed, canceled, expired or unknown | Retain resource costs and durable intents; settle child processes; reconcile physical effects; use only the original native cancellation/refund/expiry rules |

A scheduler needs a global host cap as well as source/job limits: per-key queues
alone do not bound a source that creates aliases. Admission reserves memory,
proof/witness bytes, process/GPU slots, verifier CPU and storage/retention capacity
in their appropriate units. The original reservation is not renewed by retries,
segment boundaries, queue transfers or batching. Queue wait, setup/load, proving,
compression, independent verification, encoding, delivery and final settlement
are separately timed, with an enclosing end-to-end interval. Nested CPU/wall
intervals are not added twice.

For an arrival process with rate `lambda_jobs`, `c` equivalent proving workers
and mean occupied service time `E[S]`, the necessary capacity screen is
`lambda_jobs * E[S] < c`. It is not a queue-tail or liveness guarantee: bursts,
heavy tails, memory contention, verifier capacity and nonidentical devices still
need measured bounds. Batching must charge the oldest job's wait and preserve
each member's original expiry; a batch timeout cannot create a fresh allowance.

Use the existing contribution/evaluation/mining lane only when its source and
resource semantics fit the real work. The current lane schema does not contain
a generic proof-byte/GPU-time field; unknown measurements must remain unknown,
with the adapter's conservative original-reservation charge. Do not report a
CPU-only record as complete GPU accounting or overload another resource field
with a different unit. A required schema extension needs a new version.

## 5. Two honest settlement modes

### Owner-accepted ordinary task settlement

A sponsor can independently verify an asynchronous job and, if its original
contract permits, submit the existing owner-authorized settlement for the exact
provider output. The chain verifies its actual signatures, funding, state and
settlement rules. It does not gain a trustless proof of that whole job merely
because the sponsor verified it off chain. This is the existing bilateral task
trust boundary, which must be named in any report or API.

A worker bridge still needs concrete authorization before execution, real
budget/effect wiring, cancellation and recovery tests. This document does not
claim such a bridge is already installed. The current task receipt/settlement
commands alone are not its implementation.

### Future proof-checked canonical settlement

If payment or model state must depend trustlessly on the proof, M06 needs an
explicit new proof-bearing relation/profile, canonical bounded codec and
independent validator replay. A prior off-chain check, signed verifier service
or cached `verified=true` flag cannot replace that replay without changing the
trust model. No such transaction or automatic backend switch is added here.

The original proof generation time can be asynchronous, but each including node
still pays decode, proof verification, required DA reads and state execution.
For a block containing `m` proof jobs, the resource contract must bound all of
those costs plus ordinary work/body/state verification. It cannot admit an
unbounded number merely because each job carries a fee. Bound proof count,
aggregate encoded bytes and the fixed verifier's deterministic work dimensions;
retain local deadline/CPU fences and hostile-invalid-proof admission limits.
Actual wall time remains a measured deployment property, not a deterministic
consensus rule derived from a machine-dependent stopwatch.

A recursion or aggregate proof can reduce canonical verifier work only after
its relation binds the ordered complete batch, every external job statement,
original proof system and result. Repeated jobs, partial batches, malicious
member replacement and aggregate construction failures retain explicit
semantics. Aggregation cannot delete the oldest job's queue delay, unproved
training stages or unavailable required data. It is a separately qualified
backend, not a receipt-label change.

## 6. Reorganization, availability and physical effects

The [branch recovery contract](../../../protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md)
and [native public-evaluation lifecycle](../../../protocol/pon-nakamoto-v1/details/PUBLIC_EVALUATION_LIFECYCLE.md)
remain authoritative. Canonical contribution/evaluation/adoption/reward rows
roll back with a branch switch. Physical work, local operation IDs, cancellation
observations and external effect receipts do not rewind.

After a reorganization, reobserve current funding and authority before any new
physical effect or monetary claim. A historically paid operation must not be
reported as currently paid without current-branch evidence. An unfinished local
intent must be reconciled against its target rather than replayed; an exact
completed operation must not execute again. A mathematically valid proof about
a removed parent does not authorize credit against a new model parent. Resubmit
an eligible artifact only under the surviving branch's original deduplication
and evaluation rules. Do not regenerate virtual funds from an orphaned receipt.

There is no atomic transaction spanning a native branch change, a local SQLite
journal and a remote prover/storage machine. The design must name the owner of
each recovery step and retain the unresolved state when evidence is missing.
Restoring the entire local effect database from an old copy is outside the
adapter's anti-rollback guarantee; target-side idempotency and independent
recovery fences remain necessary.

Availability is a separate predicate. A content hash, valid proof or signed
future-retention promise does not show that a new node can fetch the required
model/input/output bytes. Use the existing Cell manifest/material verification,
retention and repair owners. Do not make block validation wait for an unbounded
external download. If settlement requires bytes not already available under
its bounded contract, defer that job; distinguish missing data from invalid
cryptographic data. Proof availability must not be mistaken for model
availability or completed ordinary Hepta consumption.

## 7. Concrete implementation order and rejection controls

The next implementation should first wire one explicitly authorized,
owner-accepted task service to the real Node funding/operation owner and a fixed
relation. Its durable journal and end-to-end clocks can be validated without
changing consensus work. The minimum integration campaign must exercise real
funded native commands, an independently expected result, a failed proof, owner
rotation, cancellation while queued/running, expiry, a heavier branch, cold
reopen, `Pending` target reconciliation and once-only payment observation.
Synthetic owners are useful accounting controls and must remain labeled as such.

Before a canonical proof-bearing successor is proposed, retain these controls
on the actual complete source and original resources:

- Internally consistent proof/manifest with the wrong independently expected
  data, model, task, round, numeric contract or verifier is refused.
- A full valid W1 proof with no valid training/evaluation relation receives no
  training-quality or adoption credit.
- Two randomized proofs, two retry IDs and an equivalent normalized model update
  cannot yield a second result or claim in the same authorized scope.
- Missing, canceled, timed-out and unknown workers remain in the original attempt
  and cost denominator; producer-supplied stage totals cannot replace the owner
  clock or make unmeasured CPU/GPU work free.
- A proof finished after its original deadline or after source cancellation
  cannot reopen the source; a same-context authority rotation is rechecked.
- Reorg removes current entitlement but preserves physical costs and effect
  history; stale payment observations are not relabeled current, and an exact
  pending/completed effect is never dispatched twice.
- A block full of valid or adversarial proof packages remains within its exact
  decode, bytes, verifier, state and cancellation bounds under independent
  receiver execution. Test verifier saturation even when prover work is remote.
- Missing required Cell bytes and an unavailable verifier return the specified
  unavailable/deferred outcome; neither produces a success stub or a weaker
  fallback. Proof validity alone cannot assert future retention or consumption.

The existing original four-second confirmation, hostile-load, full-History,
PQ/context, independent-owner and model-adoption gates remain separate. Passing
this interface's unit controls would establish only those component behaviors.
It would not certify a deployable proof backend or close the system gates.
