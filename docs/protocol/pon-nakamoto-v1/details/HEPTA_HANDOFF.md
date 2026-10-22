# H2 — existing-owner handoff and unexecuted product boundary

Hepta remains the authority for actual user tasks, learning data and final execution.
Read source input: `hepta-private-ci/codex-rs/hepta-learning-artifacts/src/lib.rs` and its
technical guide. Existing exports include LearningArtifactManifestV2,
WithdrawalBoundArtifactAdmissionV3, VerifiedCurrentArtifactHeadV1,
LearningArtifactOwnerHost/Service and VerifiedArtifactSelectionV1. A chain adapter must
consume these owners; it must not construct a second artifact registry or trainer.

The dated inspections below retain their original scope. For the 2026-10-20
amendment the inspected Chain #323 source is
`9bd8b20da68f0dc199aab78c27644ed004af7411`, and the inspected Hepta #2559
source is `443692c1c16a031fbde1ca3ddf5be99770667d81`. That Hepta workflow
pins an older Chain source, so it is not a receipt for this pair. The latest
V8 document amendment is a design input, not evidence of installation or
learning. The PN3 target at the end of this file governs the remaining handoff.

## Required product sequence

1. Normal task owner records actual task/input/output and authorized learning scope.
2. Learning operator produces immutable candidate; artifact owner records lineage and
   current withdrawal head. Evaluation owner supplies frozen candidate/reference/data
   identities, real outcome scope, and independently validated role claims.
3. kernel.operations owns durable submit intent/outbox, attempt identity and lost-ACK
   reconciliation. The chain adapter submits a contribution and observes current chain
   inclusion/confirmation without turning it into a local final-use token. The native
   `packet-status` command is a read-only reconciliation primitive over an already
   existing Node namespace: it decodes the caller-retained exact packet, recomputes its
   BlockId, and reports whether identical bytes are durably stored. It never submits,
   replays work, activates a branch or creates a second operation ledger. A local
   not-found observation is not proof of global non-execution and therefore cannot
   authorize blind resubmission.
4. Consumer checks exact release/family/bytes, current local selection and generation,
   reserves real inference resources, then records model/request/input/output receipt.
5. Reorg withdraws branch entitlement, not already executed local history. Query original
   operation; compensated effects require a fresh authorization. Model change uses a new
   admitted generation rather than rewriting historical decisions.

Required fields: artifact/manifest/withdrawal-head digests; source scope and training/export
permission; task/request/input/output commitments; operation/attempt and owner generation;
model/reference/family; evaluation plan and source group; resource reservation and deadline;
chain network/parameters, observed tip, inclusion and confirmation policy.

## Current executable part

The chain contains a strict expected-hash artifact loader, native twelve-command execution,
closed inference receipt and genesis-bound consumer signatures. These test the receiving
boundary. The existing normal Hepta task pipeline has NOT been connected to this bridge
in this change. Its final-use authority, real resources, independent evaluator signatures
and actual future tasks cannot be fabricated by assembling test objects.

The portable `trnm-research-protocol` crate now also exposes
`HeptaArtifactAdmissionV1` and `SignedHeptaAdmissionV1`. This is a digest-only,
canonical-CBOR handoff envelope for an already-authorized Hepta owner result. It
binds the operation, artifact and owner-admission digests, family/parent generation,
withdrawal scope and head,
registry head, source digest-profile mapping, evaluation plan, task scope, export
permission, payload digest and length, plus an explicit validity window. The envelope
verifies a strict Ed25519 owner signature and can be checked
against the genesis Hepta authority set without constructing a second registry.
Missing parent generations, zero owner facts, altered withdrawal heads, oversized
payloads, non-canonical encodings, altered signatures and unknown authority keys
are rejected. This closes the serialization and fail-closed contract boundary;
it does not claim that the ordinary `Agentd` owner has been configured, that the
chain has a live publication caller, or that a chain confirmation grants final use.

The unshipped handoff profile signs the explicit
`trnm-hepta-artifact-admission-signature-v1` domain with the chain and owner facts.
Generation zero is rejected regardless of whether a parent is supplied. Canonical
envelope decoding rejects inputs above 4,096 bytes before parsing strings or
signature bytes. This wire bound is separate from the 64 MiB artifact payload bound.
Existing research-command encodings and signatures are unchanged.

The receiving adapter must call `verify_for_context` with the destination selected
by its operation journal and the complete admission freshly obtained from its
existing Hepta owner. It compares every admission field, including operation,
task/export scope, digest profile, current withdrawal/registry heads and
parent/generation, then checks the validity window and registered owner signature.
Passing the peer's received admission as its own expected value defeats that
comparison and is not an integration. `verify_signature` and
`verify_with_authorities` are low-level authenticity checks; they do not establish
destination, freshness or currentness. This API itself grants no final-use token.

The envelope is intentionally not a final-use token. A node must re-read the
current Hepta withdrawal head and its local operation/outbox journal before any
external effect. Reorganization may remove chain entitlement, but it cannot replay
or delete a local effect receipt. The integration tests are
`hepta_admission_requires_owner_facts_and_authority` and
`hepta_admission_rejects_missing_parent_and_unbounded_payload` in the research
protocol package. The additional adversarial selectors are
`hepta_handoff_rechecks_the_destination_and_fresh_owner_snapshot` and
`hepta_handoff_limits_wire_before_decode_and_requires_its_signature_domain`.

An earlier cross-machine probe was blocked; the subsequent owned-SSH campaign now
executes on ROG, Pocket4 and X230 and records exact source manifests and live UTC.
It tests delivery partition/catch-up, process exit/recovery, reorg, model-copy use and
quota exhaustion. This supersedes only the earlier lack of multi-host execution;
it does not establish independent operators, public WAN consensus, physical power loss,
long-term storage or an ordinary Hepta owner path. No persistent service is installed.

## Evidence required for three learning generations

Each generation must use its predecessor's actually adopted model, newly authorized task
experience and declared reproducible evaluation tasks. Existing public or
previously seen tasks are admissible for controlled three-generation engineering
tests; unseen data and independent data custody are not prerequisites. Record owner receipts,
resource use, valid no-update outcomes, budget exhaustion and withdrawals. Three signed
synthetic-score release transitions only test the ledger lifecycle and do not satisfy this
requirement. No parallel full-system rewrite is an acceptable substitute.

## Exact upstream owner boundary inspected for this increment

Upstream source: `TrillionniumFoundation/hepta-private-ci` at
`a126987b84737dbc2ee2592442a314117bddb4a2`. The existing non-test publication owner is
`LearningArtifactOwnerService::publish` in
`codex-rs/hepta-learning-artifacts/src/owner_service.rs`. Its request includes
operation_id, WithdrawalBoundArtifactAdmissionV3, payload, signed_current_head,
expected_registry_predecessor_head and now. It checks current-head/storage/withdrawal
binding and recovers acknowledged or incomplete publication from its own journal.
The chain must not replace that journal or manufacture the verified admission type.

The existing `AgentdLearningPlasticityProducerV1` submits parameters/topology through
`PlasticityRuntimeHandleV1`; it does not own authority or a blockchain writer. The
inspected `AgentdOperationsHost` currently implements the automation destination with
an independent AutomationGrantProvider and DurableOperationStore. Reusing its name or
serializing a raw operation does not create a PoN destination or an export grant.

To connect ordinary requests, the configured owner must supply an explicitly permitted
public-export publication and a durable operation intent for the chain destination.
Map both source digest algorithms and actual payload bytes; do not reinterpret a Hepta
Digest32 as the chain artifact digest. Before dispatch, revalidate withdrawal/frontier,
parent model, exact submission round, quota and local final-use generation. If a round
expires before a provably NotDispatched action, create a new authorized intent; an
Unknown effect must first query/reconcile the original identity, not blindly re-sign.

This increment reads these real owner interfaces but does not configure a live signed
owner/withdrawal frontier, implement the ordinary Agentd PoN destination, or publish
private user artifacts. `ordinary_hepta_entry=false` is mandatory in the controlled
experiments. SSH model consumers and local fixture attestors cannot satisfy that gap.

## Publication is not redistribution permission

The inspected `LearningArtifactOwnerService::publish` returns an
`ArtifactPublicationReceiptV1`; its reconstructed receipt sets
`authority: AuthorityPosture::DENY_ALL`. It certifies the named local publication fact,
not a grant to export data or invoke a chain destination. E3 bundle identity must be
carried by the existing evaluation/operation owners alongside the actual signed current
artifact head and withdrawal context. A receiving digest checker cannot manufacture
WithdrawalBoundArtifactAdmissionV3, a final-use token or an independent resource lease.

The controlled evaluator and settlement producer now consume the same locked model,
reference and task identities. This implements their boundary but does not install an
Agentd PoN destination. The repository owner has authorized development, not fabricated
past task records or independent evaluator identities. Normal integration must preserve
these distinctions while mapping the existing typed publication and operation APIs.


## Current compiled effect boundary and required recovery locator

A later upstream inspection fixes the ordinary product path at Hepta main
`78fdb0cf8537e3a84fc6e0a849707559c80881e8`, with the pending revocation-owner
correction in `a48b99ec46995f70f50c173c9ab358d603c6d115` (PR1429).
The compiled effect host is `AgentdAutomationEffectHost` in
`codex-rs/hepta-agentd/src/automation_effect_host.rs`, not the historical
unconnected `AgentdOperationsHost` file discussed above. This is a source
inspection, not a successful Hepta build or ordinary PoN integration claim.

The host currently selects a pinned HTTP provider contract, preserves TaskFlow's
durable effect-attempt owner, and delegates final-use revocation/nonce authority
to `FinalUseAuthority`. Its provider key is derived from provider scope/run/step;
its payload digest is Hepta SHA-256 of the exact transmitted bytes. A chain block,
transaction or authenticated-session identity uses a different domain. None may
be obtained by casting one digest into another.

The upstream boundary has since advanced through Hepta PR1430/PR1431. The existing
TaskFlow effect-attempt owner now persists the exact provider-effect key and exact
wire payload before provider contact, and the reconciliation adapter seam receives
those durable bytes. That closes the earlier information-loss prerequisite without
adding a PoN journal. Legacy attempt rows still carry no exact bytes and must remain
Unknown/Indeterminate for any adapter that needs packet identity.

On the chain side, `packet-status` accepts exactly one bounded packet source (file
or stdin), so the Hepta owner can hand off its already durable bytes without creating
another mutable packet file. The read-only observation reports exact durable storage
separately from current active-chain membership and active depth. A packet retained
after a heavier reorganization therefore remains `stored_exact=true` while
`active_chain_member=false`. The same command works with the explicit authenticated
local state backend. These are local observations only: absence is not global
NotDispatched, active membership is not confirmation/finality, and neither creates
local final-use authority.

In particular, chain mempool acceptance, durable publication, current branch
membership and probabilistic confirmation are distinct observations. A local
TaskFlow terminal receipt cannot be erased after a chain reorganization, and a
missing chain lookup cannot become proof of NotDispatched. Before local adoption,
the existing selection/final-use owner must recheck its actual current generation
and withdrawal head. Simply pointing the existing HTTP config at a native TCP
port, accepting a claimed recovery digest, or replaying a new operation identity
would not implement this boundary. No such fallback is installed here.

## Current stacked Agentd PoN adapter and branch-state observation

The cross-repository development stack has now advanced beyond the earlier prerequisite
inspection.  Hepta PR1432 installs a concrete `trillionnium-pon-local-v1` adapter in the
compiled `AgentdAutomationEffectHost`.  It keeps the existing TaskFlow attempt owner and
`FinalUseAuthority`, hash-pins the selected local Chain binary, requires an existing
canonical Node namespace, passes the already-durable exact effect bytes to `submit`, and
uses those same bytes for `packet-status` reconciliation.  It does not add a second
operation journal.

The follow-on Hepta PR1433 carries the Chain packet observation separately from the
terminal local effect fact.  This continuation advances that observation to v3 and adds the
exact 512-bit cumulative chainwork of the retained block and active tip plus their checked
difference when the retained block is on the active ancestry.  A previously completed effect
may therefore be reported with `stored_exact=true` and `active_chain_member=false` after a
heavier reorganization, while an active member carries both height depth and cumulative-work
depth.  The terminal TaskFlow fact is not rewound and local absence still cannot authorize
blind redispatch.  Chain unavailability removes only the optional current observation, not
the already durable local receipt.

This closes the ordinary local **submit + lost-ACK reconciliation + current branch
observation** seam with a Nakamoto-relevant work-distance fact rather than height alone.  The
work distance is still only a local current-chain observation: it is not a probabilistic
confirmation/finality certificate and does not authorize model adoption.  A
release/selection/final-use owner must independently recheck the current
artifact/withdrawal/generation authority and an explicit confirmation policy before adopting
a model.  That remaining owner decision must not be encoded by changing the provider-effect
receipt or by treating a raw work delta as a final-use capability.

## Exact task settlement binding for the ordinary upgrade coordinator

The v3 packet observation additionally returns `accepted_task`, either null or this
strictly local observation (all hashes are lowercase 32-byte hex):

```json
{
  "schema_version": 1,
  "task_id": "<task-instance-v3 identifier>",
  "owner": "<task owner public key>",
  "provider": "<task provider public key>",
  "output_sha256": "<exact Hepta upgrade binding digest>",
  "accept_tx_id": "<tx-id of the tag-5 transaction>",
  "accepted_in_exact_packet": true,
  "current_status": "settled"
}
```

The existing tag-2 reservation, tag-4 provider receipt and tag-5 owner acceptance
remain the execution contract. The coordinator binds its evaluated artifact, actual
parent generation, selector/withdrawal context and intended release to the provider
receipt's output bytes. It separately retains the exact packet SHA-256 in the
existing TaskFlow effect intent. A transfer or another task's accepted block cannot
satisfy that comparison merely because it has enough chainwork.

The Node supplies this object only when the exact packet is retained, is on the
current active ancestry, and contains exactly one tag-5 transaction. It verifies
transaction-root membership and reads the actual active state through the existing
KV/root/continuity owner. The acceptance sender, task and output must match the
currently settled task; the provider comes from that same state. A final tip and
generation check rejects a mixed view. Multi-accept blocks remain valid blocks and
return null here because they do not identify one unambiguous upgrade. Missing or
locally pruned task state also supplies no current proof.

A heavier reorg removes this optional binding without deleting the original
TaskFlow effect receipt. Acceptance of the same task in a different packet never
restores the old packet's binding. Existing authority fields remain false: the
observation grants neither confirmation, model quality, export permission nor
FinalUse. The ordinary coordinator must still apply its explicit confirmation
policy, original signed installation authority and actual next-generation model
readback. The extra state verification is paid only for a single-accept packet;
this increment makes no claim that confirmation/state scans have become sublinear.

## PN3 real-neuron integration contract

Implement I06–I10 of the
[sole plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
through existing owners. A narrow coordinator carries typed facts between them;
it owns no second learning/artifact/effect store and cannot issue capabilities.
Persist exact intent/attempt/output observations through the current TaskFlow /
kernel.operations boundary, including the original effect key and wire bytes.

The 2026-10-22 audit amendment assigns delivery priorities inside PN3; these
are I06–I10 acceptance obligations, not another roadmap. M15 owns the paired
source/interface freeze and M17 retains raw receipts and negative outcomes.
Controlled implementation may proceed before PN1/PN2 pass; public upgrade claims
remain dependent on their work-security and bounded-state acceptance.
The P0 PN3 loop gate covers all of I06–I10, including the P1 closure/loader
engineering below. I06–I08 or adapter delivery alone cannot close that gate.

| Priority / existing interface | Accountable delivery owner | Dependency and acceptance |
| --- | --- | --- |
| P0 / I06–I07 | Hepta learning/artifact/export/evaluation owners with M10/M11 | Freeze a real pretrained model family, actual installed parent, source permissions, named test data with declared exposure/reuse and versioned evaluation/decision profile. Existing public or previously seen tasks are valid for controlled engineering tests. Actual training/forward receipts and strong equal-budget controls replace fixture scores. |
| P0 / I08 | M14 with the compiled Hepta TaskFlow adapter/coordinator | Consume the same durable packet/effect identity and schema-4 exact task settlement; reconcile Unknown before further dispatch. Exercise wrong task/provider/output, stale view and reorg with zero unauthorized/repeated external effects. |
| P1 / I09–I10 | M09 and M10 release owner with Hepta safe loader, selection/resource/FinalUse owners | After the frozen I06–I08 contract, fetch the complete pinned dependency closure and install only after fresh local authority checks. Three real cycles each end in actual next-task loaded-model readback; a valid no-update retains the actual parent. |
| P1 / PN4 funding; P2 / PN5 extension of I09 | M09/M12/M14/M17 with independent storage/evaluation operators | Establish funded byte-time/repair duties before storage acknowledgement. After the configured-peer loader loop and PN4 duties, qualify independent replica renewal/repair, bounded public discovery and WAN operation. Extra providers or evaluator keys do not close PN3 efficacy. |

The current revision16 ILM3/ILF3 family is a bounded tabular neural graph. Its
zero-parent reachability and signed native adoption are real controls, not an
arbitrary pretrained Encoder/LLM release format. The public historical 25-row
tasks and owner-pinned pre-genesis external windows likewise do not qualify
prospective efficacy. Do not serialize a real Neuron into ILM3 merely to reuse
a passing scorer. Choose and implement an explicit compatible artifact/release
and evaluation profile with bounded codecs, policy identities, independent
vectors and source bindings before claiming native neural-model admission.

The selected product split keeps bulk training/inference off the consensus hot
path. PoN orders exact commitments, task acceptance, release policy and settlement.
Real model evaluation uses the existing evaluator/selector owners with an
explicit trust profile for source custody and independent attestations. A signed
quality claim is not trustless computation or PoN chainwork. If on-chain adoption
semantics change, select a fresh M10/M11 context; the schema-4 task observation
alone only binds settled task facts. Private held-out outcomes cannot silently
replace the current all-node deterministic scorer's public replay inputs.

The new evaluation profile must freeze evaluator admission/custody assumptions,
author conflicts, roster/epoch, Byzantine or collusion bound, quorum rule,
commit/reveal deadlines, objective equivocation and finite appeal handling before
candidate outcomes are known. Missing reveals cannot trigger retrospective roster
or threshold shrinkage. Current revision15's controlled keys and matching native
score checks do not prove independent private evaluation. For an attestation
profile, justify quorum intersection under its own stated fault bound; do not
inherit a threshold from the deterministic scorer. Replacement/rotation applies
to an explicitly new epoch/context. Public entry needs an explicit Sybil/admission
and conflict policy; self-declared independence or an extra key cannot supply it.
If those assumptions are unavailable, keep the campaign controlled/unqualified.
None of these application decisions contributes PoN fork weight or local use
authority, and consumers still apply their own admitted release policy.

| Order / existing owner | Required input and output | Recovery/admission rule |
| --- | --- | --- |
| 1 / task + learning.operator/plasticity | Authorized real task episode, scope and actual installed model -> immutable candidate and training/resource receipt | Preserve consent/source/forget frontiers; no training/export authority inferred from task completion or a memory projection. |
| 2 / learning.artifacts + export/withdrawal owner | Actual candidate bytes, lineage and current signed head -> scoped authorized export | DENY_ALL publication is insufficient. Withdrawal/generation changes fence later use; publication cannot promise recall of distributed copies. |
| 3 / learning.eval + independent selector | Frozen parent/candidate/controls, named task bytes/exposure/reuse, scoring and equal budgets -> selected/no-update/invalid/unknown result | Use actual parameter forward/training and report results on those tasks. Previously seen data is allowed for engineering tests; undeclared reuse or unsupported scores cannot become evidence for unseen-task gain. Preserve existing selection authority. |
| 4 / TaskFlow + compiled adapter | Exact evaluated release/task binding -> durable original effect bytes, submission and read-only reconciliation | Lost ACK queries the same identity. Unknown does not authorize re-signing/re-dispatch. Keep provider SHA256, Chain ids and upgrade-binding domains explicit. |
| 5 / M14 observation consumer | Exact packet and current schema-4 observation -> checked active acceptance plus explicit confirmation policy | Match task id, owner, provider, output, accept transaction, exact-packet ancestry and observed generation/tip. Legacy schema 3 remains readable but cannot satisfy accepted-task binding. Not-found or reorg removes entitlement, never the local terminal fact. |
| 6 / release owner + M09 fetch + existing loader | Selected release closure, pinned TCM1 ids and finite resource reservation -> verified compatible complete bytes | Withheld/corrupt dependencies, wrong base/tokenizer/dtype/shape and expired original budget stop installation. Byte retrieval itself grants no use. |
| 7 / selection/artifact/resource/FinalUse owners | Current signed head/withdrawal, local generation, confirmation and compatible artifact -> fresh CURRENT generation | Recheck immediately before admission; chain generation is not a castable local generation. Code/structural/consensus changes require their own owners. |
| 8 / neuron runtime + outcome/evaluation owner | Next ordinary task -> actual loaded weights/generation and inference/resource/outcome receipt | Record the model actually used, including cached Encoder features. Recheck feature input/model/preprocessing/scope/generation; no stale-feature reuse after install. |

The I06–I10 interface amendment must carry exact release-closure/profile identity
alongside the existing artifact, task-output and packet facts; they have distinct
digest domains. Its versioned target schema must bind both the proposed parent
and the runtime's actual loaded parent/readback, evaluation decision identity,
intended release and original owner generation. These semantic fields are not
new fields already present in TCM1/TCR1 or schema-4 `packet-status`. Publish
canonical vectors, missing/unknown-field refusal and paired-version compatibility
tests before wiring consumers. An unsupported profile returns an explicit refusal;
it cannot fall back to a tabular scorer, a fixture encoder or raw manifest trust.

The adapter observation is a point-in-time local chain fact. The coordinator
checks one coherent network/profile, task, exact packet, active tip/generation
and confirmation-policy view, then rechecks local artifact/withdrawal/selection
generation at the final-use boundary. A changed view requires reconciliation or
fresh selection. Revocation during download or after selection fences later use;
reorg removes entitlement without rewinding TaskFlow receipts or local revocation
history. A previously Unknown effect remains Unknown until its original owner
reconciles it; another signed intent cannot resolve the uncertainty.

For no-update, unexecuted candidate publication, packet submission, download and
installation steps are NOT_APPLICABLE with the decision reason in the versioned
campaign record; do not fabricate or extend existing strict wire receipts.
An already admitted or Unknown effect still requires reconciliation under its
original identity. The unchanged parent/CURRENT and actual next-task readback
remain mandatory. No-update does not waive the separate successful cross-node
I09/I10 closure/loader integration cohort.

First use one real compatible small pretrained Encoder with bounded learned
Cell heads or an explicit adapter family. Reuse the shared Encoder execution,
sparse activation, immutable feature snapshot and existing worker caller from
Hepta's V8 design; different requests cannot share an embedding just because
the Encoder weights are shared. Freeze maximum active Cells and end-to-end
CPU/RSS/VRAM, queue, training/evaluation and download budgets. A logical count
of Cells or a deterministic head proves neither a real forward nor benefit.

For each lineage cycle record parent/candidate/release/dependency hashes,
training and evaluation source/time/exposure partitions, consent/withdrawal
heads, independent owner roles, frozen decision thresholds and sample/power
justification, baseline outcomes, total cost, exact TaskFlow/packet identities,
active acceptance/confirmation, installation generation, loader readback and
subsequent named-task results. Missing fields remain unknown with a
reason. Predeclare the uncertainty-adjusted minimum gain over the installed
parent, strong-control comparison, retention/safety/cost bounds and repeated-
selection correction for statistical efficacy claims. Controlled engineering
tests may reuse declared public/seen tasks and do not require independent data
custody. Report their results within that dataset; future generalization needs
separate evidence. A losing
or unsafe candidate retains the current model and gets zero
model-improvement reward. Evaluation/transport resources still settle under
their original scoped budget.

PN3 mechanical acceptance requires three real consecutive cycles and an
independent consumer task, including valid no-update behavior. Every cycle
starts from the predecessor actually in use; replica installs cannot multiply
the learned-update count. At each cycle entry, record actual runtime parent
payload/closure hashes and local CURRENT generation, then match them to the
predecessor's exit receipt. At exit, execute an ordinary newly authorized task
and read back loaded tensor/adapter/router identities, generation and output,
including a process restart/cold-load case. A selected update advances CURRENT
through its existing owner; no-update records an unchanged parent/CURRENT and
still executes that next task. Zero completed installs with unresolved required
dependencies, zero unauthorized installs and zero repeated external effects
are mandatory across the three cycles and all injected failures. Three installed
improvements on the declared tasks require three measured gains with actual
installed-parent and next-task readbacks; public or previously seen tasks are
valid inputs. No independent future-data custodian is required for that
engineering result. A separate claim of sustained improvement on future tasks
requires prospective outcomes under a preregistered gain/retention/safety rule
and strong equal-budget controls. Three no-update cycles, ceiling scores,
exploratory retraining or three signed fixture generations do not meet that
future-task efficacy condition.

Inject lost ACK, duplicate submission, expired authorization, wrong provider/
output/packet, reorg before and after selection, withdrawal during fetch and
before CURRENT, missing/corrupt Cell, author disappearance, disk-full and process
cuts at each durable owner boundary. After restart, report the original operation
and actual loaded generation; do not execute an external effect again to repair
a missing observation. Reverting a model is a newly admitted local generation.
Historical decisions and revocation/forget frontiers remain unchanged.
