# H2 — existing-owner handoff and unexecuted product boundary

Hepta remains the authority for actual user tasks, learning data and final execution.
Read source input: `hepta-private-ci/codex-rs/hepta-learning-artifacts/src/lib.rs` and its
technical guide. Existing exports include LearningArtifactManifestV2,
WithdrawalBoundArtifactAdmissionV3, VerifiedCurrentArtifactHeadV1,
LearningArtifactOwnerHost/Service and VerifiedArtifactSelectionV1. A chain adapter must
consume these owners; it must not construct a second artifact registry or trainer.

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

An earlier cross-machine probe was blocked; the subsequent owned-SSH campaign now
executes on ROG, Pocket4 and X230 and records exact source manifests and live UTC.
It tests delivery partition/catch-up, process exit/recovery, reorg, model-copy use and
quota exhaustion. This supersedes only the earlier lack of multi-host execution;
it does not establish independent operators, public WAN consensus, physical power loss,
long-term storage or an ordinary Hepta owner path. No persistent service is installed.

## Evidence required for three learning generations

Each generation must use its predecessor's actually adopted model, newly authorized task
experience and untouched prospective evaluation sources. Record independent owner receipts,
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
