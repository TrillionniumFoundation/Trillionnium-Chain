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
   inclusion/confirmation without turning it into a local final-use token.
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
