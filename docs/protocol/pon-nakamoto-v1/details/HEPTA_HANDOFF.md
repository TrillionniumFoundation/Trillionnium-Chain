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

Cross-machine probe execution was blocked by the available execution layer. No claim of
multi-host, independent operators, WAN consensus, physical faults or live service install
is made. Separate hosts controlled by one operator would still not establish independence.

## Evidence required for three learning generations

Each generation must use its predecessor's actually adopted model, newly authorized task
experience and untouched prospective evaluation sources. Record independent owner receipts,
resource use, valid no-update outcomes, budget exhaustion and withdrawals. Three signed
synthetic-score release transitions only test the ledger lifecycle and do not satisfy this
requirement. No parallel full-system rewrite is an acceptable substitute.
