# TRNM PoCO AI-native v1 production contracts

Status: **draft target contract; design-only; not implemented; not activated**

Date: 2026-08-13

This document defines the production durability and authority boundaries for
the proposed versioned PoCO AI-native v1 protocol stack. It is not a protocol
freeze, an implementation claim, a release-readiness claim, or authorization
to activate protocol version 1. The frozen PoCO-BFT v0 rules remain unchanged
until an explicitly authorized cross-version transition completes.

The binding product decision remains
[`TRNM_POCO_BFT_NATIVE_MAINLINE_DECISION_2026-08-13.md`](TRNM_POCO_BFT_NATIVE_MAINLINE_DECISION_2026-08-13.md).
The existing v0 host contracts remain authority for v0 work:
[`TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md`](TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md).
V1 must preserve the weighted chained-HotStuff safety kernel while adding
versioned Agent, task, verification, data-availability, execution, settlement,
upgrade, and light-client contracts around it.

## 1. Current truth and non-goals

At the assessed source state:

```text
poco_ai_native_v1_status=DESIGN_ONLY
poco_ai_native_v1_spec_frozen=false
poco_ai_native_v1_implemented=false
poco_ai_native_v1_production_activation=false
zero_comet_production_dependency_achieved=false
production_consensus_activation=false
```

No v1 type, domain, file, test, or prototype may turn any of those values into
an achieved claim. In particular, this document does not authorize:

- reinterpretation of a v0 byte string, domain, block, QC, TC, receipt, epoch
  object, or persisted safety record as v1;
- digest-only ordering before a v1 availability contract is frozen and
  activated;
- replacing the HotStuff quorum, lock, TC, or three-chain safety theorem merely
  to create a new protocol name;
- putting model weights, private prompts, large datasets, long outputs, or
  nondeterministic GPU inference into replicated consensus execution; or
- accepting a self-signed v1 validator set, an in-epoch upgrade, an automatic
  downgrade, or an unverified state migration.

## 2. Native production and canonical-wire boundary

Every v1 production node, application host, signer, DA worker, sync tool, light
client, release artifact, and operator path must use TRNM-owned types and must
have no CometBFT, Tendermint, ABCI, or ABCI++ dependency or compatibility mode.
Legacy JSON command envelopes and application schemas may be read only by an
explicit, one-way migration tool; they are not v1 consensus wire types.

The v1 canonical codec, object-kind registry, schema registry, domain registry,
and hash framing must be frozen together. Every consensus-signable or
state-authoritative value must have:

- a closed object kind and schema version;
- exact, bounded, canonical bytes with strict end-of-input checking;
- a dedicated domain for its body, signing root, logical identifier,
  certificate identifier, and ordered-root role where those concepts differ;
- explicit genesis, chain, and protocol-version binding, plus epoch, validator
  set, parameters, view, or application-profile binding where relevant; and
- committed byte-exact positive and negative vectors consumed by at least two
  independent implementations.

JSON re-encoding, protobuf bytes, transport compression, database row order,
or a caller-selected hash helper must never become signing bytes. V0 decoders
must reject v1 and v1 decoders must reject v0. Unknown required variants,
duplicate or disordered signer sets, non-canonical maps, trailing bytes,
oversized lengths, arithmetic overflow, and cross-domain substitution fail
closed.

## 3. Consensus Safety, signer, and whole-node checkpoint

V1 retains the existing weighted `floor(2W/3)+1` QC intersection, one-vote-per-
view watermark, locked-QC safe-vote rule, deterministic TC high-QC selection,
TC view advancement without implicit unlock or finality, direct three-chain
finality, persist-before-sign, ordered finalization, and dual-quorum epoch
handoff.

One non-cloneable SafetyRules owner must verify the complete proposal witness,
available ancestry, locked-QC or exact higher-view unlock justification,
execution/availability authorization, active configuration, and canonical sign
intent before it requests a Vote or Timeout signature. The exact SafetyState
revision authorizing the intent must be durable before the signer sees it.

The signer owns a separate append-only anti-equivocation journal and an
external monotonic watermark. It independently recomputes the signing root,
checks the complete intent, persists the intent and signature outcome, and only
then releases a signature. Exact replay is idempotent; a conflict, rollback,
profile drift, stale Safety revision, or ambiguous producer outcome fails
closed.

Before any signature, broadcast, application effect, DA attestation, or final
report of state advancement escapes, an independently monotonic whole-node
checkpoint must bind one exact cut across:

- SafetyState record/profile/revision and record-chain checksum;
- signer journal/profile, local watermark, and external watermark;
- application committed head, authenticated state root, execution profile,
  validation/finalization outboxes, and recovery-closure checksum;
- DA store profile, durable batch/blob manifest head, attestation journal,
  retention/repair obligations, and GC watermark; and
- active protocol manifest, parameters, validator set, verification profiles,
  fee schedule, epoch, height, view, and finalized block.

Checkpoint successor creation uses compare-and-swap semantics. A successful,
failed, timed-out, or response-lost update is followed by fresh readback and
may resolve only to the exact source or exact target. A third value or any
mixed cut fails closed. Peer state sync may restore public state, but it never
restores or lowers local Safety, signer, DA-attestation, or whole-node
watermarks.

## 4. Certified DA durable-before-attest contract

Transaction batches and AI artifacts use distinct namespaces and retention
profiles. A descriptor must bind content root, byte length, encoding profile,
chunk/root geometry, producer, namespace, creation epoch/height, retention
deadline, retrieval/repair parameters, and any encryption or access-policy
commitment. A content hash alone is not availability evidence.

A DA worker may sign an availability vote only after it has:

1. exact-decoded and validated the descriptor and complete required bytes;
2. verified every content/chunk/root commitment;
3. durably stored the data and canonical manifest under the active profile;
4. durably reserved capacity through the committed retention deadline;
5. persisted the complete attestation intent in its own append-only journal;
6. reconciled the DA journal/store and whole-node checkpoint after restart;
   and
7. made the promised local retrieval and repair path operational.

The attestation journal binds signer identity, descriptor ID, content root,
profile, retention deadline, signing root, store generation, durable manifest
checksum, and monotonic journal revision. It rejects an alternative descriptor
for the same logical batch, a lower retention promise, missing local bytes, a
rolled-back store, or a conflicting attestation at an already used coordinate.

An `AvailabilityCertificateV1` contains one exact descriptor and a unique,
canonically ordered weighted signer set reaching the active DA quorum. The
certificate proves only the frozen availability promise; it does not prove
correct execution, usefulness, privacy, fair pricing, or permanent retention.

Retention GC is gated by finalized chain height/epoch, challenge windows,
state-sync and light-client obligations, evidence preservation, active repair
requests, and the whole-node checkpoint. Withholding evidence and repair
receipts are versioned, deterministic, bounded, and replay protected. Disk
pressure, queue pressure, or unavailable peers may delay service or stop the
node, but may never fabricate a positive attestation or deterministic-invalid
application result.

## 5. Batch retrieval-before-vote contract

PoCO-Order v1 orders exact `(BatchId, AvailabilityCertificateId)` references,
not unqualified content hashes. A proposal is ineligible for a Vote until the
validator has:

- verified the descriptor, certificate, signer ordering, weighted DA quorum,
  namespace, retention, active policy, and exact proposal reference;
- retrieved the complete transaction batch bytes independently of the
  proposer, or proved that the identical complete bytes already exist in its
  reconciled durable DA store;
- recomputed every content and transaction root and rejected alternate bytes,
  descriptor substitution, missing chunks, or an expired certificate;
- exact-decoded all transactions under the active protocol/profile and applied
  deterministic block admission limits; and
- reserved the local execution and validation capacity needed to finish the
  vote-authorizing path.

An availability certificate is not permission to vote without the bytes.
Missing or temporarily unavailable bytes remain retryable `Unavailable`; they
do not become `Valid` or `DeterministicallyInvalid`. A proven commitment
mismatch, invalid certificate, or canonical decode failure is deterministic
invalidity. Local OOM, I/O, disk, scheduler, or transient network failure is a
host failure or retryable unavailability, never consensus-visible invalidity.

## 6. Execution, MVCC, fees, and settlement durability

Agent transactions bind principal, session key, capability grant, nonce lane,
lane nonce, validity window, resource ceilings, fee ceilings, and command. The
application checks capability scope, model/tool/endpoint limits, budget, rate,
expiry, revocation, and lane monotonicity against the authenticated parent
state. A session key cannot broaden its parent capability, cross nonce lanes,
or replay a command under another task/profile.

Object-aware MVCC may execute independent transactions in parallel, but the
consensus result is deterministic. The scheduler must record canonical read
and write sets or equivalent conflict commitments, detect conflicts without
host-timing dependence, replay conflicted work in a frozen deterministic
order, and produce the same state root, receipts root, events, resource totals,
and error classification as the reference serial semantics. Execution receipt
commitments include an explicit outcome/status and exact transaction, batch,
profile, gas/resource, event, state-delta, and post-state binding.

Per-transaction fees accumulate into deterministic block-level deltas. No
transaction writes a global fee-collector hotspot. The final apply transaction
atomically commits:

- canonical transaction outcomes and receipts;
- the exact MVCC conflict/resolution result and state writes;
- account and capability nonce-lane advances;
- multi-resource charges for order bytes, state I/O, transaction DA, artifact
  DA/retention, verification, priority, and challenge bonds;
- escrow, provider, consumer, validator, burn, treasury, and refund deltas;
- task, lease, checkpoint, verification, challenge, and settlement state; and
- the authenticated state root, receipts root, resource totals, and committed
  application head.

Checked conservation and overflow rules apply to every asset and resource
dimension. Exact replay is idempotent. A crash cannot publish a receipt,
settlement, nonce advance, or finalization acknowledgement without the matching
durable state transition.

## 7. Proof-carrying task, verification, and challenge outbox

The task lifecycle binds one immutable `TaskSpec`, funded escrow, selected
offer/lease, verification profile, artifact descriptors, deadlines, checkpoint
and resume/migration rules, result commitment, consumption terms, challenge
policy, and settlement policy. Verification profiles are closed, versioned
objects; deterministic re-execution, reproducible ML, ZK validity, TEE
attestation, stake quorum, optimistic challenge, and subjective evaluation are
not collapsed into one ambiguous `Valid` bit.

Order finality and AI-result/settlement finality are distinct. Finalized blocks
are never rolled back because an AI result later fails a challenge. A successful
challenge produces a forward state transition for compensation, refund, slash,
reputation, or weight eligibility.

Every externally generated proof request, verification result, challenge
notification, repair request, evaluator assignment, and settlement action uses
a durable transactional outbox. The outbox row binds exact task/lease/result,
verification profile, artifact and DA certificate IDs, parent state, attempt,
deadline, idempotency key, request/response hashes, and terminal classification.
Creation of a terminal application fact and its callback/outbox is one database
transaction. Delivery may repeat; acknowledgement cannot accept different
bytes. Unknown or subjective results cannot silently become objective validity.

## 8. Ordered finalization and application apply

Core persists a strictly ordered ancestor queue of complete v1 finality proofs.
Each entry binds the three-chain proof, authenticated direct parent, proposal
witnesses, exact batch/DA references, execution overlay, state and receipt
roots, active manifest/parameters, and authorizing Safety revision.

Application apply consumes only the oldest unapplied entry. It revalidates the
overlay lineage, canonical batch bytes, MVCC result, roots, fees, task and
settlement deltas, outbox mutations, and whole-node checkpoint target before
one atomic promotion. It then durably advances the application head and queue
acknowledgement before `FinalizationApplied` is returned to Core. Descendants
cannot skip an absent ancestor. Pruning cannot remove any object, proof, batch,
artifact, overlay, state node, or outbox record needed by recovery, sync,
challenge, evidence, or the oldest trusted checkpoint.

## 9. State sync and independent light client

A native state-sync manifest binds chain/genesis/protocol, finalized block and
proof, state root, application schema/profile, protocol manifest, parameters,
validator set, DA policy, verification/fee profiles, snapshot chunks, and
retained batch/artifact availability ranges. Chunk transport is untrusted;
every commitment and finality path is reverified before installation.

Installation is staged into a separate namespace, exact-decodes all objects,
recomputes the authenticated state root, checks snapshot completeness and
protocol/profile support, then atomically swaps the public application state.
It cannot overwrite local Safety, signer, DA-attestation, or whole-node
watermarks. Startup reconciles the installed public state with those monotonic
domains before enabling any signature or attestation.

The v1 light client MUST be independently implemented and MUST NOT reuse the
full node parser, QC verifier, upgrade verifier, or state-transition code. From one
explicit weak-subjectivity checkpoint it verifies complete same-epoch
three-chain finality and every epoch/version handoff. It persists the highest
accepted checkpoint before reporting success, never rolls its trust window
forward through individually short untrusted hops, and requires an explicit
external recovery event when freshness is uncertain.

## 10. V0-to-v1 activation and migration contract

V0 remains byte-, domain-, state-, and SafetyState-frozen. A v1 transition is
implemented by a separate cross-version verifier, not by relaxing the v0
same-version verifier.

The only valid activation sequence is:

1. A governance result finalizes the frozen v0 `UpgradePlanV0` after the
   required notice. That old-chain plan commits a context-free
   `V0ToV1ArtifactManifestBodyV1`, which in turn commits the exact
   `UpgradePlanIdV1`, binary/artifact manifest, SBOM/provenance, canonical
   codec/domain registry, parameters, validator set, DA policy,
   execution/verification/fee profiles, migration program, activation epoch,
   and activation height. V0 treats the nested CEV1 digest as opaque; a
   separate cross-version verifier checks the complete two-layer projection.
2. The old v0 checkpoint is order-finalized by certified Seal1 and Seal2
   descendants. Seal2 is the terminal certified v0 block; neither seal is
   separately required to become finalized beyond that frozen three-chain
   bridge. Their next-epoch commitment binds the upgrade plan, checkpoint
   state root, migration input, and complete v1 configuration.
3. The deterministic migration executes exactly once against that finalized
   v0 checkpoint. It emits a canonical `MigrationReceiptV1`, output state root,
   unmigratable/rejected-object report, and audit manifest. Independent
   implementations reproduce the same result from committed vectors.
4. Old and new validator quorums first produce the frozen v0
   `HandoffCertificateV0` and then durably sign one identical v0-to-v1
   activation statement. These are cumulative certificate layers
   binding the terminal old proof/QC, old and new versions, codec/parser and
   protocol-manifest hashes, migration input/output roots and receipts, new
   set/parameters/profiles, and exact activation height.
5. If any prerequisite or either quorum is absent, the chain stalls safely at
   the old boundary. It does not guess a configuration, skip migration, or
   fall back to a different candidate.
6. The first v1 block appears only at the declared activation height, extends
   the exact terminal old consensus block, carries the complete frozen
   `EpochAnchorAuthorizationV0` plus the v1 activation statement, and uses the
   authorized migration output as its execution parent. A later first view
   requires the exact authorized anchor and TC path.
7. A new-set v1 three-chain finalizes a v1 block before light clients adopt the
   new checkpoint. The complete v0 checkpoint/seal proof, plan, migration,
   dual-quorum handoff, first v1 block, and v1 finality remain verifiable as one
   transition proof.

Once a validator has durably signed the handoff descriptor, it cannot sign a
different descriptor or an old-protocol block beyond the terminal height.
There is no automatic downgrade or rollback. Recovery to another history is an
explicit new trust/genesis event with separately stated assumptions.

## 11. Production evidence gate

No contract in this document is complete until source, byte-exact vectors,
formal properties and retained failing mutants, crash/power-loss/disk-full and
response-loss tests, multi-process recovery, independent implementation, WAN
fault campaigns, metrics, runbooks, and external review all agree on the same
machine-readable status. Component tests, in-memory simulation, a signed hash
without durable bytes, a self-signed new set, or a benchmark result cannot
satisfy a production contract.
