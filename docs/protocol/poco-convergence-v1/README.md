# PCC1 — Deterministic PoCO-BFT authority convergence contract

Status: **candidate implementation contract; not activated, not independently accepted**.

PCC1 is the revision of this integration contract, **not a new wire protocol number
and not a claim of a new BFT algorithm**. It retains the deterministic weighted
Chained-QC kernel. OCF, sampled committees, AI voting, real-time consumption-based
weight changes, single-QC finality and automatic fallback consensus are excluded.

This contract covers consensus, authority ownership, persistence, execution,
resource/task state and proof migration together. It supplements the sole
[engineering plan](../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
without assigning another roadmap, changing its gate order or promoting machine
truth. The candidate JSON is
[`config/poco-convergence-v1.json`](../../../config/poco-convergence-v1.json).
Implementation and evidence gaps remain open even where requirements below say MUST.

Read together:

- this file: consensus and authority/recovery contract;
- [AI_RESOURCE_STATE_MACHINE.md](AI_RESOURCE_STATE_MACHINE.md): proposed application
  extension, limits, service discipline and settlement invariants;
- [PROOF_MIGRATION.md](PROOF_MIGRATION.md): proof classes, historical verification,
  new-instance import and upgrade refusal;
- [`formal/poco-convergence-v1`](../../../formal/poco-convergence-v1): abstract
  regression examples, not an implementation or complete model checker.

## 1. Immutable baseline and normative imports

Assessed repository source is `1d46ba8423c33a35b7923516959ce7734b442f86`, tree
`3e1c8f45924b06d5e1b363ec5e1915346f7de32b`. It is an implementation baseline,
not an accepted release. The separate live-node line was inspected at
`6064b7c680891d5ce67048b5ce6fb775f2b5a552`; its proof and signing behavior MUST NOT
be inferred to implement this contract. No branch is merged or superseded by this text.

The existing `../poco-bft-v0/` documents are incorporated for the exact version-0
signed objects, CEV0 bytes, hash domains, bounds and kernel transitions:

| Document | Baseline Git blob |
|---|---|
| `01-system-model-and-threat-model.md` | `9b7791addf496d0b88f84bb37592d099ad525eec` |
| `02-chained-qc-consensus.md` | `52deb69f59cb048563b023e82b8ff927f4fb1aac` |
| `03-wire-crypto-and-domain-separation.md` | `57d85f30c9d6ed85d081ffbf63f57d2e5dc6e2ce` |
| `04-epochs-validator-sets-and-upgrades.md` | `c08f835d295d1ca7c747ccf3c3bd1af7ae7f767c` |
| `05-poco-weights-bond-and-slashing.md` | `103c899bd5c60995429feee2848991540cf6e831` |
| `06-light-client.md` | `42609bc8e36e990f4bad64b86d687f333ac3b58b` |
| `07-invariants-and-conformance.md` | `608dc2486885e162822cbb4344b6424a827fd064` |

These are imports, not permission to change frozen bytes. A difference from a
pinned import MUST be classified and reviewed before use. A conflict affecting
signing, validity, locks, finality or activation blocks the affected profile;
there is no 'more convenient implementation wins' rule. The AI extension is a
new application-profile proposal and cannot be silently enabled under an old
runtime/parameter commitment. Its complete codec/registry/vector acceptance is
an explicit activation prerequisite, not claimed by this document.

## 2. One authority graph

The target production composition has exactly one owner of each authority:

| Owner | Sole authority | Forbidden substitutions |
|---|---|---|
| M00/M01 | canonical decoding, identity and cryptographic verification | transport JSON, caller IDs, unsigned booleans |
| M02 `trnm-consensus-core` | deterministic consensus transition via Input/Effect | live helper, simulator, RPC, model or control plane deciding a fork |
| M03 | monotonic SafetyState, SignIntent and signing authorization | application receipt, telemetry, a second signer journal with independent decisions |
| M05 | provisional local admission and handoff | claiming finality from mempool acceptance |
| M06/M07 | deterministic execution and state projections | wall-clock/model output used as deterministic validity |
| M08 | contiguous finality application and Node Commit Ledger | local vote used as finalized application history |
| M13 | verification of complete finality/anchor proofs | accepting a historical QC as a new finality capability |
| M15 | wiring and lifecycle | domain state machine hidden in constructors or CLI |
| M16/M17 | advisory control and observation/evidence | vote, unlock, finalize, activate or self-approve |

One persistent node process owns one M02 instance and one generation-fenced
M03 authority. Network, timer, storage and signer completions return to that
owner as typed inputs. No secondary live protocol can sign on the same namespace.
The simulator SHOULD use this same core with substituted adapters, while an
independent specification model tests the implementation rather than copying its
answers. A test of a different binary never certifies the production entrypoint.

Legacy `trnm-node/src/live` and simulator decision logic may be retained for
historical development evidence, but MUST NOT enter the accepted production
dependency/feature closure. The production binary name alone conveys no authority.
This commit does not perform that runtime rewiring.

## 3. System model and guarantees

The retained v0 model is authenticated partial synchrony with fixed effective
weights in an epoch, strictly less than one third Byzantine weight, collision-
resistant hashing, unforgeable signatures, deterministic execution, and non-
rollback signing decisions. During handoff the weight bound applies separately
to old and new sets. Compute providers and agents are not automatically validators.

Safety does not depend on AI availability or accurate local clocks. Post-GST
liveness additionally requires enough honest online weight, eventual delivery
and retrieval, bounded validation/storage service, and an eventually adequate
pacemaker timeout. A capped timeout profile must show its cap exceeds the
qualified worst-case service/network requirement; otherwise liveness is not claimed.
No bounded wall-clock finality is promised under permanent partition.

Consumption-derived values remain shadow observations in the first convergence
profile: they change neither membership, quorum nor leader schedule. Any later
promotion requires its separate versioned economic and governance acceptance.

## 4. Message and context contract

Use the exact v0 logical layouts and signing bytes from the imports. This table
states semantics, not a replacement serialization:

| Message/fact | Required meaning |
|---|---|
| Proposal | exact context, scheduled leader, header/body, parent justify QC, optional preceding-view TC, proposal signature |
| Vote | one authenticated block decision for the active epoch/view; no invented prevote/precommit alias |
| QC | canonical unique signers over exactly one epoch/view/height/block; weights recomputed |
| Timeout | exact timed-out view and complete referenced valid high QC |
| TC | authenticated timeout quorum and exact deterministically selected high QC |
| FinalityProofV0 | complete three-certified-block proof including signed proposal justifications and required TCs |
| Handoff/anchor | versioned old/new-set authorization; not an ordinary empty-signature QC |
| Payload result | Valid, Unavailable, or DeterministicallyInvalid for one authenticated context and request generation |
| Durable completion | exact operation, predecessor, generation, digest and fresh readback from its named authority |

Every decision binds genesis, chain, protocol, epoch, validator-set hash,
parameter hash and its object coordinates wherever required by the imported
layout. Consensus signatures remain Ed25519 and CEV0 hashes remain SHA-256.
Transport compression, JSON order and protobuf bytes are not signing preimages.
Unknown tags, duplicate fields/signers, trailing bytes, overflow, bad domains,
wrong context, excessive counts and substituted signer keys are rejected before
allocating or performing avoidable expensive work.

## 5. Quorum and durable safety state

For the exact active set, total weight W and counted signer weight S:

```text
q = floor(2 * W / 3) + 1
accept quorum iff S >= q
```

All required arithmetic is checked u128, including `2*W`. A supplied quorum
number or claimed certificate weight is not authority. Signers are unique,
canonical and members of the committed set. `2f+1` is not a substitute formula
for arbitrary validator counts or weights. Normal tests include 5, 7 and 8
validators and unequal weights, not only a four-node fixture.

Durable safety state contains the active context, current view, last-voted
watermark, exact vote/timeout decisions, high QC, locked QC, retained ancestry,
finalized tip, pending validation/sync obligations, outboxes and handoff fence.
An implementation may store projections, but no source of truth is implicit.
Local high QC, local last vote and local queue timing MUST NOT be mixed into a
replicated AppHash; these differ across honest nodes. Committed validator/parameter
state and application replay/AI resources belong in the deterministic application root.

## 6. Proposal, vote and QC transition

The proposal predicate requires the exact scheduled leader, authenticated parent,
parent height plus one, the correct parent justify QC, the imported view/TC
relations, complete bounded payload availability, and deterministic execution
matching the declared state/receipt/evidence roots. It also checks mandatory
system work and epoch constraints of the active application profile.

For a validated proposal P justified by J, the safe-vote predicate is:

```text
extends(P, locked_qc.block_id) OR J.view > locked_qc.view
```

Ancestry must actually be verified. The proposal view must exceed the durable
normal-vote watermark. An exact retry of an already recorded digest may replay
that same signature; it is not a new vote or permission to regress the watermark.
Normal vote and timeout are distinct message kinds; a timeout is not a second vote.

Processing a proposal first processes its authenticated parent justify QC under
the imported rules. Processing QC(B), after full validation, may raise high QC
and raises the lock to B's justify QC when its view is higher. Merely casting a
vote for B neither assembles QC(B) nor creates finality. State changes that will
authorize signing cross the durable boundary first.

A same-epoch/same-view pair of verified QCs for different blocks is an assumption
violation: durably retain evidence and halt signing. A benign different signer
subset certifying the same block is not that violation. Ordering uses the exact
`(view, block_id, qc_digest)` tie-break where the v0 specification requires it.

Unavailable body/parent state leaves a bounded retryable obligation. A corrupt
response from one peer does not classify every copy of that header as invalid.
Deterministic invalidity of an uncertified proposal rejects it without crashing
the chain. A fully authenticated QC naming a deterministically invalid result,
or conflicting terminal execution results for the same context, is a durable
safety halt. Local overload is Unavailable, not consensus invalidity.

## 7. Pacemaker, timeout and stale-message behavior

A local timer creates at most one durable timeout decision for an epoch/view,
including its then-authorized high QC. A valid TC requires the quorum, complete
referenced QCs and exact maximum selection defined in v0. A bare future view or
unverified timeout never advances safety state.

TC processing can durably advance view while a referenced dependency is still
being fetched, but cannot vote from, adopt or finalize unvalidated ancestry.
The imported finalized-subsumed rules apply before requesting already-pruned
history. A selected obsolete/conflicting finalized prefix cannot be extended;
wait for justified progress rather than invent another QC for the TC.

A TC is not a QC, finality proof or independent unlock permission. A timeout
never releases a application budget reservation or reverses a finalized receipt.
Network partitions may delay progress; healing must converge through verified
QC/TC/sync inputs without operator editing of locks or signing watermarks.

## 8. Exact finality predicate

Retain the v0 three-certified-block predicate. For b0 <- b1 <- b2, verify three
certifying QCs q0/q1/q2, all signed proposal envelopes, one common context, exact
parent links, consecutive heights, strictly increasing views, exact embedded
justify-QC digests, and each required skipped-view TC. Views need not be consecutive
under the imported v0 rule. An implementation MUST NOT silently substitute a
new two-chain, three-consecutive-view or single-QC predicate.

Learning and validating q2 finalizes b0 and every not-yet-finalized ancestor.
It does not finalize b1/b2. Synthetic anchors do not count as any ordinary QC.
Ordinary finality never spans an epoch or protocol change. A changed finality
rule requires a separately versioned proof and explicit migration.

Finality application is ancestor-ordered and idempotent. A delayed certificate
cannot replace a finalized state. The verification of a cryptographic proof,
the application of the resulting state and publication of its receipt are
separate durable facts, not interchangeable success labels.

## 9. Two authority lifecycles, not a circular mega-transaction

### Signing lifecycle

```text
validated input / safe decision
 -> IntentDurable
 -> SignatureRecorded
 -> VotePublished
```

IntentDurable atomically records resulting SafetyState, normal-vote watermark
where relevant, exact SignIntent and outbound identity before signature release.
SignatureRecorded requires independent signer policy enforcement and exact durable
readback. The vote/timeout may be sent immediately after this point: it MUST NOT
wait for that block's finality. Publication retries are idempotent and cannot
cause a different signing decision. Lost signer response means read back the
same digest, not create a new request namespace.

### Application-finality lifecycle

```text
FinalityVerified
 -> CommitIntentDurable
 -> ApplicationApplied
 -> CommitRecorded
 -> CheckpointConfirmed
 -> ReceiptPublished
```

CommitIntentDurable binds exact finality proof, next ancestor, pre/post roots,
ordered mutation and receipt/event digests, context and predecessor ledger row.
ApplicationApplied requires fresh readback of exact application target state.
CommitRecorded records that readback in the coordinator's append-only ledger.
CheckpointConfirmed reconciles the configured checkpoint/anti-rollback profile.
Only then may a finalized receipt or authoritative RPC root be published.

A single append-only coordinator may record both lifecycles, but votes do not
need a finality receipt and application finality does not require inventing a
new local signature. A valid finality proof may be received by a node that did
not vote. The former linear Prepared-to-OutboundPublished candidate sequence
must not be interpreted as requiring FinalityApplied before every vote send.

## 10. Atomicity, recovery and publication

Each durable record binds chain/context, node identity, generation, sequence,
previous-record digest, operation kind, exact source and target roots, intent or
proof digest and receipt digest. There is one fenced writer. Record identifiers
are derived from these facts, not supplied as opaque caller assertions.

Safety decisions/sign intents need a real atomic durability boundary. Across
separate stores, use a durable intent plus idempotent projections and fresh exact
readback; do not claim a distributed atomic transaction merely because all writes
usually succeed. Replay is allowed only when source, target and operation identity
are exact. Same height with another root, missing ancestry, regressed generation,
watermark disagreement or ambiguous target fails before signing/publication.

Recovery order is identity/profile -> exclusive writer fencing -> independent
rollback anchor/signer reconciliation -> coordinator log -> application/projections
-> bounded validated ancestry -> consensus resume -> network publication. Bounded
authenticated recovery downloads may precede voting eligibility but never gain
signing authority. Ordinary catch-up unavailability is retried; it is not confused
with corrupt authority state requiring operator recovery.

Required crash cuts include every side of every durable stage, successful HSM
signing with lost reply, application commit with lost reply, checkpoint CAS with
lost reply, disk full, torn WAL, partial sidecars, duplicate callback, stale
generation, process takeover and coherent disk rollback. Local hash chains,
SQLite FULL and cached acknowledgements do not prove resistance to coherent
rollback. The external monotonic anchor must be outside that rollback domain.

A speculative application overlay is not finalized history. It is keyed by
parent/block/context and is either replayable from finality or retained with its
exact obligation. No vote response may overwrite the canonical finalized tip.
Shutdown durably drains or retains outstanding intents; upgrade never resets them.

## 11. Execution, availability and bounded work

Keep execution deterministic and parent-relative. Parallel scheduling is allowed
only if sequential and 1/2/4/8-worker outcomes match for state, receipts, fees and
events, including conflicts, cancellation and restart. Actual accesses are checked;
undeclared accesses cannot escape resource/conflict accounting. Hidden shared
budgets and nonce lanes are real conflicts.

Use incremental writes/root updates and immutable speculative overlays in the
target runtime; do not require full-state load/delete/rewrite per block. This is
an execution/storage change, not a license to alter the QC finality predicate.
Validation of a bounded submitted proof may occur before voting. Long model
execution and proof generation remain off-chain, outside that critical path.

A hash is not data availability. Before voting, the imported payload predicate
requires the complete body and deterministic state/proof dependencies. Availability
certificates for AI artifacts have separate retention/retrieval responsibilities.
Their failure affects task processing according to the pinned profile, not an
arbitrary rewriting of block validity. Availability workers cannot mint finality.

Per-peer/global caps cover bytes before allocation, decompression, signatures,
retained ancestry/QCs/TCs, validation work, recovery scans and disk/outbox growth.
Reserve control/recovery capacity separately from task submission. Batching and
pipelining do not waive deterministic validity or durable authority barriers.

## 12. Empty blocks and epoch continuity

The proposer can produce ordinary empty-user blocks. When finality descendants,
mandatory system work or task deadlines need progress, zero user submissions must
not stop the pacemaker. 'Empty user payload' does not mean omitting mandatory
system transitions. Completing a three-chain flush may require further proposals
without new user transactions.

Task time is the height of the canonical state transition being executed, never
a validator's locally observed finalized height or wall clock. The resulting facts
become usable externally only with finality. This makes proposal execution stable
across nodes that learn finality at different times.

Retain the imported checkpoint/seal and old/new-set handoff rules. No ordinary
three-chain crosses that boundary. New signing authority requires the complete
old finalized checkpoint and separately authenticated old/new handoff roles.
Old signers durably fence the handoff; new signers import exact authorization
without resetting historical evidence. The proposed AI state, unsettled escrow,
profile versions, deadlines and retention responsibilities are included in the
handoff state, not silently deleted. If a target cannot verify an outstanding
profile, it must drain/cancel under the old rules or reject the upgrade.

## 13. Proof obligations and acceptance

Required obligations are quorum intersection; safe vote/lock preservation; no
conflicting finality; justified post-GST view progress; idle finality flush;
crash/recovery refinement; epoch-handoff safety; deterministic state equivalence;
resource and asset conservation; finite terminal processing; and typed proof
migration. Existing HotStuff-family literature is background, not a proof of this
repository's particular transitions.

The executable testkit covers only small quorum sets, proof relationships,
abstract signing stages and a restricted resource ledger. It omits cryptography,
network schedules, full safe-vote/TC/epoch transitions, Rust calls and disk/HSM
behavior. A passing testkit is not complete formal verification or production
acceptance. Unsupported runtime behavior must remain explicitly disabled.

Acceptance additionally needs exact-source Rust/all-target tests, independent
verifier vectors, retained negative cases, same-core real-binary fault campaigns,
physical recovery, multi-host load and independent review on the same release.
Report admission, order, result and settlement rates separately; include p50/p95/p99,
rejection/cancellation ratios, resource high-water marks, growing state and recovery
cost. No quantitative advantage over another protocol is claimed here.

The existing release gates and signed activation process remain authoritative.
No production, testnet, release, migration or 'all gaps closed' flag is changed.

## 14. Background sources

The retained Chained-QC family is contextualized by Yin et al., *HotStuff: BFT
Consensus in the Lens of Blockchain*, arXiv:1803.05069v6 (2019). Deterministic
parallel execution with preset order is contextualized by Gelashvili et al.,
*Block-STM*, arXiv:2203.06871. Neither source establishes this implementation's
correctness or supplies its benchmark results.
