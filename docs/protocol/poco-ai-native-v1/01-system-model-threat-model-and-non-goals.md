# 01 — System model, threat model, and non-goals

Status: **DRAFT / design-only / not implemented / not activated**

## 1. System model

PoCO AI-native v1 is a replicated coordination and settlement protocol around
off-chain AI execution and off-chain artifacts. A fixed, epoch-scoped weighted
validator set runs PoCO-Order and deterministically executes the coordination
state machine. Every order-finalized block selects one immutable
`stack_profile_hash`, active validator-set commitment, consensus-parameter
commitment, and runtime-profile commitment.

The five planes are:

- **PoCO-Agent**: agent identity, key authority, capabilities, revocation,
  budgets, rate limits, and nonce lanes.
- **PoCO-Market**: task demand/supply, bids, leases, escrow, deadlines,
  checkpoint/resume, migration, cancellation, timeout, and refund.
- **PoCO-Compute**: off-chain execution, result receipts, verification profiles,
  evidence, challenges, and result maturity.
- **PoCO-DA**: durable dissemination and bounded retention for transaction
  batches and separately classified AI artifacts/evidence.
- **PoCO-Coordination**: deterministic state transitions, fees and settlement;
  its PoCO-Order subprotocol provides total order and order finality.

The logical planes MAY share implementation components, but authority cannot be
inferred across them. An order QC is not an availability certificate, an
availability certificate is not a result-validity proof, a verification receipt
is not settlement, and settlement is not a consensus vote.

## 2. Replicated and non-replicated work

Every validator replicates and deterministically validates:

- v1 transaction batches referenced by proposed blocks;
- all application objects and transitions required to reproduce committed
  state, receipt, event, and evidence roots;
- verification results whose active profile specifies deterministic validator
  verification; and
- objective challenge and settlement transitions selected by the stack profile.

Validators do not ordinarily replicate:

- model weights, datasets, private prompts, private context, long outputs, or
  training checkpoints;
- nondeterministic floating-point/GPU inference;
- private tool/API calls or external-world facts; or
- evidence that the selected verification profile delegates to a separately
  named verifier set, TEE, ZK statement, or optimistic challenge process.

Such objects remain off-chain behind content commitments, explicit DA
contracts, and versioned verification semantics. A profile that requires a
validator to retrieve or re-execute an artifact MUST state exact canonical
inputs, determinism requirements, resource bounds, and failure classification.

## 3. Network and timing model

PoCO-Order is partially synchronous. Before an unknown Global Stabilization
Time, an adversary may delay, reorder, duplicate, selectively deliver, or drop
messages for an unbounded interval. After GST, messages among correct online
validators are eventually delivered within an unknown finite bound. Local
clocks and timers drive admission and liveness; they are not independent sources
of consensus truth.

PoCO-DA dissemination and artifact retrieval may proceed asynchronously with
PoCO-Order. Availability failure can delay a positive vote or a profile-specific
verification transition. It cannot authorize a fabricated successful result.
This version makes no unconditional asynchronous-liveness claim.

## 4. Fault and trust model

Let `W_e` be total active voting weight and `B_e` Byzantine voting weight in
epoch `e`. PoCO-Order safety assumes:

```text
3 * B_e < W_e
quorum(W_e) = floor(2 * W_e / 3) + 1
```

Both expressions use checked unsigned integer arithmetic. During a validator-set
handoff the Byzantine bound applies separately to the old and new sets.

A Byzantine validator may equivocate, withhold proposals, batches, votes,
timeouts, handoff signatures or artifacts; advertise data it later refuses to
serve; submit malformed objects; clone or roll back a signer; censor selected
tasks; and coordinate market, consumption, DA, or verification identities.

The protocol additionally distinguishes:

- **DA attesters**, whose exact set and quorum are profile-committed and whose
  certificate only attests the defined durable availability obligation;
- **compute providers**, who may return arbitrary results, receipts, evidence,
  or no result;
- **verification authorities**, selected by each `VerificationProfile`, which
  may be validators, a separately committed verifier set, a cryptographic
  verifier, a TEE trust root, an optimistic challenge process, or a declared
  subjective evaluator policy; and
- **agents and sponsors**, whose keys or capabilities may be compromised,
  replayed, collusive, revoked, budget-exhausted, or unavailable.

A fault bound for one role does not transfer to another. In particular, the BFT
less-than-one-third assumption does not prove the independence of AI-result
evaluators, DA providers, consumers, or compute providers.

## 5. Adversary capabilities

The adversary may:

- replay values across chains, profiles, protocols, tasks, leases, results,
  nonce lanes, verification modes, DA namespaces, and challenge instances;
- present alternate encodings, duplicate map keys, reordered collections,
  decompression bombs, length overflows, deeply nested values, and high-cost
  invalid proofs;
- exploit parser, scheduler, numeric, cryptographic-backend, or runtime
  differences;
- cause process termination, host reboot, disk-full, fsync uncertainty,
  database rollback, stale snapshot restore, signer rollback, and mixed-store
  cuts;
- create Sybil agents/providers/consumers, reciprocal demand, wash consumption,
  related-party trades, dishonest metering, griefing challenges, and cartel
  behavior;
- withhold transaction batches, artifacts, chunks, proofs, checkpoints, state
  sync data, or old validator-set information;
- submit confidential artifacts with guessable commitments and correlate public
  metadata; and
- front-run, reorder, censor, or extract value from ordinary public-lane tasks
  where a stronger fairness lane is not explicitly selected.

## 6. Honest participant obligations

An honest validator MUST:

1. verify canonical version/profile/chain context before expensive work;
2. maintain monotonic durable consensus and signer state and persist before
   releasing every consensus signature;
3. retrieve and verify every complete referenced transaction batch before a
   positive vote;
4. execute the exact authorized deterministic runtime from the exact parent
   state and reproduce all committed roots;
5. respect capability, revocation, nonce-lane, budget, escrow, verification,
   challenge, DA, fee, and settlement transitions exactly;
6. distinguish `Unavailable` from deterministic invalidity and avoid poisoning
   a commitment merely because one source supplied wrong or missing bytes;
7. fail closed on unknown versions, ambiguous encodings, arithmetic overflow,
   corrupted durable state, unresolved safety-store disagreement, or an
   unauthenticated predecessor;
8. count no duplicate signer or weight and use only the exact committed role set;
9. retain or delegate the history and evidence required by all active trusting,
   challenge, slash, DA-retention, and state-sync windows; and
10. avoid claiming result or settlement finality merely from order finality.

An honest DA attester MUST durably store the exact required bytes before signing
and MUST serve or repair them for the certificate's full retention obligation.
An honest verifier MUST follow only the exact selected verification profile and
MUST NOT reinterpret `unavailable` or `indeterminate` as valid.

## 7. Safety and liveness claims

Subject to the cryptographic, deterministic-execution, durable-signing, profile,
and Byzantine-weight assumptions, two correct validators cannot order-finalize
conflicting blocks. This is the retained weighted chained-HotStuff claim shape,
not a new proof supplied by this draft.

Result and settlement safety are profile-conditional. A result becomes
result-final only through the exact selected verification and challenge state
machine. A settlement becomes settlement-final only after its result and all
escrow/challenge consequences reach the terminal conditions defined in
documents 04, 05, and 08.

Post-GST liveness additionally requires enough correct voting weight online, an
eventually correct leader, growing timeouts, retrievable required transaction
batches, an executable authorized runtime, sufficient application/DA capacity,
and any required verification or handoff quorum. A valid task, result, DA
certificate, or next validator set can safely stall if its mandatory dependency
or quorum is unavailable.

## 8. Explicit non-goals

Protocol v1 does not claim or attempt to provide:

- on-chain storage of general model weights, datasets, prompts, contexts, or
  outputs;
- deterministic consensus execution of arbitrary AI inference, training, web
  access, or tool calls;
- proof that an output is useful, factually true, unbiased, lawful, novel, or
  produced at a fair price;
- proof of human uniqueness, organizational independence, or Sybil resistance
  from signatures, receipts, stake, or consumption alone;
- privacy from a hash, encryption-key custody, traffic-analysis resistance, or
  general confidential computing for the default lane;
- perpetual retrieval or archival availability from an order QC or bounded DA
  certificate;
- automatic rollback or reorganization of an order-finalized block after a
  result challenge;
- unconditional asynchronous liveness, guaranteed task completion, or guaranteed
  artifact retrieval against an out-of-assumption quorum;
- universal censorship resistance, strong fairness, or MEV elimination for all
  tasks;
- production BLS/threshold signatures, sampled validator committees, sharding,
  DAG consensus, erasure coding, or data-availability sampling in the reference
  profile;
- stable mainnet fees, slash fractions, verifier economics, related-party
  policy, or PoCO economic weights; or
- an implementation, audit, deployment, throughput result, public-testnet
  candidate, or mainnet candidate.

Stronger privacy, fairness, asynchronous fallback, DAG ordering, cryptographic
aggregation, or DA encoding may be introduced only by an explicit versioned
profile whose semantics are already permitted by the protocol, or by a later
protocol version when signed bytes or validity rules change.

## 9. Deferred threat work

Adaptive corruptions, verifier-set capture, TEE supply-chain compromise, proof
system soundness per backend, related-party classification, model/data licensing,
artifact deletion law, confidential-lane key recovery, correlated slashing,
economic griefing equilibria, mainnet parameter calibration, and external
consensus/cryptography/economic review remain required before any affected
production activation.
