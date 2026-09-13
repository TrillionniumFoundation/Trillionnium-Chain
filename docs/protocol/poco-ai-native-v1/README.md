# PoCO AI-native protocol stack v1

Status: **DRAFT / design-only / not implemented / not activated**

Protocol version: `1`

Canonical codec: `CEV1`

This directory defines the proposed PoCO AI-native protocol stack v1. It is a
new protocol-version design, not an amendment to the frozen PoCO-BFT v0 wire or
validity rules. No file in this directory authorizes network signing,
deployment, economic-weight activation, public-testnet use, or a readiness
claim.

## 1. Scope

The stack coordinates verifiable AI work without requiring validators to store
model weights, private prompts, datasets, or long outputs, and without requiring
them to repeat nondeterministic GPU inference. It consists of five logical
planes:

1. **PoCO-Agent** — identities, root and session keys, delegated capabilities,
   budgets, revocation, and parallel nonce lanes.
2. **PoCO-Market** — task offers, bids, leases, escrow, deadlines,
   checkpoint/resume, migration, cancellation, timeout, and refund.
3. **PoCO-Compute** — off-chain execution receipts, versioned verification
   profiles, evidence, challenges, and result/settlement maturity.
4. **PoCO-DA** — separately namespaced transaction-batch and AI-artifact data
   availability, durable availability attestations, retrieval, repair,
   retention, expiry, and withholding evidence.
5. **PoCO-Coordination** — deterministic application coordination and
   settlement plus **PoCO-Order**, the weighted chained-HotStuff ordering and
   order-finality kernel.

The planes are logical protocol boundaries. They need not be separate
processes, databases, networks, or validator sets. A cross-plane transition is
valid only when its exact inputs and predecessor versions are authenticated by
the finalized application state selected by PoCO-Order.

## 2. Normative language and status

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** express proposed normative requirements for protocol version 1.
They do not imply implementation or activation.

The numbered protocol documents are the draft candidate normative prose.
`spec-manifest.toml`, `parameters.toml`, the reference-target profile files,
logical-schema inventory, and vector/formal/transport placeholders are
machine-readable design/evidence ledgers only; they are deliberately not
normative CEV1 profile or parameter preimages today. They do not become frozen
authority until exact schemas/values replace those ledgers and the gates in
document 10 pass. Architecture decisions, delivery
plans, implementation-gap registers, runbooks, formal models, benchmarks, and
test reports are informative or evidence unless a normative document
incorporates an exact versioned digest.

If normative artifacts disagree on consensus-affecting meaning, the v1 draft is
inconsistent and MUST NOT be implemented or activated. Implementations do not
resolve such a conflict by choosing prose, code, a more specific passage, or a
locally convenient interpretation.

## 3. Normative document set

1. [System model, threat model, and non-goals](01-system-model-threat-model-and-non-goals.md)
2. [Versioning, stack profile, wire, and cryptography](02-versioning-chain-profile-wire-and-crypto.md)
3. [Agent identity, capabilities, and nonce lanes](03-agent-identity-capabilities-and-nonce-lanes.md)
4. [Market, task, lease, escrow, and lifecycle](04-market-task-lease-escrow-and-lifecycle.md)
5. [Compute receipts, verification, and challenges](05-compute-receipts-verification-and-challenges.md)
6. [Certified data availability](06-certified-data-availability.md)
7. [Order consensus, epochs, and finality](07-order-consensus-epochs-and-finality.md)
8. [Coordination, settlement, execution, and fees](08-coordination-settlement-execution-and-fees.md)
9. [Light client, state sync, and upgrades](09-light-client-state-sync-and-upgrades.md)
10. [Invariants, formal obligations, and conformance](10-invariants-formal-obligations-and-conformance.md)

The machine-readable draft consists of:

- `spec-manifest.toml` — normative-artifact inventory and draft-state truth;
- `parameters.toml` — non-production design-target switches, not a complete
  `ConsensusParametersV1` or hash preimage;
- `profiles/stack-reference-shadow.toml` — reference benchmark/architecture
  target metadata, not a `StackProfileV1` body;
- `profiles/verification-registry-reference.toml` — verification-class status
  inventory, not complete `VerificationProfileBodyV1` values or a registry
  root; and
- `schema/` plus `vectors/` — logical schemas and independent conformance
  fixtures; and
- `formal/quint/poco-ai-native-v1/` — bounded candidate models for the
  weighted-order kernel, timeout-lock discipline, and epoch handoff/activation,
  plus retained failing mutants. These are finite evidence, not a complete
  formal proof or normative freeze.

Until every listed artifact exists, is mutually consistent, and passes the
v1 conformance gates, the specification status remains `DRAFT`.

Before freeze, `parameters.toml` must be replaced or complemented by an exact
bounded `ConsensusParametersV1` value covering every consensus-visible length,
count, nesting, epoch, view, timeout, transaction/block/batch/chunk, queue,
retention, challenge, nonce-lane, proof, and state-sync bound. Likewise, an
exact `StackProfileV1` and complete verification-registry entries must be
materialized, canonically hashed, and independently vectored. Two
implementations may not infer missing values from today's target ledgers.

## 4. Relationship to PoCO-BFT v0

PoCO-BFT v0 remains a frozen safety and persistence baseline. V0 requires a
complete proposal payload and deterministic execution before Vote. V1 changes
the signed header, proposal validity, availability predicate, application
objects, receipts, profiles, proof surfaces, and light-client rules. Therefore:

- v1 uses `protocol_version = 1`, `CEV1`, new domains, schemas, and vectors;
- a v0 signature, QC, TC, handoff proof, block, certificate, profile, or
  application object is never valid as a v1 object by inference;
- v0 data is not re-encoded into v1 and treated as signed by the original
  signer;
- coexistence or activation is possible only through the v1 upgrade contract
  or a fresh v1 genesis; and
- no v1 document silently changes a frozen v0 choice.

V1 initially retains the established weighted chained-HotStuff safety shape:
weighted `floor(2W/3)+1` QCs, lock-based safe voting, timeout certificates that
neither unlock nor finalize by themselves, three-certified-block order
finality, persist-before-sign, and dual-quorum epoch handoff. This draft does
not claim a new BFT theorem. A future change to the quorum, lock, timeout, or
finality mathematics requires another protocol version and its own formal and
independent review.

## 5. Common identity and finality rules

Every consensus-affecting v1 object binds its `schema_version`, `genesis_hash`,
`chain_id`, `protocol_version = 1`, and `stack_profile_hash`, either directly or
through a directly authenticated parent. Every object ID is a typed `Hash32`
derived from its exact `CEV1` logical preimage and a unique domain; raw hashes
MUST NOT be substituted across object kinds.

The stack distinguishes three facts:

- **Order finality**: a block and its application transition are irreversible
  under the PoCO-Order safety assumptions.
- **Result finality**: a task result has met its selected verification profile
  and no remaining protocol transition can invalidate that result.
- **Settlement finality**: the result's escrow/payment allocation and all
  challenge consequences are finalized application state.

Order finality does not imply result correctness, artifact availability beyond
its certificate contract, challenge-window completion, or payment maturity. A
later successful challenge MUST be represented by a forward order-finalized
state transition; it MUST NOT reorg an order-finalized block.

## 6. Draft invariants

The complete invariant set is defined in document 10. The following boundaries
apply across this draft:

- unknown protocol, schema, stack-profile, verification-profile, meter, or
  evidence versions fail closed;
- all counters, balances, weights, lengths, heights, and fee calculations use
  checked integer arithmetic;
- canonical ordering is verified, never produced by sorting untrusted input and
  accepting the normalized result;
- local overload may delay or return an explicitly retryable unavailable result,
  but cannot fabricate deterministic invalidity or change an application root;
- session-key revocation, budget accounting, nonce-lane advancement, escrow
  movement, verification decisions, challenge outcomes, settlement, and PoCO
  eligibility are deterministic application state;
- DA signatures require durable store-before-attest and are not consensus votes;
- consensus signatures require persist-before-sign and an independently
  monotonic signer/safety checkpoint;
- validators retrieve and deterministically validate complete transaction
  batches before voting, while AI artifacts are fetched only as required by
  their selected verification profile; and
- only matured, settlement-final, challenge-closed, policy-eligible consumption
  may contribute to a later PoCO validator-weight snapshot.

## 7. Explicit non-claims

This draft does not establish implementation, interoperability, formal proof,
audit completion, economic security, privacy, censorship resistance, fair
ordering, sustained throughput, unit cost, public-testnet readiness, or mainnet
readiness. It does not activate PoCO economic voting power. It does not prove
that an AI output is useful, truthful, unbiased, legally authorized, or fairly
priced. It does not make hashes hide low-entropy data, and it does not make a DA
certificate a perpetual archival promise.
