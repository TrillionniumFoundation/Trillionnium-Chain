# PoCO AI-native v1 vectors boundary

Status: **one candidate CEV1 foundation/order-kernel corpus exists; the global
v1 conformance corpus remains incomplete and non-normative**

`cev1-foundation-order-kernel-v1.json` contains positive and negative vectors
only for the closed type list in its paired schema. The standard-library
checker at `scripts/ci/check_poco_ai_native_v1_foundation_vectors.py` validates
exact little-endian encoding, bounds, end-of-input, contexts, typed domains,
ordered signer sets, checked quorum arithmetic, Vote/QC, Timeout/TC, and the
minimum activation/handoff anchors. Signature bytes are opaque deterministic
carriers; this corpus makes no Ed25519 or other cryptographic interoperability
claim. The current deterministic fixture contains 27 positive cases, one
ordered-root derivation, and 24 negative cases; these counts are enforced by
the design truth gate and do not imply a global conformance corpus.

The separately authored, standard-library-only parser at
`scripts/ci/check_poco_ai_native_v1_foundation_independent.py` also decodes,
re-encodes, semantically validates, and reproduces every listed digest without
importing the corpus authoring checker or any TRNM implementation crate. It
must reject all 24 negative fixtures and its own malformed-input mutants. This
closes an independent-parser evidence tranche for this listed type set only;
because the corpus still uses opaque signature carriers, it is not crypto
interoperability, light-client, upgrade, global schema, or freeze evidence.

`cev1-order-signature-crypto-v1.json` is a separate bounded strict-Ed25519 order-signature corpus.
Its independently authored standard-library checker
reconstructs the four-validator definition and descriptor, reproduces their
CEV1 digests, re-encodes one Vote and two distinct Timeout signing statements,
verifies one direct Vote claim, four QC signature claims, and four TC entries
whose complete statements are independently encoded, domain-hashed, and
verified against their own validator keys. It binds the foundation TC context
and justification projection, enforces strict signer ordering and weighted
quorum, and rejects 18 domain/key/signature/statement/canonicality/quorum
mutants. QC claims use the schema's `voter_id`; TC claims use `validator_id`
and carry the exact four-field `TimeoutSignatureEntryV1` shape. This closes only the listed bounded
crypto/domain tranche: it is not full crypto interoperability, full QC/TC wire
semantics, a light client, an upgrade verifier, a normative freeze, activation,
or release evidence.

There are still no complete proposal, transaction/DA, state-transition,
availability-certificate, verification-profile, settlement, state-sync,
or complete same-version/cross-version light-client corpora.

`cev1-order-finality-light-client-kernel-v1.json` is a bounded same-version
light-client corpus, not a complete light-client corpus. It carries raw CEV1
for one externally authenticated fresh-genesis trust bundle; FreshGenesis and
first-Ordinary proofs; and one exact checkpoint -> dual-quorum handoff ->
V1HandoffFirst -> Ordinary trust progression. The first Ordinary path includes
one exact skipped-view `TimeoutCertificateV1`. A separately authored
stdlib-only decoder exact-reencodes all five top-level byte strings,
independently recomputes the old/new committed validator sets, parameters,
descriptors, BlockIds, QC/TC/checkpoint/handoff/proof IDs, verifies 60
strict-Ed25519 QC signatures, four timeout signatures, and eight role-specific
handoff signatures with independent old/new weighted quorums, exact-compares
the imported foundation structural snapshot, and checks all decidable
committed parameters and FreshGenesis empty ordered roots. It rejects 212
exact-error negative mutants; every negative fixture declares and must hit one
exact rejection code. The shell gate cross-checks all 72 signatures with
OpenSSL and requires a mutated signature to fail. More than one handoff,
arbitrary-length trust-path iteration, activation, multiple skipped views,
EpochStart TC parents, other proof classes, and second-implementation
interoperability remain absent, so `light_client_spec_complete=false` remains
authoritative.

`cev1-order-trust-path-iterator-v1.json` composes that one-step authority into
a bounded path without reinterpreting its FreshGenesis-only anchor tag. It
carries four positive raw 0/1/2/3-hop paths, plus exact replay and
prefix-append determinism controls. Position zero is the existing raw epoch
transition; positions one and two are the new versioned checkpoint-anchored
carrier. The same independent stdlib checker exact-reencodes every byte string,
binds every intermediate canonical state, and requires all 63 rejection
mutants to hit their declared error code. It also binds the global
length-prefixed `DigestV1` rule and recomputes the exact one-item protocol
sidecar root for every `V1HandoffFirst`, including the complete handoff wrapper
and both signature lists. The inventory is 63 mutants after adding empty,
wrong, and different-wrapper sidecar-root controls plus 11 epoch-start TC
controls. Its three-hop path includes one V1HandoffFirst at
`initial_new_view+1`, authenticated by the exact handoff safe parent, absent
lock, latest checkpoint anchor, and immediate TC target. It verifies 88 QC,
four TC, and 24 role-specific handoff signatures; the shell gate cross-checks all 116
with OpenSSL and rejects a mutated control. This is bounded candidate
evidence, not v0 activation, weak-subjectivity selection, arbitrary-length
iteration, complete wire/crypto conformance, a second implementation, global
light-client completeness, normative freeze, implementation, or activation.

`cev1-order-ordinary-finality-advance-v1.json` contains four positive controls
for one source proof and two sequential same-epoch Ordinary advances, plus 52
error-code-exact rejection mutants. The independent stdlib checker derives the
source trusted state from raw FreshGenesis/Ordinary proof bytes, requires the
first successor to consume the trusted certified-head QC, and permits at most
one skipped view per advance under a complete checkpoint-anchored TC. It
recomputes all block, QC, TC and state identifiers and verifies 40 QC plus
eight TC signatures; the shell gate cross-checks all 48 with OpenSSL and
rejects a mutated signature. The corpus does not execute payloads, admit
arbitrary history or epoch changes, complete the wire/crypto inventory, provide
a second implementation, or change any global light-client, freeze,
implementation, or activation bit.

`cev1-weak-subjectivity-checkpoint-renewal-v1.json` carries the exact same
three-hop raw path plus one raw renewal envelope. The independent checker
derives both anchors from authenticated checkpoint objects, exact-reencodes all
bytes, binds chain/genesis/protocol lineage, checkpoint epoch, validator set,
parameters and application/schema roots, and checks the prior anchor against
positive epoch/block age windows. Its two positive controls and 45
error-code-exact mutants include rollback, insufficient advance, expired
anchor, same-height conflict, context/authority/root substitution, and terminal
state/checkpoint substitution. It does not authenticate an operator or
governance decision, select an arbitrary network checkpoint, prove wall-clock
age, lift the three-hop bound, or establish global light-client completeness,
freeze, implementation, or activation.

`v0-to-v1-activation-kernel-v1.json` is a separate bounded activation corpus:
one positive fixture and 31 rejection mutations. Its stdlib-only verifier
recomputes the exact listed CEV0 old-set and CEV1 new-set descriptor hashes,
rejects duplicate IDs/keys, independently derives both weighted quorums,
checks role-separated strict-Ed25519 signatures, and binds the projected plan,
migration receipt, activation statement/anchor, and empty first-v1 block at
the unique next epoch boundary. The corpus deliberately does not verify the
opaque frozen-v0 governance/finality/handoff proof, execute migration, prove
the full mapping or header, implement a light client, or establish durability.
It is candidate upgrade evidence, not a complete upgrade contract.

`cev1-cross-version-activation-proof-kernel-v1.json` is a second, cumulative
activation corpus, not an alternative to the relation kernel. It contains one
positive raw CEV1 proof and 44 exact-error rejection mutants. Its stdlib-only
checker reruns the source activation kernel, exact-decodes and re-encodes raw
frozen-v0 `UpgradePlanV0` field 12 under the v0 domain, rejects presence of
frozen fields 13 or 14 on the cross-version path, verifies the separately
versioned CEV1 `V0ActivationFirst` proposal carrier, and verifies all twelve
QC signatures in its direct three-chain finality proof. The shell gate
cross-checks the proposer plus twelve QC signatures with OpenSSL and requires
a mutated signature to fail. The corpus does not prove governance-state
membership/finality for the plan, complete frozen-v0 authority, migration
execution, full `OrderProposalV1` admission/transport, durability, or an
upgrade-contract freeze, so `upgrade_contract_complete=false` remains
authoritative.

PoCO-BFT v0 vectors cannot be relabelled as PoCO AI-native v1 evidence. Before a
v1 specification freeze, the complete corpus must bind exact canonical bytes, hashes,
domain separation, bounds, rejection cases, upgrade behavior, and independent
reproduction. Until then `conformance_vectors_complete=false`, implementation
and activation remain false, and this directory provides no readiness evidence.

`cev1-transaction-batch-da-kernel-v1.json` inventories the bounded executable
G2A candidate: twelve positive behaviors, twenty negative classes, and seven
transaction/reopen cases. The Rust tests independently exercise deterministic
batch/chunk derivation, exact replay, author/queue quotas, unsigned attestation
journal recovery and high-watermark non-reuse, immutable manifest signatures,
strict signatures, checked weighted quorum, retrieval, tamper-to-repair,
monotonic retention, and test-only authorized durable GC. This is a test inventory,
not a complete raw CEV1 interoperability corpus; global
`conformance_vectors_complete` therefore remains false.

`cev1-agent-market-kernel-v1.json` inventories the bounded executable G2B
candidate: thirteen positive behaviors, 58 rejection classes and six
crash/reopen classes. Rust tests cover capability/session admission, atomic
lane creation, independent lanes against one budget, funded task/escrow, bid,
five-object lease acceptance, Lease-to-Task-scoped provider activation, exact
scope enforcement, monotonic Order-finalized height/deadline/rate-window
behavior, exact replay, immutable reopen preflight, self-consistent row
substitution rejection and all three commit-uncertain outcomes.
This remains a local kernel inventory rather than complete raw CEV1 or
`AgentTransactionV1` interoperability; global vector completeness,
implementation, freeze, production candidate and activation stay false.

`cev1-verify-challenge-kernel-v1.json` inventories the bounded executable G2C
candidate: sixteen positive behaviors, thirty rejection classes, and six
crash/reopen classes for StakeQuorum receipt/evaluation/single-challenge state.
The inventory now covers unique verifier identities rather than claim-ID
counting, exact claim statement/evidence/sequence binding, committed trust-hash
recomputation, a fixed four-member verifier set, checked transition arithmetic,
a 64-entry evidence cap, monotonic Order context/deadline behavior, duplicate
trust keys, immutable existing-store preflight, and self-consistent
state/journal row substitutions against durable roots.
It is a local candidate inventory, not a complete Compute-plane/raw-CEV1 or
interoperability corpus; every global G2/freeze/production/activation claim is false.

`cev1-object-mvcc-fee-kernel-v1.json` inventories the bounded executable G2D
candidate: twelve positive behaviors, thirty-nine rejection classes, and six
crash/reopen classes. The corpus covers version conflicts and canonical retry,
all three receipt outcomes, exact read/write and intermediate roots, four
resource dimensions, checked fee ceilings/splits, per-transaction fee deltas,
one block-end destination credit, replay, schema/sidecar refusal and durable
root tamper. It is a local candidate inventory, not global transaction wire,
parallel execution, state-proof, complete fee economics, Node or G2 evidence.

`cev1-consumption-settlement-kernel-v1.json` inventories the bounded G2E
candidate: ten positive behaviors, 56 rejection classes and six crash/reopen
classes. Rust tests cover strict bilateral signatures, receipt sequence and
period continuity, cumulative usage/charge recomputation, exact complete
rollup assignment, challenge-window maturity, derived provider/refund/protocol
deltas, single-asset conservation, one-shot settlement, exact replay,
source/target/fence crash outcomes and deterministic full-journal replay. This
is local candidate evidence only; Agent/DA/Result/Order/MVCC authority,
multi-asset policy completeness, Node integration, global G2 completion,
freeze, production candidacy and activation remain false.

`cev1-cross-plane-readback-kernel-v1.json` inventories three positive controls,
thirteen exact negative classes, and two compiler-enforced carrier negatives
for the G2F fresh-readback join. It now covers one-snapshot DA head/certificate
readback plus exact terminal-receipt binding to sampled store heads. The corpus
does not claim a real five-store Node fixture, Order-proof authority, or
whole-node CAS.

`cev1-global-execution-binding-kernel-v1.json` is the explicit tag-50 CEV1
corpus. Its six positive controls reproduce the binding body/typed ID,
immutable object/create-once state, application envelope/state key,
domain-separated leaf, exact 256-level sparse root, and strict claim bytes.
The separately invoked standard-library checker imports no TRNM crate and
requires 51 parser, identity, context, ancestry, version, envelope, nested
value, path-length, sibling, orientation, and materialization mutants to hit
their exact rejection classes. The valid byte/membership fixture ends only in
the positive carrier. The authoritative local Order-state writer and typed
receipt projection provide the normal issuer, while the externally
authenticated ancestry flag is test input, not an Order proof verified by this
corpus. The public raw claim is not self-authorizing.
`ExecutionBindingWriterUnavailable` remains a reserved compatibility error
code. This corpus is not evidence for global conformance completeness,
normative freeze, G2 completion, Node integration, production candidacy, or
activation.
