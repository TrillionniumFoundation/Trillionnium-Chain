# PoCO-BFT v0 Protocol Freeze

Status: **P0 normative design freeze; implementation target, not an implementation or readiness claim**

Freeze date: 2026-08-04

Last pre-activation normative correction: 2026-08-05

Protocol version: `0`

## 1. Scope and normative language

This directory freezes the consensus-critical behavior targeted by PoCO-BFT v0. The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as normative requirements.

The freeze covers:

- the system and threat model;
- a deterministic chained-QC consensus state machine;
- canonical signed and hashed preimages, domain separation, and wire limits;
- validator-set snapshots, epoch handoff, and protocol-version activation;
- deterministic integer PoCO/bond-derived validator weights and rollout gates;
- light-client verification and weak-subjectivity recovery;
- safety/liveness invariants and the P0 exit criteria.

This freeze does **not** claim that the protocol is implemented, formally proved, audited, production-ready, or economically secure. A conforming implementation still requires the P1–P4 work described in the architecture freeze.

Items explicitly marked `UNDECIDED` are outside the frozen v0 safety kernel or must fail closed. An `UNDECIDED` item MUST be resolved before any deployment phase that depends on it. Implementations MUST NOT silently choose consensus-affecting behavior for such an item.

## 2. Normative documents

The documents are read together. If two passages appear to conflict, the more specific rule wins; an unresolved consensus-affecting conflict blocks implementation and MUST be repaired in this freeze.

1. [System model and threat model](01-system-model-and-threat-model.md)
2. [Chained-QC consensus](02-chained-qc-consensus.md)
3. [Wire, cryptography, and domain separation](03-wire-crypto-and-domain-separation.md)
4. [Epochs, validator sets, and upgrades](04-epochs-validator-sets-and-upgrades.md)
5. [PoCO weights, bond, and accountability](05-poco-weights-bond-and-slashing.md)
6. [Light client](06-light-client.md)
7. [Invariants and conformance](07-invariants-and-conformance.md)
8. [`parameters.toml`](parameters.toml), the machine-readable reference parameter profile

The current independent golden-vector subset is indexed in
[`vectors/README.md`](vectors/README.md).

The current Rust prototype's release-blocking differences from this freeze are
tracked in [`IMPLEMENTATION_GAP_REGISTER.md`](IMPLEMENTATION_GAP_REGISTER.md).

The logical Consumption Certificate is frozen separately in
[`../poco-consumption-certificate-v0.md`](../poco-consumption-certificate-v0.md).

The architecture and delivery boundary is frozen in
[`../../architecture/TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md`](../../architecture/TRNM_POCO_BFT_V0_FREEZE_2026-08-04.md).

## 3. Protocol summary

PoCO-BFT v0 is a partially synchronous, authenticated, chained HotStuff-family state-machine-replication protocol. Validators vote with a fixed, epoch-scoped effective weight. A quorum certificate (QC) requires

```text
quorum(W) = floor(2 * W / 3) + 1
```

where `W` is the total effective voting weight of the exact active validator-set commitment for the epoch.

A direct chain of three certified blocks finalizes the oldest block. More precisely, for blocks `b0 <- b1 <- b2`, all three blocks MUST have valid QCs, the parent relationships MUST be exact, heights MUST increase by one, and views MUST strictly increase. Learning `QC(b2)` finalizes `b0` and its ancestors.

The protocol's safety mechanism is the validator lock plus persist-before-sign. A validator MUST durably record its consensus decision and monotonic safety state before releasing a vote, timeout, or epoch-handoff signature. A timeout certificate changes view; it never finalizes a block and never unlocks a validator by itself.

PoCO does not make consumption itself a finality signal. Finality comes only from BFT quorum signatures. At an epoch snapshot, matured and capped Consumption Certificates determine a candidate raw capacity; active slashable bond independently caps that capacity. The committed validator set is immutable during the epoch.

## 4. Frozen choices

The following choices are frozen for v0:

- full validator sets; no sampled committees;
- Ed25519 individual signatures and SHA-256 digests;
- transport-independent canonical encoding `CEV0` for every signed or hashed preimage;
- one normal vote per `(genesis_hash, chain_id, protocol_version, epoch, view)`;
- an unweighted round-robin leader over the canonical validator order;
- weighted quorum with `floor(2W/3)+1` and unique signers;
- three-certified-block finality;
- timeout certificates that carry signed `highQC` digests but cannot unlock/finalize;
- fixed-length reference epochs and joint old-set/new-set handoff certificates;
- deterministic checked-`u128`, floor-only PoCO/bond arithmetic;
- rollout sequence `shadow -> eligibility-only -> capped-weight -> full`, with governance-controlled epoch-boundary promotion;
- trusted-checkpoint light clients with a finite weak-subjectivity period.

Review clarification on the freeze date: QC ordering and TC high-QC selection
use `(view, block_id, qc_digest)`, not only `(view, block_id)`. Two valid QCs
for the same block may have different canonical signer subsets and therefore
different digests; the third key makes selection unique without treating that
benign case as conflicting finality. Same-view QCs for different block IDs
remain a mandatory safety halt.

The 2026-08-05 pre-activation correction closes three review-discovered
ambiguities without preserving experimental compatibility: `GenesisQC` and
`EpochAnchorQC` now have exact empty-signature QC preimages and
context-authorized validity; `FinalityProofV0` carries complete signed header
proposals, exact justifications, and skipped-view TCs; and the first block of
an epoch may move beyond view 1 through a TC selecting its authorized anchor.
It also adds the previously missing
`trnm.poco-bft.handoff-descriptor.v0` domain. All earlier experimental
CommitProof/finality and handoff digests are invalid and MUST NOT be upgraded
by inference. No production or public interoperability promise existed for
those values.

## 5. Explicitly deferred or undecided

The following are not part of the v0 safety freeze:

- the transport container and RPC/P2P framing (`UNDECIDED`);
- aggregate or threshold signature schemes (`DEFERRED`);
- weighted leader selection (`DEFERRED`);
- validator committee sampling (`DEFERRED`);
- mainnet economic constants and slash fractions (`UNDECIDED`);
- privacy-preserving consumption proofs and related-party detection policy (`UNDECIDED`);
- the concrete governance transaction schema and upgrade payload format (`UNDECIDED`).

Changing a frozen choice requires a new protocol version and the epoch-boundary upgrade procedure. Tuning a parameter without changing semantics requires a finalized parameter-set commitment and is still subject to the same activation rules.

## 6. Safety and liveness statement

Safety is conditional. It requires collision resistance of SHA-256, unforgeability of Ed25519, deterministic correct execution, non-rollback durable signing state, and strictly less than one third Byzantine effective voting weight in every active epoch. During a validator-set transition, the bound applies separately to both the old and new sets.

Liveness is also conditional. It is expected only after the network reaches a Global Stabilization Time, messages between correct online validators are eventually delivered within a bounded delay, enough correct effective voting weight is online, and the pacemaker eventually selects a correct leader with a sufficient timeout. The protocol makes no unconditional asynchronous-liveness claim.

## 7. Conformance posture

Before a P1 prototype may be designated a conforming candidate, every
safety-relevant field, comparison, transition, threshold, and signing preimage
MUST be unambiguous. An implementation is conforming only if it passes the
golden-vector, state-machine, fault-simulation, formal-model, recovery, and
interoperability obligations in `07-invariants-and-conformance.md`.

Current local development gates are:

```sh
./scripts/ci/check_poco_bft_v0_parameters.py
./scripts/ci/check_poco_bft_v0_wire_vectors.py
./scripts/ci/check_poco_bft_v0_anchor_finality_vectors.py
./scripts/ci/check_poco_bft_v0_formal.sh
PROTOC=/path/to/protoc-29.3 ./scripts/ci/check_poco_bft_v0_proto.sh
```

The parameter, foundational-wire, and partial anchor/finality gates
independently reconstruct committed CEV0 bytes and digests. The latter is
explicitly shape/relationship evidence and does not validate complete handoff
authorization, composite signatures, or weighted quorums. The formal gate
combines bounded seeded exploration with required failing mutants. The proto
gate compiles a descriptor for transport schemas; it does not make protobuf the
signed encoding or replace strict semantic validation. Passing these partial
gates does not satisfy the complete P0 exit criteria above.
