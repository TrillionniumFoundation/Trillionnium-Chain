# Inert PoCO-BFT safety rules

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M03. Target responsibility: Mining-attempt ownership, identity custody and local fencing.
See [M03 technical contract](../../../docs/modules/M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Reuse descriptor/nonce/fence/custody and bounded worker mechanisms where matching. Retire
SafetyRules vote locks and PoCO double-vote slashing as target requirements; retained signer
records stay historical.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


`trnm-consensus-safety-rules` is a pure, `no_std`, intra-epoch HotStuff
lock-and-watermark evaluator. It re-verifies complete typed proposals and their
QC/TC witnesses, reconstructs bounded ancestry from a finalized reference, and
builds canonical vote or timeout intents from an immutable safety state.

The result is deliberately an inert consensus-safety candidate. It is not an
application-validity attestation, complete vote admission, signer authority,
authoritative state seed, authoritative finalized reference, durable state,
remote CAS, HSM policy, authoritative Core transition, runtime activation, or
production consensus path. Core invokes it only as a fail-closed shadow: Core
independently constructs the complete input, compares the candidate exactly to
the already-admitted legacy transition, and discards it before persistence or
effects. This v1 Core integration uses the evaluator's fixed 64-block
post-finalized ancestry limit even when Core's BlockTree is configured larger.
An otherwise legacy-admissible Vote above that limit fails closed before state
mutation; the shadow does not claim long-ancestry liveness equivalence.
Fresh intent creation is the complete v1 coverage boundary: a recovered
`pending_sign` subsequently released by `Resume` after `Core::recover` and a
tag-3 post-ack signature remint remain on Core's existing durable-outbox path
and do not re-run the shadow. The evaluator therefore cannot authorize recovery
replay or cross-upgrade signer release, or prove that an older persisted intent
passed a shadow evaluation. Fresh QC signature validation does not prove the
supplied high-QC, lock, and finalized-reference ancestry, finality, freshness,
or durability. Caller-supplied seed and header data therefore never become
authority merely by passing this pure evaluator. In particular, the crate has
no private key, generic signing callback, storage, socket, clock, or application
interface.

High-QC and locked-QC strength is view-ordered, not height-ordered. A later-view
high QC on another fork may legitimately certify a shallower block than the
retained lock. Both references must still be valid, non-conflicting at one
view, and independently at or above finality in both view and height. A QC at
the finalized height must identify the exact finalized block, while a repeated
block identifier may not carry different coordinates. Height alone does not
order high QC against lock.

The fixed v1 digest domains are:

- `trnm.consensus.safety-rules.state.v1`
- `trnm.consensus.safety-rules.transition.v1`

Epoch anchors and checkpoint/seal/handoff blocks remain unsupported. QC/TC
observation is intentionally absent; a later integration must prove and persist
those state changes before this evaluator can participate in a signing flow.
