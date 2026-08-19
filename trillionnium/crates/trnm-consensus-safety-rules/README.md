# Inert PoCO-BFT safety rules

`trnm-consensus-safety-rules` is a pure, `no_std`, intra-epoch HotStuff
lock-and-watermark evaluator. It re-verifies complete typed proposals and their
QC/TC witnesses, reconstructs bounded ancestry from a finalized reference, and
builds canonical vote or timeout intents from an immutable safety state.

The result is deliberately an inert consensus-safety candidate. It is not an
application-validity attestation, complete vote admission, signer authority,
authoritative state seed, authoritative finalized reference, durable state,
remote CAS, HSM policy, Core integration, runtime activation, or production
consensus path. Fresh QC signature validation does not prove the supplied
high-QC, lock, and finalized-reference ancestry, finality, freshness, or
durability. Caller-supplied seed and header data therefore never become
authority merely by passing this pure evaluator. In particular, the crate has
no private key, generic signing callback, storage, socket, clock, or application
interface.

The fixed v1 digest domains are:

- `trnm.consensus.safety-rules.state.v1`
- `trnm.consensus.safety-rules.transition.v1`

Epoch anchors and checkpoint/seal/handoff blocks remain unsupported. QC/TC
observation is intentionally absent; a later integration must prove and persist
those state changes before this evaluator can participate in a signing flow.
