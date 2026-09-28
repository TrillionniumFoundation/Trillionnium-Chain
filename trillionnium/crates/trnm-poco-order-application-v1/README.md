# PoCO AI-native v1 inert Order application preview

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M08. Target responsibility: Probabilistic confirmations, reorg coordination and recovery.
See [M08 technical contract](../../../docs/modules/M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Reuse durable coordinator/intents/readback. Retire three-QC ancestor-finalization and joint
epoch handoff for new history; retain their old decoders and storage meaning solely for
migration.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


This candidate crate provides the first bounded canonical Order application
slice. From one exact empty-state anchor or an earlier inert preview it can
plan an Ordinary no-op block or an atomic, strictly ordered set of immutable
system object-kind-50 creates. It recomputes the complete 256-level sparse-JMT
post-state root, fills the other seven roots with their exact empty ordered
roots, seals the timestamp-free v1 header, and derives its typed block ID.

The root is not caller supplied. A tag-50 value whose candidate block ID would
equal the containing block ID is rejected, as are non-earlier heights,
duplicates, collisions, reordered creates, opaque/legacy operations, and
prepared-plan root substitutions.

`PreparedOrderBlockV1` is non-Clone, has private fields, and has no commit API.
The crate owns no durable store, Core, Safety, signer, finality, Node, or G2
permit. A future top-level v1 Node must adapt retained non-Clone terminal G2
owners into this public planning material and separately own the joint CAS,
commit, finality, binding, and recovery phases. No Node/G2/freeze/production
truth is claimed here.

Tests consume the repository's shared tag-50 machine vector and lock the exact
object ID/value, state key, leaf, and 256-level sparse root. That is a
cross-implementation encoding/root consistency check only, never an issuer or
commit authority.
