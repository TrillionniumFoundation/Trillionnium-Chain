# PoCO AI-native v1 shared Order types

## PoN target and current-source scope

This crate remains existing implementation/reference source; this documentation does
not turn it into a PoN runtime. Selected development profile: `pon-nakamoto-v1`.
Source owner: M00. Target responsibility: Protocol, canonical neural-work and public-model contracts.
See [M00 technical contract](../../../docs/modules/M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md) and the
[PoN protocol](../../../docs/protocol/pon-nakamoto-v1/README.md).

Reuse bounded canonical-codec patterns and exact historical verification. New header/work/model
byte domains need implementation; old type names and existing golden vectors do not establish
it.

## Retained implementation documentation

The source interfaces, stored formats, commands and tests below retain their actual
legacy/profile semantics. PoCO consensus is retired as the target. No old finality,
committee, vote, consumption weight or test pass is new neural-work/efficacy evidence.


This candidate crate owns the exact CEV1 public-data representation for
`ProtocolContextV1`, `BlockHeaderV1`, `VoteStatementBodyV1`, and
`QuorumCertificateV1`, including typed block/certificate IDs and strict
decode/re-encode codecs.

`BlockHeaderV1` has eight named roots and no consensus timestamp. Block, vote
signature, and QC identifiers use their frozen v1 domain separators. The
crate contains no Node, Core, Safety, signer, finality, application store, or
G2 dependency and grants no authority by decoding or hashing bytes.

This is still candidate, non-normative implementation work. It does not close
the v1 wire stack, Node integration, G2, freeze, production, or activation.
