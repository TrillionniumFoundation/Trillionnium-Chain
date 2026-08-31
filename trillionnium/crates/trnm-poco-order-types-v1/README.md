# PoCO AI-native v1 shared Order types

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
