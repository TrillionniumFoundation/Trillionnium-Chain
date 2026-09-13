# PoCO AI-native Stack v1 transport-schema boundary

Status: **placeholder only; no v1 protobuf or consensus wire schema is frozen**

Future transport messages may live here after the CEV1 logical object schemas
and canonical vectors are frozen. Protobuf bytes will be transport envelopes,
never consensus signing or hashing preimages. Field numbers, unknown-field
handling, size limits, version negotiation, and CEV1 payload bindings must be
specified and tested before adding generated code.

The absence of `.proto` files is intentional and is consistent with
`wire_schemas_complete=false`. PoCO-BFT v0 protobufs cannot be relabelled as v1.
