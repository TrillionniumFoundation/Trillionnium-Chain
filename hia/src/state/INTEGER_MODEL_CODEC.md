# Integer model value codec

This pure HIA entry implements
[`IntegerModelV2::from_coefficients`, `from_evolution_coefficients`,
`decode`, `decode_evolution`, `encode`, and `id`](../../../trillionnium/crates/trnm-mvcc-fee/src/integer_factor_candidate_v2.rs)
for opaque in-memory data. A family is exactly 32 bytes. In decode mode
it must equal the caller's supplied value, which is not authentication.
No model is evaluated, no factors are checked, and this component does
not adopt a model or change storage, consensus, or production dispatch.

The original 7,756-byte ILM2 and 7,758-byte ILM3 encodings contain the
four-byte magic, version as little-endian u16, family, and little-endian
u16 geometry (1024, 3, 257, 3). ILM3 then has an active count, 1–7, and
one reserved zero byte. The remaining 3,855 coefficients are
little-endian i16, excluding -32768. Other values from -32767 to 32767
are retained exactly. Both formats are exact-length; no conversion of a
different version or normalization is permitted.

Decode rejects length, version, context (family, geometry and ILM3
reserved byte), active count for ILM3, then forbidden coefficient,
in the original order. Typed construction checks the ILM3 active count
before coefficient length and range, also matching the original.
For admitted fields the fixed-width re-encoding is byte-identical;
the original final canonical comparison introduces no additional
reachable outcome.

The original content ID is SHA-256 over the
[protocol framing](../../../trillionnium/crates/trnm-protocol/src/pon_wire.rs):
`TRNM-PON1\0`, u16 domain length, the original
`integer-linear-model-artifact-v2` or `integer-linear-model-artifact-v3`
domain, u32 value length, and all canonical bytes. Lengths are
little-endian. The ID labels content; it is not a proof or authorization.

## Private in-memory frame

Input is `IML1`, typed u8 version (2 or 3), u8 operation (0 construct
or 1 decode), u8 ILM3 active count for construction only (zero
otherwise), one reserved zero byte, the 32-byte family, then either
the complete coefficient bytes or one original encoded model. The
output on success is the 32-byte content ID followed by the complete
original bytes. Only the fixed successful extent changes.

Codes 1–5 are original length, version, context, active count, and
coefficient range. Codes 100, 102 and 103 are local malformed frame,
insufficient capacities and internal failures. Scratch is bounded to
9,014 bytes; caller input and output on refusal are unchanged.

The [test](../../tests/test_integer_model_codec.py) compiles the unchanged
original struct/methods and PON hash framing with pinned Rust, using an
independent system SHA-256 seam. Both locked HIA emitters are compared on
complete synthetic bytes and content IDs, all graph count classes,
header mutations, signed endpoints and late coefficient checks, error
precedence, and exact output/scratch canaries.
