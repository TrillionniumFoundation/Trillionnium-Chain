# Canonical bytes from a typed Cell Model

This private native kernel serializes the fixed public original Rust
`Model` shape into the exact bytes from `cell_native_v1::canonical`.
It is complementary to the unchanged artifact-identity kernel, which
consumes but does not construct the canonical byte stream. This kernel
does not hash its output or give it any release or activation authority.

The `CMCV0001` input is exactly 30,848 bytes: 8-byte magic, then five
row-major matrices in the order base, delta 0, delta 1, delta 2, router.
Each matrix has 3 rows of 257 little-endian signed i64 values in
[-32767,32767], the original validated model domain. The schema is fixed
to `pon-cell-stateful-native-int257-v1/model`; it is not caller text.
The JSON key order is `base`, `deltas`, `router`, `schema`. There is no
whitespace, padding, BOM, terminator or trailing byte. Values use the
existing shared canonical signed-integer writer.

Success returns the actual written length, 7,830 to 27,105. Status 1
rejects the frame or domain; status 102 rejects an output span shorter
than the exact serialization. A full first pass validates every word
and measures its exact signed-decimal length plus 3,975 fixed bytes.
Only then is the second pass allowed to emit, so normal refusal never
writes a prefix. The disjoint immutable input, the output tail, and
the entire arena are unchanged. No staging arena is needed and an
empty arena works at the maximum result size.

The test builds and links the actual original locked Node library,
calls `canonical(&model)` on synthetic typed models, and compares
complete bytes, all matrix positions, and inert buffer boundaries on
both stock emitters. There is no model execution, training, persistence,
adoption, authority or proof.
