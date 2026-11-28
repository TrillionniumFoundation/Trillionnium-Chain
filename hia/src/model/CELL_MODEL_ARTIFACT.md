# Cell Model artifact identity

This private HIA value entry accepts the exact canonical ASCII JSON emitted
for the original `trnm_pon_node::cell_native_v1::Model`. It verifies ordered
keys and fixed schema, exactly five 3×257 signed matrices in the original
base, three ordered deltas and router positions, and canonical decimal
integers in the inclusive range −32767 to 32767. It does not reinterpret
JSON, reorder rows or canonicalize a second buffer. The original
`model_artifact()` hash is computed over the same admitted borrowed bytes
using the original PoN framing. It emits the raw 32-byte hash underlying
the original lower-case hexadecimal ID only on success.

The input spans exactly the supported canonical extent range of 7,830
through 27,105 bytes. The caller provides 32 disjoint output bytes and
1,312 disjoint scratch bytes. Status 0 returns the hash, 1 refuses a value
outside the canonical typed projection, 102 refuses unavailable output or
scratch capacity, and 103 reports an internal hash failure. No failure
publishes any output. Canonical-wire refusal is diagnostic and is not a
promise to reproduce individual Rust JSON-reader messages.

This is not the ILM2/ILM3 handoff; it does not interpret weights for
inference, execute a Cell, train, adjudicate model quality, mutate state
or activate a model anywhere. The comparator builds the unchanged original
node library under the pinned toolchain and calls public Rust functions
only with locally generated inert matrices.
