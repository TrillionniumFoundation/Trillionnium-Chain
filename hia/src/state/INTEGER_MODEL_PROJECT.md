# Offline integer-model row projection

IMP1 projects immutable native Execution State exports into the existing
typed IMD2 transport consumed by the unchanged
[named model loader](../../platform/integer_model_snapshot/README.md).
It neither touches live State nor authenticates the supplied snapshot.
The stock owner's pipe operations, the existing [IMS1
selector](INTEGER_MODEL_SELECT.md) and named IMD2 machine code are unchanged.

The private frame is `IMP1`, four zero reserved bytes, a 32-byte requested
artifact ID, the exact stock `state.export` bytes, then a 32-byte expected
family. The export has the same caps as IMS1: 64 rows, ≤512-byte keys,
9–4,096-byte encoded value extents, exact sorted unique UTF-8 keys and
a bounded JVT1 outer envelope. Whole private input is ≤296,016 bytes.
No offset descriptor, membership witness or computed validity flag is
accepted from the caller. The projector checks both namespaces itself,
using the exact official selector's key and envelope helpers.

The first admitted slice is nine rows in exactly one selected version:
`00` through `07` storing strings of ≤2,048 UTF-8 bytes, and `meta` storing
a four-field JVT1 object in the stock field order (`bytes`, `chunks`,
`family`, `schema`). The first two fields must be typed u64 values. The
last two fields must be UTF-8 strings of ≤64 bytes. No coefficient, extent
value, schema, family or chunk-zero padding is repaired. Actual source bytes
are copied into the corresponding typed IMD2 slots. Only the loader owns
those values' semantics, including exact lengths, lowercase hex,
version, geometry, range, family and requested artifact ID.

The caller passes disjoint input, output and scratch buffers. Scratch
needs 18,648 bytes and may change even on failure; its suffix is untouched.
The projector stages the entire fixed IMD2 output. Malformed frame (100),
insufficient local capacity (102), both namespaces present (1), missing
exact meta (2) and unsupported typed projection shape (104) leave output
untouched. With enough scratch and valid framing, collision precedes
missing, which precedes projection shape. The success result is 18,648
bytes in the output prefix (status 0), with suffix untouched. The named
loader remains a separate native call, not a host implementation or
fallback. No production, adoption, identity, storage or authority claim
follows from an ordinary local projection.

The offline qualification sends genuine stock op11 export bytes held
under a View to independently emitted native projectors and to the exact
locked Rust test projection. The test forwards the unmodified HIA-produced
bytes into the named native loader, independently checking final bytes and
errors with original Rust `load_model`. It includes valid ILM2 and ILM3,
wrong metadata family and numeric value, uppercase chunk bytes, late
requested-ID mismatch, and explicit private refusal cases. The original
oracle requires verified `HIA_M06_ORACLE_PREBUILT`; the native-only envelope
checks do not qualify Rust parity.
