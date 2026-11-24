# M09 declared closure/member metadata equality

The private TCX1 testable entry runs the original
[`CellReleaseClosureV1::verify_manifest`](../../../trillionnium/crates/trnm-data-availability/src/cell/closure.rs)
relation over two canonical immutable records. It does not authorize either record.
The original Rust production callers remain unchanged.

The byte loan is exactly `TCD1 || TCM1 || LE32(TCD1 extent) || "TCX1"`.
The trailer permits the full TCD1 byte decoder to start at zero, and the
existing offset-aware TCM1 decoder sees exactly its own region. TCD1 first
populates its validated private row table. The entry validates TCM1 and
computes its original domain ID, uses that computed ID to find a declared
file, then checks the release and member contexts (family and all five
digests), declared payload digest and declared size against that exact row.
There is no caller-supplied identity, context, purported match or approval
beyond the two actual input values. The comparisons neither read nor attest
to any payload.

Success writes exactly 32 bytes (the computed TCM1 ID). This observes the
successful comparison plus the original member ID getter, not an authority
token. Public output remains untouched on refusal; scratch is private
workspace. The original TCD1 diagnostics win before any TCM1 diagnostics;
TCM1 validation wins before lookup; unlisted ID is distinct from an
existing row with unequal declarations. The frame diagnostic is 100; TCM1
decode diagnostics are 64 plus the standalone code; relation failures
80 and 81 are the original unlisted and unequal conditions. Capacity 102
and internal 103 are private. The new entry shares the existing 13,944-byte
TCD1 scratch bound; no format bound or compiler capability is enlarged.
The standard loan limit represents every valid pair: conservative
TCD1 maximum 225,053 bytes plus exact TCM1 maximum 590,101 plus 8 trailer bytes.

[`test_cell_closure_manifest_relation.py`](../../tests/test_cell_closure_manifest_relation.py)
compares both pinned emitters to the unchanged Rust decoders and direct
`verify_manifest` call, using the existing verified Rust and Cargo-locked
SHA-256 artifacts when configured. Both originals must re-encode the
accepted input bytes exactly. Oversized malformed frames that the generic
1 MiB native test loan cannot represent are tested only in Rust. The
standalone TCD1/TCR1/TCM1 entries retain their existing observable behavior.

This does not open files, resolve any paths, compare owner pins, apply
loader policy, authenticate, recover or transfer payload, use a cache,
authorize selection/adoption, or install or activate anything.
