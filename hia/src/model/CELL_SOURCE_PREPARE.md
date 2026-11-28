# Private bounded Cell source preprocessing

This private native f0 projects the original single-source
`cell_native_v1/source.rs::prepare` into numeric observations and
normalized bytes. It does not run the source, admit a request, assert
provenance, ingest real sources, train, infer, emit actions, or access
a file. The earlier CSS/CSB canonical JSON entry remains independent.

One immutable loan contains the 8-byte magic `CSP00001`, then 257
canonical boolean bytes (one per feature lane, bias lane required true
as in the original admitted mask), then one nonempty even-length
lowercase ASCII hex string representing 1–4,096 bytes. There is no
mutable or alternative source loan. Private structural status 100 is
an invalid frame and 101 invalid mask. Original source decode carries
10 (noncanonical hex or outside original bounds) and 11 (invalid UTF-8).
Physical short loans give 102; an unexpected checked SHA failure gives
103. No failed path writes public output. A short scratch leaves
scratch untouched; any failure after decoding may leave bounded scratch
staging. Output capacity is checked after exact decode/UTF-8 and
normalization but before hashing or publishing.

Normalization trims and collapses only ASCII bytes 9–13 and 32 to
one intermediate space. All remaining UTF-8 bytes are preserved,
including non-ASCII whitespace. ASCII letters and underscore start a
token; ASCII digits join a token but cannot start one. Token hashing
uses the lowercase ASCII token and excludes the prefix `trnm`
and the complete words `m00`, `m04`, `m10`. At most 1,024
nonexcluded tokens contribute, even if additional source spans remain.
The decoder still validates the entire source before scanning tokens.
The first digest byte selects the coordinate, and the low bit of
digest byte two chooses ±1. Accumulation completes before clipping
each of 256 values into [-8, 8]; lane 256 is 8. The typed mask zeros
disabled lanes.

The output is two little-endian u64 words (normalized byte length,
used tokens), raw SHA-256 (32 bytes), then original and masked vectors
of 257 little-endian signed i64 words each, then exactly the normalized
bytes. The caller's output tail is untouched. Maximum physical input
is 8,457 bytes; maximum public result 8,256 bytes. Fixed private arena
19,712 bytes:

- [0,1208): reused SHA state; its 32-byte raw digest is first saved.
- [1208,5304), [5304,9400), [9400,13496): decoded, normalized and
  one private lowercase token; each extent is at most 4,096 bytes.
- [13496,15552): unsigned biased token counts with ±1, initialized to
  1,024 and bounded between 0 and 2,048.
- [15552,19712): staged output header, raw digest and vectors.

All source scanning uses bounded resident slices, and both SHA domains
are computed by the unchanged stock SHA helper. The differential
witness embeds the exact frozen full original `source.rs` and invokes
its original private `prepare` against inert typed fixture values.
No original execution or owner-validation routine is invoked. Both
stock backends are tested on the exact original stage observations,
including physical maximum, valid scalar/spacing boundaries, clipping,
hex-before-UTF-8 error priority and the independent atomic output guards.

    python3 -B -m unittest -v hia.tests.test_cell_source_prepare
