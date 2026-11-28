# Bounded same-byte typed activation projection

This private stage accepts the very same TAR1 input, calls the published
pin-before-strict-scan owner, then captures field starts within the loan
that was just scanned. It does not accept detached caller-projected values.
The original public-facing semantics are not invoked by the native code.
The comparison uses the exact frozen private `Activation` and `Runtime`
Serde definitions with their established raw SHA and strict JSON owners.

This is the bounded named **object form**: exactly 13 root fields and 16
runtime fields, arbitrary object key order, equality of decoded keys, and
original types. The original Serde implementation also supports positional
struct representations; those are out of scope. Fixed `shape` needs
exactly three u64 values. The three homogeneous Vec fields contain 0–64
u64 values. Strings are decoded as original UTF-8 (max 256 bytes except
`hidden_hex` max 294,912). The hexadecimal string is treated only as
text here. No dtype/schema/observations/tokens/hidden data is validated
semantically; deliberately semantically invalid but correctly typed values
are reflected rather than approved.

The stock entry is `f0(TAR1, output, scratch) -> u32`; the three buffers are
disjoint and scratch requires 315,000 bytes. The deterministic private
output is a concatenation of root fields in original declaration order
excluding `runtime`, followed by runtime fields in declaration order.
Text is u64 little-endian decoded byte length followed by exact UTF-8;
array is u64 little-endian length then u64 little-endian lanes; scalar
u64 and bool (0 or 1) use eight little-endian bytes. On success, prefix
only is published. All refusals leave input/output untouched. Status 3
means the original concrete field stage refused; other numbers remain
TAR1 (with 103 also covering private string/representation bounds and
102 public output capacity). Scratch is private and no byte outside its
specified extent is written. Old TAR1 retains its existing scratch
contract and never publishes a typed value.

This output is not a validated activation, material, run observation,
provenance, permission, clock, file/network event, or authorization.
