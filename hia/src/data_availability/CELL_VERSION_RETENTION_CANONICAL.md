# Immutable TCA3 decode and commitment

This private finite value kernel decodes bounded canonical TCA3 and
computes the exact original `CellVersionRetentionContractV3::commitment`.
It performs no storage, retention, funding, ownership, reservation,
adoption, authorization, external verification, or actual loading.

The single read-only loan begins with eight bytes `NTA30001`, the declared
opaque store ID (32 bytes), big-endian capacity (u64), maximum obligations
(u32), maximum versions (u32), and maximum metadata bytes (u64). The rest
is the original TCA3 wire, not an alternate encoding. The complete shared
loan is limited to 1 MiB including the 64-byte adapter; larger original
contracts are out of scope. Scratch is 16,032 bytes, the first 32 bytes
of the output hold the digest on success, and all other output bytes are
unchanged. Any refusal leaves the complete output unchanged.

The original decoder's structural pass precedes configuration or semantic
checks. It admits the canonical embedded TCV1 span, reads and validates
both actual wire-format pins, the optional already-validated TMA1 span,
the optional snapshot fields, and the exact object count and ordered
raw object frames. Every TCM1 is decoded before any semantic object
checks. Stable native diagnostics distinguish outer decoder errors,
nested decoder refusals, bounded ABI failures and selected predicates.

The semantic pass validates original typed configurations, binds the two
decoded pins to the two canonical TCD1 closures in order, checks their
declared payload and independent chunk budgets (using the existing
TCV1 sorted membership merge), compares optional TMA1's actual canonical
root bytes against the exact nested TMR1, then checks outer and optional
snapshot terms. TCV1's internal Rust commitment comparison is against
its own recomputation in this caller; there is no independently supplied
version commitment in TCA3. This path does not consume a host prehash as
a substitute for any of the actual borrowed wire ranges.

Ordered actual object TCM1 bytes must match the exact validated nested
TCV1 values, not a caller-provided roster or digest. The old checked
term/successor, operation/funding identity-set, alias, lease, alignment,
and capacity predicates retain their order. The bounded full wire
makes individual original 16 MiB size checks and u64 addition overflow
unreachable. Exact structural completion and canonical nested children
preserve the original canonical re-encoding. Only then does the kernel
publish SHA-256 of the original 40-byte domain including NUL, the
declared store ID, and all exact TCA3 wire bytes.

The frozen Rust comparison uses actual public `decode`, checks its
`encode` round trip, and compares actual `commitment` for owned ordinary
synthetic values. Both pinned emitters see the identical bytes and
test ordinary refusal ordering, optional TMA and snapshot, positive and
negative capacities, and full 512-item canonical roster. No operational
gates or product wiring change.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_version_retention_canonical
```
