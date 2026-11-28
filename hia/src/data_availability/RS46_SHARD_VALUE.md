# Standalone immutable CRS1 shard value

The independent shard entry checks the same shape as the unchanged
public Rust `CellRs46ShardV1::decode` and computes the original
`CellRs46ShardV1::id` over an already canonical value. It is not the
existing RS(6,4) encoding or recovery entry. No manifest authentication,
source-integrity check, reconstruction of a chunk, files, network,
custody, or storage are involved.

Original shape order is complete wire size (82 through 1,048,657 bytes),
`CRS1` tag, source size (1 through 4,194,304 bytes), chunk number
(0 through 16,383) and shard number (0 through 5), then exact declared
and actual shard extent `ceil(source/4)`. The digest is SHA-256 of the
original 24-byte domain `trnm.cell-rs46-shard.v1\0` followed by the
complete exact shard wire. Declared manifest/source digest bytes are
opaque. A shape or addressing digest match does not validate the source.

The private caller supplies disjoint spans. On acceptance the first 113
output bytes contain the 32-byte ID and exact canonical 81-byte header.
Canonical encode is that header followed by the same unchanged borrowed
payload, not a new larger owned buffer. The input and remaining output
are untouched. On refusal all output bytes are untouched. Scratch
requires 1,232 bytes, and may only change after shape and capacity checks.

- `f0` takes one complete read-only wire loan, output and scratch. The
  stock Direct wrapper retains its 1 MiB cap per loan. The stock Selfhost
  private entry physically executes this same canonical wire through the
  exact original 1,048,657-byte maximum.
- Direct `f1` takes an 81-byte read-only header and a separate read-only
  payload of at most 1 MiB, followed by output and scratch. It validates
  the length of each loan before use, and streams the two exact ranges,
  without changing compiler or per-loan bounds. The caller only splits
  the canonical wire at byte 81; no host hash or wrapper verdict is
  consumed. This path covers the original full source/shard limit.

The locked Cargo oracle invokes actual public `decode`, `encode` and
`id` on deterministic inert synthetic values. It compares the original
encoded bytes to the full accepted input. Native qualification compares
the exact ID, re-encoded header and unchanged payload on both backends,
including exact 1 MiB and its first successor, all final source lengths
with maximal shard extent, and separate refusal/order controls.

```sh
python3 -B -m unittest -v hia.tests.test_da_rs46_shard_value
```
