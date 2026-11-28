# Offline BEP52 bencode value access

This detached native value owner projects the frozen private Rust
`Value::{dictionary, optional, field, number, integer, bytes, list}` after an
entire original-shaped encoded root prefix has successfully parsed. It does
not assign meaning to a key or payload, construct an owned AST, or interpret
unconsumed suffix bytes.

`f0(readbuf, mutbuf, mutbuf) -> u32` receives one immutable loan:
`root bytes || key bytes || u32 big-endian root extent || mode byte`.
The inherited combined loan limit is 1,048,576 bytes. The caller supplies
at least 32 output and 81 scratch bytes. Modes 1–3 accept a raw borrowed key,
including an empty key. No key is present in other modes. All offsets are
zero-based half-open offsets relative to the original root loan. Result
words are four unsigned 64-bit big-endian values: kind, start, end, value.

| Mode | Operation | Projected successful observation |
| --- | --- | --- |
| 0 | `dictionary` | kind 4, whole consumed range, immediate pair count |
| 1 | `optional` | selected kind (1 bytes, 2 integer, 3 list, 4 dictionary), selected encoded range, value 0; four zero words for absence |
| 2 | `field` | same selected record, missing field refused |
| 3 | `number` | kind 2, selected encoded range, decoded unsigned value |
| 4 | `integer` | kind 2, whole encoded integer range, decoded unsigned value |
| 5 | `bytes` | kind 1, decoded payload range excluding the decimal length prefix, value 0 |
| 6 | `list` | kind 3, whole consumed range, immediate item count |

Wrong dictionary/container, unsigned integer, bytes, or list kinds use
40, 41, 42, or 43; a missing required field uses 44. Negative integers
may be selected as encoded values, but refuse 41 for unsigned access.
Root structure failures retain the existing
[offline prefix statuses](BEP52_BENCODE_PREFIX.md) and precede accessor
failures. A frame/cap refusal is 100; short capacity is 102; 103 indicates
an internal observation disagreement rather than accessor success. Output
is never changed on refusal and trailing output is untouched on success.
Scratch may change during structural validation, never beyond its original
81-byte stack area.

The scanner is shared with the existing prefix export, including its depth,
value count, strict key order, integer, and byte-string rules. The access
walk only revisits original validated immediate child ranges in the same
immutable loan. The original Rust witness calls each actual frozen accessor.
For selected encoded ranges, it reencodes the borrowed original result in
its parsed order and checks that the reconstructed root prefix exactly
equals the consumed input before observing the selected range.

This owner performs no peer protocol parsing or key interpretation,
transport, addressing, dialing, discovery, metadata downloading, storage,
or authorization. It does not replace the independently pinned canonical
metainfo comparison.
