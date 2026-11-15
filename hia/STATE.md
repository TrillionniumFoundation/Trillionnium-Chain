# Native sparse state root

[state_root.hepta](src/protocol/state_root.hepta) implements the complete byte
relation from `trnm-protocol::pon_wire::state_root_from_entries`. It consumes
actual keys and values, derives every path and leaf, sorts the hash paths,
rejects collisions and computes all 256 levels of the sparse tree.

This component does not validate M06's JSON value grammar, bind a parent to a
stored snapshot, execute transactions or create an admission capability. Those
checks belong to the corresponding execution and persistent owners. In
particular, M06 validates every value before applying the state count and wire
limits; a caller must preserve that complete grammar pass.

## Input and result

The only public entry is `f0(readbuf, mutbuf, mutbuf) -> u32`, with three valid,
disjoint borrowed regions. It uses the fixed compiler's borrowed-byte ABI.
The source does not accept arbitrary external pointers as authority and does
not establish safety for a caller that violates the ABI's ownership contract.

The local request descriptor is:

| Field | Encoding |
| --- | --- |
| Magic | Four bytes `SRV1` |
| Entry count | `u32LE` |
| Each entry's key length | `u32LE` |
| Each entry's value length | `u32LE` |
| Key | Exactly the declared bytes |
| Value | Exactly the declared bytes |

All entries must be present and no trailing bytes are accepted. The descriptor
is a local invocation format, not a new signed transaction or stored ledger
schema. Keys and values are arbitrary byte strings at this wire layer. Empty
keys and present empty values are accepted; an absent entry has a different
root. Entry order does not affect the result. Repeated keys are not collapsed:
they produce the original hash-path collision error.

The original limits remain 65,536 entries, 160 bytes per key and 4,096 bytes per
value. The function does not impose the shared Python test runner's 1 MiB
message bound on the native relation. The maximum fully populated descriptor
is 279,445,512 bytes, so production integration requires an owner that can
supply or stream that complete input; the current module takes one borrowed
input region. It does not clone that full region into scratch.

Output must have at least 32 bytes. Success writes exactly the raw 32-byte
root, leaves its suffix intact and returns zero. Every refusal leaves the
entire output unchanged; no partial root escapes.

| Code | Meaning |
| --- | --- |
| 0 | Complete root written |
| 1 | Truncated descriptor, inconsistent extent or trailing bytes |
| 2 | Descriptor magic/version differs |
| 4 | Entry count, key length or value length exceeds the original wire limit |
| 5 | Equal derived hash paths |
| 100 | Insufficient output or scratch capacity |
| 101 | Internal hash/tree contract refusal |

The check order is: minimum descriptor length; magic; count limit; output and
scratch capacity; each row's complete length header, original wire limits and
body extent; exact end of input; hashing and collision detection; complete
tree. Count and row bounds are deliberately distinguished from malformed
local framing. All framing and per-row checks finish before any scratch write.
Collision refusal may change scratch, but it still preserves output.

## Hash grammar and tree construction

The exact existing domain function is:

`SHA256(ASCII("TRNM-PON1") || 0x00 || tag_length:u16LE || tag || each(part_length:u32LE || part))`

The source uses `state-key(key)` for a 256-bit path,
`state-leaf(key, value)` for an occupied leaf, `state-empty()` at depth 256 and
`state-node(left, right)` at each parent. Path bits are consumed most
significant first. The input is never allowed to supply precomputed hashes.

An in-place heapsort orders complete 64-byte `(path, leaf)` records. A scan
rejects equal adjacent paths before any root is published. A 257-frame explicit
stack traverses the sparse tree; binary partitioning finds each left/right
split. Empty subtree hashes are computed from the original domains on every
invocation. No cache from a previous request, supplied root or source verdict
can bypass input processing.

Key, leaf and empty-leaf hashing explicitly includes the single shared
`sha256_arena.hepta` implementation through [components.json](components.json).
The heavily repeated branch message has exactly 94 bytes. Its two SHA-256
blocks use an equivalent fixed-length implementation with typed `u32` schedule
and working words, grouped into private HIA functions to respect the pinned
compiler's unchanged per-function identifier limit. This specialization still
hashes both actual child values and the complete original framing. It does not
use a host hash function, a different digest, a shortened tree or a fallback
backend.

## Scratch ownership and bounds

For `N` entries, the minimum scratch length is `157024 + 64*N` bytes. This is
157,024 bytes for an empty state and 4,351,328 bytes at the original count cap.

| Region | Start | Length |
| --- | --- | --- |
| Shared SHA arena and branch compression work | 0 | 132,256 |
| Sorted path/leaf records | 132,256 | `64*N` |
| Empty subtree hashes | `132256 + 64*N` | 8,224 |
| Explicit traversal frames | `140480 + 64*N` | 16,448 |
| Heap-swap temporary | `156928 + 64*N` | 64 |
| Complete root temporary | `156992 + 64*N` | 32 |

Every byte beyond the required working extent is preserved. No frame deeper than
depth 256 is allocated, and no arithmetic offset depends on an unchecked row
length. Hash paths and leaf digests are retained; complete key/value payloads
are borrowed from the input.

Private helpers have narrower preconditions than the public entry. The branch
hash reads both children from the validated leaf/empty/stack/result regions
into its private 94-byte message before updating either digest destination.
This permits the actual `out == right` return path while keeping message,
schedule, heap temporary and traversal state disjoint. These helpers are not
exported as arbitrary-offset foreign APIs.

## Validation and performance scope

[The main suite](tests/test_state_root.py) compares actual native roots with an
independent SHA-based byte oracle, exhausts descriptor truncations, exercises
all input/output boundary classes and key/value mutations, permutes entry
order, tests duplicate paths and selects the separate direct machine emitter
explicitly. The existing original-Rust protocol adapter calls the retained
crate's real root function; CI requires that differential and never treats a
missing Rust executable as a pass.

The independent adversarial suite exercises the original maximum count, real
pointer offsets and reuse of one physical arena across successive calls.
Maximum-count native execution has a separate finite qualification budget;
passing it does not establish the original node's four-second service budget.

The first implementation measured 26.874647021 seconds for 1,024 rows. A single
fully expanded compression function was refused by the fixed native compiler;
the compiler and its admission limit were left unchanged. Grouping the same
arithmetic into explicit HIA helpers produced the same observed root in
5.236884767 seconds for the same 1,024-row input. These are local development
observations, not a controlled service benchmark or full-node qualification.
