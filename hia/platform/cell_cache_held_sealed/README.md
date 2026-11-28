# Private sealed descriptor for the existing held cache-chunk reader

This uninstalled Linux x86-64 static fixture reuses the exact already-qualified
sealed fd 0 / stdout adapter bytes and the unchanged pinned Selfhost
cell_cache_payload_held_read machine text. The input format matches the private
memory-only held reader: little-endian position (u64), desired bytes (u64),
TCM1 manifest length (u32), manifest, and one supplied chunk. The entire input
must fit the unchanged 65,536-byte adapter. The private test launcher creates
a freshly sealed anonymous input memfd at offset zero and anonymous output
pipe. No external file names, configurable descriptors, network, cache
lookup, clocks, provenance decisions or node authority are supported.

The adapter still checks all four seals, fixed extent and cursor, reads exactly
the declared descriptor extent in bounded requests, verifies EOF with its
existing one-byte probe, verifies the final cursor and closes fd 0 before the
one native dispatch. No literal newline or extra terminator is added to either
payload. The separate fixed syscall-free thunk passes a disjoint 65,552-byte
output loan and exactly 1,232 scratch bytes, checks the complete native status
before reading the admitted result count, and bounds that count at 65,536
before returning 16 plus count to the old adapter. On success the pipe holds
the unchanged little-endian u64 next position and u64 count, then the copied
bytes. Semantic refusal emits no bytes and has the old process exit 74; its
exact diagnostic status remains the memory interface's responsibility.
Pipe transport failure after a write is not an atomic file-publication protocol.

The test re-reads each same held sealed descriptor with pread in the parent,
checks its identity, seals and offset and hands those actual bytes to the
original locked Rust held-reader comparison. It independently binds the old
syscall sites, pure thunk and resolved Selfhost text, verifies a whole 64 KiB
frame and smaller input, and checks no stdout on physical or semantic refusal.
No Direct static execution or ARM support is claimed; the separate memory
reader still runs the original differential on both stock backends. No real
cache objects or mutable files are used.
