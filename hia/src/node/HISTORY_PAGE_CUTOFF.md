# Retained History packet-length cutoff

This private, non-effecting kernel selects opaque IDs from a held window.
It implements only the complete final packet loop of the frozen original
`history_with_decoders`. No packet is parsed or produced; callers provide
already-known, bounded original wire lengths. The mempool, original
packet loader, its errors, cursor/ancestry traversal, progress/cancellation,
network, and real reply encoding are outside this kernel.

The only input is `HPCB0001`, a little-endian u64 count (0 through 16), then
exactly that many rows of 32 opaque ID bytes and one little-endian u64
held wire length. Input row order is the original retained traversal
order, so selection starts with the final row. A visited wire length
must lie within 49,508 through 1,048,576, the geometry envelope covering
both original encoders (the PQ-tagged minimum can be eight bytes higher).
This is not evidence a particular length came from a valid packet.

The first visited candidate is kept even if it exceeds 800,000 bytes.
Each subsequent candidate is kept exactly when the sum would be at most
800,000. The first larger sum stops the scan without considering older
input positions. The rejected boundary candidate's length is inspected;
the untouched remainder does not affect the result. At most sixteen
bounded lengths make overflow unreachable.

The result is two little-endian u64 words, selected ID count and retained
payload-byte sum, then the selected opaque IDs in visit order. Success
requires exactly 16 + 32*count result bytes at minimum; status 100
indicates wrong physical frame or out-of-envelope visited length, and
102 indicates insufficient output. No failure writes output. The input
span, output tail and whole scratch are unchanged. No authority is carried.

The differential compiles the exact whole original packet-selection loop
from a source-hash-bound Rust file. The fixture stands in only for the
original already-loaded packet and checked length seams with synthetic
typed values. It observes the original lookup/length order, a terminating
candidate, equality, the first exception and reverse output on both
stock native emitters. It never opens a Node or a packet.
