# Paired SHA-256 message schedule

The [stream compressor](sha256_stream.hepta) retains its original SHA-256
rounds, state accumulation, and observable workspace layout. Its guarded
32-bit fast path ingests and expands adjacent message-schedule words in pairs.

At an even expansion index `t`, packed slot `j` contains
`W[t-16+2*j]` in its low half and `W[t-15+2*j]` in its high half.
For the usual SHA-256 recurrence, the ordered inputs
`(W[t-15], W[t-2], W[t-16], W[t-7])` are window indices
`(1, 14, 0, 9)`. The next word uses indices `(2, 15, 1, 10)`.
Both recurrences refer only to the current window. Dropping the first pair
and appending the new pair in low/high order preserves the invariant at
`t+2`, without shifting halves between seven surviving pairs. Starting
with zero pairs and ingesting eight big-endian input pairs establishes the
invariant for `t=16`.

Ingress starts at 0 and stops at 16; expansion starts at 16 and stops at 64.
Both increment by 2. The last second-word input ends at workspace byte 1167,
and the last second-word schedule slot ends at byte 1023. Each slot still
receives the same four little-endian bytes followed by four zero bytes, in
the same order. The path still requires a workspace of at least 1168 bytes
and eight incoming 32-bit state words; neither guard nor the fallback blocks
for short buffers and wide state words changed.

The existing [full-memory and alias differential](../../tests/test_sha256_schedule.py)
compares the original native compressor, not just digest outputs. The
[Settlement native gate](../../platform/service_settlement/README.md) retains
its complete original fixture roster and 240-second native stage limit. The
paired-loop change does not assert an overall Settlement qualification
result or a production cost improvement on other systems.

On the exact `c99a3775` source baseline, the existing public Engine
qualification body produced the same 1,029 original receipt-chain operations
and all 7,227 captured call records (excluding elapsed times) with either
compiler output. The paired loop lowered calling-thread CPU time by 9.02%
and 3.38% in two opposite-order, same-filesystem pairs. An extra baseline
repeat was retained separately; a disk-exhausted attempt is not a timing
sample. These are machine-local measurements, not a guarantee of hosted
timing. The unfiltered original native stage also matched all 320 retained
fixtures (2,636 operations, 16,066 native calls) inside its unchanged
240-second deadline. The original Rust rebuild, allocator and independent
complete hosted evidence gate are separate.
