# Runtime file metadata root (private offline profile)

This module implements the frozen public
`trnm_data_availability::cell::runtime_files_root_v1` transcript over 1–256
ordered declared runtime file records. The original allows as many as 32,768;
this private ABI intentionally does not. It validates the same ASCII path
alphabet, ordinary relative components and strict bytewise sorted uniqueness.
The hashing transcript starts with `hepta.smollm-runtime-files.v1\0`, then
each path and exact original role name prefixed by its u64 big-endian byte
length, followed by u64 big-endian declared size and the supplied 32-byte SHA.
It does not validate segment lists, resolve any path, or check a file's content
against the declared digest. For example, distinct metadata rows `A` and
`A/B` are valid here; the unrelated original materializer is stricter.

`f0(input, output, scratch) -> u32` uses pairwise disjoint buffers. Input is
`RFR1\0\0\0\0`, a u64 little-endian row count, then consecutive row spans:
u64 big-endian path length, path bytes, one role index (original enum order),
u64 big-endian size, 32 digest bytes. Exact extent is bounded by 274,704
bytes, with up to 1,024 path bytes per row. Scratch requires 1,504 bytes.
On success only the first 32 output bytes are changed. Original statuses are
0 success, 1 count, 2 path, 3 order; private frame and capacity statuses are
100 and 102 (103 is an internal SHA failure). Scratch is private, and no
refusal changes output. This computes a metadata digest only: no segments,
filesystem access, materialization, runtime claims, or authority.
