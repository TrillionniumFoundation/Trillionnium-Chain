# Runtime file declaration plan (private offline profile)

This companion to `CELL_RUNTIME_FILES_ROOT.md` uses the same native RFR1
kernel on a bounded subspan of a single immutable input. It does not emit or
expose the intermediate root. The private stock ABI is unchanged:
`f0(input, output, scratch) -> u32`, with disjoint buffers and 1,504 scratch
bytes. The earlier RFR1 export retains its full previous profile and behavior.

RFP1 uses 32 fixed header bytes: `RFP1\0\0\0\0`, then u64 little-endian RFR1
extent, metadata budget and context extent. Its held context is a one-byte
family length, 1–64 family bytes, and the original five 32-byte context
digests. Then comes one RFR1 frame and a segment collection for each row in
the identical order: a u64 little-endian segment count, then a u64
little-endian extent and canonical TCM1 bytes for each segment. The profile
is 1–64 rows, up to four TCM1 objects per row, up to 1,024 bytes per encoded
TCM1, and at most 333,649 total frame bytes (original accepts wider typed
plans). The target context is compared as typed bytes; it is not independently
authorized or applied.

After RFR1, checks run in the original order: lexically exact ancestor
collision, payload overflow, individual and aggregate plan bounds, canonical
TCM1 geometry/context, per-segment metadata allowance, byte coverage, and
the exact empty-SHA and role truth table. The local row and segment bounds
make u64 metadata/segment accumulator overflow unreachable. No original
clock is called by native code; the frozen original test-only function
runs with a fixture-local non-expiring deadline. The original receives
typed TCM1 instances; malformed encoded TCM1 is a private wire refusal, not
a claimed original `validate_files` typed error. Nonempty file SHA and TCM1
digest fields are declarations, not validated content or proof.

Success writes exactly two u64 little-endian totals to output: payload,
metadata. Refusal leaves output unchanged; scratch is private. Status 1–3
is as in RFR1; 4 ancestor, 5 payload overflow, 6 individual cap, 7 aggregate
plan, 8 segment geometry/context, 9 segment metadata cap, 10 coverage, 11
ineligible empty. Private errors are 100 wire, 101 profile cap, 102 capacity,
103 shared SHA failure. This is not live path admission, peer/network
opening, custody, materialization, reservation, deployment, or authority.
