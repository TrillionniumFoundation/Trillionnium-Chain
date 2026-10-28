# W1 continuation v2: preserve the original execution witnesses

V2 continues the exact 62 witnesses from original run `40511022475` and
reuses only its 26 verified segment receipts. Fresh guest execution is an
independent check of the complete W1 statement. It never supplies witnesses
for the retained receipt chain. The original relation, fixture, guest image,
backend, no-extra-PoW profile, Cargo graph, 30 source pins and all original
process/resource budgets remain unchanged.

## Why v1 correctly refused its fresh execution

Both shards of actual run `40606062524`, source
`8a99968115d76069dc4cc49607929f42d183ad1b`, completed the native controls and
fresh guest export, then refused with `fresh execution is not the same
original session`. No missing segment was proved. Both failures, their actual
process costs and every original job/phase log remain in
[the v2 evidence](../../../../../evidence/pon-w1-frozen-witness-v2-20261028/README.md).
The v1 policy, implementation and exact-byte guard remain available unchanged.

This was a real execution difference. SDK commit
`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` initializes
`risc0_zkvm::guest::env::MEMORY_IMAGE_ENTROPY` with `sys_rand` before `main`.
The fixed original ELF places this 16-byte symbol at `0x223b00`, exactly
page 2190, offset 768. The original first ordered host read was
`69926f804ae3f60aeefeb994005f2ffc`; shard 0's fresh read was
`b926aa81aecabcad2877256e53b52c9a`.

The complete decoder consumed every byte of all 124 original/fresh witness
structures. The only different host read was segment 0's first read. All
other reads and writes retained their order and values. Other changed fields
were that memory cell, its ancestor memory digests and the segment pre/post
roots. All 62 raw segment hashes differed. The final journal and full halted
session claim matched because the SDK maps a halted final post-state to the
zero SystemState. The checked source references and all differing fields are
retained; there is no map sorting or trace normalization in acceptance.

## Explicit v2 validation path

`segment-continuation-v2.json` binds the unchanged original policy by hash.
V2 selection requires this policy; an absent or malformed declaration cannot
silently select another proof source. The original complete ZIP and all 315
members are checked through the original archive reader before extraction.

The fresh fixture and baked guest bytes must match the original input and
image byte for byte. Every fresh session metadata field except elapsed time
and raw segment hashes must match. All fresh raw files are checked against
that fresh inventory, the fresh 62-segment memory chain must be internally
connected, and the complete session claim bytes must match the original.
This control does not authorize any fresh witness to join the old chain.

Proving reads `original/segmented/session/segment-N` only. Before and after
proving, every original witness, session JSON and session claim must remain
byte-identical to the checked archive. The bounded witness parser records
all fields, refuses trailing bytes, malformed/oversized collections,
noncanonical map order, PoVW, assumptions, changed dimensions and broken
adjacent roots. It supplies no cryptographic authority.

The new `check_frozen_receipts` binary uses the same pinned SDK and Cargo
lockfile. It is a separate Cargo-discovered binary; no original host source
or dependency changes. It first checks exact frozen witness hashes and the
full session claim, including the complete W1 public journal. It then uses
the SDK's `SystemState.digest` and `SegmentReceipt` deserializer to bind each
receipt's pre-state, post-state, input, output, exit, index, po2 and verifier
parameters, and calls the actual SDK STARK integrity verifier with development
mode disabled. Bincode lengths are preflighted and trailing bytes rejected.
The claims JSON must equal the runner's closed canonical encoding; duplicate
keys and additional fields are refused.

Each shard actually verifies original receipts 0 through 25 before proving
its disjoint missing range, then verifies its new receipts against the same
frozen witness claims. Assembly verifies all 62 receipts against the original
witnesses again, then calls the original unchanged Composite assembler and
full image/journal/claim-chain verifier. The original positive and 17 negative
proof controls remain required. Source-before/source-after checks, the v2
source inventory and each helper executable hash are recorded. The final
reader repeats exact original input/image comparison and closes the assembly
claim JSON and all 62 assembly receipt bytes against the checked original and
shard material, so a later equal-length input substitution cannot reuse old logs.

## Budgets and costs

Shard ownership remains 26–43 and 44–61. Each shard retains two proof workers,
two Rayon threads per worker, 300 seconds per child stage, a 3,500-second work
stop and a 3,600-second outer process phase. The existing available-memory and
CPU gates are unchanged. Each shard's repeated export and original-26 receipt
verification are real costs inside that shard's outer accounting. Child
stage details are retained but are not added to outer CPU totals again.

Reports separately identify the original failed 3,500-second attempt, both
failed v1 continuation phases, and the new v2 continuations plus assembly.
They report a cumulative research proof-attempt subtotal and explicitly set
`complete_from_zero_generation_measured=false`. Build, native controls and
other diagnostic costs remain separate. A continued proof, if successful,
does not retroactively make the original bounded attempt successful or
establish a from-zero complete-proof production cost.

The maximum rejected-input cost remains the maximum of the actual tested
cases. It is not a proof of the global worst case. The final propagation
experiment is local TCP loopback between two native verifications; WAN,
gossip, production ingress and sustained capacity remain unmeasured. Full
proof success is declared only after the real two shards, all-receipt binding,
unchanged full verifier, invalid-proof audit and propagation stages finish.
