# Original execution trace recovery

The actual first hosted continuation run [40606062524](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40606062524)
tested source `8a99968115d76069dc4cc49607929f42d183ad1b`, tree
`49df03a6b02083f62e6a1a98a58c461527ba1648`. Both shards failed before a new
segment proof started. Guest build, complete execution, actual late-invalid
input checks and full source-before/source-after checks succeeded. This is
**FAILURE**, not a completed W1 proof.

[The raw observation](first-ci-observation.json) binds the two complete fetched
artifact ZIPs by size/SHA-256, their GitHub artifact/job IDs and retained raw
process, attempt, session and source-identity members. Each archive has 466
members and passed ZIP CRC validation. Full archives remain separately retained
with the delivery; this directory is a compact subset, not the full archives.

Every one of the 62 fresh segment assets differed from the original. Segment
sizes, cycle counts, full statement, journal and complete claim bytes matched.
The two continuation outer phases used 0.867692403 and 0.666237416 seconds;
they produced zero new receipts. No cryptographic conclusion follows from
matching metadata or matching final claims alone.

The pinned upstream [guest environment](risc0-v3.0.6-guest-env.rs) initializes
`MEMORY_IMAGE_ENTROPY` with 16 host-supplied random bytes. Its
[host syscall](risc0-v3.0.6-host-random.rs) uses `rand::fill`. Both complete
upstream files retain their license headers and were checked against the exact
Git blob hashes in the observation. This explains why replaying the same
ELF/input is not byte-identical trace recovery.

The v2 continuation keeps the original exact-rerun check as a historical
diagnostic and retains its tests. A separate independent-execution check still
binds all full-relation invariants and each fresh file's own bounded hash. The
proof path instead reads the original extracted session, checks every byte
including its manifest, and uses that original directory for every segment
prover. Report validation repeats this exact original-session check. Fresh
trace bytes cannot replace old trace bytes or old receipts. The unchanged Rust
assembler checks all 62 STARKs, chained states, image, complete claim, journal
and empty assumptions before any full proof is accepted.

No guest, proof backend, Rust prover, verifier, source pin, worker/thread count,
wall limit or no-added-PoW setting changes. Old policy v1 is refused in the
new explicit v2 namespace. The eight added controls are provenance/parser
controls; a self-consistent synthetic fresh trace is deliberately **not** a
proof. The local 45-control pass includes the previous 37 controls. Corrected
heavy proving and complete receipt propagation remain **NOT_RUN** at this
source freeze.

## Actual local gates

The complete Python backend suite ran 86 controls. The first default sandbox
attempt retained nine socket-permission errors; after allowing only the needed
local loopback sockets, the unchanged 86-control suite passed in 43.169465
seconds. The original denied logs remain. All 34 source-integrity controls,
locked metadata (26 workspace members / 173 packages), formatting, distributed
inventory and whitespace checks passed. Full repository Markdown validation
retains the inherited missing `evidence/pon-v1/README.md` failure in this
source-only checkout. Full exact-source CI must supply the complete checkout.
