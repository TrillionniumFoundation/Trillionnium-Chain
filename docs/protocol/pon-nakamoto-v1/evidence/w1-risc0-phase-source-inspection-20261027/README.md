# Complete W1 proving phases: bounded source inspection

This is a read-only inspection of the source pinned for the RISC Zero 3.0.6
experiment. It introduces no implementation, profiling run, receipt, or
qualification. File identities and the exact source revisions are recorded in
`source-inspection.json`.

## What the source establishes

The complete W1 guest reads its fixed input, evaluates the complete relation and
commits its 228-byte journal. It requests neither a Keccak proof nor verification
of another guest receipt. Its host selects `ReceiptKind::Composite`, explicitly
disables development mode and selects the backend's `poseidon2` proof hash.

| Stage | Pinned RISC Zero source | What can be concluded |
| --- | --- | --- |
| Execute the guest | `risc0/zkvm/src/host/server/prove/prover_impl.rs:53–65` | `prove_with_ctx` executes the program before proving the resulting session. A separately timed execute command is not the duration of this whole operation. |
| Iterate segments | Same file, lines 83–93 | This implementation visits session segments in an ordinary sequential loop. Configuring Rayon threads does not make this loop prove four segments concurrently. |
| Per-segment preflight and witness | `risc0/circuit/rv32im/src/prove/hal/mod.rs:129–162` | Each segment generates preflight data and a witness before constructing its STARK. |
| Per-segment polynomial commitments and checks | Same file, lines 168–222; `risc0/zkp/src/prove/prover.rs:81–108,111–178` | Code, data and accumulator groups are committed; finalization evaluates circuit constraints and performs polynomial operations including NTT interpolation. The CPU circuit has a Rayon parallel constraint-evaluation loop at `risc0/circuit/rv32im/src/prove/hal/cpu.rs:179–209`. |
| FRI and segment verification | `risc0/zkp/src/prove/prover.rs:366–392`; `risc0/zkvm/src/host/server/prove/prover_impl.rs:246–282` | A segment produces a FRI proof and authenticates its resulting segment receipt before returning it to the session loop. |
| Composite verification and return | `risc0/zkvm/src/host/server/prove/prover_impl.rs:155–181` | The combined receipt is checked and returned as Composite. This precedes `composite_to_succinct` at lines 184–191 and Groth16 conversion at line 205. |

The last point applies to this guest and its selected receipt type. The generic
SDK also contains a pending-Keccak assumption path at lines 121–138, before the
Composite return. Consequently it would be incorrect to generalize this
inspection into a claim that every possible Composite workload performs no
recursive work. This guest does not request that path. Its slow proof cannot be
explained as intentional recursion compression in the configured host.

The source is pinned at
[`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`](https://github.com/risc0/risc0/tree/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9).
The relevant entry points are
[`prover_impl.rs`](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/host/server/prove/prover_impl.rs),
[`hal/mod.rs`](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/circuit/rv32im/src/prove/hal/mod.rs),
and [`prover.rs`](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkp/src/prove/prover.rs).

## W1 SHA-256 is already accelerated, and still has proof cost

The guest uses the locked RustCrypto SHA-256 patch at
[`7fd6900c4f637bd15ee2642dfa77110f8f1ad065`](https://github.com/risc0/RustCrypto-hashes/tree/7fd6900c4f637bd15ee2642dfa77110f8f1ad065).
Its `sha2/src/sha256.rs:19–22` selects the zkVM implementation;
[`sha2/src/sha256/risc0.rs:20–27,43–60`](https://github.com/risc0/RustCrypto-hashes/blob/7fd6900c4f637bd15ee2642dfa77110f8f1ad065/sha2/src/sha256/risc0.rs)
calls `sys_sha_buffer` and preserves the SHA-256 state byte order. RISC Zero's
`risc0/circuit/rv32im/src/prove/witgen/mod.rs:253–259` injects `Back::Sha2`
cycles into its main execution witness. Acceleration therefore does not remove
the need to prove these operations.

The W1 algorithm remains SHA-256. The STARK's polynomial/Merkle commitments use
the separate Poseidon2 hash suite in
`risc0/circuit/rv32im/src/prove/hal/cpu.rs:222–227`. Neither observation proves a
post-quantum security level.

## What the measurements cannot establish

The original local 1800-second attempt and hosted 5400-second attempt timed out
without a retained receipt. The hosted run's prove stdout and stderr are empty;
its evidence is retained separately in
[`w1-risc0-hosted-run-40482711995`](../w1-risc0-hosted-run-40482711995/README.md).
These facts establish failed completion within those budgets. They do not
identify the last completed segment, establish per-segment throughput, or
measure receipt verification latency.

The measured complete guest execution used 13,364,385 user cycles and 62
segments. Dividing a timeout by 62 is not a measured segment proving cost:
neither the count of completed proofs nor the time spent in each phase is
recorded. It is also invalid to extrapolate full proof latency from the
separate execute command.

The new four-thread run's process-group sampler records process identity,
self CPU ticks and resident-memory observations at intervals. It can recover a
lower bound on CPU used by observed descendants that a killed wrapper's
`RUSAGE_CHILDREN` misses. It records no function stack or phase boundary, so it
cannot split time into SHA, witness generation, polynomial commitments, FRI or
verification. Its sum of process RSS values is not a physical-memory peak.

No speedup factor, bottleneck percentage or completed proof is asserted here.
Determining such a split would require an explicitly separate, reproducible
profiling attempt with phase instrumentation. This inspection neither changes
nor restarts the current run.
