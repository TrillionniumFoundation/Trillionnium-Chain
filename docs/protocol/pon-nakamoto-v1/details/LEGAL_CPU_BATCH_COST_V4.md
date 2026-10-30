# Legal CPU batch costs V4

This is a finite positive-ticket experiment under the original maintenance work,
ticket predicate, target, Node admission and authenticated SQLite owners. It does
not change consensus or claim a globally cheapest solver.

## Frozen workload

Two rounds compare the general and eligible maintenance split-limb producers at
1, 2 and 4 actual scoped CPU worker threads. Each of the 12 cohorts has one shared
immutable prepared producer, a fresh Node/store, 64 searches and at most eight
complete W1 attempts per search. Nonces, headers and complete proof streams are
paired across strategies and worker counts. Both worker-count and strategy order
reverse in the second round. The original 240-second campaign and 250-second
capture limits remain fixed. The only argument is a new absolute packet archive
directory; it cannot alter work, attempts, workers or time limits.

Every worker has a distinct recorded Rust thread identity and a bounded start/end
observation. All workers are joined before admission starts. Wall-span overlap is
an observation, not hardware attestation or proof of simultaneous core execution.
The hosted jobs separately retain actual architecture, CPU affinity and cgroup
limits. Four workers may oversubscribe the available cores.

## Accounting and retained bytes

One outer process-clock interval covers the entire batch, including thread setup,
join and per-trial diagnostic recording. Overlapping per-trial wall times are
retained but never summed into that batch cost. Failed attempts and exhausted
searches stay in the denominator. Native admission is serialized after generation
and includes the original complete verification and SQLite work; a standalone
verifier is not charged again.

Fourteen exclusive phases include actual native template acquisition, one shared
preparation, the whole CPU batch, first admission, ordinary cold recovery and
byte readback. Winning packet payloads are also written into separate cohort
directories with file fsync. That archive cost is its own phase. The recurring
producer/encoding/admission subtotal excludes archiving, while the all-phase and
outer observations include it. Whole-process capture additionally includes
settings, output serialization and temporary-store cleanup.

The actual encoded winning packets are retained, and cold-read bytes must match
them exactly. The independent reader checks every retained file hash/length and
the complete file inventory. This readback is not another cryptographic admission
execution. Repeated fixture packets in paired independent stores are explicitly
counted separately from distinct packet identities and are not live-chain rewards.

## Reproduction and limits

- [Native driver](../../../../trillionnium/crates/trnm-pon-node/examples/pon_legal_ticket_batch_v4.rs)
- [Independent reader](../../../../scripts/ci/check_legal_ticket_batch_v4.py)
- [Reader controls](../../../../scripts/ci/test_legal_ticket_batch_v4.py)
- [Exact-source hosted lane](../../../../.github/workflows/pon-legal-ticket-batch-v4.yml)

The old V3 serial driver and its measured outputs remain unchanged. V4 is a new
experiment with additional archive I/O and a whole-batch observation scope; its
all-phase number must not be treated as a pure algorithm-only difference from V3.
GPU, ASIC, SIMD batching, energy, exclusive hardware and global optimality remain
unmeasured. No invalid-transcript solver experiment is introduced here.
