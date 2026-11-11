# SP27-01 producer-history observer

This research-only example extends observation coverage over the existing
Sparse/FullLimb/TargetHit producer. It changes no work relation, task authority,
admission, reward, chainwork, public service limits or production qualification.
The sole development plan remains authoritative.

`sp27_01_history` accepts one JSON configuration path. Declared families are
dense, zero, sparse and rank-one base recipes; caps are 1/8/32, with at most
eight sessions and target bits at most seven. Each session stops at first hit
or its original cap. Both policies have identical cache/batch/structure rights.
The reset-session policy voluntarily discards the cache; it is not an optimal
honest miner or a lower bound on any legal miner.

Each output line has a consecutive sequence number. The observer includes input
generation and content task identity; actual preparation and post-construction
requested-heap residency; all hits and misses; all 512 transcript callbacks;
local file output/fsync, receiver read, full native and reference verification;
delivery unlink and task drop. Negative controls cover changed challenge/task/
product, noncanonical input, cancellation and equal retry. It grants **zero
Node credit**, including after full relation verification.

An external harness must record source/tree, binary, configuration, original
stdout/stderr, process lifetime, exit status, child CPU and RSS. It can launch
new processes at a fixed session boundary; no cache is implicitly restored.
Changing a job label does not create a new native content task. Alternating
A[0] uses a one-entry cache; a two-entry legal cache could retain both products.
The altered zero/rank-one families need not retain their base structural rank.

Requested heap bytes exclude allocator metadata and physical RSS. Byte-time is
post-preparation residency and includes interleaved verification/observation;
construction/destruction allocation integrals are not observed. Parent totals
are inclusive and must not be added to nested stage spans. Controls are separate
from workload attempts. Archived evidence copy cost is separate from delivery.

CPU affinity and a cooperative lock do not establish exclusive machine access.
On an unqualified shared host, timings are diagnostic only; no formal performance,
node TPS, energy, GPU, monetary or all-algorithm cost claim follows. Incomplete
runs retain their original prefix and no estimated replacement cost.

Build after project preflight:

```sh
cargo build --locked --release --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example sp27_01_history
```

This observer is a minimal research patch for coordinator integration. Existing
V4 lifecycle, preparation factorials, interruption, cost-frontier and conditional
calibration evidence retain their original identities and novelty boundaries.
