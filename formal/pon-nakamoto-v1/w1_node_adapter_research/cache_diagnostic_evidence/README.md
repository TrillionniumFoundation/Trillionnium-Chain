# Instrumented DFT cache diagnosis

Source d12cd31e43f984196f01a517341c2017071dd697 is an isolated diagnostic
rooted at published #871 f2ad. The checksum-pinned original p3-dft0.8.0 is
vendored with explicit stderr events at actual request and miss closures.
Both setups, PCS checks, fresh challengers, durable owner and native replay
remain. This path patch and separately generated lock belong to the diagnostic
only. Published #871 runtime and the completed ABBA remain unchanged.

One benign retained-proof exercise observes 12 requests, 10 misses and 2 hits.
Coset keys at log-height13 and14 are disjoint. Each height requests shift7
twice and misses once; the other six coset keys each miss once. Inverse13
and inverse14 each miss once. No forward requests are observed. This single
operation observes reuse within a height, with no repeated key shared between
the two component heights. It is not a universal statement about all inputs.
The full keys and counts are in checks-probe-04/manifest.json; raw stderr is
retained. Logging changes timing: no speedup or formal performance sample
is claimed. This diagnostic adds one retained full-proof replay, zero new
complete W1 proofs, and zero formal ABBA samples.

The isolated source passes27 adapter tests, strict all-target/all-feature
Clippy, both locked/offline graphs, original source43 and repository50 controls,
repository/link checks and equal original full-source before/after receipts.
The upstream standalone vendor formatter also passes. These selected checks
are not the historical217 methods or a prospective merge pass.

Retained-index.json binds the top-level raw logs/manifests of six named
execution directories, including initial branch/preflight refusal, standalone
workspace refusal and mistaken source-suite path refusal. None are hidden.
Original diagnostic ELF remains on ai395 at task suffix
-diag-1017/target/release/w1-node-adapter-research,8401448B, SHA-256
cc80eb2ad1d7a42cc9546e3959f17ddc90255aa3eb324f4429cf063ab0c87a8d.
It is excluded from these retained files. Proof assets remain the same original
Git fixture; owner/receiver database directories are also excluded explicitly.
No execution authentication, original service resource envelope or WAN result
follows. Qualification remains HOLD_NO_GO.

Next decompose public-table materialization, polynomial extension and Merkle
commitment hashing before choosing an equivalent preprocessing algorithm.
Do not promote these cache counts into receiver-cost savings or remove native
replay. All production, whole-chain, WAN/ACK and cryptographic gates remain.
