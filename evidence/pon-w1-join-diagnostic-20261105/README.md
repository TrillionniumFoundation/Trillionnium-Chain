# Same-input recursive join diagnostics

The original [full two-hour experiment](../pon-w1-v2-deadline-20261105/README.md)
remains failed. These are four newly generated **partial-operation** proofs,
using the same saved verified inputs for the previously slow join-through-0032.
They are not full guest proofs or a reset of that experiment's budget.

The small retained tool uses SDK 3.0.3, strictly decodes and verifies all three
saved inputs, pins the original r0vm SHA-256, invokes the actual SDK join API,
then verifies integrity and the expected joined claim. The prior input receipts
are setup for this diagnostic only. Their creation cost is not represented by
these timings. Each run is observed with the unchanged stage measurement tool.

The ordered prover times were:

- 8 threads, first run: 170.050 seconds.
- 4 threads, first run: 73.530 seconds.
- 8 threads, second run: 43.444 seconds.
- 4 threads, second run: 48.859 seconds.

All four operations produced fresh outputs with distinct recorded hashes and
passed integrity/claim verification. The same input and eight-thread setting
varied by almost fourfold. This does not establish an intrinsically expensive
join32, an exclusive host cause, or a four-thread speed advantage. Two samples
per setting cannot establish p99, stable throughput or a minimum work cost.
The first repeat's prolonged CPU cost also prevents attributing the original
256.843-second event solely to a short wall-clock observation stall.

[results.json](results.json) preserves the exact input/output hashes, individual
wall/CPU/RSS records and all four reports. `raw-diagnostics.tar.gz` includes the
original stage observations. The complete diagnostic source, lock and build log
are retained. It is a measurement helper, not a consensus or verifier fallback.

The next full trial starts from a new empty checkpoint with the same frozen
original guest/host/verifier, eight threads and the original 7,200-second total
budget. It regenerates every segment and recursive receipt. No proof receipt
from the failed experiment or these partial diagnostics is imported.
