# Repeated-sender execution: less speculation, timing remains variable

The production change avoids speculative state work for repeated classical
senders whose nonce already depends on an earlier transaction. Every signature,
ordered state effect and final commitment still executes. This does not change
PQ/Growth state ownership or introduce concurrent publication.

The frozen-source observation uses one libtest, three distributions of 256
signed transactions, four execution workers, two recorded warm-up pairs and
twelve measured alternating-order pairs per distribution. All 84 rows are
retained: 12 warm-up and 72 measured rows. Every execution checks State, root,
receipts, all 256 signature verifications and worker count against the serial
reference. The original full-speculation implementation remains a private test
oracle in the same binary.

| Distinct senders | Reference speculative / reexecuted | Candidate speculative / reexecuted | Reference wall median | Candidate wall median | Median paired candidate/reference |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 256 / 255 | 2 / 1 | 8.784539 ms | 8.869534 ms | 0.974690 |
| 64 | 256 / 255 | 64 / 63 | 11.789661 ms | 11.615358 ms | 0.988131 |
| 256 | 256 / 255 | 256 / 255 | 22.370567 ms | 23.067949 ms | 1.011258 |

The reduction in unnecessary speculation is deterministic for these fixtures.
Wall times vary, and per-arm medians and paired-ratio medians are different
statistics. No consistent whole-executor speedup or confirmed TPS increase is
qualified. [summary.json](summary.json) retains all twelve paired ratios per
case. This is the complete transaction-execution function, not a Node/W1/RPC
or public-confirmation measurement. Per-execution CPU was not captured.

The profile is the original per-package test profile with debug information
disabled, not a whole-Node release benchmark. All data uses the frozen native
source `a9efd4cba7546a8ef1e854ee0acdce9f5903ac2d`. The
[named-execution check](../validation/repeated-sender-named-execution.json)
confirms that the fully qualified selector actually ran the intended test.

An initial mistaken selector selected zero tests despite returning exit zero.
Its complete log and receipt are retained and do not count as an observation.
The corrected selector produced the 84 rows above. Earlier pre-freeze diagnostic
controls and timing logs are retained separately as `*-initial.log.gz`; they
have no complete-checkout command attestation and are not relabelled as this
frozen-source experiment. Their different timing ratios are not discarded.
