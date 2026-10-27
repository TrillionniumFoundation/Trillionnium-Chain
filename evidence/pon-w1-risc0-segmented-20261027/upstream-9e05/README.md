# Actual upstream four-thread full W1 timeout

The original exact-head [run 40492528095](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40492528095)
used source `9e05ad5d237660fb0ea8b40dd5c29af4225551d3`, tree
`952666bff72a49d8bc7693b27ff747f56a56b240`. Its complete 54-file artifact is
retained byte-for-byte in [original-attempt1.zip](original-attempt1.zip), with
every member inventoried in [original-attempt.json](original-attempt.json).
The ZIP is 281,153 bytes, SHA-256
`34e745c52311ed632b61cab65f8adcc4e365d4592aa4e0c625a3d0dbb1cae690`.
The [original job metadata](github-original-job.json) preserves every step's
actual success, failure or skipped outcome.

The complete pinned guest executed successfully with 13,364,385 user cycles,
62 segments at po2 18, and a journal equal to native full W1. This remains
execution-only evidence. Actual proof generation started at 11:16:25 UTC and
timed out at 12:46:25 UTC on 2026-10-27: 5,400.004265402 captured seconds,
return code 124, empty prover stdout/stderr and **no receipt**. Independent
proof verification and proof attacks were skipped. Both source-byte checks
passed at the original head: 5,968 tracked entries and 757,782,524 bytes.

The actual 15-second process-group sampler retained 362 observations and two
PID/start-time identities. It observed at least 21,349.52 user plus 8.55 system
CPU seconds. Its maximum sampled sum RSS was 2,471,399,424 bytes. These are
sampling observations: two partial read errors are retained, short-lived or
escaped processes may be missed, and summed RSS may double-count shared pages.
The values are neither complete CPU accounting nor a physical memory peak.
The wrapper's separately reported 0.023048/0.003353 waited-child CPU seconds and
14,840 KiB RSS must not be relabelled as the prover's cost: they omit the orphan
prover's complete settlement. Resource limits were not established by missing
root cgroup files. The timeout's root cause is still unknown; substantial
sampled CPU use alone does not identify which segment or phase was expensive.

This failure is preserved separately from the earlier d961 timeout. No failed
attempt is replaced with success. The proposed next attempt keeps the exact
same guest, complete W1 relation, image, po2 and proof acceptance policy, while
exporting actual segments and independently waiting for two two-thread workers.
It retains each actual segment outcome and requires final complete Composite
verification before producing a complete-proof success. At this source freeze,
the successor Rust host build and full proof remain unexecuted. This observation
grants no consensus authority, useful-model quality or post-quantum qualification.
