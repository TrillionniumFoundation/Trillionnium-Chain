# Descriptive statistics for the actual balanced strata batch

The [complete result](DESCRIPTIVE_RESULT.md) reports all thirteen phase endpoints,
two observations per arm, execution-half contrasts, observed arrival ranges,
and queue/CPU scopes. [STATISTICS.json](STATISTICS.json) retains the exact integer
nanoseconds, actual stage and deadline/cancellation fields, and missing values.

The actual frozen reader and SP27-06 consumer accepted this batch: thirteen
planned phases completed, including five healthy controls/sentinels and eight
pressure controls. All thirteen independent business operations confirmed before
their original four-second endpoints. The result is `COLLECTED_CONTROL_SERIES`;
the causal mechanism remains `UNKNOWN`.

This is one predeclared forward/reverse series with two phases per arm. Same
request count and body bytes do not imply identical arrived load. The valid arm
includes admission, execution, fork choice and storage. Recorded calling-thread
CPU excludes scoped-worker CPU, and nested CPU/queue intervals must not be added
into a whole-system cost. No significance test or extra native experiment was
performed to obtain a preferred result.

## Provenance and acknowledgments

- [Statistics freeze receipt](RECEIPT.json) binds the summarizer and both result
  files; SHA-256 `4b552c5899185f49f2d9096eb71ef53f13c73c48a5f32b2c94070790dc081db9`.
- [Primary actual consumer receipt](../strata_analysis_v1/CONSUMER_RECEIPT.json)
  binds the unchanged originals and full detailed outputs; SHA-256
  `51e0e351a93f3fe70fef3e809c0e2204a1eb7dcfbe5c5fd9d7c3e03f8e66c8f1`.
- [Root's independent analysis replay](../ROOT_ACK.json) uses the same immutable
  native batch. It is an analysis reproduction, not another native replicate.
- [Current measurement collaboration acknowledgment](../../../strata_analysis_v1/CURRENT_MEASUREMENT_ACK_20261112.json)
  confirms the actual contract and read-back results for this task. The previous
  Agent 06 author and original portfolio coordinator acknowledgments remain
  `NOT_OBSERVED`.

## Reproduce the descriptive tables

After reproducing the primary audit with its frozen contract, run from the Chain
worktree root with a new output directory:

```sh
python3 -B research/sp2027/02_receiver_liveness/batches/ci-43131129970/summarize_strata_descriptive_v1.py \
  --analysis-dir research/sp2027/02_receiver_liveness/batches/ci-43131129970/strata_analysis_v1 \
  --out-dir /absolute/new-descriptive-output
```

The summarizer refuses changed primary input digests and never overwrites an
existing result directory. All input evidence and earlier failed observations
remain unchanged.
