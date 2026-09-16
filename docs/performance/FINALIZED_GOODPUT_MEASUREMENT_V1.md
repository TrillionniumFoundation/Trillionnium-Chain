# Finalized goodput measurement v1

This gate measures chain-level performance only from canonical transaction
telemetry. It deliberately excludes the speculative executor and scheduler
micro-benchmarks.

The input is JSON Lines using
`docs/schemas/e2e_tx_event_v1.schema.json`, one record per submitted
transaction. A record is eligible for the result only when all of the
following hold:

- `execution_path` is exactly `canonical`;
- `finality_status` is `finalized`;
- `replay_verified` is `true`;
- `finalized_at_utc` is present and not earlier than `submitted_at_utc`.

The measurement refuses to run if a record is marked `speculative` or if no
transaction satisfies the finality and replay conditions. This prevents an
executor-only benchmark from being reported as chain TPS.

Run:

```bash
python3 trillionnium/scripts/measure_finalized_goodput.py \
  run/bench/e2e-events.jsonl \
  --output run/bench/finalized-goodput.json
```

The output contains the source SHA-256, exact counts, measurement window,
finalized goodput, and latency p50/p95/p99. Percentiles use deterministic
nearest-rank (`ceil(p*n)`). Goodput is replay-verified finalized transactions
divided by the interval from the first submission to the last qualifying
finalization. Pending, rejected, and finalized-but-not-replay-verified records
are counted as exclusions and cannot increase goodput.

`segment_latency_ms_avg` is optional telemetry, reported only for qualifying
transactions. It is diagnostic and does not alter the goodput denominator.
Independent reproductions must use a new event-file digest whenever workload,
topology, binary, protocol, or measurement window changes.
