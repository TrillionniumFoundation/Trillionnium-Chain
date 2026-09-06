# TRNM Native Live-Path Baseline — 2026-07-27

Scope: single-host native development fixture. This is a regression baseline, not a public-testnet or mainnet performance claim.

## Reproduction

Run four `trnm-chain-validator` processes and one `trnm-chain-node`, then execute:

```bash
TRNM_BENCH_TRANSACTIONS=100 \
TRNM_BENCH_PAYLOAD_BYTES=256 \
trillionnium/scripts/bench_trnm_chain_live.sh
```

The benchmark uses signed HTTP submissions, durable SQLite state, complete block proposals, independent validator execution, `2/3+1` quorum, and receipt lookup for the final transaction.

## Historical reference run

- Build profile: `release`
- Transactions: `100`
- Payload: `256` bytes per transaction
- Submission throughput: `707.97 tx/s`
- Submission p50: `1.232 ms`
- Submission p95: `1.836 ms`
- Finalization of two blocks: `115 ms`
- Chain SQLite + WAL + SHM after abrupt process stop: approximately `3.07 MiB`
- Each validator SQLite + WAL + SHM: approximately `185 KiB`

These numbers are historical single-host development data. Submission throughput is not finalized TPS.

## Local regression thresholds

For the same fixture on a comparable host:

- submission throughput at least `300 tx/s`;
- submission p95 at most `10 ms`;
- finalization at most `1,000 ms`;
- chain SQLite family below `5 MiB`;
- each validator SQLite family below `512 KiB`.

Replace these thresholds with multi-host SLOs only after secure networking, authenticated state sync, validator lifecycle, and sustained adversarial testing are complete.
