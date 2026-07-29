# TRNM Live Path Baseline — 2026-07-27

Scope: `loopback-local-devnet`; this is a regression baseline, not a public
testnet or mainnet performance claim.

## Reproduction

Run four legacy `trnm-chain-validator` processes and one legacy
`trnm-chain-node`, then execute. This requires the explicit
`legacy-harness` feature and is historical-only evidence:

```bash
TRNM_BENCH_TRANSACTIONS=100 \
TRNM_BENCH_PAYLOAD_BYTES=256 \
trillionnium/scripts/bench_trnm_chain_live.sh
```

The benchmark uses signed HTTP submissions, durable SQLite state, complete
block proposals, independent validator execution, `2/3+1` quorum, and receipt
lookup for the final transaction.

## Measured reference run

- Build profile: `release`
- Transactions: `100`
- Payload: `256` bytes per transaction
- Submission throughput: `707.97 tx/s`
- Submission p50: `1.232 ms`
- Submission p95: `1.836 ms`
- Finalization of two blocks: `115 ms`
- Chain SQLite + WAL + SHM after abrupt process stop: approximately `3.07 MiB`
- Each validator SQLite + WAL + SHM: approximately `185 KiB`

## Frozen local regression thresholds

For the same 100-transaction/256-byte loopback fixture on this reference host:

- submission throughput must remain at least `300 tx/s`;
- submission p95 must remain at most `10 ms`;
- finalization must remain at most `1,000 ms`;
- chain SQLite family must remain below `5 MiB`;
- each validator SQLite family must remain below `512 KiB`.

These thresholds intentionally allow host noise. They must be replaced by
multi-host SLOs only after authenticated networking, state sync, and the chosen
mature consensus engine are integrated.
