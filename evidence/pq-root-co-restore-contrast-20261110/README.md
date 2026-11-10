# PQ Root V4: common-restore vs recovery-pin contrast (2026-11-10)

**Scope:** a single local Rust native negative/control test, not an independent custody qualification. The test is stacked on #837 source commit `44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0` and changes no product gate, signing profile, time window, or budget.

The first enrolled root operation is signed and recorded, then a second distinct operation advances the journal and anchor. After restoring the root SQLite bytes **and** the anchor's remembered head to operation one, the test explicitly replays a recovery-floor pin **from the same old state**: it passes signed ancestry and a fresh authenticated anchor exchange and accepts the old operation. Merely possessing a structurally valid `RecoveryFloorV4` is not evidence that the pin survived the attack.

In the paired control, the second operation's pin is held outside the rollback of the fixture, while the restored owner and anchor remain unchanged. The same open is refused with `ROOT_OWNER_RECOVERY_FLOOR_NOT_IN_SIGNED_HISTORY` before anchor exchange; file contents and mock-anchor call count do not change. The test uses in-process mock owner/anchor and real native signatures; it **does not** authenticate an independent operator, key custody, freshness source, clock, network channel, physical recovery domain, or production deployment.

## Reproduction

```sh
PATH=/home/qq/.cargo/bin:$PATH \
TMPDIR=/dev/shm/pq-root-co-restore-20261110 \
CARGO_TARGET_DIR=/home/qq/trnm-v4-e12ecc-recovery/tmp/pq-root-co-restore-target-20261110 \
CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 \
cargo test --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --features pq-root-v3 --test recovery_floor_v4_native -- --nocapture
```

Observed on `ai395`: **9 passed, 0 failed**, including the new contrast. The exact original stdout and stderr from durable job `1a1c52749c1-cf39-622` are retained without editing:

- `native-stdout.log`: SHA256 `18a8bd22dc7781e1a81f5780801f56e3e7806bcbcb3eceb6e68d1908f8bc0819`
- `native-stderr.log`: SHA256 `052ae54bde20fbf4bd9c01e73b4708978edd305e311b05eed50b8b6185d3cc11`

**Qualification:** `HOLD`; `actual_lifetime_failure_bound=null`; `independent_custody_verified=false`; `anchor_independence_verified=false`; `freshness_source_authenticated=false`; `whole_chain_pq_qualified=false`; `production_activation=false`. Closing common-restore anti-rollback still requires independently authenticated, operationally separate, surviving freshness history and a real recovery drill. Neither fixture control supplies these proofs.
