# Trillionnium Chain — PoN / Hepta-PoH

A public-model commons and Nakamoto-style neural-work chain under development.
The retired PoCO-BFT implementation and its protocol/deployment/test trees are removed.
Only consensus-neutral portable components remain. There is **no enabled ledger node or
qualified neural-work primitive**, and no silent historical fallback.

[Development plan](docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) ·
[Protocol](docs/protocol/pon-nakamoto-v1/README.md) · [M00-M17](docs/modules/README.md) ·
[Actual source inventory](config/portability-inventory-v1.json)

```bash
git clone https://github.com/TrillionniumFoundation/Trillionnium-Chain.git trillionnium-chain
cd trillionnium-chain
bash scripts/project-preflight.sh
python3 scripts/ci/check_repository.py
python3 scripts/ci/test_repository.py
python3 formal/pon-nakamoto-v1/test_reference.py
RUST_TEST_THREADS=1 cargo test --locked --workspace --all-targets --all-features --manifest-path trillionnium/Cargo.toml
```

Use the pinned Rust toolchain. Tests cover retained local components and explicitly
labelled reference examples, not a mining network or measured AI efficacy. Task/MVCC/
settlement stores require future branch/reorg integration. Storage/assessment thresholds
are not ledger votes. Fresh stores are mandatory; old databases are not upgrade inputs.

See [security](SECURITY.md), [operations](OPERATIONS.md) and
[release status](RELEASE_READINESS.md). Production and release remain disabled.

The hosted qualification serializes separate test cases to isolate process/disk fault
fixtures. Explicit parallel actors, worker counts and race assertions inside each test
remain unchanged. Product deadlines are not increased. Parallel-harness timing failures
are retained as observations and do not establish or revoke a production SLO.

The peer-lease partial-client scheduling test uses a private memory-backed fixture on
Linux to keep disk contention out of that network property. Disk-backed persistence
and corruption tests remain separate. No physical disk latency SLO is claimed.
