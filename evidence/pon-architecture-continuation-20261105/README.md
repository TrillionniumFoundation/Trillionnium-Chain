# Permissionless architecture continuation — 2026-11-05

Continue the existing Draft PR #688 from
`6ee529046d295e3175f09112492abee373f1f54c`, with protected main still
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` at initial inspection.
The [existing development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [comparison contract](../../docs/protocol/pon-nakamoto-v1/details/ARCHITECTURE_COMPARISON_V1.md)
remain the authority. This package contains scoped engineering/research evidence,
not a complete Bitcoin-NG, Prism, OHIE or GHOSTDAG native successor.

## Implemented changes

- Repair the bounded OHIE model's invalid-conflict-prefix proposal starvation.
  Stable executable selection retains all mempool entries for dependency arrival
  or reorganization. Explicit input transactions and protocol domains are unchanged.
- Bind architecture observations to sequential wall lower bounds, positive equal
  frame bytes per workload, exact signed-transaction payload bytes and integer
  denominators. Concurrent pool calls contribute a per-round maximum, not their
  summed waiter time. Consistency is not execution authentication.
- Carry the original two-second frame and 15-second campaign deadlines across
  socket progress and completion. Cancel siblings on error, join threads and
  retain the original sender/receiver failures. Connect and filesystem/kernel
  stalls are not universally preemptible; late success is refused after return.
- Add a bounded uniform-work Algorithm 1 GHOSTDAG ordering kernel and an
  independent set-based oracle. Complete dependencies, deterministic ordering,
  the whole blue-set anticone invariant and all red vertices remain explicit.
  Unsupported work/difficulty and exhausted budgets refuse success.

## Reproduction

Run from a clean checkout of the recorded source commit, using the pinned
Rust 1.95.0 toolchain and the unchanged lockfile. Use a private Cargo home/target
for concurrent projects. The Python graph campaign uses no native work or PQ.

```sh
bash scripts/project-preflight.sh
python3 -B formal/pon-nakamoto-v1/test_parallel_variable_ohie.py -v
python3 -B formal/pon-nakamoto-v1/test_ghostdag_order_reference.py -v
python3 -B formal/pon-nakamoto-v1/experiments/test_architecture_compare.py -v
python3 -B scripts/ci/test_architecture_host_ci.py -v
python3 -B formal/pon-nakamoto-v1/experiments/ghostdag_order_campaign.py --max-blocks 6 --output /absolute/new/ghostdag.json
python3 -B formal/pon-nakamoto-v1/experiments/ghostdag_order_campaign.py --replay /absolute/new/ghostdag.json
cargo test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test architecture_delivery_compare --no-run
cargo test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test architecture_delivery_compare -- --skip signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract --nocapture --test-threads=1
cargo clippy --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test architecture_delivery_compare -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/test_ci_source_integrity.py
python3 scripts/ci/test_project_boundary.py
python3 scripts/ci/check_repository.py
```

The component native command deliberately reports its omitted full-business
selector. Run that original selector separately through its unchanged fixed Host
and complete execution owner:

```sh
python3 formal/pon-nakamoto-v1/experiments/architecture_compare.py --out /absolute/new/architecture-business
```

No changed budget or locally fabricated Host substitutes for that run. The
original no-attack and four-second/16-hostile-W1 acceptance, depth plus required
work, 4,105-block History, current PQ roots, native state/effect recovery,
independent WAN operation and successor security assumptions remain open.
The final execution record and failure logs are added after freezing source;
uncommitted exploratory results retain their separate byte identities.
