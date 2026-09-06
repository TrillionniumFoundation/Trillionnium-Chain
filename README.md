# Trillionnium Chain

Trillionnium Chain is a Rust L1 built around a **native, self-developed consensus stack**.
External consensus engines are not part of the architecture and must not be added as runtime, build, test, release, or documentation dependencies.

## Canonical path

```text
signed transaction
  -> trnm-chain-node ingress and mempool
  -> native proposal / vote / round-change protocol
  -> trnm-chain-validator quorum and anti-equivocation checks
  -> deterministic execution and state transition
  -> durable state, receipts, and AppHash
```

Canonical binaries live in `trillionnium/crates/trnm-node`:

- `trnm-chain-node`
- `trnm-chain-validator`
- `trnm-chain-cli`
- `trnm-sim` for deterministic simulation and regression testing

`trnm-runtime`, `trnm-state`, `trnm-executor`, `trnm-mempool`, and the protocol/type crates provide reusable state-machine and execution boundaries. The native node remains the only consensus implementation.

## Build and test

```bash
cd trillionnium
cargo test --workspace --locked
cargo build -p trnm-node --features self-consensus --bins --locked
./scripts/check_bft_4node_smoke.sh
./scripts/check_bft_restart_recovery.sh
./scripts/check_bft_message_auth.sh
./scripts/check_bft_round_change.sh
```

Repository policy and residue checks:

```bash
bash scripts/project-preflight.sh --audit
bash scripts/ci/check_self_consensus_only.sh
```

## Documentation

- Architecture decision: `docs/architecture/TRNM_SELF_DEVELOPED_CONSENSUS_CANONICAL_2026-09-07.md`
- Operations: `OPERATIONS.md`
- Release posture: `RELEASE_READINESS.md`
- Security policy: `SECURITY.md`
- Documentation index: `docs/README.md`

## Release posture

The native consensus direction is binding, but the repository is **not yet public-mainnet ready**. Multi-host adversarial testing, state sync, validator lifecycle, secure signing, governance, economic security, independent audit, and sustained end-to-end performance evidence remain release blockers.
