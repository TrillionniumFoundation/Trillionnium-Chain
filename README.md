# Trillionnium Chain (TRNM)

Trillionnium Chain is a Rust-native Layer 1 built around a **self-developed
Proof of Consumption (PoCO) consensus and settlement protocol**.

## Binding architecture

The native mainline is:

`trnm-node -> trnm-mempool -> trnm-executor -> trnm-pouw/trnm-state -> finality receipts`

`trnm-protocol` and `trnm-runtime` provide typed transaction and deterministic
state-transition libraries. Third-party consensus engines and adapter runtimes
are outside the production candidate.

## Main modules

- `trnm-node`: native node, validator, proposal/vote, round/view change,
  recovery and finality.
- `trnm-pouw`: PoCO task, proof, challenge, resolution and settlement rules.
  The historical crate name is retained only for source compatibility.
- `trnm-state`: versioned state, balances, governance state and state roots.
- `trnm-executor`: deterministic conflict analysis and grouped execution.
- `trnm-mempool`: bounded admission, QoS, fairness and backpressure.
- `trnm-finality-types` / `trnm-finality-verifier`: portable finality receipts.
- `trnm-rpc`, `trnm-worker-agent`, `trnm-cli`: integration and operator surfaces.

## Build and test

The dependency lock must be regenerated after the consensus-adapter removal:

```bash
cd trillionnium
cargo generate-lockfile
cargo test --workspace
```

Run the native simulator:

```bash
cd trillionnium
cargo run -p trnm-node --bin trnm-sim -- \
  --config configs/node1.toml \
  --block-ms 50 \
  --max-blocks 10
```

## Documentation

- Architecture: `docs/architecture/TRNM_NATIVE_POCO_CONSENSUS.md`
- PoCO protocol: `trillionnium/docs/protocol/poco-proof-of-consumption-v1-draft.md`
- Release posture: `RELEASE_READINESS.md`
- Operations: `OPERATIONS.md`
- Security reporting: `SECURITY.md`

## Status

The native PoCO implementation is under active development. Local tests and
development networks are useful engineering evidence, but the repository is
**not yet public-mainnet ready**. See `RELEASE_READINESS.md` for the current
blockers and evidence rules.
