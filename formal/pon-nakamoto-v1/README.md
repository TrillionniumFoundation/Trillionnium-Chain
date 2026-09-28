# PoN executable contracts and scientific experiments

This directory extends the existing arithmetic reference into a separately coded
executable design oracle. It is not a second production consensus engine. Native
work and wire candidates live in the existing `trnm-crypto-primitives` and `trnm-protocol`
packages. Production hardness, ordinary-node/Hepta integration and independent acceptance
remain false. Do not restore an old engine or use an accept-all work stub.

## Run conformance

Use the isolated development Python requirements and pinned Rust toolchain:

```bash
python3 -m venv /tmp/pon-conformance-env
/tmp/pon-conformance-env/bin/python -m pip install -r formal/pon-nakamoto-v1/requirements.txt
cargo build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-crypto-primitives --examples
/tmp/pon-conformance-env/bin/python formal/pon-nakamoto-v1/test_contracts.py
CARGO_TARGET_DIR=/path/to/cargo-target TRNM_NATIVE_MODE=release /tmp/pon-conformance-env/bin/python formal/pon-nakamoto-v1/test_interop.py
python3 formal/pon-nakamoto-v1/test_reference.py
```

The requirements reproduce the controlled scientific environment, not runtime or host
production dependencies. Dependency security/upgrades are reviewed separately. Vector
generation is explicit (`generate_vectors.py`) and is NEVER performed by test gates.
`test_interop` fails if native probes are missing rather than turning absence into a skip.

## Run the bounded complete campaign

```bash
CARGO_TARGET_DIR=/path/to/cargo-target python3 formal/pon-nakamoto-v1/experiments/run_campaign.py --source e7b36311fe5306bf63b7f88985801307e9e47d8c --out /tmp/new-pon-campaign-directory
```

The output path must be new. The campaign records real command exits, source/configuration
hashes, native costs, three-process loopback evidence, disk crash tests, real public-source
model optimization, attested score settlement and sponsored consumption. It never accesses
private user tasks, remote provider credentials or deployed services. All child processes
are bounded and reaped. Chain timestamps are fixed logical time, not real UTC acceptance.

Scientific caveats are in [the detailed acceptance contract](../../docs/protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md).
First failed model results, negative shortcut tests, stronger single-expert controls and
cheap-forgery amplification are retained. Multiple authored processes/languages do not
establish independently administered security or future model efficacy.
