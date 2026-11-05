#!/usr/bin/env bash
# Run through record_pq_native_command.py from a clean, complete checkout.
# No model, deployment, paid custody or WAN acceptance is performed here.
set -euo pipefail
bash scripts/project-preflight.sh
cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline --workspace --all-targets -- -D warnings
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-data-availability --all-targets --all-features
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-data-availability --doc --all-features
test -n "${CARGO_TARGET_DIR:-}"
export TRNM_CELL_BIN="$CARGO_TARGET_DIR/debug/trnm-cell"
test -x "$TRNM_CELL_BIN"
sha256sum "$TRNM_CELL_BIN"
python3 scripts/test_llm_python_runtime_contract.py -v
python3 scripts/test_llm_neural_read_worker.py -v
python3 scripts/test_llm_cell_release.py -v
python3 scripts/ci/test_llm_cell_host_handoff.py -v
python3 scripts/ci/test_llm_cell_handoff_deadline.py -v
python3 scripts/ci/test_llm_cell_provider_ready.py -v
python3 scripts/ci/test_ci_source_integrity.py -v
python3 scripts/ci/test_pq_research_integration.py -v
python3 scripts/ci/test_ci_contract.py -v
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/check_ci_contract.py
python3 scripts/ci/check_repository.py
git diff --check
