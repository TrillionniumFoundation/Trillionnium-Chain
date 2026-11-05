#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"
bash scripts/project-preflight.sh

case "${1:?select native, checks or clippy}" in
  native)
    cargo test --manifest-path trillionnium/Cargo.toml --locked \
      -p trnm-data-availability --all-targets --all-features
    cargo test --manifest-path trillionnium/Cargo.toml --locked \
      -p trnm-data-availability --all-features --doc
    ;;
  checks)
    cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
    python3 scripts/refresh_distributed_source_inventory.py --check
    python3 scripts/ci/check_pq_research_integration.py
    python3 scripts/ci/check_ci_contract.py
    python3 -m unittest discover -s scripts/ci -p 'test_ci_source_integrity.py' -v
    python3 -m unittest discover -s scripts/ci -p 'test_pq_research_integration.py' -v
    python3 -m unittest discover -s scripts/ci -p 'test_pq_chain_claim_guard.py' -v
    python3 -m unittest discover -s scripts/ci -p 'test_pq_authority_surface_scan.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_cell_dependency_closure.py' -v
    python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_model_release_root.py' -v
    python3 scripts/ci/check_repository.py
    cargo metadata --manifest-path trillionnium/Cargo.toml --locked --offline \
      --format-version 1
    ;;
  clippy)
    cargo clippy --manifest-path trillionnium/Cargo.toml --locked \
      --workspace --all-targets -- -D warnings
    ;;
  *)
    exit 2
    ;;
esac
