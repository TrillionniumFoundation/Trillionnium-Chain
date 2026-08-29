#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

python3 -m py_compile \
  scripts/ci/check_cev1_registry_spec_v1.py \
  tools/independent-cev1-parser/registry_conformance.py \
  tools/w0-w7-codegen/generate.py \
  tools/da-fullrep-model/fullrep_model.py \
  tools/agent-market-model/model.py \
  tools/mvcc-serial-model/model.py \
  tools/verification-model/deterministic_reexecution.py \
  simulations/economics/settlement_model.py \
  tools/whole-node-model/model.py \
  tools/independent-light-client-v1/client.py \
  tools/benchmark-contract/validate.py

python3 scripts/ci/check_cev1_registry_spec_v1.py
bash scripts/ci/check_independent_cev1_registry_v1.sh
bash scripts/ci/check_w0_w7_traceability_v1.sh
bash scripts/ci/check_da_fullrep_model_v1.sh
bash scripts/ci/check_agent_market_model_v1.sh
bash scripts/ci/check_mvcc_serial_equivalence_model_v1.sh
bash scripts/ci/check_deterministic_reexecution_model_v1.sh
bash scripts/ci/check_settlement_conservation_model_v1.sh
bash scripts/ci/check_whole_node_light_client_model_v1.sh
bash scripts/ci/check_benchmark_security_ops_contract_v1.sh

echo "A08-A17 candidate package aggregate: ok"
