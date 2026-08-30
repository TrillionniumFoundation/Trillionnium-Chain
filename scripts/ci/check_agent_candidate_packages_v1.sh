#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

# The historical A16/A17 whole-node and benchmark branches were explicitly
# invalidated by the G15/A08 base repair (PR 10).  Their standalone model and
# light-client files are therefore intentionally absent from this source head;
# do not silently resurrect or execute them as if they were current evidence.
# Keep this assertion executable so a future replay must update this aggregate
# and its source binding at the same time.
python3 - <<'PY'
from pathlib import Path
import tomllib

manifest_path = Path("docs/development/packages/trnm-g2f-manifest-v1.toml")
manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
assert manifest["status"] == "STOP_CONDITION"
assert manifest["blocking_status"] == "BLOCKED_UPSTREAM"
prior = {entry["pull_request"]: entry for entry in manifest["prior_candidate"]}
for pull_request in (18, 19):
    entry = prior[pull_request]
    assert entry["classification"] == "upstream-invalidated-candidate"
    assert entry["terminal_status"] == "BLOCKED_UPSTREAM"
    assert entry["invalidated_by"] == 10

historical_paths = (
    "tools/whole-node-model/model.py",
    "tools/independent-light-client-v1/client.py",
    "scripts/ci/check_whole_node_light_client_model_v1.sh",
)
present = [path for path in historical_paths if Path(path).exists()]
assert not present, f"invalidated A16/A17 paths unexpectedly present: {present}"
print("A16/A17 historical candidate paths: intentionally absent and invalidated")
PY

python3 -m py_compile \
  scripts/ci/check_cev1_registry_spec_v1.py \
  tools/independent-cev1-parser/registry_conformance.py \
  tools/w0-w7-codegen/generate.py \
  tools/da-fullrep-model/fullrep_model.py \
  tools/agent-market-model/model.py \
  tools/mvcc-serial-model/model.py \
  tools/verification-model/deterministic_reexecution.py \
  simulations/economics/settlement_model.py \
  tools/benchmark-contract/validate.py

python3 scripts/ci/check_cev1_registry_spec_v1.py
bash scripts/ci/check_independent_cev1_registry_v1.sh
bash scripts/ci/check_w0_w7_traceability_v1.sh
bash scripts/ci/check_da_fullrep_model_v1.sh
bash scripts/ci/check_agent_market_model_v1.sh
bash scripts/ci/check_mvcc_serial_equivalence_model_v1.sh
bash scripts/ci/check_deterministic_reexecution_model_v1.sh
bash scripts/ci/check_settlement_conservation_model_v1.sh
bash scripts/ci/check_benchmark_security_ops_contract_v1.sh

echo "A08-A15 candidate package aggregate: ok; A16-A17 historical candidates remain invalidated"
