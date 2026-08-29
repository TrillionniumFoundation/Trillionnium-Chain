#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

bash scripts/ci/check_g2e_source_binding_v2.sh
bash scripts/ci/check_settlement_conservation_model_v1.sh

cargo +1.95.0 test --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-poco-consumption-settlement-v1 --all-targets
cargo +1.95.0 clippy --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-poco-consumption-settlement-v1 --all-targets -- -D warnings
cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check

out=$(PYTHONDONTWRITEBYTECODE=1 python3 -B simulations/economics/settlement_risk_v2.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-settlement-risk-evidence-v2'
assert v['positive']==4
assert len(v['negative'])==11
assert v['risk_root']=='8c9b246d0c94f0ffaf477c9385f296cc98f70951bed9316eb970efedb15d3a57'
assert v['ordering_invariant'] is True
for key in ('settlement_authority','governance_authority','poco_weight_eligible','production_activation'):
    assert v[key] is False, key
print('G2E Rust/SQLite settlement, risk, concentration and collusion assurance: ok')
PY

git diff --check
