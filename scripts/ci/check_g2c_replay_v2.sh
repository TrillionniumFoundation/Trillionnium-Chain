#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

bash scripts/ci/check_g2c_source_binding_v2.sh
bash scripts/ci/check_g2c_profile_registry_v1.sh
out=$(PYTHONDONTWRITEBYTECODE=1 python3 -B tools/verification-model/outbox_recovery_v2.py --self-test)
python3 - "$out" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v['schema']=='trnm-g2c-outbox-recovery-evidence-v2'
assert v['positive']==10
assert len(v['negative'])==8
assert len(v['outbox_root'])==64
assert v['final_status']==v['unchallenged_status']=='ResultFinal'
for key in ('economic_authority','order_reorg_authority','governance_authority','production_activation'):
    assert v[key] is False, key
print('G2C outbox/retry/appeal assurance: ok')
PY

git diff --check
