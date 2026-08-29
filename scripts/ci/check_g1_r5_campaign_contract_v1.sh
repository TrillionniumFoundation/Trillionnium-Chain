#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

tmp=${TMPDIR:-/tmp}/trnm-g1-r5-campaign-v1
rm -rf "$tmp"
mkdir -p "$tmp"

evidence=$(python3 tools/g1-r5-campaign/validate.py \
  --self-test \
  --write-fixtures "$tmp")

for count in 4 7; do
  python3 tools/g1-r5-campaign/validate.py --manifest "$tmp/${count}-validator.json"
done

python3 - "$evidence" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v["schema"]=="trnm-g1-r5-campaign-contract-evidence-v1"
assert v["fixtures"]==[4,7]
assert len(v["scenarios"]["4"])==10
assert len(v["scenarios"]["7"])==10
assert len(v["negative"])==12
assert v["campaign_execution_authorized"] is False
assert v["validator_run_completed"] is False
assert v["g1_r5_exit"] is False
print("G1-R5 campaign contract: ok")
PY

cmp "$tmp/4-validator.json" conformance/g1-r5/4-validator-campaign-fixture-v1.json
cmp "$tmp/7-validator.json" conformance/g1-r5/7-validator-campaign-fixture-v1.json
