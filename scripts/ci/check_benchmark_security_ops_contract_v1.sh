#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

tmp=${TMPDIR:-/tmp}/trnm-benchmark-security-ops-v1
rm -rf "$tmp"
mkdir -p "$tmp"

evidence=$(python3 tools/benchmark-contract/validate.py \
  --self-test \
  --write-fixture "$tmp/fixture.json")

python3 tools/benchmark-contract/validate.py --manifest "$tmp/fixture.json"

python3 - "$evidence" <<'PY'
import json,sys
v=json.loads(sys.argv[1])
assert v["schema"]=="trnm-benchmark-security-ops-contract-evidence-v1"
assert v["positive"]=="harness-contract-valid"
assert len(v["negative"])==14
assert v["claim_class"]=="harness-only"
assert v["results_present"] is False
assert v["surpass_claim_allowed"] is False
assert v["public_testnet_ready"] is False
assert v["production_candidate"] is False
print("benchmark/security/operations contract: ok")
PY
