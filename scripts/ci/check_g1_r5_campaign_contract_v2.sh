#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

PYTHONDONTWRITEBYTECODE=1 python3 -B \
  tools/g1-r5-campaign-v2/generate_fixtures.py \
  config/campaigns/g1-r5-v2-fixture-source.json \
  --output-dir "$tmp"

for count in 4 7; do
  manifest="$tmp/g1-r5-${count}-validator-v2.json"
  report=$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
    tools/g1-r5-campaign-v2/validate.py "$manifest")
  python3 - "$count" "$report" <<'PY'
import json,sys
count=int(sys.argv[1]); report=json.loads(sys.argv[2])
assert report['schema']=='trnm-g1-r5-campaign-validation-v2'
assert report['validator_count']==count
assert report['campaign_execution_authorized'] is False
assert report['outcome']=='BLOCKED_UPSTREAM'
assert report['topology_counts']['validators']==count
assert report['topology_counts']['hosts']==count
assert report['topology_counts']['operators']==count
assert report['topology_counts']['custody_domains']==count
assert report['topology_counts']['regions']==3
assert report['scenario_count']>=12
assert report['production_candidate'] is False
assert report['production_consensus_activation'] is False
PY
  self_test=$(PYTHONDONTWRITEBYTECODE=1 python3 -B \
    tools/g1-r5-campaign-v2/validate.py "$manifest" --self-test)
  python3 - "$self_test" <<'PY'
import json,sys
report=json.loads(sys.argv[1])
assert report['schema']=='trnm-g1-r5-campaign-self-test-v2'
assert report['baseline_outcome']=='BLOCKED_UPSTREAM'
assert report['retained_mutants']==8
assert report['retained_mutants_rejected']==8
PY
done

python3 - <<'PY'
import json
from pathlib import Path
source=json.loads(Path('config/campaigns/g1-r5-v2-fixture-source.json').read_text())
assert source['source_commit']=='e88cda9401eb6219fe1425bebb1ef6b54b4c429d'
assert source['source_tree']=='9c4249ce36061fcbd6eb8e522accd29127f7c01c'
assert source['harness_only'] is True
assert source['production_candidate'] is False
assert source['production_consensus_activation'] is False
validator=Path('tools/g1-r5-campaign-v2/validate.py').read_text()
for token in (
    'region_id',
    'workload_sha256',
    'fault_schedule_sha256',
    'binary_sha256',
    'sbom_sha256',
    'genesis_sha256',
    'accepted-r4-evidence-required',
    'transport-smoke-is-not-validator-evidence',
    'conflicting_finality',
    'double_sign',
    'root_divergence',
):
    assert token in validator, token
print('G1-R5 campaign contract v2: ok; execution remains BLOCKED_UPSTREAM')
PY

git diff --check
