#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
out=${TMPDIR:-/tmp}/trnm-independent-cev1-registry-evidence.json
rm -f "$out"
python3 tools/independent-cev1-parser/registry_conformance.py \
  --registry-dir docs/protocol/poco-ai-native-v1/registry \
  --evidence-out "$out"
python3 - "$out" <<'PY'
import json, sys
p=sys.argv[1]
d=json.load(open(p, encoding='utf-8'))
assert d['classification']=='candidate-non-normative'
assert len(d['registry_digests'])==6
assert len(d['negative_cases'])==8
assert all(x['result']=='rejected' for x in d['negative_cases'])
assert d['global_cev1_conformance_complete'] is False
assert d['normative_freeze'] is False
print('independent cev1 registry conformance: ok')
PY
