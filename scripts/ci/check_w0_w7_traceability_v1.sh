#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"
out=${TMPDIR:-/tmp}/trnm-w0-w7-operation-matrix-v1.json
python3 tools/w0-w7-codegen/generate.py --output "$out"
python3 - "$out" <<'PY'
import json, sys
value=json.load(open(sys.argv[1], encoding='utf-8'))
assert value['schema']=='trnm-w0-w7-operation-matrix-v1'
assert value['status']=='candidate-non-normative'
assert value['g2_0_complete'] is False
rows=value['rows']
assert len(rows)==30
assert [r['kind'] for r in rows]==list(range(30))
assert rows[29]['status']=='disabled'
assert rows[29]['required_links']==['W0']
assert all(set(r['evidence'])==set(r['required_links']) for r in rows)
assert all(all(v is None for v in r['evidence'].values()) for r in rows)
assert all('W7' in r['required_links'] for r in rows[:29])
assert all('W6' not in r['required_links'] for r in rows if r['plane']!='settlement')
print('w0-w7 traceability generator: ok')
PY
