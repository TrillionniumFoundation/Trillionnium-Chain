set -euo pipefail
set +e
python3 scripts/w1_lifetime_ledger.py --input evidence/pon-w1-lifetime-20261107/project-input.json > "$W1_CLOSURE_OUT/historical-reader.stdout" 2> "$W1_CLOSURE_OUT/historical-reader.stderr"
code=$?
set -e
test "$code" -eq 2
python3 - "$code" <<'PY'
import json, os
from pathlib import Path
import sys
sys.path.insert(0, 'scripts/ci')
import w1_qrom_closure_current_controls as controls
out = Path(os.environ['W1_CLOSURE_OUT'])
controls.require((out / 'historical-reader.stdout').read_bytes() == b'', 'historical refusal emitted a success report')
refusal = controls.strict_json((out / 'historical-reader.stderr').read_bytes())
controls.require(set(refusal) == {'status', 'error'} and refusal['status'] == 'REFUSED'
                 and refusal['error'].startswith('source identity mismatch: '), 'unexpected historical refusal')
record = {'schema': 'TRNM-W1-LIFETIME-HISTORICAL-CURRENT-REFUSAL2',
          'expected_source': os.environ['EXPECTED_SOURCE'], 'exit_code': int(sys.argv[1]),
          'historical_refusal': refusal, 'historical_pins_relaxed': False}
with (out / 'historical-refusal.json').open('x') as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write('\n')
PY
