#!/usr/bin/env python3
"""Prepare the explicit native expected-row subset from retained audit output."""
from hashlib import sha256
from pathlib import Path
import json

BASE = Path(__file__).resolve().parent
source = BASE/'results/full_range_audit/candidates.json'
rows = json.loads(source.read_text())
selected = [row for row in rows if row['target_passes']]
output = BASE/'results/native_expected_rows.json'
raw = (json.dumps(selected,indent=2)+'\n').encode()
if output.exists() and output.read_bytes()!=raw:
    raise ValueError('REFUSE_REPLACE_DIFFERENT_NATIVE_EXPECTED_ROWS')
output.write_bytes(raw)
print(json.dumps({'audit_candidates_sha256':sha256(source.read_bytes()).hexdigest(),
                  'native_expected_rows_sha256':sha256(raw).hexdigest(),
                  'selected_rows':len(selected),'new_ticket_evaluations':0}))
