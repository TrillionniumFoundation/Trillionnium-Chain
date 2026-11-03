#!/usr/bin/env python3
"""Repeat only the import-blocked Host suite after exact sparse input hydration."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path('/tmp/chain-cell-startup-current-20261103')
OUT = Path(__file__).resolve().parent

def identity():
    paths = subprocess.check_output(['git', 'ls-files', '-z', 'scripts', 'formal', 'config', '.github'], cwd=ROOT).split(b'\0')
    return {raw.decode(): hashlib.sha256((ROOT / raw.decode()).read_bytes()).hexdigest()
            for raw in paths if raw and (ROOT / raw.decode()).is_file()}

argv = ['python3', 'scripts/ci/test_from_zero_host_ci.py', '-v']
before = identity()
start = time.monotonic_ns()
p = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
after = identity()
row = {'schema': 'chain-original-host-controls-after-exact-sparse-hydration-v1',
       'argv': argv, 'cwd': str(ROOT), 'elapsed_ns': time.monotonic_ns() - start,
       'exit_code': p.returncode, 'source_before': before, 'source_after': after,
       'source_unchanged': before == after,
       'native_business_executed': False, 'actual_fixed_host_provisioned': False}
for name, raw in [('stdout', p.stdout), ('stderr', p.stderr)]:
    (OUT / ('host-positive.' + name + '.log')).write_bytes(raw)
    row[name] = raw.decode('utf-8')
    row[name + '_sha256'] = hashlib.sha256(raw).hexdigest()
row['passed'] = p.returncode == 0 and before == after
(OUT / 'HOST_CONTROLS.json').write_text(json.dumps(row, indent=2, sort_keys=True) + '\n')
print(json.dumps({'passed': row['passed'], 'exit_code': p.returncode,
                  'source_inputs': len(before), 'stderr_tail': row['stderr'][-500:]}))
raise SystemExit(0 if row['passed'] else 1)
