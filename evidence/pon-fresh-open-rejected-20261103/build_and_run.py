#!/usr/bin/env python3
"""Small component experiment; no production source or Host policy edits."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent
SOURCE = Path('/tmp/chain-cell-startup-current-20261103/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs')
EXPECTED = '6f4cf524831e8af8e23c954764e388d6d167f125c3de0dd19ce235630ce7df7d'
RUSTC = Path('/workspace/scratch/1f1d02319616/recovered-toolchain-20261103/bin/rustc')
DEPS = Path('/tmp/chain-cell-target-20261103/debug/deps')

def sha(data):
    return hashlib.sha256(data).hexdigest()

raw = SOURCE.read_bytes()
if sha(raw) != EXPECTED:
    raise SystemExit('production reader differs from the selected source')
source = raw.decode()
if source.count('mod kernel_parent {') != 1 or source.count('    pub struct KernelBudget {') != 1:
    raise SystemExit('unexpected production insertion boundary')
observed = source.replace('mod kernel_parent {', 'pub mod kernel_parent {').replace(
    '    pub struct KernelBudget {',
    (ROOT / 'probe_addition.rs').read_text() + '    pub struct KernelBudget {')
(ROOT / 'observed_production_reader.rs').write_text(observed)
command = [str(RUSTC), '--edition=2021', '-C', 'opt-level=3',
           '-L', 'dependency=' + str(DEPS), str(ROOT / 'main.rs'),
           '-o', str(ROOT / 'fresh-open-probe')]
dependencies = {}
for name in ('serde', 'serde_json', 'rustix'):
    paths = list(DEPS.glob('lib' + name + '-*.rlib'))
    if len(paths) != 1:
        raise SystemExit('ambiguous existing dependency: ' + name)
    path = paths[0]
    dependencies[name] = {'path': str(path), 'sha256': sha(path.read_bytes())}
    command += ['--extern', name + '=' + str(path)]
environment = dict(os.environ)
environment['LD_LIBRARY_PATH'] = str(RUSTC.parent.parent / 'lib')
receipt = {'production_source': str(SOURCE), 'production_sha256': EXPECTED,
           'original_library_error_type': 'component harness uses boxed errors, not a complete Node build',
           'command': command, 'dependencies': dependencies,
           'rustc_sha256': sha(RUSTC.read_bytes()),
           'production_source_edited': False}
for name, command in [('compile', command), ('run', [str(ROOT / 'fresh-open-probe')])]:
    start = time.time_ns()
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True)
    end = time.time_ns()
    (ROOT / (name + '.stdout')).write_bytes(result.stdout)
    (ROOT / (name + '.stderr')).write_bytes(result.stderr)
    receipt[name] = {'argv': command, 'start_unix_ns': start, 'end_unix_ns': end,
                     'exit': result.returncode, 'stdout_sha256': sha(result.stdout),
                     'stderr_sha256': sha(result.stderr)}
    print(name, result.returncode, flush=True)
    if result.returncode:
        break
receipt['production_after_sha256'] = sha(SOURCE.read_bytes())
receipt['binary_sha256'] = sha((ROOT / 'fresh-open-probe').read_bytes()) if (ROOT / 'fresh-open-probe').exists() else None
receipt['source_manifest'] = {f.name: sha(f.read_bytes()) for f in ROOT.iterdir() if f.suffix in ('.rs', '.py')}
(ROOT / 'RECEIPT.json').write_text(json.dumps(receipt, indent=2) + '\n')
if result.returncode:
    raise SystemExit(result.returncode)
