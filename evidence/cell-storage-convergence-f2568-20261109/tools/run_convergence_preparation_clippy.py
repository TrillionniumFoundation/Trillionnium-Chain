#!/usr/bin/env python3
"""Retained preparation compile; explicitly not committed-source acceptance."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HELPER = Path('/home/qq/work/chain-cell-f2568-exact-gates-runner.py')
assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == '806329aaa71ff9952ebefa84995ebd0a0ae576e6e89ed0774cb77f7891892d4a'
spec = importlib.util.spec_from_file_location('original_gate_helpers', HELPER)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
root = Path('/home/qq/work/chain-cell-storage-convergence-f2568-20261109')
out = Path(sys.argv[1])
native_tmp = Path(sys.argv[2])
target = Path('/home/qq/work/chain-cell-storage-convergence-f2568-target')
cfg = {'root': str(root), 'out': str(out)}
runner = helper.Runner(cfg, json.dumps(cfg).encode())
runner.root = root
runner.manifest['schema'] = 'cell-storage-convergence-preparation-clippy-v1'
runner.manifest['scope'] = 'uncommitted preparation Clippy only; no final committed-source acceptance or qualification'
runner.env, removed = helper.scrub_environment(os.environ.copy())
runner.manifest['removed_environment_names'] = removed
runner.provider_path = Path('/home/qq/work/chain-cell-discovery-provider-f2568-20261108/validated-provider.json')
runner.provider_receipt_path = runner.provider_path.parent / 'observations/pq-provider/provider.json'
native_tmp.mkdir(exist_ok=False)
target.mkdir(exist_ok=True)
runner.env.update(CARGO_BUILD_JOBS='2', CARGO_TARGET_DIR=str(target), TMPDIR=str(native_tmp), TMP=str(native_tmp), TEMP=str(native_tmp))
runner.env['PATH'] = '/home/qq/.cargo/bin:' + runner.env.get('PATH', '/usr/bin:/bin')
runner.manifest['mounts'] = {name: runner.mount_receipt(name, path, native=True) for name, path in [('root', root), ('out', out), ('target', target), ('native_tmp', native_tmp)]}
runner.manifest['cargo_configs'] = helper.cargo_config_inputs(root, Path('/home/qq/.cargo'))
runner.manifest['rustup'] = helper.file_identity(Path('/home/qq/.cargo/bin/rustup'))
assert runner.manifest['rustup']['sha256'] == 'b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55'
runner.probe('preflight', ['bash', 'scripts/project-preflight.sh'])
runner.manifest['base_head'] = runner.probe('head', ['git', 'rev-parse', 'HEAD'])
runner.manifest['base_tree'] = runner.probe('tree', ['git', 'rev-parse', 'HEAD^{tree}'])
runner.manifest['status_before'] = runner.probe('status-before', ['git', 'status', '--porcelain'])
for program in ('rustc', 'cargo'):
    runner.probe(program + '-version', ['/home/qq/.cargo/bin/rustup', 'run', '1.95.0', program, '-Vv'])
provider_before = runner.validate_provider('before')
runner.env.update(provider_before['exports'])
runner.manifest['provider_before'] = provider_before

def source_snapshot():
    rows = []
    for directory in ('trillionnium', 'scripts', 'config', '.github'):
        for path in sorted((root / directory).rglob('*')):
            if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
                rows.append({'path': str(path.relative_to(root)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size})
    return rows

before = source_snapshot()
(out / 'source-before.json').write_text(json.dumps(before, indent=2) + '\n')
commands = [('strict-workspace-clippy', ['/home/qq/.cargo/bin/rustup', 'run', '1.95.0', 'cargo', 'clippy', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'])]
success = True
for name, argv in commands:
    entry = {'name': name, 'command': argv, 'started_unix': time.time(), 'exit_code': None}
    runner.manifest['commands'].append(entry)
    runner.checkpoint()
    with (out / (name + '.stdout')).open('wb') as stdout, (out / (name + '.stderr')).open('wb') as stderr:
        p = subprocess.run(argv, cwd=root, env=runner.env, stdout=stdout, stderr=stderr, timeout=2700)
    entry.update(exit_code=p.returncode, ended_unix=time.time())
    for channel in ('stdout', 'stderr'):
        entry[channel] = helper.file_identity(out / (name + '.' + channel))
    success = success and p.returncode == 0
    runner.checkpoint()
    print(json.dumps({'step': name, 'exit_code': p.returncode, 'output': str(out)}), flush=True)
after = source_snapshot()
(out / 'source-after.json').write_text(json.dumps(after, indent=2) + '\n')
runner.manifest['source_unchanged'] = before == after
runner.manifest['provider_after'] = runner.validate_provider('after')
runner.manifest['provider_unchanged'] = provider_before == runner.manifest['provider_after']
runner.manifest['status_after'] = runner.probe('status-after', ['git', 'status', '--porcelain'])
runner.manifest['passed'] = success and runner.manifest['source_unchanged'] and runner.manifest['provider_unchanged'] and runner.manifest['status_before'] == runner.manifest['status_after']
runner.manifest['state'] = 'complete'
runner.manifest['native_tests_executed'] = 0
runner.checkpoint()
sys.exit(0 if runner.manifest['passed'] else 1)
