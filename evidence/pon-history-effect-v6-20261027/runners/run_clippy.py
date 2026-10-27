#!/usr/bin/env python3
"""Required strict M01/Node metadata gate on a stable original 25-package graph."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('binding', HERE / 'run_native.py')
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)
out = HERE / sys.argv[1]
out.mkdir(exist_ok=False)
env = os.environ.copy()
env.update(PATH='/workspace/scratch/301262829a43/pon-build-inputs/unpacked/toolchain/bin:' + env['PATH'],
           CARGO_HOME='/workspace/scratch/301262829a43/pon-build-inputs/original-cargo-home',
           CARGO_TARGET_DIR='/tmp/pon-history-final-20261027', CARGO_BUILD_JOBS='1',
           CARGO_PROFILE_TEST_DEBUG='0', CARGO_INCREMENTAL='0')
assert not env.get('RUSTFLAGS') and not env.get('CARGO_ENCODED_RUSTFLAGS')
command = ['cargo', 'clippy', '--offline', '--locked', '--manifest-path',
           'trillionnium/Cargo.toml', '-p', 'trnm-crypto-primitives', '-p',
           'trnm-pon-node', '--all-targets', '--all-features', '--', '-D', 'warnings']
before = binding.snapshot()
(out / 'source-before.json').write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
record = {'schema': 'history-effect-v6-strict-clippy-source-bound-v1', 'command': command,
          'environment': {k: env[k] for k in ('PATH', 'CARGO_HOME', 'CARGO_TARGET_DIR',
                                             'CARGO_BUILD_JOBS', 'CARGO_PROFILE_TEST_DEBUG',
                                             'CARGO_INCREMENTAL')},
          'started_unix': time.time(), 'runner_sha256': binding.sha(Path(__file__)),
          'source_binding_runner_sha256': binding.sha(HERE / 'run_native.py'),
          'cargo_lock_sha256': binding.sha(binding.ROOT / 'trillionnium/Cargo.lock'),
          'production_qualified': False}
(out / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
with (out / 'clippy.log').open('w') as log:
    process = subprocess.run(command, cwd=binding.ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
after = binding.snapshot()
(out / 'source-after.json').write_text(json.dumps(after, sort_keys=True, indent=2) + '\n')
record.update(returncode=process.returncode, source_stable=before == after,
              finished_unix=time.time(), log_sha256=binding.sha(out / 'clippy.log'))
record['passed'] = process.returncode == 0 and before == after
(out / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record), flush=True)
raise SystemExit(0 if record['passed'] else 1)
