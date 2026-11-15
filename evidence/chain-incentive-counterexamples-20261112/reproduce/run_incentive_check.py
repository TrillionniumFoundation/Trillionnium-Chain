#!/usr/bin/env python3
"""Record one explicitly scoped local command, preserving original output and exit."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--name', required=True)
parser.add_argument('--repo', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('command', nargs=argparse.REMAINDER)
args = parser.parse_args()
command = args.command[1:] if args.command[:1] == ['--'] else args.command
if not command:
    parser.error('empty command')
args.output.mkdir(parents=True, exist_ok=True)
base = args.output / args.name
if base.with_suffix('.receipt.json').exists() or base.with_suffix('.stdout.log').exists():
    raise SystemExit('refusing to overwrite an observation')

def git(*command):
    return subprocess.check_output(['git', *command], cwd=args.repo, text=True).strip()

receipt = {'schema': 'chain-incentive-local-command-observation-v1',
           'argv': command, 'cwd': str(args.repo.resolve()),
           'source_commit_before': git('rev-parse', 'HEAD'),
           'source_status_before': git('status', '--porcelain'),
           'environment': {name: os.environ.get(name) for name in
                           ['CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_PROFILE_TEST_DEBUG',
                            'RUSTC', 'TRNM_MODEL_COMPOSITION_VECTORS',
                            'TRNM_MODEL_COMPOSITION_RUN_ID', 'TRNM_NATIVE_EXECUTOR']},
           'started_utc': datetime.now(timezone.utc).isoformat(),
           'production_activation': False,
           'economic_security_qualified': False}
start = time.monotonic()
with base.with_suffix('.stdout.log').open('wb') as stdout, base.with_suffix('.stderr.log').open('wb') as stderr:
    result = subprocess.run(command, cwd=args.repo, stdout=stdout, stderr=stderr)
receipt.update({'finished_utc': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': time.monotonic()-start, 'exit_code': result.returncode,
                'source_commit_after': git('rev-parse', 'HEAD'),
                'source_status_after': git('status', '--porcelain')})
base.with_suffix('.receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2)+'\n')
print(json.dumps({'name': args.name, 'exit_code': result.returncode,
                  'duration_seconds': receipt['duration_seconds']}, sort_keys=True))
raise SystemExit(result.returncode)
