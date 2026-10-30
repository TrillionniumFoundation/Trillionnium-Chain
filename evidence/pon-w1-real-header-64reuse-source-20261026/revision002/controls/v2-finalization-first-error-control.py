#!/usr/bin/env python3
"""Negative metadata-cap predicate only; no W1 actor/build/payment/qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import sys
import time

sys.dont_write_bytecode = True
parser = argparse.ArgumentParser()
parser.add_argument('--owner', type=Path, required=True)
parser.add_argument('--owned-source', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--remaining', type=float, required=True)
args = parser.parse_args()
assert 0 < args.remaining <= 15
def expired(*unused):
    raise TimeoutError('new-v2-mechanism-budget-not-reset')
signal.signal(signal.SIGALRM, expired)
signal.setitimer(signal.ITIMER_REAL, args.remaining)
os.nice(19 - os.getpriority(os.PRIO_PROCESS, 0))
MIB = 1024 * 1024
resource.setrlimit(resource.RLIMIT_AS, (1024 * MIB, 1024 * MIB))
resource.setrlimit(resource.RLIMIT_FSIZE, (16 * MIB, 16 * MIB))
args.output.mkdir(exist_ok=False)
sys.path.insert(0, str(args.owned_source / 'scripts'))
spec = importlib.util.spec_from_file_location('v2_finalization_first_error_owner', args.owner)
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
for name, size in [('first.bin', 16 * MIB), ('second.bin', 16 * MIB - 256)]:
    with (args.output / name).open('xb') as stream:
        stream.truncate(size)
original = {'type': 'controlled-original-fixture-error', 'message': 'negative-predicate-not-a-native-run'}
result = {'component_execution_complete': False, 'first_error': original,
          'qualifying_execution_receipt': False, 'whole_work_hardness_qualified': False}
observed = None
try:
    owner.seal_outputs(args.output, result, time.monotonic(), time.monotonic() + 2)
except ValueError as error:
    observed = {'finalization_error': str(error), 'preserved_first_error': getattr(error, 'first_error', None)}
assert observed is not None and observed['preserved_first_error'] == original
assert not (args.output / 'owner-result.json').exists()
assert not (args.output / 'post-write-terminal.json').exists()
print(json.dumps({'scope': 'negative-Python-finalization-predicate-only',
                  'owner_sha256': hashlib.sha256(args.owner.read_bytes()).hexdigest(),
                  'metadata_overcap_refused_before_final_files': True, **observed,
                  'actual_W1_or_native_or_Cargo_or_payment_run': False,
                  'qualifying_execution_receipt': False, 'merge_ready': False}))
