#!/usr/bin/env python3
"""One bounded negative Python/fd error-propagation control, never a W1 run."""
import argparse
import ast
import copy
import errno
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
MIB = 1024 * 1024
parser = argparse.ArgumentParser()
parser.add_argument('--old-owner', type=Path, required=True)
parser.add_argument('--new-owner', type=Path, required=True)
parser.add_argument('--owned-source', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--remaining', type=float, required=True)
args = parser.parse_args()
assert 0 < args.remaining <= 15
def expired(*unused):
    raise TimeoutError('same-new-source-fifteen-second-mechanism-budget-not-reset')
signal.signal(signal.SIGALRM, expired)
signal.setitimer(signal.ITIMER_REAL, args.remaining)
os.nice(19 - os.getpriority(os.PRIO_PROCESS, 0))
resource.setrlimit(resource.RLIMIT_AS, (1024 * MIB, 1024 * MIB))
resource.setrlimit(resource.RLIMIT_FSIZE, (MIB, MIB))
args.output.mkdir(exist_ok=False)
sys.path.insert(0, str(args.owned_source / 'scripts'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exact_finally(module):
    tree = ast.parse(Path(module.__file__).read_text())
    run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run')
    outer = next(n for n in run.body if isinstance(n, ast.Try) and n.finalbody)
    wrapper = ast.FunctionDef(name='isolated_exact_finally',
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg='event_file'), ast.arg(arg='result')],
                           vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=copy.deepcopy(outer.finalbody), decorator_list=[])
    scope = dict(module.__dict__)
    code = ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[]))
    exec(compile(code, '<exact-retained-run-finally>', 'exec'), scope)
    retained = ast.Module(body=copy.deepcopy(outer.finalbody), type_ignores=[])
    return scope['isolated_exact_finally'], hashlib.sha256(ast.dump(retained, include_attributes=False).encode()).hexdigest()


class FaultStream:
    def __init__(self, actual, mode):
        self.actual, self.mode = actual, mode
    def fileno(self):
        return self.actual.fileno()
    def flush(self):
        if 'flush' in self.mode:
            raise OSError(errno.ENOSPC, 'controlled-flush-ENOSPC-not-historical-IO')
        return self.actual.flush()
    def close(self):
        self.actual.close()
        if 'close' in self.mode:
            raise OSError(errno.EIO, 'controlled-close-EIO-after-real-close')


def fd_closed(fd):
    try:
        os.fstat(fd)
        return False
    except OSError as error:
        assert error.errno == errno.EBADF
        return True


old = load('event_finally_frozen_v2', args.old_owner)
new = load('event_finally_revision003', args.new_owner)
old_finally, old_ast = exact_finally(old)
new_finally, new_ast = exact_finally(new)
prior = {'type': 'controlled-prior-negative-fixture', 'message': 'not-an-actual-RPC-or-native-failure'}
cases = []
for name, action, mode, first in [
    ('frozen-v2-fsync-EIO', old_finally, 'fsync', prior),
    ('revision003-fsync-EIO', new_finally, 'fsync', prior),
    ('revision003-flush-ENOSPC', new_finally, 'flush', prior),
    ('revision003-close-EIO', new_finally, 'close', prior),
    ('revision003-flush-and-close', new_finally, 'flush-close', prior),
    ('revision003-no-prior-fsync-EIO', new_finally, 'fsync', None),
]:
    path = args.output / (name + '.events')
    actual = path.open('x', encoding='utf-8')
    actual.write('negative event-file fixture; no work proof or qualification\n')
    fd = actual.fileno()
    before = os.fstat(fd)
    stream = FaultStream(actual, mode)
    original_fsync = os.fsync
    def fault(target):
        if mode == 'fsync' and target == fd:
            raise OSError(errno.EIO, 'controlled-fsync-EIO-on-exact-held-event-fd')
        return original_fsync(target)
    observed = None
    try:
        os.fsync = fault
        try:
            action(stream, {'first_error': copy.deepcopy(first)})
        except Exception as error:
            observed = {'raised_type': type(error).__name__, 'raised_message': str(error),
                        'existing_first_error_field_as_main_reads_it': getattr(error, 'first_error', None)}
        assert observed is not None
        closed_before_fixture_cleanup = fd_closed(fd)
    finally:
        os.fsync = original_fsync
        actual.close()
    assert fd_closed(fd)
    if name.startswith('frozen'):
        assert observed['existing_first_error_field_as_main_reads_it'] is None
        assert not closed_before_fixture_cleanup
    elif first is not None:
        assert observed['existing_first_error_field_as_main_reads_it'] == first
        assert closed_before_fixture_cleanup
    else:
        assert observed['existing_first_error_field_as_main_reads_it']['type'] == 'OSError'
        assert 'controlled-fsync-EIO' in observed['existing_first_error_field_as_main_reads_it']['message']
        assert closed_before_fixture_cleanup
    cases.append({'name': name, 'real_fd': fd, 'real_device': before.st_dev, 'real_inode': before.st_ino,
                  **observed, 'fd_closed_by_candidate_before_fixture_cleanup': closed_before_fixture_cleanup,
                  'fd_closed_after_fixture_cleanup': True, 'controlled_error_injection': True,
                  'physical_hardware_IO_failure_or_historical_cause_proven': False})
assert prior == {'type': 'controlled-prior-negative-fixture', 'message': 'not-an-actual-RPC-or-native-failure'}
result = {'schema': 'event-file-finally-negative-Python-control-only-v1',
          'source_pins': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                          for p in (args.old_owner, args.new_owner)],
          'exact_finally_AST_sha256': {'frozen_v2': old_ast, 'revision003': new_ast},
          'actual_nice': os.getpriority(os.PRIO_PROCESS, 0),
          'actual_parent_AS': resource.getrlimit(resource.RLIMIT_AS),
          'case_wall_cap_seconds': args.remaining,
          'cases': cases, 'all_expected_negative_mechanisms_observed': True,
          'actual_W1_or_native_or_RPC_or_payment_or_Cargo_run': False,
          'qualifying_execution_receipt': False, 'merge_ready': False}
raw = json.dumps(result, indent=2, sort_keys=True).encode() + b'\n'
assert len(raw) <= MIB
with (args.output / 'result.json').open('xb') as report:
    report.write(raw)
print(json.dumps({'result': str(args.output / 'result.json'), 'all_expected_negative_mechanisms_observed': True,
                  'cases': len(cases), 'qualifying_execution_receipt': False}))
