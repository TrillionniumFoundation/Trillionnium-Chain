"""Real process deadline/group controls; no tested PQ image is replaced."""
from __future__ import annotations
from pathlib import Path
from unittest.mock import patch
import argparse
import errno
import hashlib
import json
import os
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from hia.platform.pq_auth.qualification import supervision

NAMES = ('normal', 'nonzero', 'native-timeout', 'group-timeout', 'orphan-after-exit',
         'held-pipe-timeout', 'cleanup-denied', 'launch-error')
CHILD = r'''import json, os, signal, sys
mode = sys.argv[1]
if mode == 'normal':
    data = sys.stdin.buffer.read()
    sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
    sys.stderr.buffer.write(b'normal-stderr\x00\n'); sys.stderr.buffer.flush()
    raise SystemExit(0)
if mode == 'nonzero':
    print('nonzero-stdout', flush=True)
    print('nonzero-stderr', file=sys.stderr, flush=True)
    raise SystemExit(7)
pid = 0
if mode in ('group', 'orphan', 'held-pipe'):
    pid = os.fork()
    if pid == 0:
        if mode == 'orphan':
            for fd in (0, 1, 2):
                os.close(fd)
        while True:
            signal.pause()
print(json.dumps({'mode': mode, 'leader': os.getpid(), 'grandchild': pid}), flush=True)
print('before-native-pause', file=sys.stderr, flush=True)
if mode in ('orphan', 'held-pipe'):
    os._exit(0)
while True:
    signal.pause()
'''


def specs(output, python):
    commands = []
    for name, mode, limit in [('normal', 'normal', 3), ('nonzero', 'nonzero', 3),
            ('native-timeout', 'pause', 0.2), ('group-timeout', 'group', 0.2),
            ('orphan-after-exit', 'orphan', 3), ('held-pipe-timeout', 'held-pipe', 0.2),
            ('cleanup-denied', 'pause', 0.2), ('launch-error', None, 0.2)]:
        argv = [python, '-I', '-S', '-B', '-c', CHILD, mode] if mode else [str(Path(output) / 'absent-executable')]
        commands.append({'name': name, 'argv': argv, 'limit': limit,
                         'data': b'full\x00input\n' * 128 if name == 'normal' else b''})
    return commands


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def fixture_teardown(pgid, real_killpg):
    """Test-only restoration after the explicitly injected denial failure.

    This never changes the tested supervisor receipt to success and is recorded
    separately. It is not a second cleanup attempt by the production supervisor.
    """
    started = time.monotonic()
    deadline = started + 3
    try:
        real_killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    reaped = []
    while time.monotonic() < deadline:
        reaped += supervision.reap_group(pgid, deadline)
        if not supervision.group_exists(pgid):
            return {'status': 'REMOVED_INJECTED_FIXTURE', 'seconds': time.monotonic() - started,
                    'reaped': reaped, 'group_absent': True}
        time.sleep(min(0.005, max(0, deadline - time.monotonic())))
    raise RuntimeError('injected cleanup-control fixture leaked a process')


def reaper_deadline_control():
    """A bounded algorithm control, explicitly separate from real processes.

    Injected waitpid always offers another child. The existing deadline must
    stop the reaper before a third wait; no synthetic observation is used as
    evidence that any actual child was killed or reaped.
    """
    calls = []
    def ready(pgid, options):
        calls.append([pgid, options])
        assert len(calls) <= 2, 'reaper ignored the existing absolute deadline'
        return 1000 + len(calls), 9
    with patch.object(supervision.time, 'monotonic', side_effect=[100.0, 100.5, 101.0]), \
         patch.object(supervision.os, 'waitpid', ready):
        observations = supervision.reap_group(777, 101.0)
    assert calls == [[-777, os.WNOHANG], [-777, os.WNOHANG]]
    assert observations == [{'pid': 1001, 'wait_status': 9, 'exit_code': -9},
                            {'pid': 1002, 'wait_status': 9, 'exit_code': -9}]
    return {'status': 'PASS', 'scope': 'injected-clock-and-waitpid-algorithm-only',
            'absolute_deadline': 101.0, 'clock_readings': [100.0, 100.5, 101.0],
            'waitpid_calls': calls, 'actual_process_cleanup_claimed': False}


def run(output):
    output = Path(output).absolute()
    output.mkdir()
    report = {'status': 'FAIL', 'scope': 'short-real-deadlines-not-the-separate-240-second-demonstration',
              'python': str(Path(sys.executable).resolve()), 'cwd': str(ROOT), 'cases': []}
    started = time.monotonic()
    try:
        report['reaper_deadline_control'] = reaper_deadline_control()
        for spec in specs(output, report['python']):
            name = spec['name']
            real_killpg = os.killpg
            injected = []
            def denied(pgid, sig):
                if sig == signal.SIGKILL:
                    injected.append({'pgid': pgid, 'signal': int(sig), 'errno': errno.EPERM})
                    raise PermissionError(errno.EPERM, 'qualification injected killpg denial')
                return real_killpg(pgid, sig)
            if name == 'cleanup-denied':
                with patch.object(supervision.os, 'killpg', denied):
                    result = supervision.run(spec['argv'], cwd=ROOT, data=spec['data'], execution_seconds=spec['limit'])
            else:
                result = supervision.run(spec['argv'], cwd=ROOT, data=spec['data'], execution_seconds=spec['limit'])
            receipt = result['receipt']
            row = {'name': name, 'receipt': receipt, 'injection': injected}
            for stream, raw in [('stdin', spec['data']), ('stdout', result['stdout']), ('stderr', result['stderr'])]:
                (output / (name + '.' + stream + '.raw')).write_bytes(raw)
                row[stream] = identity(raw)
            (output / (name + '.receipt.json')).write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
            if name == 'cleanup-denied':
                # Even a failed assertion below is reached only after restoring
                # this deliberately denied, real owned process fixture.
                row['fixture_teardown'] = fixture_teardown(receipt['pid'], real_killpg)
            report['cases'].append(row)
            (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
            expected = {'normal': 'success', 'nonzero': 'exit-nonzero', 'native-timeout': 'timeout',
                        'group-timeout': 'timeout', 'orphan-after-exit': 'descendants-outlived-leader',
                        'held-pipe-timeout': 'timeout', 'cleanup-denied': 'cleanup-incomplete',
                        'launch-error': 'launch-error'}[name]
            assert receipt['outcome'] == expected, (name, receipt)
            assert receipt['cleanup_limit_seconds'] == 3 and len(receipt['killpg_attempts']) <= 1
            if name == 'normal':
                assert result['stdout'] == spec['data'] and result['stderr'] == b'normal-stderr\x00\n'
            if name not in ('cleanup-denied', 'launch-error'):
                assert receipt['cleanup_complete'] and receipt['group_absent'] and receipt['direct_child_reaped']
                assert receipt['cleanup_seconds'] <= 3 and not supervision.group_exists(receipt['pgid'])
            if name in ('group-timeout', 'orphan-after-exit', 'held-pipe-timeout'):
                announced = json.loads(result['stdout'])
                assert announced['leader'] == receipt['pid'] and announced['grandchild'] > 1
                assert any(item['pid'] == announced['grandchild'] and item['exit_code'] == -9 for item in receipt['adopted_reaped'])
            if name == 'cleanup-denied':
                assert injected == [{'pgid': receipt['pgid'], 'signal': 9, 'errno': errno.EPERM}]
                assert not receipt['cleanup_complete'] and not receipt['group_absent']
                assert 3 <= receipt['cleanup_seconds'] < 3.5
                assert row['fixture_teardown']['group_absent'] is True
        assert [row['name'] for row in report['cases']] == list(NAMES)
        report['status'] = 'PASS'
    finally:
        report['seconds'] = time.monotonic() - started
        (output / 'fixture.py').write_bytes(Path(__file__).read_bytes())
        (output / 'supervision.py').write_bytes(Path(supervision.__file__).read_bytes())
        (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.output)
    print(json.dumps({'status': report['status'], 'real_process_controls': len(report['cases']), 'seconds': report['seconds']}, sort_keys=True))
