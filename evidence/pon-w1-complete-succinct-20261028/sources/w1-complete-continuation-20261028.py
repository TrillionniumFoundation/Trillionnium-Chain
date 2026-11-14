#!/usr/bin/env python3
"""One independently budgeted continuation of the frozen full W1 experiment.

The original 90-minute outcome is immutable. This coordinator never edits
the frozen source, overwrites a receipt, substitutes a backend, or labels an
intermediate proof as complete. Existing original source performs all resume
and full-claim checks. An independent pinned verifier supplies a second gate.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

SOURCE = Path('/workspace/scratch/56818e4fba76/chain-w1-next')
CHECKPOINT = Path('/tmp/w1-staged-full-20261028-r3')
ORIGINAL = Path('/tmp/w1-full-90min-20261028')
OUT = Path('/tmp/w1-full-continuation-60min-20261028')
OBSERVER = Path('/tmp/w1-proc-observer-continuation-20261028')
STOP = Path('/tmp/w1-proc-observer-continuation-20261028.stop')
HOST = Path('/tmp/trnm-w1-r2-target/release')
R0VM = Path('/tmp/pure-pon-risc0-3.0.3/r0vm')
SOURCE_COMMIT = '64be7c4ad51d432e7736ad135476262e23e968f5'
SOURCE_TREE = '4157fb5cec32f74dc0d0fe50a4ad93ee11eafbca'
EXPERIMENTS = SOURCE / 'formal/pon-nakamoto-v1/experiments'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    if sys.flags.optimize:
        raise RuntimeError('Python optimization would disable the explicit preflight guards')
    started = time.monotonic()
    started_unix_ns = time.time_ns()
    started_process_cpu = time.process_time()
    deadline = started + 3600
    original_bytes = (ORIGINAL / 'result.json').read_bytes()
    original = json.loads(original_bytes)
    assert original['total_wall_budget_seconds'] == 5400
    assert original['complete_proof_claim'] is False
    assert any(row['result']['timed_out'] for row in original['stages'])
    assert original['error'] is not None
    assert not (CHECKPOINT / 'succinct.bin').exists(), 'Existing final receipt requires direct gates; never rerun compress over it'
    assert not STOP.exists() and not OBSERVER.exists()
    assert len(list(CHECKPOINT.glob('receipt-*.bin'))) == 59
    manifest = json.loads((CHECKPOINT / 'manifest.json').read_text())
    assert manifest['source_commit'] == SOURCE_COMMIT and len(manifest['segments']) == 59
    for filename, key in [('input.bin', 'input_sha256'), ('guest.bin', 'guest_sha256'),
                          ('expected-journal.bin', 'journal_sha256')]:
        assert digest(CHECKPOINT / filename) == manifest[key]
    identity = subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], cwd=SOURCE, text=True).splitlines()
    assert identity == [SOURCE_COMMIT, SOURCE_TREE]
    assert subprocess.check_output(['git', 'status', '--porcelain'], cwd=SOURCE) == b''
    binaries = {
        HOST / 'w1-staged-prover': '1640e4304ad09e6db494c94d0d5069b9e2c3f83e7adb401481a431d81e1f1c2c',
        R0VM: '2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6',
        HOST / 'trnm-w1-zk-host': 'f87b03adcf1d268f724150b5f39fd81c09ca4afd585c7ea239d568ed117fe1b0',
        HOST / 'w1-native-cost': '36e3fcb4042a809a16c5cd153c26cd1059bc7a473f302061348f976c46a6b68d',
        HOST / 'trnm-w1-hardened-verifier': '0a96d752c4418c35b6ff3f6912d5c6b824490dff60f83e26a6101a99c96a3274',
    }
    for path, expected in binaries.items():
        assert digest(path) == expected, str(path)
    files = []
    for path in sorted(CHECKPOINT.rglob('*')):
        assert not path.is_symlink()
        if path.is_file():
            files.append({'path': str(path.relative_to(CHECKPOINT)), 'bytes': path.stat().st_size,
                          'sha256': digest(path)})
    assert shutil.disk_usage(CHECKPOINT).free >= 1024**3
    OUT.mkdir(exist_ok=False)
    write_new(OUT / 'frozen-prefix-before-continuation.json', files)
    with (OUT / 'original-90min-result.json').open('xb') as stream:
        stream.write(original_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    preflight_wall_seconds = time.monotonic() - started
    preflight_cpu_seconds = time.process_time() - started_process_cpu
    declaration = {
        'schema': 'TRNM-W1-INDEPENDENT-CONTINUATION1', 'started_unix_ns': started_unix_ns,
        'prefix_and_source_preflight_wall_seconds': preflight_wall_seconds,
        'prefix_and_source_preflight_cpu_seconds': preflight_cpu_seconds,
        'preflight_consumes_new_total_wall_budget': True,
        'python_assert_guards_enabled': sys.flags.optimize == 0,
        'source_commit': SOURCE_COMMIT, 'source_tree': SOURCE_TREE,
        'original_result_sha256': hashlib.sha256(original_bytes).hexdigest(),
        'original_round_outcome_preserved': True, 'maximum_new_total_wall_seconds': 3600,
        'maximum_original_controller_wall_seconds': 3540,
        'independent_gate_time_reserved_seconds': 60,
        'controller_pauses_consume_wall_budget': True,
        'free_disk_floor_bytes': 1024**3, 'planned_full_segments': 59,
        'checkpoint_manifest_sha256': digest(CHECKPOINT / 'manifest.json'),
        'prefix_inventory_sha256': digest(OUT / 'frozen-prefix-before-continuation.json'),
        'binaries': {str(k): v for k, v in binaries.items()},
        'coordinator_sha256': digest(Path(__file__)),
        'observer_source_sha256': digest(Path('/tmp/w1-owned-proc-observer-20261028.py')),
        'original_controller_source_sha256': digest(EXPERIMENTS / 'w1_full_staged_run.py'),
        'measurement_supervisor_source_sha256': digest(EXPERIMENTS / 'w1_stage_measure.py'),
        'disk_guard_scope': 'Checks before outer proof and additional verification stages; shared disk is also observed externally. This is not a continuous in-compress disk enforcement claim.',
        'no_prior_cost_erased_or_relabelled': True, 'one_fixed_original_execution': True,
        'proof_randomness_tickets': 0, 'complete_proof_claim': False,
        'production_qualification': False, 'consensus_admission': False,
    }
    write_new(OUT / 'declaration.json', declaration)
    observer_command = [sys.executable, '/tmp/w1-owned-proc-observer-20261028.py',
                        '--out', str(OBSERVER), '--checkpoint', str(CHECKPOINT),
                        '--run', str(OUT / 'proof-run'), '--stop-file', str(STOP)]
    observer = subprocess.Popen(observer_command, cwd=SOURCE)
    additional = []
    controller_code = None
    original_gate = False
    hardened_gate = False
    error = None
    observer_outcome = None

    def measured(label, command):
        remaining = deadline - time.monotonic()
        if remaining <= 16 or shutil.disk_usage(CHECKPOINT).free < 1024**3:
            raise RuntimeError('independent total budget or disk floor reached')
        invocation = [sys.executable, str(EXPERIMENTS / 'w1_stage_measure.py'),
                      '--wall-seconds', str(min(30, remaining - 16)),
                      '--out', str(OUT / label), '--', *map(str, command)]
        with (OUT / f'{label}.supervisor.stdout').open('xb') as stdout, \
             (OUT / f'{label}.supervisor.stderr').open('xb') as stderr:
            result = subprocess.run(invocation, cwd=SOURCE, stdout=stdout, stderr=stderr)
        record = json.loads((OUT / label / 'result.json').read_text())
        additional.append({'stage': label, 'result': record})
        write_new(OUT / f'{label}.record.json', record)
        if result.returncode:
            raise RuntimeError(f'actual independent stage failed: {label}: {result.returncode}')

    try:
        command = [sys.executable, str(EXPERIMENTS / 'w1_full_staged_run.py'),
                   '--runner', str(HOST / 'w1-staged-prover'), '--r0vm', str(R0VM),
                   '--checkpoint', str(CHECKPOINT), '--out', str(OUT / 'proof-run'),
                   '--total-wall-seconds', str(min(3540, deadline - time.monotonic() - 60))]
        with (OUT / 'controller.stdout').open('xb') as stdout, \
             (OUT / 'controller.stderr').open('xb') as stderr:
            controller_code = subprocess.run(command, cwd=SOURCE, stdout=stdout, stderr=stderr).returncode
        result = json.loads((OUT / 'proof-run/result.json').read_text())
        original_gate = result['complete_proof_claim']
        if controller_code != 0 or result['error'] is not None:
            raise RuntimeError(f'original continuation controller failed: {controller_code}: {result["error"]}')
        assert original_gate and (CHECKPOINT / 'succinct.bin').is_file()
        pair = [CHECKPOINT / 'header.bin', CHECKPOINT / 'succinct.bin']
        hardened = HOST / 'trnm-w1-hardened-verifier'
        measured('hardened-full-verification', [hardened, 'verify', *pair])
        hardened_gate = True
        measured('hardened-full-cost', [hardened, 'benchmark', *pair])
        measured('hardened-full-negative-controls',
                 [hardened, 'controls', *pair, OUT / 'full-negative-control-assets'])
    except (AssertionError, OSError, RuntimeError, ValueError) as failure:
        error = str(failure)
    finally:
        STOP.write_text('stop after this independent round\n')
        observer_timeout = False
        try:
            observer.wait(timeout=5)
        except subprocess.TimeoutExpired:
            observer_timeout = True
            # This is only the direct Popen child created above, never a
            # /proc PID or another workspace's process group.
            observer.terminate()
            try:
                observer.wait(timeout=2)
            except subprocess.TimeoutExpired:
                observer.kill()
                try:
                    observer.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        observer_outcome = {
            'stop_wait_timed_out': observer_timeout,
            'returncode': observer.returncode,
            'terminal_record_present': (OBSERVER / 'result.json').is_file(),
        }
        if (observer_timeout or observer.returncode != 0
                or not observer_outcome['terminal_record_present']) and error is None:
            error = 'independent resource observer did not close successfully; raw samples retained'
    preserved = digest(ORIGINAL / 'result.json') == declaration['original_result_sha256']
    if not preserved and error is None:
        error = 'original 90-minute raw result changed'
    if time.monotonic() > deadline and error is None:
        error = 'independent total wall budget exceeded'
    report = {**declaration, 'finished_unix_ns': time.time_ns(),
              'new_round_wall_seconds': time.monotonic() - started,
              'coordinator_process_cpu_seconds': time.process_time() - started_process_cpu,
              'coordinator_cpu_scope': 'This Python process only; includes preflight and excludes children, which are separately measured. Do not add the preflight CPU a second time.',
              'controller_returncode': controller_code, 'additional_stages': additional,
              'observer_outcome': observer_outcome,
              'original_full_gate_passed': original_gate, 'hardened_full_gate_passed': hardened_gate,
              'complete_proof_claim': original_gate and hardened_gate,
              'all_declared_controls_and_measurements_completed': error is None,
              'benefit_gate_passed': None, 'error': error,
              'original_90min_result_still_same_sha256': preserved,
              'disk_free_final_bytes': shutil.disk_usage(CHECKPOINT).free}
    write_new(OUT / 'result.json', report)
    print(json.dumps({k: report[k] for k in ['new_round_wall_seconds', 'original_full_gate_passed',
          'hardened_full_gate_passed', 'all_declared_controls_and_measurements_completed', 'error']}))
    return 0 if error is None and original_gate and hardened_gate else 1


if __name__ == '__main__':
    raise SystemExit(main())
