#!/usr/bin/env python3
"""Finish this one already-authorized C3 observation chain; never rebuild C3 gates.

Only controller waits are bounded here. The original gate runner retains every
command timeout, and the prepared model runner retains 300s native/360s outer.
An unresolved or failed phase preserves all outputs and admits no later phase.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace


REPO = Path('/home/qq/work/chain-cell-four-gates-20261111-2bfb')
SOURCE = '030de92be05bfd4f73e199098c12dfeaedf29b17'
TREE = '21e970bfdb11ab64403d2af5f3c56536a2961f80'
TARGET = Path('/home/qq/work/chain-cell-four-gates-2bfb-target-c1')
CANDIDATE = Path('/home/qq/work/chain-cell-four-gates-2bfb-c3-full-gates/summary.json')
OBSERVERS = Path('/home/qq/work/chain-cell-four-gates-2bfb-c3-observers')
MODEL_EVIDENCE = Path('/home/qq/work/chain-cell-four-gates-2bfb-real-operation-01-evidence')
MODEL_OUTPUT = Path('/home/qq/work/chain-cell-four-gates-2bfb-real-operation-01')
RECORDS = Path('/home/qq/work/chain-cell-four-gates-2bfb-c3-phase-supervisor')
MODEL_RUNNER = Path('/home/qq/work/run_cell_four_gates_paged_operation_2bfb.py')
MODEL_RUNNER_PIN = 'b407dcfc881589388cbd0f2f0a29273647780184f745e2b1db04e193225b0481'
FRESH_SPEC = Path('/home/qq/work/cell-four-gates-paged-source-operation-01.json')
FRESH_SPEC_PIN = 'cfeb462afd142ba0c2dd29f722216161346810038e19c0ac1815b12f4828d107'
ORIGINAL_SPEC = Path('/home/qq/work/chain-cell-paged-model-34e09-20261110/evidence/cell-paged-model-release-34e09-20261110/paged-source-inputs.operation02.release.v1.json')
ORIGINAL_SPEC_PIN = 'f1a5f11fafda16ff865b1cc71fab4d64aa652e2ca7addb5a2a3ab9ce03deead6'
PROVIDER = Path('/home/qq/work/chain-cell-discovery-provider-f2568-20261108/runner/trnm-pq-provider-3.5.9.ReYCJ9gV/install')
PROVIDER_PIN = 'ed29dfe14c0686c876833e39fbeedb277846987f3728acc279c256b32259cf62'
RUST_BIN = '/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin'
CARGO_HOME = '/home/qq/.cargo'
CONTROLLER_WAIT_SECONDS = 7200


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def failure_details(summary):
    if not summary.is_file():
        return {'summary': str(summary), 'present': False}
    value = json.loads(summary.read_bytes())
    failed = []
    for item in value.get('commands', []):
        if item.get('exit_code') == 0 and not item.get('timed_out') and item.get('exact_native_test_observed', True):
            continue
        detail = {key: item.get(key) for key in ('name', 'status', 'exit_code', 'timed_out', 'exact_native_test_observed')}
        for stream in ('stdout', 'stderr'):
            path = summary.parent / (item['name'] + '.' + stream)
            if path.is_file():
                with path.open('rb') as source:
                    source.seek(max(0, path.stat().st_size - 4096))
                    detail[stream + '_tail'] = source.read().decode('utf-8', errors='replace')
        failed.append(detail)
    return {'summary': str(summary), 'summary_sha256': pin(summary),
            'completed': value.get('completed'), 'all_commands_passed': value.get('all_commands_passed'),
            'source_unchanged': value.get('source_unchanged'), 'provider_pin_unchanged': value.get('provider_pin_unchanged'),
            'run_passed': value.get('run_passed'), 'native_stage': value.get('native_stage'),
            'native_error': value.get('native_error'), 'failure': value.get('failure'),
            'failed_commands': failed}


def main():
    os.umask(0o077)
    sys.dont_write_bytecode = True
    # The exclusive directory is the single owner for this exact continuation.
    # Idempotent PTY starts reuse the existing process; a competing owner refuses.
    RECORDS.mkdir(mode=0o700)
    report = {'schema': 'cell-c3-authorized-phase-supervisor-v1', 'source': SOURCE, 'tree': TREE,
              'started_unix_ns': time.time_ns(), 'pid': os.getpid(), 'phase': 'admission',
              'completed': False, 'passed': False, 'stages': [],
              'controller_wait_seconds': CONTROLLER_WAIT_SECONDS,
              'controller_wait_scope': 'Waiting for existing C3 completion and target release only; no child timer changes or termination',
              'production_qualified': False, 'independent_domains_qualified': False, 'wan_qualified': False}
    command_line = Path('/proc/self/cmdline').read_bytes().split(b'\0')
    if b'-c' in command_line:
        report['supervisor_sha256'] = hashlib.sha256(command_line[command_line.index(b'-c') + 1]).hexdigest()
    else:
        report['supervisor_sha256'] = pin(Path(__file__))

    def save():
        pending = RECORDS / 'summary.pending.json'
        with pending.open('wb') as stream:
            stream.write((json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, RECORDS / 'summary.json')

    def event(**values):
        values['unix_ns'] = time.time_ns()
        raw = json.dumps(values, sort_keys=True)
        with (RECORDS / 'events.jsonl').open('a') as stream:
            stream.write(raw + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        print(raw, flush=True)

    def run_phase(name, argv):
        report['phase'] = name
        item = {'phase': name, 'argv': argv, 'cwd': str(REPO), 'started_unix_ns': time.time_ns(), 'status': 'starting'}
        report['stages'].append(item)
        save()
        event(phase=name, status='starting', argv=argv)
        # Each original runner owns its original child timeouts and evidence.
        process = subprocess.Popen(argv, cwd=REPO)
        item.update(pid=process.pid, status='running')
        save()
        code = process.wait()
        item.update(exit_code=code, status='completed', ended_unix_ns=time.time_ns())
        save()
        event(phase=name, exit_code=code, status='completed')
        require(code == 0, name + ' failed; preserve its original records')

    try:
        save()
        for path in (OBSERVERS, MODEL_EVIDENCE, MODEL_OUTPUT):
            require(not path.exists(), 'fresh later-phase output required: ' + str(path))
        require(pin(MODEL_RUNNER) == MODEL_RUNNER_PIN, 'prepared model runner pin')
        require(pin(FRESH_SPEC) == FRESH_SPEC_PIN and pin(ORIGINAL_SPEC) == ORIGINAL_SPEC_PIN, 'prepared input pins')
        spec = importlib.util.spec_from_file_location('cell_original_prepared_observer', MODEL_RUNNER)
        model = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(model)
        require(model.verify_spec(json.loads(FRESH_SPEC.read_bytes()), json.loads(ORIGINAL_SPEC.read_bytes())) == MODEL_OUTPUT,
                'original operation contract')
        args = SimpleNamespace(repo=REPO, source=SOURCE, tree=TREE)
        deadline = time.monotonic() + CONTROLLER_WAIT_SECONDS
        report['phase'] = 'wait-existing-candidate'
        save()
        seen = None
        while True:
            require(time.monotonic() < deadline, 'existing candidate unresolved at controller wait bound')
            value = json.loads(CANDIDATE.read_bytes())
            require(value.get('source') == SOURCE and value.get('root') == str(REPO) and value.get('lane') == 'candidate',
                    'existing candidate identity')
            progress = (len(value.get('commands', [])), value.get('completed'),
                        value.get('commands', [{}])[-1].get('name'), value.get('commands', [{}])[-1].get('status'))
            if progress != seen:
                event(phase=report['phase'], command_count=progress[0], completed=progress[1], latest_command=progress[2], latest_status=progress[3])
                seen = progress
            if value.get('completed') is True:
                break
            time.sleep(2)
        report['phase'] = 'validate-candidate'
        save()
        require(len(value['commands']) == 68, 'complete C3 candidate command roster')
        committed_runner = REPO / 'scripts/ci/run_cell_storage_four_gates_v1.py'
        runner_pin = model.file_hash(committed_runner)
        candidate_pin = model.file_hash(CANDIDATE)
        candidate, _ = model.verify_gate(CANDIDATE, candidate_pin, 'candidate', args, runner_pin)
        model.checked_identity(REPO, SOURCE, TREE)
        require(candidate['environment']['CARGO_TARGET_DIR'] == str(TARGET), 'original target')
        require(candidate['environment']['TRNM_PQ_OPENSSL_SHA256'] == PROVIDER_PIN
                and candidate['environment']['TRNM_PQ_OPENSSL'] == str(PROVIDER / 'bin/openssl')
                and model.file_hash(PROVIDER / 'bin/openssl') == PROVIDER_PIN, 'original provider')
        report['candidate_summary_sha256'] = candidate_pin
        with Path(str(TARGET) + '.owner.lock').open('r+b') as target_lock:
            while True:
                require(time.monotonic() < deadline, 'target release unresolved at controller wait bound')
                try:
                    fcntl.flock(target_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(1)
            fcntl.flock(target_lock.fileno(), fcntl.LOCK_UN)
        event(phase='candidate-qualified', commands=68, candidate_summary_sha256=candidate_pin, target_lock_closed=target_lock.closed)
        require(not OBSERVERS.exists(), 'preserve observer output')
        run_phase('observers', [sys.executable, '-B', str(committed_runner), '--repo', str(REPO),
                  '--source', SOURCE, '--lane', 'observers', '--output', str(OBSERVERS), '--target', str(TARGET),
                  '--rust-bin', RUST_BIN, '--cargo-home', CARGO_HOME, '--provider', str(PROVIDER),
                  '--provider-sha256', PROVIDER_PIN])
        report['phase'] = 'validate-observers'
        save()
        observer_summary = OBSERVERS / 'summary.json'
        observer_pin = model.file_hash(observer_summary)
        observer, _ = model.verify_gate(observer_summary, observer_pin, 'observers', args, runner_pin)
        require(len(observer['commands']) == 7, 'complete C3 observer command roster')
        model.checked_identity(REPO, SOURCE, TREE)
        require(model.file_hash(PROVIDER / 'bin/openssl') == PROVIDER_PIN, 'provider unchanged')
        require(pin(MODEL_RUNNER) == MODEL_RUNNER_PIN and pin(FRESH_SPEC) == FRESH_SPEC_PIN, 'prepared observer inputs unchanged')
        binary = TARGET / 'release/examples/cell_sealed_research_paged_next_use_v1'
        binary_pin = model.file_hash(binary)
        report.update(observer_summary_sha256=observer_pin, binary_sha256=binary_pin)
        save()
        event(phase='observers-qualified', commands=7, observer_summary_sha256=observer_pin, binary_sha256=binary_pin)
        for path in (MODEL_EVIDENCE, MODEL_OUTPUT):
            require(not path.exists(), 'preserve fresh model output: ' + str(path))
        run_phase('model', [sys.executable, '-B', str(MODEL_RUNNER), '--repo', str(REPO), '--target', str(TARGET),
                  '--source', SOURCE, '--tree', TREE, '--original-spec', str(ORIGINAL_SPEC), '--spec', str(FRESH_SPEC),
                  '--spec-sha256', FRESH_SPEC_PIN, '--candidate-summary', str(CANDIDATE),
                  '--candidate-summary-sha256', candidate_pin, '--observer-summary', str(observer_summary),
                  '--observer-summary-sha256', observer_pin, '--binary-sha256', binary_pin, '--output', str(MODEL_EVIDENCE)])
        model_result = json.loads((MODEL_EVIDENCE / 'summary.json').read_bytes())
        require(model_result.get('completed') is True and model_result.get('run_passed') is True, 'actual model receipt did not pass')
        report.update(phase='complete', completed=True, passed=True, model_summary_sha256=pin(MODEL_EVIDENCE / 'summary.json'))
        event(phase='complete', passed=True, model_summary_sha256=report['model_summary_sha256'])
    except BaseException as error:
        report.update(completed=True, passed=False, failure_type=type(error).__name__, failure=str(error))
        report['diagnostics'] = [failure_details(path) for path in
                                 (CANDIDATE, OBSERVERS / 'summary.json', MODEL_EVIDENCE / 'summary.json')]
        event(phase=report['phase'], passed=False, failure_type=type(error).__name__, failure=str(error))
    finally:
        report['ended_unix_ns'] = time.time_ns()
        save()
    print(json.dumps({'phase_summary': str(RECORDS / 'summary.json'), 'passed': report['passed'],
                      'phase': report['phase'], 'failure': report.get('failure')}, sort_keys=True), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
