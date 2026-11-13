#!/usr/bin/env python3
"""Validate the inventory correction and replay failed suites without relaxing gates."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

WORK = Path(__file__).resolve().parent
ROOT = WORK.parent / 'chain-pq'
ORIGINAL = WORK / 'frozen-campaign-c9fb3fa6'
OUT = WORK / 'serial-followup-d239bc8f'
HEAD = 'd239bc8f683da7cdc8a4b9dc8e763d67e74680f6'
sys.path.insert(0, str(ROOT / 'scripts/ci'))
from verify_ci_source import verify
from run_pq_root_native_v3 import checked_result, suites as suites_v3
from run_pq_root_continuation_v4 import suites as suites_v4


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    original = json.loads((ORIGINAL / 'summary.json').read_text())
    assert original['source'] == 'c9fb3fa61e2aadbdeaf39e85a7e21604d72581b7'
    assert original['complete_source_endpoints_match']
    assert not original['all_commands_exit_zero'], 'no redundant rerun of a passing campaign'
    env = dict(os.environ)
    env['PATH'] = str(WORK / 'rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin') + ':' + env['PATH']
    env.update(CARGO_HOME=str(WORK / 'cargo'), CARGO_TARGET_DIR='/tmp/trnm-pq-target-a6fe',
               CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0', RUST_TEST_THREADS='1', PYTHONDONTWRITEBYTECODE='1')
    for line in (WORK / 'provider.env').read_text().splitlines():
        if line:
            key, value = line.split('=', 1)
            env[key] = value
    subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, env=env, check=True)
    OUT.mkdir(exist_ok=False)
    before = verify('head', HEAD, root=ROOT)
    delta = subprocess.check_output(['git', 'diff', '--name-only', original['source'], HEAD], cwd=ROOT, text=True).splitlines()
    assert delta == ['config/pon/pq-cross-branch-corpus-v1.json', 'trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs']
    save(OUT / 'source-delta.json', {'original_source': original['source'], 'followup_source': HEAD, 'changed_paths': delta, 'cryptographic_implementation_and_cost_example_bytes_unchanged': True})
    save(OUT / 'source-before.json', before)
    save(OUT / 'environment.json', {
        'source': HEAD,
        'original_source': original['source'],
        'source_delta': ['trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs', 'config/pon/pq-cross-branch-corpus-v1.json'],
        'cryptographic_source_and_cost_example_bytes_changed': False,
        'reason': 'Original owner build received SIGKILL and original V2 signing exceeded its unchanged 15-second cap. These failures are retained; the kill source is unestablished.',
        'changes_from_original': {'cargo_build_jobs': [2, 1], 'lanes': ['native plus controls in parallel', 'all follow-up commands serial']},
        'profile_optimization_and_debug_settings_overridden': False,
        'test_budgets_or_timeouts_relaxed': False,
        'environment': {k: env.get(k) for k in ('CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL', 'RUST_TEST_THREADS', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'OPENSSL_DIR', 'OPENSSL_STATIC', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'TRNM_PQ_OPENSSL', 'TRNM_PQ_OPENSSL_SHA256', 'TRNM_PQ_OPENSSL_VERSION')},
        'initial_load_average': list(os.getloadavg()), 'shared_executor_load_is_controlled': False,
    })
    cargo = ['cargo', '--offline', '--locked', '--manifest-path', 'trillionnium/Cargo.toml']
    control_commands = [
        ('inventory', ['python3', 'scripts/refresh_distributed_source_inventory.py', '--check']),
        ('corpus', ['python3', 'scripts/ci/check_pq_research_integration.py']),
        ('claim-guard', ['python3', 'scripts/ci/pq_chain_claim_guard.py']),
        ('root-register', ['python3', 'scripts/ci/pq_root_dependency_register.py']),
        ('cargo-graph', ['cargo', 'metadata', *cargo[1:], '--all-features', '--format-version=1']),
        ('cargo-tree', ['cargo', 'tree', *cargo[1:], '--workspace', '--all-features']),
        ('format', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check']),
        ('source-integrity-controls', ['python3', 'scripts/ci/test_ci_source_integrity.py']),
        ('native-command-controls', ['python3', 'scripts/ci/test_record_pq_native_command.py']),
        ('corpus-controls', ['python3', 'scripts/ci/test_pq_research_integration.py']),
        ('claim-guard-controls', ['python3', 'scripts/ci/test_pq_chain_claim_guard.py']),
        ('authority-surface-controls', ['python3', 'scripts/ci/test_pq_authority_surface_scan.py']),
        ('repository-and-links', ['python3', 'scripts/ci/check_repository.py']),
        ('crypto-strict-clippy', ['cargo', 'clippy', *cargo[1:], '-p', 'trnm-crypto-primitives', '--all-targets', '--all-features', '--', '-D', 'warnings']),
        ('strict-workspace-clippy', ['cargo', 'clippy', *cargo[1:], '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']),
    ]
    selected = [(name, argv, None, None) for name, argv in control_commands]
    old_journal = next(row for row in original['commands'] if row['name'] == 'v2-native-journal')
    if old_journal['exit_code']:
        selected.append(('v2-native-journal', old_journal['argv'], None, old_journal['stderr']['path']))
    for name, make_suites in [('native-v3', suites_v3), ('native-v4', suites_v4)]:
        rows = json.loads((ORIGINAL / name / 'commands.json').read_text())
        by_name = {row['name']: row for row in rows}
        for child, argv, expected in make_suites():
            old = by_name[child]
            if old['exit_code'] != 0 or old['error'] is not None:
                assert argv == old['argv']
                selected.append((name + '-' + child, argv, expected, name + '/' + old['log']))
    assert all(row['name'] in ('v2-native-journal', 'native-v3', 'native-v4', 'strict-workspace-clippy') for row in original['commands'] if row['exit_code']), 'inspect any new failure before broadening follow-up'
    records = []
    node_build_blocked = False
    for name, argv, expected, original_log in selected:
        if node_build_blocked and name.startswith('native-v4-'):
            row = {'name': name, 'argv': argv, 'source': HEAD, 'original_failed_log': original_log,
                   'executed': False, 'exit_code': None, 'observation': None,
                   'error': 'Not rerun: identical trnm-pon-node prerequisite build was SIGKILLed again under serial follow-up. Original V4 failures remain retained.'}
            records.append(row)
            save(OUT / 'commands.json', records)
            print(json.dumps(row), flush=True)
            continue
        start = time.monotonic()
        timed_out = False
        with (OUT / (name + '.log')).open('xb') as log:
            process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=1200 if expected else 1800)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                code = 124
        raw = (OUT / (name + '.log')).read_bytes()
        if name == 'native-v3-root-owner' and code == 101 and b'SIGKILL' in raw and b'could not compile `trnm-pon-node`' in raw:
            node_build_blocked = True
        observation = None
        error = None
        try:
            text = raw.decode('utf-8', errors='strict')
            if expected:
                observation = checked_result(text, expected, code)
            elif name == 'v2-native-journal':
                if code != 0 or re.findall(r'^Ran (\d+) tests in ', text, re.M) != ['14'] or not re.search(r'^OK$', text, re.M):
                    raise ValueError('complete 14-test original journal suite did not pass')
                observation = {'tests_run': 14, 'terminal': 'OK'}
            elif code != 0:
                raise ValueError('command did not pass')
        except (ValueError, UnicodeError) as problem:
            error = str(problem)
        row = {'name': name, 'argv': argv, 'source': HEAD, 'original_failed_log': original_log,
               'executed': True, 'exit_code': code, 'elapsed_seconds': time.monotonic() - start, 'timed_out': timed_out,
               'log': name + '.log', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
               'observation': observation, 'error': error}
        records.append(row)
        save(OUT / 'commands.json', records)
        print(json.dumps({'name': name, 'exit_code': code, 'seconds': round(row['elapsed_seconds'], 3), 'error': error}), flush=True)
    after = verify('head', HEAD, root=ROOT)
    save(OUT / 'source-after.json', after)
    passed = before == after and all(row['error'] is None for row in records)
    save(OUT / 'summary.json', {
        'schema': 'trnm-pq-signature-cost-serial-followup-v1', 'source': HEAD,
        'original_campaign_all_commands_exit_zero': False,
        'original_failed_observations_replaced': False,
        'followup_passed': passed, 'completed_commands': sum(row['executed'] for row in records), 'not_executed_commands': sum(not row['executed'] for row in records), 'commands': records,
        'complete_source_endpoints_match': before == after,
        'continuous_source_immutability_enforced': False, 'independent_execution_authentication': False,
        'full_protocol_lane_executed': False, 'all_workspace_tests_executed': False,
        'whole_chain_pq_qualified': False, 'composition_coverage_proved': False,
        'actual_lifetime_failure_bound': None, 'production_activation': False, 'status': 'HOLD',
    })
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
