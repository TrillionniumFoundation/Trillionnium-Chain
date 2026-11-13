#!/usr/bin/python3
"""Tree-external exact-HEAD CI observations; no source edits or activation."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time
import traceback

ROOT = Path('/home/qian-qi/work/chain-daa-resource-competition-20261112-600e')
BASE = Path('/home/qian-qi/work/chain-daa-ci-gates-600e')
PY = '/usr/bin/python3'
OVERRIDES = {'PATH': '/usr/bin:/bin:/usr/local/bin',
             'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1'}


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    payload = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    pending = path.with_name(path.name + '.pending')
    with pending.open('xb') as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(pending, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def gate(name, argv, timeout=600, *, expected_exit=0, tests=None, check=None):
    return {'name': name, 'argv': argv, 'cwd': str(ROOT),
            'timeout_seconds': timeout, 'expected_exit_code': expected_exit,
            'expected_unittest_count': tests, 'output_check': check}


def plan(head):
    source = [PY, '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', head]
    return [
        gate('source-before', source, check='source'),
        gate('preflight-audit', ['/bin/bash', 'scripts/project-preflight.sh', '--audit'], check='preflight'),
        gate('ci-contract-negatives', [PY, '-B', 'scripts/ci/test_ci_contract.py', '-v'], 1800, tests=169),
        gate('source-integrity-negatives', [PY, '-B', 'scripts/ci/test_ci_source_integrity.py', '-v'], 600, tests=43),
        gate('pq-corpus-negatives', [PY, '-B', 'scripts/ci/test_pq_research_integration.py', '-v'], 600, tests=57),
        gate('ci-contract-current', [PY, '-B', 'scripts/ci/check_ci_contract.py'], check='ci'),
        gate('pq-corpus-current', [PY, '-B', 'scripts/ci/check_pq_research_integration.py'], check='pq'),
        gate('repository-and-markdown-links', [PY, '-B', 'scripts/ci/check_repository.py'], check='repository'),
        gate('distributed-source-inventory', [PY, '-B', 'scripts/refresh_distributed_source_inventory.py', '--check'], check='inventory'),
        gate('joint-qualification-current-hold', [PY, '-B', 'formal/pon-nakamoto-v1/joint_consensus_qualification.py', '--check'], check='joint'),
        gate('joint-unproved-qualification-refusal', [PY, '-B', 'formal/pon-nakamoto-v1/joint_consensus_qualification.py', '--require-qualified'], expected_exit=3, check='joint-refusal'),
        gate('source-after', source, check='source'),
    ]


def evaluate(specification, outcome, head, stdout_path, stderr_path):
    errors = []
    if outcome['state'] != 'completed':
        errors.append('process did not reach an observed normal terminal state')
    if outcome['exit_code'] != specification['expected_exit_code']:
        errors.append('unexpected exit code')
    result = {'errors': errors}
    if errors:
        return result
    stdout = stdout_path.read_text(errors='replace')
    stderr = stderr_path.read_text(errors='replace')
    if specification['expected_unittest_count'] is not None:
        combined = stdout + '\n' + stderr
        counts = re.findall(r'^Ran ([0-9]+) tests? in ', combined, re.M)
        result['observed_unittest_counts'] = [int(value) for value in counts]
        if counts != [str(specification['expected_unittest_count'])]:
            errors.append('observed test count differs from the reviewed complete suite')
        if re.findall(r'^OK(?: \(.*\))?$', combined, re.M) != ['OK']:
            errors.append('complete no-skip unittest success footer absent')
        if re.search(r'^.* \.\.\. skipped(?: |$)|^OK \(skipped=|^FAILED|^ERROR:', combined, re.M):
            errors.append('a skipped or failed unittest was observed')
        return result
    check = specification['output_check']
    if check == 'inventory':
        if stdout.strip() != 'distributed source inventory: PASS':
            errors.append('inventory success output differs')
        return result
    try:
        data = json.loads(stdout)
    except (ValueError, TypeError) as error:
        errors.append('checker stdout is not one JSON report: ' + str(error))
        return result
    result['checker_report'] = data
    if not isinstance(data, dict):
        errors.append('checker report is not an object')
    elif check == 'source':
        if (data.get('schema') != 'trnm-ci-source-v1' or data.get('kind') != 'head'
                or data.get('tested_commit') != head or data.get('candidate') != head
                or data.get('tracked_worktree_verified') is not True
                or data.get('tests_executed_by_identity_check') is not False):
            errors.append('exact source identity was not verified')
    elif check == 'preflight':
        if data.get('result') != 'PASS' or data.get('mode') != '--audit' or data.get('remote_policy_mutated') is not False:
            errors.append('audit preflight did not preserve the expected boundary')
    elif check == 'ci':
        if data.get('tests_executed') is not False or data.get('head_jobs') != 5 or data.get('merge_lanes') != 5:
            errors.append('current CI structural report differs')
    elif check == 'pq':
        if (data.get('status') != 'HOLD_NO_GO' or data.get('exact_source_blobs') != 915
                or data.get('cryptographic_acceptance') is not False or data.get('node_activated') is not False):
            errors.append('PQ current corpus or qualification boundary differs')
    elif check == 'repository':
        if (data.get('result') != 'PASS' or data.get('head') != head
                or data.get('source_state') != 'committed-clean'
                or data.get('runtime_implemented') is not False or data.get('activation') is not False):
            errors.append('repository/link report is not a clean exact-HEAD pass')
    elif check in ('joint', 'joint-refusal'):
        if (data.get('contract_validation') != 'PASS' or data.get('qualification') != 'HOLD_NO_GO'
                or data.get('production_activation') is not False
                or data.get('security_probability_calibrated') is not False
                or any(data.get(key, 'missing') is not None for key in (
                    'actual_lifetime_failure_bound', 'common_prefix_failure_bound',
                    'chain_growth_failure_bound', 'chain_quality_failure_bound',
                    'six_confirmations_failure_bound'))):
            errors.append('unproved joint qualification was promoted or its contract failed')
        if check == 'joint-refusal' and data.get('qualification_request') != 'REFUSED_UNPROVED_JOINT_CONSENSUS':
            errors.append('expected unproved-qualification refusal absent')
    else:
        errors.append('unknown output checker')
    return result


def observe(specification, output, head, environment):
    directory = output / specification['name']
    directory.mkdir()
    stdout_path, stderr_path = directory / 'stdout.raw', directory / 'stderr.raw'
    record = {'schema': 'trnm-daa-external-ci-command-v1', **specification,
              'expected_head': head, 'environment_overrides': OVERRIDES,
              'started_utc': now(), 'ended_utc': None, 'elapsed_monotonic_seconds': None,
              'state': 'starting', 'exit_code': None, 'pid': None, 'exception': None}
    write_json(directory / 'record.json', record)
    began = time.monotonic()
    with stdout_path.open('xb') as stdout_file, stderr_path.open('xb') as stderr_file:
        try:
            child = subprocess.Popen(specification['argv'], cwd=ROOT, env=environment,
                                     stdin=subprocess.DEVNULL, stdout=stdout_file,
                                     stderr=stderr_file, start_new_session=True)
            record.update(state='running', pid=child.pid)
            write_json(directory / 'record.json', record)
            try:
                record['exit_code'] = child.wait(timeout=specification['timeout_seconds'])
                record['state'] = 'completed'
            except subprocess.TimeoutExpired:
                record['state'] = 'timed-out'
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    record['exit_code'] = child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    record['exit_code'] = child.wait()
        except Exception as error:
            record['state'] = 'controller-error'
            record['exception'] = {'type': type(error).__name__, 'message': str(error),
                                   'traceback': traceback.format_exc()}
        finally:
            stdout_file.flush()
            stderr_file.flush()
            os.fsync(stdout_file.fileno())
            os.fsync(stderr_file.fileno())
    record.update(ended_utc=now(), elapsed_monotonic_seconds=time.monotonic() - began,
                  stdout={'file': 'stdout.raw', 'bytes': stdout_path.stat().st_size, 'sha256': sha(stdout_path)},
                  stderr={'file': 'stderr.raw', 'bytes': stderr_path.stat().st_size, 'sha256': sha(stderr_path)})
    record['evaluation'] = evaluate(specification, record, head, stdout_path, stderr_path)
    record['expectation_met'] = not record['evaluation']['errors']
    write_json(directory / 'record.json', record)
    print(json.dumps({'gate': specification['name'], 'state': record['state'],
                      'exit_code': record['exit_code'], 'expectation_met': record['expectation_met'],
                      'errors': record['evaluation']['errors']}, sort_keys=True), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-head', required=True)
    args = parser.parse_args()
    head = args.expected_head
    if not re.fullmatch(r'[0-9a-f]{40}', head):
        raise SystemExit('exact forty-character HEAD required')
    if ROOT.is_symlink() or ROOT.resolve() != ROOT or not ROOT.is_dir():
        raise SystemExit('canonical source directory unavailable')
    BASE.mkdir(exist_ok=True)
    if BASE.is_symlink() or BASE.resolve() != BASE or BASE.is_relative_to(ROOT):
        raise SystemExit('external evidence base is not canonical')
    output = BASE / ('head-' + head)
    output.mkdir(exist_ok=False)
    environment = dict(os.environ)
    environment.update(OVERRIDES)
    specifications = plan(head)
    meta = {'schema': 'trnm-daa-external-ci-plan-v1', 'expected_head': head,
            'source_root': str(ROOT), 'evidence_root': str(output),
            'controller': str(Path(__file__).resolve()), 'controller_sha256': sha(Path(__file__)),
            'controller_argv': sys.argv, 'controller_cwd': os.getcwd(),
            'python_executable': sys.executable, 'python_version': sys.version,
            'platform': platform.platform(), 'environment_overrides': OVERRIDES,
            'started_utc': now(), 'gates': specifications,
            'scope': 'CI/source/claim observations; no native run, efficacy, security or release qualification'}
    write_json(output / 'plan.json', meta)
    records = []
    source_ok = False
    controller_error = None
    try:
        records.append(observe(specifications[0], output, head, environment))
        source_ok = records[0]['expectation_met']
        if source_ok:
            for specification in specifications[1:-1]:
                records.append(observe(specification, output, head, environment))
    except Exception as error:
        controller_error = {'type': type(error).__name__, 'message': str(error),
                            'traceback': traceback.format_exc()}
    finally:
        try:
            records.append(observe(specifications[-1], output, head, environment))
        except Exception as error:
            controller_error = {'type': type(error).__name__, 'message': str(error),
                                'traceback': traceback.format_exc(), 'stage': 'source-after'}
    complete = len(records) == len(specifications) and controller_error is None
    passed = complete and all(record['expectation_met'] for record in records)
    observed_names = {record['name'] for record in records}
    summary = {'schema': 'trnm-daa-external-ci-summary-v1', 'expected_head': head,
               'started_utc': meta['started_utc'], 'ended_utc': now(),
               'controller_sha256': meta['controller_sha256'],
               'planned_commands': len(specifications), 'observed_commands': len(records),
               'not_observed': [item['name'] for item in specifications if item['name'] not in observed_names],
               'source_before_passed': source_ok,
               'source_after_passed': any(row['name'] == 'source-after' and row['expectation_met'] for row in records),
               'controller_error': controller_error, 'complete': complete,
               'all_expected_outcomes_observed': passed,
               'qualification': 'HOLD_NO_GO', 'release_ready': False,
               'records': [str(Path(row['name']) / 'record.json') for row in records]}
    write_json(output / 'summary.json', summary)
    files = {str(path.relative_to(output)): {'bytes': path.stat().st_size, 'sha256': sha(path)}
             for path in sorted(output.rglob('*')) if path.is_file()}
    write_json(output / 'manifest.json', {'schema': 'trnm-daa-external-ci-manifest-v1',
                                        'expected_head': head, 'files': files})
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
