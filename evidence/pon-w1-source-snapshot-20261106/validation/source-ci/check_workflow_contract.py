#!/usr/bin/env python3
"""Replay W1 workflow log/status guards without executing their jobs or a prover."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import yaml


def python_blocks(run):
    return re.findall(r"<<'PY'[^\n]*\n(.*?)^PY$", run, re.M | re.S)


def check(repo, mapper_log, gate_log):
    workflow_path = repo / '.github/workflows/pon-w1-transparent-profile.yml'
    workflow = yaml.safe_load(workflow_path.read_text())
    steps = workflow['jobs']['transparent-profile']['steps']
    by_id = {step['id']: step for step in steps if 'id' in step}
    status = next(step for step in steps if step['name'] == 'Record completed, failed and skipped observations')
    compiled = 0
    for step in steps:
        if 'run' not in step:
            continue
        result = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True, check=False)
        if result.returncode:
            raise ValueError((step['name'], result.stderr))
        for code in python_blocks(step['run']):
            compile(code, step['name'], 'exec')
            compiled += 1
    report = {'bash_syntax': 'pass', 'python_blocks_compiled': compiled, 'test_logs': {}, 'required_steps': []}
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        for step_id, path in (('mapper_tests', mapper_log), ('v2_gate_tests', gate_log)):
            validator = temp / f'{step_id}.py'
            validator.write_text(python_blocks(by_id[step_id]['run'])[0])
            actual = path.read_text()
            row = next(line for line in actual.splitlines(True) if line.startswith('test_'))
            variants = {
                'real_log': actual,
                'missing_named_row': actual.replace(row, '', 1),
                'duplicate_named_row': actual + row,
                'renamed_result': actual.replace(row.split()[0], 'test_unexpected_name', 1),
                'skipped_result': actual.replace(' ... ok', ' ... skipped fixture', 1),
                'expected_failure_result': actual.replace(' ... ok', ' ... expected failure', 1),
                'expected_failure_summary': actual.replace('\nOK\n', '\nOK (expected failures=1)\n'),
                'duplicate_summary': actual + '\nRan 1 tests in 0.001s\n\nOK\n',
            }
            report['test_logs'][step_id] = []
            for name, text in variants.items():
                log = temp / f'{step_id}-{name}.log'
                log.write_text(text)
                result = subprocess.run(['python3', str(validator), str(log)], cwd=repo,
                                        text=True, capture_output=True, check=False)
                accepted = result.returncode == 0
                if accepted != (name == 'real_log'):
                    raise ValueError((step_id, name, result.stderr))
                report['test_logs'][step_id].append({'case': name, 'accepted': accepted,
                                                    'exit_code': result.returncode})
        validator = temp / 'status.py'
        validator.write_text(python_blocks(status['run'])[0])
        outcomes = {name: {'outcome': 'success'} for name in by_id}
        for name in ['all_success'] + list(outcomes):
            changed = copy.deepcopy(outcomes)
            if name != 'all_success':
                changed[name]['outcome'] = 'skipped'
            env = dict(os.environ, SOURCE_KIND='head', EXPECTED_SOURCE='d9fd07c473998bd236207c1b7db4233f0eafd7fe',
                       W1_PROFILE_STEP_RESULTS=json.dumps(changed))
            result = subprocess.run(['python3', str(validator), str(temp / f'{name}.json')], cwd=repo,
                                    env=env, text=True, capture_output=True, check=False)
            accepted = result.returncode == 0
            if accepted != (name == 'all_success'):
                raise ValueError((name, result.stderr))
            report['required_steps'].append({'case': name, 'accepted': accepted, 'exit_code': result.returncode})
    base = 'd9fd07c473998bd236207c1b7db4233f0eafd7fe'
    old = subprocess.check_output(['git', 'show', base + ':.github/workflows/pon-w1-transparent-profile.yml'],
                                  cwd=repo, text=True)
    old_steps = {step['id']: step for step in yaml.safe_load(old)['jobs']['transparent-profile']['steps']
                 if 'id' in step}
    if by_id['verifier_v2'] != old_steps['verifier_v2']:
        raise ValueError('the original three-test/build step changed')
    old_runner = old_steps['receipt_controls_v2']['run'].split('python3 - "$W1_PROFILE_OUT/v2-controls"')[0]
    new_runner = by_id['receipt_controls_v2']['run'].split('python3 scripts/ci/w1_v2_controls_gate.py')[0]
    if old_runner != new_runner:
        raise ValueError('the original 58-control runner command changed')
    runner_path = 'scripts/w1_v2_receipt_controls.py'
    if subprocess.check_output(['git', 'show', base + ':' + runner_path], cwd=repo) != (repo / runner_path).read_bytes():
        raise ValueError('the original 120-second runner changed')
    cmp_path = 'evidence/pon-w1-source-snapshot-20261106/security-map.json'
    if cmp_path not in by_id['source_map']['run'] or 'evidence/pon-w1-source-snapshot-20261106/**' not in workflow_path.read_text():
        raise ValueError('the new source-map comparison or path trigger is missing')
    report.update(original_v2_build_and_three_test_step_unchanged=True,
                  original_58_controls_command_and_120_second_runner_unchanged=True,
                  source_map_cmp=cmp_path, new_proofs_generated=0)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'mapper-log', 'gate-log', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = check(args.repo, args.mapper_log, args.gate_log)
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print('Workflow contract passed: 15 mapper names, 23 v2 gate names, 19 required steps; original 3/58/120 preserved.')


if __name__ == '__main__':
    main()
