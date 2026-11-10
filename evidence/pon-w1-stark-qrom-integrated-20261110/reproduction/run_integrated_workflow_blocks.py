#!/usr/bin/env python3
"""Execute the repository's actual current-job shell blocks as a local head run.

This does not execute actions/checkout, upload-artifact, GitHub's scheduler,
historical positive lanes, or a prospective-merge lane. Completion environment
records are derived from observed subprocess outcomes, with the checkout
prerequisite supplied by a real clean committed local clone and verified again
by each workflow's actual source-before/source-after shell blocks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

import yaml


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()


def identity(root):
    return {'head': git(root, 'rev-parse', 'HEAD'),
            'tree': git(root, 'rev-parse', 'HEAD^{tree}'),
            'status': git(root, 'status', '--porcelain=v1')}


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def ready(condition, steps):
    if not condition:
        return all(value['outcome'] == 'success' for value in steps.values())
    residue = re.sub(r"steps\.[A-Za-z_]+\.outcome == 'success'", 'CHECK', condition)
    residue = residue.replace('always()', 'ALWAYS').replace(' ', '')
    if not re.fullmatch(r'ALWAYS(?:&&CHECK)*', residue):
        raise ValueError('unreviewed workflow condition: ' + condition)
    names = re.findall(r"steps\.([A-Za-z_]+)\.outcome == 'success'", condition)
    return all(steps.get(name, {}).get('outcome') == 'success' for name in names)


def execute(root, out, job_kind, expected, base):
    if job_kind == 'implementation':
        workflow, job_name = 'pon-w1-qrom-implementation.yml', 'qrom-current-implementation'
        required = ('observations', 'source_before', 'preflight', 'named_tests',
                    'historical_drift', 'implementation', 'source_after', 'status')
        stage_var = 'W1_QROM_CURRENT_STEP_RESULTS'
    else:
        workflow, job_name = 'pon-w1-qrom-closure.yml', 'closure'
        required = ('observations', 'source_before', 'preflight', 'named_controls',
                    'historical_refusal', 'reproduce', 'source_after', 'completion')
        stage_var = 'W1_CLOSURE_STEPS'
    raw = (root / '.github/workflows' / workflow).read_bytes()
    doc = yaml.safe_load(raw)
    job = doc['jobs'][job_name]
    blocks = [step for step in job['steps'] if 'run' in step]
    if tuple(step['id'] for step in blocks) != required:
        raise ValueError('current job shell-block roster changed')
    job_out = out / job_kind
    job_out.mkdir()
    env_path = job_out / 'github-env'
    env_path.touch(exist_ok=False)
    env = dict(os.environ)
    env.update({
        'RUNNER_TEMP': str(job_out), 'GITHUB_ENV': str(env_path),
        'GITHUB_WORKSPACE': str(root), 'SOURCE_KIND': 'head',
        'EXPECTED_SOURCE': expected, 'EXPECTED_HEAD': expected, 'EXPECTED_BASE': base,
        'GITHUB_RUN_ID': 'local-integration-' + expected[:12], 'GITHUB_RUN_ATTEMPT': '1',
        'PYTHONDONTWRITEBYTECODE': '1',
    })
    # Workflow literals are copied only when they contain no Actions expression.
    for values in (doc.get('env', {}), job.get('env', {})):
        for key, value in values.items():
            if '${{' not in str(value):
                env[key] = str(value)
    steps, records = {}, []
    start_identity = identity(root)
    if start_identity['head'] != expected or start_identity['status']:
        raise ValueError('requires an exact clean committed local source')
    for step in job['steps']:
        name = step.get('id')
        if name == 'checkout':
            # No Action execution is claimed. Check the prerequisite directly.
            actual = identity(root)
            ok = actual['head'] == expected and actual['status'] == ''
            steps[name] = {'outcome': 'success' if ok else 'failure',
                           'conclusion': 'success' if ok else 'failure'}
            records.append({'id': name, 'source_identity': actual,
                            'basis': 'existing isolated local clone; not actions/checkout execution'})
            continue
        if 'run' not in step:
            records.append({'id': name, 'uses': step.get('uses'),
                            'basis': 'not executed locally'})
            continue
        if not ready(step.get('if'), steps):
            steps[name] = {'outcome': 'skipped', 'conclusion': 'skipped'}
            records.append({'id': name, 'executed': False})
            continue
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                key, separator, value = line.partition('=')
                if not separator or not re.fullmatch('[A-Z_][A-Z0-9_]*', key):
                    raise ValueError('unsupported GITHUB_ENV output')
                env[key] = value
        for key, value in step.get('env', {}).items():
            if value == '${{ toJSON(steps) }}' and key == stage_var:
                env[key] = json.dumps(steps)
            elif '${{' not in str(value):
                env[key] = str(value)
            else:
                raise ValueError('unsupported step environment expression')
        script = step['run']
        script_path = job_out / (name + '.sh')
        script_path.write_text(script)
        started = time.monotonic()
        try:
            result = subprocess.run(['bash', str(script_path)], cwd=root, env=env,
                                    text=True, capture_output=True, timeout=1200)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except (OSError, subprocess.TimeoutExpired) as error:
            code, stdout, stderr = None, '', repr(error) + '\n'
        (job_out / (name + '.stdout')).write_text(stdout)
        (job_out / (name + '.stderr')).write_text(stderr)
        ok = code == 0
        steps[name] = {'outcome': 'success' if ok else 'failure',
                       'conclusion': 'success' if ok else 'failure'}
        record = {'id': name, 'exit_code': code,
                  'seconds': round(time.monotonic() - started, 3),
                  'shell_sha256': hashlib.sha256(script.encode()).hexdigest()}
        records.append(record)
        print(json.dumps({'job': job_kind, **record}), flush=True)
    end_identity = identity(root)
    passed = all(steps.get(name, {}).get('outcome') == 'success' for name in required)
    passed = passed and start_identity == end_identity and end_identity['status'] == ''
    report = {
        'schema': 'TRNM-LOCAL-ACTUAL-CURRENT-WORKFLOW-BLOCKS1',
        'workflow': workflow, 'workflow_sha256': hashlib.sha256(raw).hexdigest(),
        'job': job_name, 'required_shell_blocks': list(required),
        'step_results_from_actual_execution': steps, 'records': records,
        'source_before': start_identity, 'source_after': end_identity,
        'all_required_shell_blocks_passed': passed,
        'scope': 'local head source; actual stored shell blocks; not hosted Actions',
        'checkout_prerequisite_basis': 'preexisting clean local checkout verified by real source blocks',
        'actions_checkout_or_upload_executed': False,
        'historical_positive_lanes_executed': False, 'prospective_merge_lane_executed': False,
        'native_execution_or_security_qualification_inferred': False,
    }
    save(job_out / 'local-workflow-summary.json', report)
    return passed


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--base', required=True)
    p.add_argument('--jobs', nargs='+', choices=('implementation', 'closure'),
                   default=['implementation', 'closure'])
    args = p.parse_args()
    root, out = args.root.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    expected = git(root, 'rev-parse', 'HEAD')
    results = {job: execute(root, out, job, expected, args.base) for job in args.jobs}
    save(out / 'SUMMARY.json', {'source_commit': expected, 'job_results': results,
                               'hosted_actions_executed': False,
                               'native_or_security_qualification_inferred': False})
    return 0 if all(results.values()) else 2


if __name__ == '__main__':
    raise SystemExit(main())
