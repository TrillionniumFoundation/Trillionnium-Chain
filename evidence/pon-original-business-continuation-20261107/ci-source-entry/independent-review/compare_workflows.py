#!/usr/bin/env python3
"""Independently compare original workflow YAML against the added push adapter."""
import hashlib
import json
from pathlib import Path
import subprocess
import yaml

REPO = Path('/workspace/scratch/ae364bcbabfb/publication-check')
OUT = Path(__file__).resolve().parent
HEAD = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
NEW_STEPS = {'Reproduce the frozen integration-push source',
             "Preserve this lane's actual push source context"}
EXPECTED = {
    'pon-priority-acceptance.yml': '6a7eeb14bc2fe1a005d0ee7403e1c6d2e5ba41e941c51892baf35002ecdd62fb',
    'pon-w1-work-security.yml': '739854d721f5be0f2055bf211a9ebf929b64e8a3a5047a777fea4ab4166b3490',
}


def sha(value):
    return hashlib.sha256(value).hexdigest()


rows = []
for filename, expected in EXPECTED.items():
    path = '.github/workflows/' + filename
    original = subprocess.check_output(['git', 'show', HEAD + ':' + path], cwd=REPO)
    current = (REPO / path).read_bytes()
    assert sha(current) == expected
    before = yaml.load(original, Loader=yaml.BaseLoader)
    after = yaml.load(current, Loader=yaml.BaseLoader)
    assert after['on']['pull_request'] == before['on']['pull_request']
    assert after['on']['push'] == {'branches': ['fix/chain-six-axis-performance-20261103']}
    assert set(after['on']) == {'push', 'pull_request'}
    for key in before:
        if key in ('on', 'jobs'):
            continue
        if key == 'concurrency' and filename == 'pon-w1-work-security.yml':
            assert after[key] == dict(before[key], group=before[key]['group'].replace(
                'github.event.pull_request.number', 'github.event.pull_request.number || github.ref'))
        else:
            assert after[key] == before[key], (filename, key)
    assert set(after['jobs']) == set(before['jobs']) | {'push-source-context'}
    lanes = []
    for name, old in before['jobs'].items():
        now = after['jobs'][name]
        if name == 'retained-pressure-failure':
            assert now == old
            lanes.append({'job': name, 'unchanged': True,
                          'original_run_steps': sum('run' in step for step in old['steps'])})
            continue
        assert now['needs'] == 'push-source-context'
        assert now['if'] == "${{ !cancelled() && (github.event_name == 'pull_request' || needs.push-source-context.result == 'success') }}"
        for key in old:
            if key not in ('env', 'steps'):
                assert now[key] == old[key], (filename, name, key)
        changed_env = {key for key in set(old.get('env', {})) | set(now.get('env', {}))
                       if old.get('env', {}).get(key) != now.get('env', {}).get(key)}
        assert changed_env <= {'EXPECTED_SOURCE', 'EXPECTED_HEAD', 'EXPECTED_BASE',
                               'EXPECTED_MERGE', 'TRNM_EXPECTED_SOURCE_SHA'}
        kept = [step for step in now['steps'] if step.get('name') not in NEW_STEPS]
        assert len(kept) == len(old['steps'])
        for old_step, new_step in zip(old['steps'], kept):
            if old_step.get('uses', '').startswith('actions/checkout@'):
                new_step = dict(new_step, **{'with': dict(new_step['with'], ref=old_step['with']['ref'])})
            if filename == 'pon-priority-acceptance.yml' and old_step.get('uses', '').startswith('actions/upload-artifact@'):
                assert new_step['with']['name'] == old_step['with']['name'].replace(
                    '${{ github.event.pull_request.head.sha }}', '${{ env.EXPECTED_HEAD }}')
                new_step = dict(new_step, **{'with': dict(new_step['with'], name=old_step['with']['name'])})
            assert old_step == new_step, (filename, name, old_step.get('name'))
        matrix = old['strategy']['matrix']
        count = 1
        for key, value in matrix.items():
            if key not in ('include', 'exclude'):
                count *= len(value)
        lanes.append({'job': name, 'original_run_steps': sum('run' in step for step in old['steps']),
                      'original_steps': len(old['steps']), 'matrix': matrix,
                      'expanded_matrix_rows': count, 'runs_on': old['runs-on'],
                      'timeout_minutes': old['timeout-minutes'], 'fail_fast': old['strategy']['fail-fast'],
                      'changed_env_keys': sorted(changed_env),
                      'original_commands_conditions_and_retention_unchanged': True})
    assert (REPO / path).read_bytes() == current
    rows.append({'path': path, 'head_blob_sha256': sha(original), 'reviewed_sha256': sha(current),
                 'pull_request_trigger_unchanged': True, 'jobs': lanes})

record = {
    'schema': 'integration-push-workflow-independent-preservation-v1', 'head': HEAD,
    'comparison': 'Independent YAML tree comparison; permitted differences are frozen source expressions, checkout ref, priority artifact source-name substitution, W1 PR-number-or-ref concurrency key, added resolver and two source-context steps. All original commands, step conditions, order, matrices, budgets, runners, upload paths/retention and old-failure job compare unchanged.',
    'earlier_comparator_refusals': [
        'Initial comparator rejected the intended priority artifact name substitution. Exact literal replacement independently reviewed.',
        'Second comparator rejected the intended W1 concurrency fallback. Original PR group and cancel-in-progress=false remain unchanged.'
    ],
    'workflows': rows,
    'original_run_steps_preserved': sum(job['original_run_steps'] for row in rows for job in row['jobs']),
    'original_matrix_rows_preserved': sum(job.get('expanded_matrix_rows', 0) for row in rows for job in row['jobs']),
    'github_actions_execution': False, 'native_execution': False,
}
(OUT / 'workflow-preservation.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({key: record[key] for key in (
    'head', 'original_run_steps_preserved', 'original_matrix_rows_preserved')}, indent=2))
