#!/usr/bin/env python3
"""Independently read and verify the already-published #6062 evidence; no writes."""
import sys

if not __debug__ or sys.flags.optimize != 0:
    raise RuntimeError("optimized Python is refused before verification")

import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

SOURCE = Path('/home/qian-qi/work/hepta-pon-outcome-7612-native')
EVIDENCE = Path('/home/qian-qi/work/hepta-pon-outcome-7612-native-evidence')
RELATIVE = Path('qualification/pon-outcome-readback-20261112-7612')
CODE = '93fc43f6e87c4514485adcb01a7ffec8ad3b632f'
TREE = '1de575fdbba23d25c483f539a15b455c9e8859cb'
PUBLISHED = 'ef3a398d460574813957a25f5455e12c60db6d5d'
BASE = '3c8dabe46598599e91b2b8b80081e09069ff9426'
BRANCH = 'codex/pon-outcome-readback-20261111-7612'
BASE_BRANCH = 'codex/ordinary-owner-assembly-20261111-af52'
REPO = 'TrillionniumFoundation/hepta-private-ci'
ENV = {
    'RUSTUP_TOOLCHAIN': '1.96.0',
    'CARGO_TARGET_DIR': '/home/qian-qi/hepta-learn-ce434-target',
    'CARGO_BUILD_JOBS': '4',
    'HEPTA_GENERATION_LEARNING_READBACK_STDOUT': '1',
    'RUST_BACKTRACE': '1',
}
TARGETS = [
    'qualified_local_retention_reaches_actual_parent_use_and_cold_recovery',
    'qualified_local_adoption_reaches_actual_candidate_and_keeps_decision_operation',
    'ordinary_actor_reads_actual_use_and_cold_recovery_without_reexecution',
    'updated_candidate_uses_original_actor_and_recovers_without_another_reset',
    'q24_native_sgd_reports_no_update_when_actual_quantized_bytes_stay_equal',
    'q24_training_owner_cold_readback_preserves_candidate_and_no_update',
    'original_training_stage_runs_both_outcomes_and_reopens_exactly',
]
EIGHTH = 'q24_actual_trainer_no_update_requires_published_retained_task_and_committed_distinct_input_after_reopen'
JUST = '/home/qian-qi/.cargo/bin/just'
TEST_PREFIX = [JUST, 'test', '--locked', '--offline', '-p', 'codex-hepta-agentd', '--lib', '-E']
CMD7 = TEST_PREFIX + [' | '.join('test(' + name + ')' for name in TARGETS), '--no-capture']
CMD8 = TEST_PREFIX + ['test(' + EIGHTH + ')', '--no-capture']
LOG7_SHA = '3e7ee2dcd9019949256a2987a3c8612d976952a58503d7050198adaab11a5261'
LOG8_SHA = 'bf752718b91d313dfd2a626e998f52c95dcb5e41d4a63705a4f63fbf9b1b375e'
PREFLIGHT_SHA = 'dc603f06afa86bfcae8ab7ed8dbcf82cfc62be0c60e333754ec83d64e805c9d9'
FAILURE_TRANSFER_SHA = 'dad4618f424f35067820a4cfed2e36b4b0182687d4f60a845bb74f39bace5004'


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def command(args, *, raw=False):
    result = subprocess.run(args, cwd=SOURCE, capture_output=True, timeout=60)
    require(result.returncode == 0, f'read failed: {args!r}; exit={result.returncode}; stderr={result.stderr[-500:]!r}')
    return result.stdout if raw else result.stdout.decode().strip()


def git(*args, raw=False):
    return command(['git', *args], raw=raw)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    require(git('rev-parse', 'HEAD') == PUBLISHED, 'unexpected published worktree head')
    require(git('rev-parse', PUBLISHED + '^') == CODE, 'evidence commit has unexpected parent')
    require(git('rev-parse', CODE + '^{tree}') == TREE, 'runtime tree mismatch')
    require(git('rev-parse', PUBLISHED + ':codex-rs') == git('rev-parse', CODE + ':codex-rs'), 'published runtime source drift')
    require(git('status', '--porcelain=v1') == '', 'published worktree is dirty')
    require(git('branch', '--show-current') == BRANCH, 'unexpected local branch')
    require(not Path('/proc/2699893').exists(), 'original publisher PID still exists; reconcile original PTY')
    require(not (EVIDENCE / 'publication-v2.lock').exists(), 'another publisher admission exists')
    require(not (EVIDENCE / 'publication-v2-admission.json').exists(), 'another publisher admission exists')
    changes = git('diff', '--name-only', CODE, PUBLISHED).splitlines()
    require(changes and all(p.startswith(str(RELATIVE) + '/') for p in changes), 'non-evidence publication change')
    code_changes = git('diff', '--name-only', BASE, CODE).splitlines()
    require(set(code_changes) == {
        'codex-rs/hepta-agentd/src/neuron_generation_local_decision_tests.rs',
        'codex-rs/hepta-agentd/src/neuron_generation_learning_readback_test_support.rs',
    }, 'unexpected runtime diff scope')

    def committed(name):
        return git('show', PUBLISHED + ':' + str(RELATIVE / name), raw=True)

    originals = {}

    def original(name):
        if name not in originals:
            raw = (EVIDENCE / name).read_bytes()
            require(committed(name) == raw, 'committed bytes differ from original: ' + name)
            require((SOURCE / RELATIVE / name).read_bytes() == raw, 'working evidence differs from original: ' + name)
            originals[name] = raw
        return originals[name]

    first = json.loads(original('native-result.json'))
    eighth = json.loads(original('native8-result.json'))
    maintenance = json.loads(original('maintenance-and-native8.json'))
    preflight = json.loads(original('native-preflight.json'))
    require(sha(original('native-preflight.json')) == PREFLIGHT_SHA, 'pinned preflight mismatch')
    require(preflight['status'] == 'PREPARED' and first['status'] == 'FINISHED', 'missing native terminal status')
    require(all(first[key] == value for key, value in preflight.items() if key != 'status'), 'native preflight/result mismatch')
    require(first['command'] == CMD7 and eighth['command'] == CMD8, 'native test target mismatch')
    for record in (first, eighth):
        require(record['exit'] == 0, 'native target failed')
        require(record['source_head'] == record['head_after'] == CODE, 'native head mismatch')
        require(record['source_tree'] == record['tree_after'] == TREE, 'native tree mismatch')
        require(record['status_after'] == '' and record['environment'] == ENV, 'native state or environment mismatch')
    require(eighth['complete_ack_join_claimed'] is False and eighth['output_ack_event_verified'] is False, 'native8 ACK overclaim')
    require(maintenance['source_head'] == CODE and maintenance['source_tree'] == TREE and maintenance['environment'] == ENV, 'maintenance provenance mismatch')
    require([stage['label'] for stage in maintenance['stages']] == ['maintenance-fmt', 'maintenance-fix', 'maintenance-final-fmt', 'native8'], 'maintenance stage roster mismatch')
    stage_commands = [[JUST, 'fmt', '--base', BASE], [JUST, 'fix', '-p', 'codex-hepta-agentd', '--lib', '--locked', '--offline'], [JUST, 'fmt', '--base', BASE], CMD8]
    for stage, expected in zip(maintenance['stages'], stage_commands):
        require(stage['exit'] == 0 and stage['status_after'] == '' and stage['source_head'] == CODE and stage['source_tree'] == TREE, 'maintenance stage failed or drifted')
        require(stage['command'] == expected, 'maintenance command mismatch')
        name = stage['label'] + '.log'
        require(stage['log'] == str(EVIDENCE / name), 'maintenance log path mismatch')
        raw = original(name)
        require(len(raw) == stage['log_bytes'] and sha(raw) == stage['log_sha256'], 'maintenance raw log mismatch: ' + name)
    for key in ('command', 'exit', 'log', 'log_sha256', 'log_bytes', 'source_head', 'source_tree', 'status_after', 'started_at', 'finished_at', 'elapsed_seconds'):
        require(eighth[key] == maintenance['stages'][-1][key], 'native8 stage/result mismatch: ' + key)
    raw7, raw8 = original('native.log'), original('native8.log')
    require(sha(raw7) == first['log_sha256'] == LOG7_SHA and len(raw7) == first['log_bytes'] == 235411, 'pinned native7 raw log mismatch')
    require(sha(raw8) == eighth['log_sha256'] == LOG8_SHA and len(raw8) == eighth['log_bytes'] == 31925, 'pinned native8 raw log mismatch')
    require(re.search(rb'7 tests run:\s+7 passed,\s+1035 skipped', raw7) is not None, 'native7 success summary absent')
    require(re.search(rb'1 tests? run:\s+1 passed', raw8) is not None and EIGHTH.encode() in raw8, 'native8 success/target absent')
    for name, result in [('junit.xml', first), ('native8-junit.xml', eighth)]:
        require((EVIDENCE / name).exists() == ('junit_sha256' in result), 'unbound or missing JUnit file')
        if 'junit_sha256' in result:
            require(sha(original(name)) == result['junit_sha256'], 'JUnit hash mismatch')

    markers = json.loads(original('native-markers.json'))
    require(markers['source_head'] == CODE and markers['source_tree'] == TREE and markers['log_sha256'] == LOG7_SHA, 'marker header provenance mismatch')
    require(markers['payloads_are_exact_stdout_json_bytes_without_line_ending'] is True, 'marker extraction contract mismatch')
    tags = {'HEPTA_LEARNING_INITIAL_V1': 'initial', 'HEPTA_LEARNING_READBACK_V1': 'readback', 'HEPTA_LEARNING_CHECKPOINT_V2': 'checkpoint', 'HEPTA_LEARNING_COMPLETION_V1': 'completion'}
    phases = {'local_defer_cold', 'local_retain_cold', 'local_adopt', 'retained_pending', 'retained_acked', 'adopted_pending', 'adopted_acked'}
    expected_keys = {(tag, phase) for tag in tags for phase in phases if tag != 'HEPTA_LEARNING_COMPLETION_V1' or not phase.endswith('_pending')}
    slices = {}
    for line in raw7.splitlines():
        if not line.startswith(tuple((tag + ' ').encode() for tag in tags)):
            continue
        tag, phase, payload = line.split(b' ', 2)
        key = (tag.decode(), phase.decode())
        require(key in expected_keys and key not in slices, 'unexpected or duplicate stdout marker')
        json.loads(payload)
        slices[key] = payload
    require(set(slices) == expected_keys, 'stdout marker roster mismatch')
    retained = set()
    for marker in markers['markers']:
        key = (marker['tag'], marker['phase'])
        require(key in slices and key not in retained, 'unexpected or duplicate marker manifest record')
        retained.add(key)
        path = Path(marker['path'])
        require(path.parent == EVIDENCE and path.name == marker['phase'] + '.' + tags[marker['tag']] + '.json', 'marker path mismatch')
        raw = original(path.name)
        require(raw == slices[key] and len(raw) == marker['bytes'] and sha(raw) == marker['sha256'], 'marker is not original stdout slice')
    require(retained == expected_keys, 'retained marker roster mismatch')
    history = Path('/home/qian-qi/hepta-pon-outcome-7612-historical-failure.json').read_bytes()
    require(sha(history) == FAILURE_TRANSFER_SHA, 'historical failure transfer mismatch')
    failures = json.loads(history)
    require({item['name'] for item in failures} == {'local-native-attempt-1.json', 'local-native-attempt-1.log'} and len(failures) == 2, 'historical failure roster mismatch')
    for item in failures:
        raw = base64.b64decode(item['data_base64'], validate=True)
        require(sha(raw) == item['sha256'] and len(raw) == item['bytes'], 'historical failure bytes mismatch')
        require(committed(item['name']) == raw, 'committed historical failure mismatch')

    expected_names = set(originals) | {item['name'] for item in failures} | {'qualification-summary.json', 'README.md', 'SHA256SUMS'}
    tree_files = git('ls-tree', '-r', '--name-only', PUBLISHED, '--', str(RELATIVE)).splitlines()
    require(set(tree_files) == {str(RELATIVE / name) for name in expected_names}, 'committed evidence inventory mismatch')
    sums = {}
    for line in committed('SHA256SUMS').decode().splitlines():
        digest, name = line.split('  ', 1)
        require(name in expected_names - {'SHA256SUMS'} and name not in sums, 'unexpected or duplicate SHA256SUMS row')
        require(sha(committed(name)) == digest, 'committed SHA256SUMS digest mismatch: ' + name)
        sums[name] = digest
    require(set(sums) == expected_names - {'SHA256SUMS'}, 'SHA256SUMS inventory mismatch')
    summary = json.loads(committed('qualification-summary.json'))
    require(summary['runtime_source'] == CODE and summary['runtime_tree'] == TREE and summary['base'] == BASE, 'qualification summary source mismatch')
    require(summary['native_targets_passed'] == 7 and summary['additional_native_targets_passed'] == 1 and summary['historical_cloud_attempt_exit'] == 101, 'qualification counts mismatch')
    require(summary['output_ack_event_verified'] is False and summary['full_caller_or_root_gate_claimed'] is False, 'qualification overclaim')
    require(summary['authority'] == 'DENY_ALL' and summary['current_permission'] == 'NOT_EXPORTED' and summary['production_qualification'] == 'HOLD_NO_GO', 'qualification authority widened')

    original_publisher = Path('/home/qian-qi/hepta-pon-outcome-7612-publish-readbacks.py').read_bytes()
    require(sha(original_publisher) == 'f64d0d25738cbe1697c292168f15dcb7711b0381022709ac62c8bc954d7fa68f', 'original publisher file changed')
    publication = json.loads((EVIDENCE / 'publication-result.json').read_bytes())
    require(publication['runtime_source'] == CODE and publication['published_head'] == PUBLISHED and publication['source_status_after'] == '', 'original publication result mismatch')
    require(publication['pull_request']['number'] == 6062, 'original publication PR mismatch')
    allowed = 'https://github.com/' + REPO
    require(git('remote', 'get-url', 'origin').removesuffix('.git') == allowed, 'fetch remote mismatch')
    push_urls = git('remote', 'get-url', '--push', '--all', 'origin').splitlines()
    require(len(push_urls) == 1 and push_urls[0].removesuffix('.git') == allowed, 'effective push destination mismatch')
    refs = git('ls-remote', '--heads', 'origin', 'refs/heads/' + BRANCH).splitlines()
    require(len(refs) == 1 and refs[0].split() == [PUBLISHED, 'refs/heads/' + BRANCH], 'published remote branch mismatch')
    gh = ['/usr/bin/gh']
    require(command(gh + ['api', 'user', '--jq', '.login']) == 'ProfHepta', 'current authenticated principal mismatch')
    # This host's gh pr --json omits baseRefOid; the REST response binds both OIDs.
    pr_raw = json.loads(command(gh + ['api', 'repos/' + REPO + '/pulls/6062']))
    pr = {
        'number': pr_raw['number'], 'url': pr_raw['html_url'],
        'state': pr_raw['state'].upper(), 'isDraft': pr_raw['draft'],
        'headRefName': pr_raw['head']['ref'], 'baseRefName': pr_raw['base']['ref'],
        'headRefOid': pr_raw['head']['sha'], 'baseRefOid': pr_raw['base']['sha'],
        'author': {'login': pr_raw['user']['login']},
    }
    require(pr['number'] == 6062 and pr['state'] == 'OPEN' and pr['isDraft'] is True and pr['author']['login'] == 'ProfHepta', 'PR state/author mismatch')
    require(pr['headRefName'] == BRANCH and pr['baseRefName'] == BASE_BRANCH and pr['headRefOid'] == PUBLISHED and pr['baseRefOid'] == BASE, 'PR exact head/base binding mismatch')
    parent_raw = json.loads(command(gh + ['api', 'repos/' + REPO + '/pulls/6006']))
    parent = {'state': parent_raw['state'].upper(), 'headRefName': parent_raw['head']['ref'], 'headRefOid': parent_raw['head']['sha']}
    require(parent['state'] == 'OPEN' and parent['headRefName'] == BASE_BRANCH and parent['headRefOid'] == BASE, 'parent PR moved')
    require(git('rev-parse', 'HEAD') == PUBLISHED and git('status', '--porcelain=v1') == '', 'source changed during readback')
    result = {
        'schema': 'hepta.pon-outcome.postpublication-readback.v1',
        'started_at': started, 'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'verification': 'PASS', 'verification_mode': 'read-only, after original publication',
        'python_optimize': sys.flags.optimize, 'debug_guards_active': __debug__,
        'runtime_source': CODE, 'runtime_tree': TREE, 'published_head': PUBLISHED,
        'published_tree': git('rev-parse', PUBLISHED + '^{tree}'),
        'native7_exit': first['exit'], 'native8_exit': eighth['exit'],
        'native7_log_sha256': LOG7_SHA, 'native8_log_sha256': LOG8_SHA,
        'native8_finished_at': eighth['finished_at'],
        'maintenance': [{'label': s['label'], 'exit': s['exit'], 'log_bytes': s['log_bytes'], 'log_sha256': s['log_sha256']} for s in maintenance['stages']],
        'original_marker_slices_verified': len(slices), 'original_files_verified': len(originals),
        'committed_files_verified': len(tree_files), 'sha256sums_verified': len(sums),
        'original_publisher_pid_present': False, 'original_publisher_sha256': sha(original_publisher),
        'original_publisher_optimization_mode_verified': False,
        'new_publisher_started': False, 'new_remote_writes': False,
        'original_push_exit': publication.get('push_exit'), 'original_create_exit': publication.get('create_exit'),
        'effective_push_urls': push_urls, 'pull_request': pr, 'parent_pr': parent,
        'historical_cloud_attempt_exit': 101, 'historical_cloud_tests_executed': 0,
        'output_ack_event_verified': False, 'full_caller_or_root_gate_claimed': False,
        'authority': 'DENY_ALL', 'current_permission': 'NOT_EXPORTED', 'production_qualification': 'HOLD_NO_GO',
    }
    print('HEPTA_POSTPUBLICATION_READBACK ' + json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
