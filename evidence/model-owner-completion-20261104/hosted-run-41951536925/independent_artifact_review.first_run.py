#!/usr/bin/env python3
"""Read-only audit of published run 41951536925/attempt 1; never execute a model.

Run with: python -I -S -B independent_artifact_review.py
Writes only a separate review report and disposable immutable SQLite byte copies
under this script's task-owned tmpfs directory. Original artifact bytes are read
and hashed before/after; TrialLedger.inspect/_transaction are never called.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.abc
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import sys
import tempfile
import traceback
import urllib.parse
import zipfile

BASE = Path(__file__).resolve().parent
ARTIFACT = BASE / 'artifact'
REPOSITORY = Path('/workspace/scratch/f4976366a32a/chain')
REGISTRATION = Path('/workspace/scratch/f4976366a32a/hosted-original-authority/published-registration.json')
SOURCE = 'f388f46d9df150a3599b9d961b48918b3ff1fb48'
INTENT = '6bdaf9598d72c118798eb51a03db2e1c0e7c8507'
POLICY = '9096c33705a1c4695b695b2c8ebf047c57fa373a32cb54ada663214dd1ec827e'
TRIAL = '009805004f8e3b37bd2c92173a786a70a1c0b9014dd4b1a45190e5deff149604'
PLAN = '5e0fd5bd92f271737d8460d1aa603a0f1355b132b654294dd965bd51351271c5'
REGISTRATION_SHA = '1bce00490405ab6c1e4eee3e2a9d8d45ba96a5efe3e61aa13b5b3f3977e26e1b'
ZIP_SHA = '0890a0ff94f3ba2fc912b45805531c2058f4ca344f538133d863ab74f35ec924'
FLAGS = ('public_network_ready', 'authenticated_inference_accepted',
         'independent_accepted', 'prospective_accepted', 'public_reward_eligible')
BLOCKED_MODULES = ('torch', 'transformers', 'peft', 'safetensors', 'tokenizers')
REPORT = dict(schema='independent-read-only-artifact-review-v1', run_id=41951536925,
              run_attempt=1, source_commit=SOURCE, intent_commit=INTENT,
              artifact_root=str(ARTIFACT), checks=[], model_execution_performed=False,
              new_trial_or_registration_performed=False, original_artifact_writes=False,
              full_release_or_quality_acceptance=False)


class NoModelImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in BLOCKED_MODULES:
            raise ImportError('AUDIT_FORBIDS_MODEL_OR_TOKENIZER_IMPORT:' + fullname)
        return None


sys.dont_write_bytecode = True
sys.meta_path.insert(0, NoModelImports())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def identity(value):
    return sha(canonical(value))


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('AUDIT_DUPLICATE_JSON_KEY:' + key)
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda text: (_ for _ in ()).throw(ValueError(text)))


def read(name):
    return decode((ARTIFACT / name).read_bytes())


def check(name, condition, detail=None):
    REPORT['checks'].append(dict(name=name, passed=bool(condition), detail=detail))
    if not condition:
        raise ValueError('AUDIT_CHECK_FAILED:' + name)


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_dir():
            continue
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode) or path.is_symlink():
            raise ValueError('AUDIT_NONREGULAR_ARTIFACT:' + str(path))
        raw = path.read_bytes()
        result[path.relative_to(root).as_posix()] = dict(size=len(raw), sha256=sha(raw))
    return result


def replay_detached(raw, policy_id, ledger_module, name):
    check(name + '_sqlite_header', raw.startswith(b'SQLite format 3\0') and raw[18:20] == b'\x01\x01')
    with tempfile.TemporaryDirectory(prefix='independent-readonly-', dir=BASE) as tmp:
        path = Path(tmp) / (name + '.sqlite3')
        with path.open('xb') as handle:
            handle.write(raw)
        path.chmod(0o400)
        before_sha = sha(path.read_bytes())
        uri = 'file:' + urllib.parse.quote(str(path), safe='/') + '?mode=ro&immutable=1'
        db = sqlite3.connect(uri, uri=True, timeout=0, isolation_level=None)
        try:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA query_only=ON')
            check(name + '_query_only', db.execute('PRAGMA query_only').fetchone() == (1,))
            check(name + '_quick_check', db.execute('PRAGMA quick_check').fetchall() == [('ok',)])
            policy, checkpoint, attempts, count = ledger_module.TrialLedger(path, policy_id)._read(db)
            events = [dict(seq=row[0], trial=row[1], kind=row[2], payload=decode(row[3]),
                           previous=row[4], root=row[5])
                      for row in db.execute('SELECT seq,trial,kind,payload,previous,root FROM events ORDER BY seq')]
        finally:
            db.close()
        after_sha = sha(path.read_bytes())
        check(name + '_detached_bytes_unchanged', before_sha == after_sha == sha(raw))
        check(name + '_no_sidecars', not list(Path(tmp).glob(path.name + '-*')))
    return dict(policy=policy, policy_id=policy_id, checkpoint=checkpoint,
                spent=len(attempts), attempts=attempts, events=count, scope=ledger_module.SCOPE), events


def main():
    reg_raw = REGISTRATION.read_bytes()
    reg = decode(reg_raw)
    check('retained_registration_bytes', len(reg_raw) == 100969 and sha(reg_raw) == REGISTRATION_SHA)
    check('registration_pins', reg['source_commit'] == SOURCE and reg['policy_id'] == POLICY
          and reg['trial_id'] == TRIAL and reg['plan_id'] == PLAN
          and reg['ref'] == 'refs/heads/fix/chain-model-owner-hosted-once-20261105')
    check('plan_and_policy_hashes', identity(reg['plan']) == PLAN and identity(reg['policy']) == POLICY)
    source_rows = []
    for name, expected in reg['source_hashes'].items():
        actual = sha((REPOSITORY / name).read_bytes())
        source_rows.append(dict(path=name, expected_sha256=expected, actual_sha256=actual))
    mismatches = [r for r in source_rows if r['actual_sha256'] != r['expected_sha256']]
    check('all_frozen_source_hashes_match', not mismatches, dict(count=len(source_rows), mismatches=mismatches))
    REPORT['frozen_source_check'] = dict(count=len(source_rows), mismatches=mismatches)

    zip_raw = (BASE / 'artifact.zip').read_bytes()
    check('zip_bytes', len(zip_raw) == 55433 and sha(zip_raw) == ZIP_SHA)
    with zipfile.ZipFile(BASE / 'artifact.zip') as archive:
        names = archive.namelist()
        check('zip_entry_inventory', len(names) == len(set(names)) == 26)
        for name in names:
            pure = PurePosixPath(name)
            check('zip_safe_path:' + name, not pure.is_absolute() and '..' not in pure.parts)
            check('zip_equals_extracted:' + name, archive.read(name) == (ARTIFACT / name).read_bytes())
        check('zip_uncompressed_size', sum(i.file_size for i in archive.infolist()) == 221532)
    check('exact_extracted_inventory', set(names) == set(BEFORE))
    collection = read('collection.json')
    retained = []
    for entry in collection['files']:
        actual = BEFORE[entry['path']]
        matched = actual == dict(size=entry['size'], sha256=entry['sha256'])
        retained.append(dict(path=entry['path'], declared=entry, actual=actual, matched=matched))
        check('retained_file_hash:' + entry['path'], matched)
    check('retained_files_complete', len(retained) == 24
          and len({r['path'] for r in retained}) == 24
          and set(BEFORE) == {r['path'] for r in retained} | {'collection.json', 'ledger.sqlite3'})
    check('no_collector_omissions', collection['omitted'] == [])
    check('collector_missing_paths_absent', len(collection['missing']) == 81
          and all(not (ARTIFACT / name).exists() for name in collection['missing']))
    REPORT['retained_file_verification'] = retained
    REPORT['artifact_inventory_before'] = BEFORE
    REPORT['zip'] = dict(size=len(zip_raw), sha256=sha(zip_raw), entries=len(names), uncompressed_bytes=221532)

    admission = collection['admission']
    for name, value in [('collection.admission', admission), ('validation.json', read('validation.json')),
                        ('launch-intent.json', read('launch-intent.json'))]:
        check('admission_pins:' + name, value['source_commit'] == SOURCE and value['intent_commit'] == INTENT
              and value['run_id'] == '41951536925' and value['run_attempt'] == 1
              and value['intent_sha256'] == REGISTRATION_SHA and value['policy_id'] == POLICY
              and value['trial_id'] == TRIAL and value['plan_id'] == PLAN
              and value['before'] == SOURCE and value['git_intent_spent'] is True
              and all(value['qualifications'][flag] is False for flag in FLAGS))
    check('collection_outcome', collection['workflow_steps'] == dict(checkout='success', admission='success',
          python_setup='success', execution='failure') and collection['automatic_retry_allowed'] is False
          and collection['git_publication_spends_opportunity'] is True
          and all(collection['qualifications'][flag] is False for flag in FLAGS))
    terminal = read('execution-terminal.json')
    check('wrapper_known_failure', terminal['outcome'] == 'failed' and terminal['pilot_started'] is True
          and terminal['pilot_returned'] is True and terminal['error'] == 'HOSTED_COMMAND_EXIT:original-pilot:1'
          and terminal['automatic_retry_allowed'] is False and read('original-pilot-exit.json')['returncode'] == 1)

    sys.path.insert(0, str(REPOSITORY / 'scripts'))
    import llm_runtime_trial_ledger as ledger_module
    import llm_runtime_pilot as runtime
    import llm_runtime_assessment as assessment
    # Only pure metadata validators and the historical journal interpreter run.
    plan, loader_plan = read('run/experiment-plan.json'), read('run/loader-1thread-plan.json')
    check('registered_plan_exact', canonical(plan) == canonical(reg['plan']) and identity(plan) == PLAN)
    check('one_thread_plan_exact', canonical(loader_plan) == canonical(dict(plan, threads=1)))
    runtime.validate_plan(plan)
    runtime.validate_plan(loader_plan)
    check('strict_original_plan', plan['threads'] == 4 and plan['training_steps'] == 10
          and plan['backend'] == 'cpu' and plan['dtype'] == 'float32' and 'exit_observation' not in plan)

    db_raw = (ARTIFACT / 'ledger.sqlite3').read_bytes()
    check('ledger_file_pin', collection['ledger']['state'] == 'READ_ONLY_SNAPSHOT'
          and collection['ledger']['size'] == len(db_raw)
          and collection['ledger']['sha256'] == sha(db_raw)
          and not list(ARTIFACT.glob('ledger.sqlite3-*')))
    replay, events = replay_detached(db_raw, POLICY, ledger_module, 'spent-ledger')
    check('collector_readback_exact', canonical(replay) == canonical(collection['ledger']['readback']))
    initial_raw = base64.b64decode(reg['empty_ledger']['base64'], validate=True)
    check('original_authority_bytes', len(initial_raw) == reg['empty_ledger']['size'] == 12288
          and sha(initial_raw) == reg['empty_ledger']['sha256'])
    initial, initial_events = replay_detached(initial_raw, POLICY, ledger_module, 'registered-empty-ledger')
    check('original_genesis', initial['spent'] == initial['events'] == 0 and initial_events == []
          and initial['checkpoint'] == reg['initial_checkpoint'])
    check('actual_journal_events', replay['spent'] == 1 and replay['events'] == 3
          and [e['kind'] for e in events] == ['reserve-v2', 'phase', 'terminal']
          and set(replay['attempts']) == {TRIAL} and events[0]['previous'] == initial['checkpoint'])
    attempt = replay['attempts'][TRIAL]
    check('aborted_terminal', attempt['state'] == attempt['terminal']['outcome'] == 'aborted'
          and attempt['receipts'] == {} and attempt['roster'] is None
          and len(attempt['phases']) == 1 and attempt['phases'][0]['name'] == 'loader-1thread'
          and attempt['replay_profile'] == 'llm-runtime-public-history-contained-v2')
    aborted = read('run/abort.json')
    check('abort_equals_journal_terminal', canonical(attempt['terminal']['record']) == canonical(aborted)
          and identity(aborted) == attempt['terminal']['record_id'])
    check('abort_cause', aborted['error_type'] == 'ValueError'
          and aborted['error'] == 'RUNTIME_REQUIRED_PHASE_ABORT:loader-1thread'
          and aborted['experiment'] == PLAN and all(aborted[f] is False for f in FLAGS)
          and aborted['adoption'] is False and aborted['reward'] is False and aborted['no_update'] is False)
    checkpoint = read('run/trial-checkpoint.json')
    expected_checkpoint = dict(schema='llm-runtime-trial-receipt-v1', scope=ledger_module.SCOPE,
        policy=POLICY, checkpoint=replay['checkpoint'], trial=TRIAL, spent=1, maximum=1,
        state='aborted', plan=PLAN, alpha_per_comparison=[1, 80], statistical_acceptance=False)
    check('checkpoint_exact', canonical(checkpoint) == canonical(expected_checkpoint))
    freeze = read('run/experiment-freeze.json')
    check('freeze_matches_committed_reserve', freeze['plan'] == PLAN
          and freeze['trial']['checkpoint'] == events[0]['root'] and freeze['trial']['state'] == 'reserved'
          and freeze['trial']['spent'] == freeze['trial']['maximum'] == 1
          and freeze['frozen_before_candidate_training'] is True)
    REPORT['ledger'] = dict(sha256=sha(db_raw), bytes=len(db_raw), before_sha256=sha(db_raw),
        after_sha256=sha((ARTIFACT / 'ledger.sqlite3').read_bytes()), read_only_immutable_replay=True,
        spent=replay['spent'], maximum=replay['policy']['max_attempts'], events=replay['events'],
        event_kinds=[e['kind'] for e in events], event_roots=[e['root'] for e in events],
        checkpoint=replay['checkpoint'], state=attempt['state'], receipt_count=0, roster=None,
        original_authority_sha256=sha(initial_raw), collector_readback_exact=True)

    supervisor = read('run/loader-1thread/supervisor.json')
    phases = read('run/phase-outcomes.json')
    check('phase_record_exact', phases == [dict(name='loader-1thread', **supervisor)]
          and phases == aborted['phases']
          and attempt['phases'][0]['observation'] == supervisor)
    pilot_log = (ARTIFACT / 'original-pilot.log').read_text()
    check('pilot_log_phase_exact', decode(pilot_log.splitlines()[0]) == dict(phase='loader-1thread', **supervisor)
          and pilot_log.rstrip().endswith('ValueError: RUNTIME_REQUIRED_PHASE_ABORT:loader-1thread'))
    check('strict_resource_failure_preserved', supervisor['exit_code'] == 0
          and supervisor['outcome'] == 'failed' and supervisor['stop_reason'] == 'rss-observation-unavailable'
          and supervisor['waited_child_reaped'] is True and supervisor['owned_child_reap_resolved'] is True
          and supervisor['waited_child_observation_error'] is None)
    gap = supervisor['rss_observation_gaps'][0]
    check('missing_rss_not_reclassified', len(supervisor['rss_observation_gaps']) == 1
          and gap['before']['child']['State'] == 'R (running)'
          and gap['before']['child']['VmRSS'] is None and gap['before']['exit_cleanup_proof'] is None
          and gap['reconciliation']['mode'] == 'unproved-exit-race'
          and gap['reconciliation']['pidfd_ready_after_wait'] is False
          and gap['after']['child']['State'] == 'Z (zombie)'
          and gap['after']['exit_cleanup_proof']['rss_sample_produced'] is False)

    receipt = read('run/loader-1thread/actual-receipt.json')
    check('standalone_actual_receipt_identity', receipt['schema'] == 'llm-runtime-actual-child-v1'
          and receipt['phase'] == 'loader' and receipt['role'] == 'current-backbone'
          and receipt['outcome'] == 'success' and receipt['actual_backend'] == receipt['actual_device'] == 'cpu'
          and receipt['actual_threads'] == 1 and receipt['experiment'] == identity(loader_plan)
          and receipt['runtime_source'] == plan['runtime_source']
          and all(receipt[f] is False for f in FLAGS))
    assessment._material_context(loader_plan, receipt)
    check('actual_model_material_binding', receipt['parameter_count'] == 134515008
          and receipt['source_weight_sha256'] == runtime.WEIGHT_SHA
          and receipt['forward_executed'] is True and receipt['greedy_decode_executed'] is True
          and receipt['requests'] == 8 and receipt['python'] == '3.12.3'
          and receipt['torch_cuda'] is None and receipt['torch_hip'] is None)
    installed = decode((ARTIFACT / 'installed-metadata.log').read_bytes())
    check('child_installed_versions_match', all(installed[name] == version for name, version in receipt['environment'].items()))
    lock_text = (REPOSITORY / 'scripts/ci/model-runtime-cpu-requirements.txt').read_text()
    lock_pairs = re.findall(r'^([A-Za-z0-9_.-]+)==([^\s]+)', lock_text, re.MULTILINE)
    normalized = {re.sub(r'[-_.]+', '-', key).lower(): val for key, val in installed.items()}
    check('all_locked_dependency_versions_match', len(lock_pairs) == 31
          and all(normalized.get(re.sub(r'[-_.]+', '-', name).lower()) == version for name, version in lock_pairs))
    stages = [decode(line) for line in (ARTIFACT / 'stages.jsonl').read_text().splitlines()]
    verified_materials = [row for row in stages if row.get('state') == 'verified']
    check('seven_material_download_verifications', len(verified_materials) == 7
          and {row['stage'].removeprefix('material:'): (row['size'], row['sha256'])
               for row in verified_materials} == runtime.PUBLIC_FILES)

    c = runtime.contract_module()
    family = runtime.verify_family(runtime.read_json(runtime.FAMILY_PATH))
    contract_raw = (ARTIFACT / 'run/loader-1thread/target-contract.json').read_bytes()
    contract = c.verify_target_contract(contract_raw, receipt['contract'],
        expected_backbone_root=family['material_pins']['fp32_backbone_index_root'],
        expected_tokenizer_root=family['material_pins']['tokenizer_files_root'])
    check('contract_raw_canonical', c.freeze_target_contract(contract)[0] == contract_raw)
    index, bf16 = contract['backbone']['index'], receipt['source_bf16_inventory']
    check('source_and_derived_tensor_inventory', len(index) == len(bf16) == 272 and set(index) == set(bf16)
          and all(bf16[name]['dtype'] == 'BF16' and index[name]['dtype'] == 'float32'
                  and bf16[name]['shape'] == index[name]['shape'] for name in index)
          and sum(math.prod(value['shape']) for value in index.values()) == 134515008)
    pred_raw = (ARTIFACT / 'run/loader-1thread/predictions.json').read_bytes()
    rows = decode(pred_raw)
    expected_tasks = [row['id'] for row in plan['tasks'] if row['partition'] == 'training'][:8]
    check('loader_prediction_file_hash', sha(pred_raw) == receipt['predictions_sha256'])
    check('exact_training_fixture_request_set', len(rows) == 8 and [row['task'] for row in rows] == expected_tasks)
    for n, row in enumerate(rows):
        request_id = c.validate_decoder_request(row['request'], contract, receipt['contract'])
        output_hashes = c.validate_decoder_response(row['response'], row['request'], contract, receipt['contract'])
        check('loader_prediction_context:' + str(n), row['request_id'] == request_id
              and row['snapshot'] == plan['snapshot'] and row['numeric_dtype'] == 'float32'
              and row['actual_device'] == 'cpu' and row['role'] == 'current-backbone'
              and row['artifact'] == receipt['derived_backbone_root']
              and row['generated_tokens'] == row['request']['generation_tokens'] == 8
              and row['input_tokens'] == len(row['request']['input_ids'][0])
              and len(row['response']['generated_token_ids'][0]) == 8
              and output_hashes == [row['output_sha256']])

    cost_events = receipt['cost_events']
    check('cost_exact_stage_inventory', [e['stage'] for e in cost_events] == assessment._stages('loader', 'current-backbone'))
    for event in cost_events:
        check('cost_stage_fields:' + event['stage'], set(event) == {'stage', 'outcome', 'error_type',
              'cpu_ns', 'wall_ns', 'memory_peak_bytes', 'bytes_read', 'bytes_written', 'gpu_ns'}
              and event['outcome'] == 'success' and event['error_type'] is None)
        for key in ('cpu_ns', 'wall_ns', 'memory_peak_bytes', 'bytes_read', 'bytes_written', 'gpu_ns'):
            value = event[key]
            check('cost_integer:' + event['stage'] + ':' + key,
                  type(value) is int and 0 <= value <= (1 << 63) - 1
                  and (key != 'memory_peak_bytes' or value > 0))
        check('cost_cpu_gpu_scope:' + event['stage'], event['gpu_ns'] == 0)
    stage_wall = sum(e['wall_ns'] for e in cost_events)
    stage_cpu = sum(e['cpu_ns'] for e in cost_events)
    budget = plan['inference_budget']
    check('cost_numeric_containment', supervisor['budget'] == budget
          and 0 < receipt['process_wall_ns'] <= supervisor['observed_wall_ns'] <= budget['wall_seconds'] * 10**9
          and receipt['process_cpu_ns'] - supervisor['child_cpu_ns'] <= assessment._wait4_cpu_slack_ns(supervisor['child_cpu_ns'])
          and 0 < receipt['process_peak_rss_bytes'] <= supervisor['waited_child_peak_rss_bytes'] <= budget['rss_bytes']
          and 0 <= supervisor['sampled_peak_rss_bytes'] <= budget['rss_bytes']
          and stage_wall <= receipt['process_wall_ns'] and stage_cpu <= receipt['process_cpu_ns']
          and all(e['memory_peak_bytes'] <= receipt['process_peak_rss_bytes'] for e in cost_events))
    try:
        assessment.observe_phase(loader_plan, 'loader-1thread', 'loader', 'current-backbone', supervisor, receipt)
    except ValueError as error:
        expected_error = str(error)
    else:
        expected_error = None
    check('unmodified_success_validator_rejects_actual_records', expected_error == 'RUNTIME_COST_SUPERVISOR_INCOMPLETE', expected_error)
    unstarted = list(ledger_module.PHASES[1:])
    check('all_eleven_later_phase_directories_absent', len(unstarted) == 11
          and all(not (ARTIFACT / 'run' / name).exists() for name in unstarted))
    check('no_roster_or_assessment', not (ARTIFACT / 'run/evaluation-roster.json').exists()
          and not (ARTIFACT / 'run/assessment.json').exists())
    REPORT['actual_loader'] = dict(
        receipt_hash=identity(receipt), receipt_file_sha256=BEFORE['run/loader-1thread/actual-receipt.json']['sha256'],
        child_exit_code=0, standalone_child_outcome='success', supervisor_outcome='failed',
        phase_accepted=False, receipt_recorded_in_ledger=False,
        receipt_not_recorded_reason='run.phase persists failed supervision, then raises before observe_phase and ledger.child_receipt',
        stop_reason=supervisor['stop_reason'], actual_backend='cpu', actual_threads=1,
        parameter_count=receipt['parameter_count'], source_weight_sha256=receipt['source_weight_sha256'],
        derived_backbone_root=receipt['derived_backbone_root'], contract=receipt['contract'],
        forward_executed=True, greedy_decode_executed=True, requests=8, generated_tokens_total=64,
        prediction_file_sha256=sha(pred_raw), prediction_request_response_hashes_valid=True,
        prediction_task_scope='first eight public training fixtures; no calibration/evaluation tasks',
        quality_scoring_performed=False, independent_argmax_or_tokenizer_reexecution=False,
        actual_environment=receipt['environment'], locked_dependencies_matched=len(lock_pairs),
        cost=dict(supervised_wall_ns=supervisor['observed_wall_ns'], waited_child_cpu_ns=supervisor['child_cpu_ns'],
            observer_cpu_ns=supervisor['observer_cpu_ns'], child_wall_ns=receipt['process_wall_ns'],
            child_cpu_ns=receipt['process_cpu_ns'], sampled_peak_rss_bytes=supervisor['sampled_peak_rss_bytes'],
            waited_peak_rss_bytes=supervisor['waited_child_peak_rss_bytes'], child_peak_rss_bytes=receipt['process_peak_rss_bytes'],
            stage_wall_sum_ns=stage_wall, stage_cpu_sum_ns=stage_cpu,
            stage_bytes_read=sum(e['bytes_read'] for e in cost_events),
            stage_bytes_written=sum(e['bytes_written'] for e in cost_events),
            observed_numbers_contained=True, rss_sampling_gap_count=1,
            strict_supervision_complete=False, complete_economic_cost=False,
            scope='Partial real observations from failed phase; no full-pilot aggregate or release economics.'),
        gap=dict(at_wall_ns=gap['at_wall_ns'], initial_state=gap['before']['child']['State'],
            initial_rss=gap['before']['child']['VmRSS'], reconciliation_mode=gap['reconciliation']['mode'],
            elapsed_ns=gap['reconciliation']['elapsed_ns'], pidfd_ready_after_wait=False,
            later_state=gap['after']['child']['State'], late_proof_produces_rss=False,
            interpretation='Later zombie/exit diagnostics cannot replace the missing live RSS observation.'))
    REPORT['not_started_phases'] = unstarted
    REPORT['scope_conclusion'] = dict(
        registered_phases=12, attempted_phases=1, accepted_phases=0, not_started_phases=11,
        train_roles_started=0, quality_evaluations_started=0, candidate_artifact_created=False,
        full_release_evaluation=False, adoption=False, reward=False, accepted_no_update=False,
        model_or_runtime_quality_gain='NOT_EVALUATED', run_outcome='aborted', local_spent=1,
        campaign_opportunity_consumed=True, retry_authorized=False,
        independent_management_or_future_task_custody_established=False)
    REPORT['audit_outcome'] = 'CONSISTENT_FAILED_ATTEMPT_EVIDENCE'


BEFORE = inventory(ARTIFACT)
ZIP_BEFORE = sha((BASE / 'artifact.zip').read_bytes())
try:
    main()
except BaseException as error:
    REPORT['audit_outcome'] = 'AUDIT_ERROR'
    REPORT['audit_error'] = dict(type=type(error).__name__, message=str(error), traceback=traceback.format_exc())
finally:
    AFTER = inventory(ARTIFACT)
    REPORT['artifact_bytes_unchanged'] = BEFORE == AFTER
    REPORT['artifact_inventory_after'] = AFTER
    REPORT['zip_bytes_unchanged'] = ZIP_BEFORE == sha((BASE / 'artifact.zip').read_bytes())
    REPORT['forbidden_model_modules_loaded'] = [name for name in sys.modules if name.split('.')[0] in BLOCKED_MODULES]
    REPORT['review_script_sha256'] = sha(Path(__file__).read_bytes())
    output = BASE / 'independent-artifact-review.json'
    with output.open('x', encoding='utf-8') as handle:
        json.dump(REPORT, handle, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        handle.write('\n')
    print(json.dumps(dict(path=str(output), size=output.stat().st_size, sha256=sha(output.read_bytes()),
                         audit_outcome=REPORT['audit_outcome'], checks=len(REPORT['checks']),
                         failed_checks=[r['name'] for r in REPORT['checks'] if not r['passed']],
                         artifact_bytes_unchanged=REPORT['artifact_bytes_unchanged'],
                         error=REPORT.get('audit_error')), sort_keys=True))
    if REPORT['audit_outcome'] == 'AUDIT_ERROR' or not REPORT['artifact_bytes_unchanged'] or not REPORT['zip_bytes_unchanged']:
        raise SystemExit(1)
