#!/usr/bin/env python3
"""Execute a frozen inherited SmolLM trial without acquiring owner authority.

``freeze`` commits the installed-parent bytes, training data, held-out data hash,
all recipes, equal per-role caps and a strictly positive gain threshold. ``train``
never receives the held-out file: it invokes the original once-only inherited
executor and the four existing pilot control trainers. ``evaluate`` subsequently
loads all six actual artifacts in separate, identically bounded workers. ``run``
combines those two commands for a local execution experiment.

These are execution observations for the original LearningIterationOwnerPortsV1,
not an implementation of that owner. A caller-supplied parent or input scope is
not proof of installation or task authorization. Independent custody, signed
evaluation acceptance, payment, Selection and next-task FinalUse remain with
their original owners. NoUpdate here means only the completed frozen numerical
comparison retained the parent; it does not complete the native iteration.

The original operation journal fences candidate dispatch. A child stage journal,
bound to that same original authority/intent/profile, fences every control and
evaluation dispatch. Pending work is UNKNOWN, never a license to run again.
Neither journal provides an external anti-rollback witness.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import resource
import struct
import sys
import time
from types import SimpleNamespace

import llm_inherited_operation as operation
import llm_inherited_runtime as inherited
import llm_parent_material as material
import llm_runtime_assessment as costs
import llm_runtime_pilot as runtime

PROFILE = 'hepta-smollm-frozen-evaluation-profile-v1'
INPUT = 'hepta-smollm-held-out-input-v1'
RUN = 'hepta-smollm-frozen-trial-v1'
ROSTER = 'hepta-smollm-frozen-artifact-roster-v1'
CHILD = 'hepta-smollm-frozen-evaluation-actual-v1'
RESULT = 'hepta-smollm-frozen-evaluation-result-v1'
PARTICIPANTS = ['retained-parent', *runtime.PARTICIPANTS]
AUTHORITY = inherited.NO_AUTHORITY.copy()
MAX_DOCUMENT = 2 * 1024**2
MAX_ARTIFACT = 600 * 1024**2


def require(value, code):
    if not value:
        raise ValueError('FROZEN_EVALUATION_' + code)


def closed(value, fields, code):
    require(type(value) is dict and set(value) == set(fields.split()), code)


def sources():
    return dict(inherited.source_pins(),
                frozen_evaluation=runtime.file_sha(__file__),
                operation_journal=runtime.file_sha(operation.__file__),
                cost_assessment=runtime.file_sha(costs.__file__))


def read_pinned(path, digest, maximum=MAX_DOCUMENT):
    operation.digest(digest)
    raw = material.read_regular(path, maximum)
    require(hashlib.sha256(raw).hexdigest() == digest, 'FILE_PIN')
    return operation.decode(raw), raw


def publish(path, raw):
    """An immutable local observation, fsynced before subsequent dispatch."""
    path = Path(path)
    operation.private_directory(path.parent)
    require(type(raw) is bytes and 0 < len(raw) <= MAX_DOCUMENT, 'DOCUMENT_BOUND')
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        require(operation.snapshot(path) == raw, 'PUBLISHED_BYTES_CHANGED')
        return
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    operation.sync_directory(path.parent)


def publish_json(path, value):
    publish(path, runtime.canonical(value) + b'\n')


def validate_freeze(profile, *, current_sources=True):
    closed(profile, 'schema operation_id parent training_input_sha256 evaluation_input_sha256 '
           'runtime evaluation source_pins authority', 'PROFILE_FIELDS')
    require(profile['schema'] == PROFILE, 'PROFILE_SCHEMA')
    operation.label(profile['operation_id'])
    inherited.validate_parent(profile['parent'])
    for name in ('training_input_sha256', 'evaluation_input_sha256'):
        operation.digest(profile[name])
    require(profile['training_input_sha256'] != profile['evaluation_input_sha256'], 'DATASET_ALIAS')
    require(type(profile['authority']) is dict and set(profile['authority']) == set(AUTHORITY)
            and all(value is False for value in profile['authority'].values()), 'AUTHORITY')
    pins = profile['source_pins']
    require(type(pins) is dict and set(pins) == set(sources()), 'SOURCE_FIELDS')
    for pin in pins.values():
        operation.digest(pin)
    if current_sources:
        require(pins == sources(), 'SOURCE_CHANGED')
    plan = runtime.validate_plan(profile['runtime'])
    require(plan['backend'] == 'cpu' and plan['threads'] <= 4, 'CPU_PROFILE')
    # There is one recipe/budget interpretation. A permissive pilot plan cannot
    # silently introduce per-role tuning or a different exit-observation mode.
    template = runtime.experiment_plan({}, threads=plan['threads'], steps=plan['training_steps'])
    require(set(plan) == set(template) and
            all(plan[key] == value for key, value in template.items()
                if key not in ('snapshot', 'tasks')), 'EXACT_RUNTIME')
    operation.digest(plan['snapshot'])
    require(type(plan['tasks']) is list and 1 <= len(plan['tasks']) <= inherited.MAX_TASKS
            and all(row['partition'] == 'training' for row in plan['tasks']), 'TRAINING_ONLY')
    rule = profile['evaluation']
    closed(rule, 'metric min_correct_gain rows participants rule', 'RULE_FIELDS')
    require(rule['metric'] == 'greedy-exact-match-v1' and
            rule['rule'] == 'candidate-exceeds-retained-parent-and-every-control-v1' and
            rule['participants'] == PARTICIPANTS, 'RULE')
    require(type(rule['rows']) is int and 1 <= rule['rows'] <= inherited.MAX_TASKS and
            type(rule['min_correct_gain']) is int and
            1 <= rule['min_correct_gain'] <= rule['rows'], 'POSITIVE_GAIN_REQUIRED')
    return profile


def create_profile(args):
    inputs, _ = read_pinned(args.training_input, args.training_input_sha256)
    parent, _ = read_pinned(args.parent, args.parent_sha256)
    inherited.read_parent(parent)
    manifest, _ = runtime.verify_materials(args.materials)
    plan = runtime.experiment_plan(manifest, threads=args.threads, steps=args.steps)
    plan['tasks'] = inherited.training_rows(inputs)
    profile = dict(schema=PROFILE, operation_id=args.operation_id, parent=parent,
        training_input_sha256=args.training_input_sha256,
        evaluation_input_sha256=args.evaluation_input_sha256, runtime=plan,
        evaluation=dict(metric='greedy-exact-match-v1', min_correct_gain=args.min_correct_gain,
            rows=args.evaluation_rows, participants=PARTICIPANTS.copy(),
            rule='candidate-exceeds-retained-parent-and-every-control-v1'),
        source_pins=sources(), authority=AUTHORITY.copy())
    validate_freeze(profile)
    path = Path(args.output)
    require(path.is_absolute() and path.resolve() == path and not path.exists(), 'NEW_PROFILE_PATH')
    publish_json(path, profile)
    return dict(schema=PROFILE, operation_id=profile['operation_id'], path=str(path),
                evaluation_profile_sha256=runtime.file_sha(path), authority=AUTHORITY.copy())


def evaluation_rows(value, profile):
    closed(value, 'schema scope records', 'HELD_OUT_FIELDS')
    require(value['schema'] == INPUT and
            value['scope'] in ('operator-held-out-inputs', 'public-smoke-fixtures'), 'HELD_OUT_SCOPE')
    # Reuse the bounded text and duplicate checks without upgrading this scope
    # string into authentication of the original task or an independent cohort.
    rows = inherited.training_rows(dict(schema='hepta-smollm-training-input-v1',
        scope='public-smoke-fixtures', records=value['records']))
    require(len(rows) == profile['evaluation']['rows'], 'HELD_OUT_COUNT')
    training_prompts = {row['prompt_sha256'] for row in profile['runtime']['tasks']}
    require(not any(row['prompt_sha256'] in training_prompts for row in rows), 'TRAINING_EVALUATION_OVERLAP')
    for row in rows:
        row.pop('id')
        row.update(partition='evaluation', source_group=runtime.identity(
            dict(schema=INPUT, scope=value['scope'])))
        row['id'] = runtime.identity(row)
    return rows


def file_pin(path, maximum=MAX_DOCUMENT, *, durable=False):
    """Stream large control artifacts through one checked descriptor."""
    with os.fdopen(operation.private_file(path, maximum), 'rb') as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.sha256()
        native = hashlib.sha256(b'TRNM-PON1\0' + struct.pack('<H', 8) + b'artifact' +
                                struct.pack('<I', before.st_size))
        count = 0
        for block in iter(lambda: stream.read(1024**2), b''):
            count += len(block)
            require(count <= maximum, 'ARTIFACT_BOUND')
            digest.update(block)
            native.update(block)
        after = os.fstat(stream.fileno())
        require(count == before.st_size and
                (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'ARTIFACT_CHANGED')
        if durable:
            os.fsync(stream.fileno())
    return dict(sha256=digest.hexdigest(), bytes=count, native_artifact_H=native.hexdigest())


def budget_readback(supervisor, receipt, budget):
    require(supervisor.get('budget') == budget, 'BUDGET_CHANGED')
    require(supervisor.get('outcome') == 'success' and supervisor.get('exit_code') == 0
            and supervisor.get('stop_reason') is None, 'CHILD_FAILED')
    values = {key: costs._integer(supervisor.get(key), 'FROZEN_EVALUATION_COST', 1 if key in
              ('observed_wall_ns', 'waited_child_peak_rss_bytes') else 0) for key in
              ('observed_wall_ns', 'child_cpu_ns', 'observer_cpu_ns',
               'sampled_peak_rss_bytes', 'waited_child_peak_rss_bytes')}
    child_wall = costs._integer(receipt.get('process_wall_ns'), 'FROZEN_EVALUATION_COST', 1)
    child_rss = costs._integer(receipt.get('process_peak_rss_bytes'), 'FROZEN_EVALUATION_COST', 1)
    require(child_wall <= values['observed_wall_ns'] <= budget['wall_seconds'] * 10**9 and
            child_rss <= values['waited_child_peak_rss_bytes'] and
            max(child_rss, values['waited_child_peak_rss_bytes'], values['sampled_peak_rss_bytes'])
            <= budget['rss_bytes'], 'BUDGET_EXCEEDED')
    return dict(values, child_reported_wall_ns=child_wall,
                child_reported_peak_rss_bytes=child_rss, budget=budget,
                complete_economic_cost=False)


def control_artifact(directory, plan, role, receipt, *, durable=False):
    raw = operation.snapshot(directory / 'artifact.json', durable=durable)
    record = operation.decode(raw)
    closed(record, 'role artifact contract kind source_model experiment parent_backbone '
           'resulting_backbone file_sha256 native_artifact_H native_domain native_admission_accepted',
           'CONTROL_ARTIFACT_FIELDS')
    require(record['role'] == role and record['kind'] == plan['recipes'][role]['kind'] and
            record['experiment'] == runtime.identity(plan) and record['source_model'] == runtime.WEIGHT_SHA
            and record['native_domain'] == 'artifact' and record['native_admission_accepted'] is False
            and record['artifact'] == receipt['artifact'] and record['contract'] == receipt['contract']
            and record['parent_backbone'] == receipt['parent_backbone']
            and record['resulting_backbone'] == receipt['resulting_backbone'], 'CONTROL_ARTIFACT_BINDING')
    pins = {'artifact.json': hashlib.sha256(raw).hexdigest()}
    for name in ('artifact', 'contract', 'parent_backbone', 'resulting_backbone'):
        operation.digest(record[name])
    if record['kind'] == 'immutable-backbone':
        require(record['file_sha256'] is None and record['native_artifact_H'] is None and
                record['artifact'] == record['parent_backbone'] == record['resulting_backbone'],
                'IMMUTABLE_CONTROL')
    else:
        pin = file_pin(directory / 'artifact.safetensors', MAX_ARTIFACT, durable=durable)
        require(pin['sha256'] == record['file_sha256'] and
                pin['native_artifact_H'] == record['native_artifact_H'], 'CONTROL_ARTIFACT_BYTES')
        pins['artifact.safetensors'] = pin['sha256']
        if record['kind'] in ('lora', 'random-lora'):
            pins['wrapped-adapter.json'] = file_pin(directory / 'wrapped-adapter.json',
                                                   durable=durable)['sha256']
    return record, pins


def observe_stage(record, *, durable=False):
    request, profile = record['request'], record['plan']
    directory = Path(request['directory'])
    if not directory.exists():
        return None
    operation.private_directory(directory)
    try:
        raw_supervisor = operation.snapshot(directory / 'supervisor.json', durable=durable)
    except FileNotFoundError:
        return None
    supervisor = operation.decode(raw_supervisor)
    require(type(supervisor) is dict and supervisor.get('outcome') in ('success', 'failed'), 'SUPERVISOR')
    if (supervisor.get('waited_child_reaped') is not True or
            supervisor.get('owned_child_reap_resolved') is not True or
            supervisor.get('waited_child_observation_error') is not None):
        return None
    phase, role = request['phase'], request['role']
    budget = profile['runtime']['training_budget' if phase == 'train' else 'inference_budget']
    require(supervisor.get('budget') == budget, 'BUDGET_CHANGED')
    pins = {'supervisor.json': hashlib.sha256(raw_supervisor).hexdigest()}
    if supervisor['outcome'] == 'failed':
        require(type(supervisor.get('exit_code')) is int and
                (supervisor['exit_code'] != 0 or supervisor.get('stop_reason') is not None), 'FAILED_EXIT')
        return dict(status='FAILED', pins=pins, stop_reason=supervisor.get('stop_reason'),
                    costs={key: supervisor.get(key) for key in
                           ('observed_wall_ns', 'child_cpu_ns', 'waited_child_peak_rss_bytes')})
    try:
        raw_receipt = operation.snapshot(directory / 'actual-receipt.json', durable=durable)
    except FileNotFoundError:
        return None
    receipt = operation.decode(raw_receipt)
    pins['actual-receipt.json'] = hashlib.sha256(raw_receipt).hexdigest()
    measured = budget_readback(supervisor, receipt, budget)
    if phase == 'train':
        measured = costs.observe_phase(profile['runtime'], 'train-' + role, 'train', role,
                                       supervisor, receipt)
        artifact, artifact_pins = control_artifact(directory, profile['runtime'], role, receipt,
                                                  durable=durable)
        pins.update(artifact_pins)
        observation = dict(status='SUCCESS', pins=pins, artifact=artifact['artifact'],
                           contract=artifact['contract'], training=receipt['training'], costs=measured)
    else:
        for key, value in dict(schema=CHILD, operation_id=profile['operation_id'], phase='evaluate',
                role=role, evaluation_profile_sha256=request['evaluation_profile_sha256'],
                roster_sha256=request['roster_sha256'], evaluation_input_sha256=profile['evaluation_input_sha256'],
                authority=AUTHORITY, outcome='success', source_pins=profile['source_pins'],
                actual_backend='cpu', actual_threads=profile['runtime']['threads'],
                forward_executed=True, requests=profile['evaluation']['rows']).items():
            require(receipt.get(key) == value, 'EVALUATION_RECEIPT')
        inputs, _ = read_pinned(request['evaluation_input'], profile['evaluation_input_sha256'])
        rows = evaluation_rows(inputs, profile)
        roster, _ = read_pinned(request['roster'], request['roster_sha256'])
        validate_roster(roster, profile, request['evaluation_profile_sha256'])
        expected = roster['artifacts'][role]
        require(receipt.get('artifact') == expected['artifact'] and
                receipt.get('contract') == expected['contract'], 'EVALUATED_ARTIFACT')
        raw_predictions = operation.snapshot(directory / 'predictions.json', durable=durable)
        pins['predictions.json'] = hashlib.sha256(raw_predictions).hexdigest()
        require(pins['predictions.json'] == receipt.get('predictions_sha256'), 'PREDICTION_PIN')
        predictions = operation.decode(raw_predictions)
        outputs = runtime.verify_predictions(predictions, dict(profile['runtime'], tasks=rows),
                                             role, expected['artifact'], expected['contract'])
        observation = dict(status='SUCCESS', pins=pins, artifact=expected['artifact'],
            contract=expected['contract'], outputs=outputs, costs=measured)
    if durable:
        operation.sync_directory(directory)
    return observation


def stage_once(journal, stage_id, intent, request, profile, dispatch=None):
    """A retained pending reservation is queried, never redispatched."""
    record = journal.lookup(stage_id, intent)
    if record is None:
        if dispatch is None:
            return dict(status='NOT_STARTED', dispatch_allowed=False)
        require(not Path(request['directory']).exists(), 'STAGE_OUTPUT_EXISTS')
        freeze_raw = operation.snapshot(Path(request['directory']).parent / 'evaluation-profile.json')
        require(hashlib.sha256(freeze_raw).hexdigest() == request['evaluation_profile_sha256'] and
                operation.decode(freeze_raw) == profile, 'STAGE_FREEZE_BINDING')
        freeze = dict(raw_utf8=freeze_raw.decode('utf-8'), sha256=request['evaluation_profile_sha256'])
        if journal.reserve(stage_id, intent, request, profile, freeze):
            # Even a spawn exception leaves the stable identity reserved.
            try:
                dispatch()
            except Exception:
                pass
        record = journal.lookup(stage_id, intent)
    require(record['request'] == request and record['plan'] == profile, 'STAGE_REQUEST_CHANGED')
    require(record['freeze']['sha256'] == request['evaluation_profile_sha256'] and
            hashlib.sha256(record['freeze']['raw_utf8'].encode()).hexdigest() ==
            request['evaluation_profile_sha256'] and operation.decode(record['freeze']['raw_utf8']) == profile,
            'STAGE_FREEZE_BINDING')
    observation = observe_stage(record, durable=record['result'] is None)
    if record['result'] is not None:
        require(observation == record['result'], 'TERMINAL_EVIDENCE_CHANGED')
    elif observation is not None:
        journal.complete(stage_id, intent, observation)
    return dict(status='UNKNOWN', dispatch_allowed=False) if observation is None else observation


def prepare_context(args, *, create=False):
    profile, raw_profile = read_pinned(args.profile, args.profile_sha256)
    validate_freeze(profile, current_sources=args.action != 'query')
    operation.digest(args.authority_id)
    operation.digest(args.intent_sha256)
    directory = Path(args.output)
    require(directory.is_absolute() and directory.resolve() == directory, 'OUTPUT_PATH')
    context = dict(schema=RUN, operation_id=profile['operation_id'],
        evaluation_profile_sha256=args.profile_sha256, original_authority_id=args.authority_id,
        original_intent_sha256=args.intent_sha256, materials=str(Path(args.materials)), output=str(directory))
    require(Path(args.materials).is_absolute() and Path(args.materials).resolve() == Path(args.materials),
            'MATERIALS_PATH')
    if not directory.exists():
        require(create, 'RUN_ABSENT')
        directory.mkdir(mode=0o700)
        publish_json(directory / 'context.json', context)
    else:
        operation.private_directory(directory)
        require(operation.decode(operation.snapshot(directory / 'context.json')) == context, 'RUN_CHANGED')
    publish(directory / 'evaluation-profile.json', raw_profile) if create else require(
        operation.snapshot(directory / 'evaluation-profile.json') == raw_profile, 'PROFILE_CHANGED')
    if create:
        inputs, raw_inputs = read_pinned(args.training_input, profile['training_input_sha256'])
        require(inherited.training_rows(inputs) == profile['runtime']['tasks'], 'TRAINING_INPUT_BINDING')
        publish(directory / 'training-input.json', raw_inputs)
        publish_json(directory / 'installed-parent.json', profile['parent'])
        publish_json(directory / 'training-plan.json', profile['runtime'])
    return profile, context, directory


def candidate_args(profile, directory, materials):
    parent_path = directory / 'installed-parent.json'
    return SimpleNamespace(command='train', operation_id=profile['operation_id'], materials=materials,
        output=str(directory / 'candidate'), input=str(directory / 'training-input.json'),
        input_sha256=profile['training_input_sha256'], parent=str(parent_path),
        parent_sha256=runtime.file_sha(parent_path), bootstrap=False,
        threads=profile['runtime']['threads'], steps=profile['runtime']['training_steps'],
        evaluation_freeze=str(directory / 'evaluation-profile.json'),
        evaluation_profile_sha256=runtime.file_sha(directory / 'evaluation-profile.json'))


def child_journal(context, directory, *, create):
    authority_path, path = directory / 'stage-authority.json', directory / 'stages.sqlite3'
    if not authority_path.exists():
        require(create and not path.exists(), 'STAGE_AUTHORITY_UNKNOWN')
        created = operation.initialize(path)
        publish_json(authority_path, dict(schema=RUN, authority_id=created['authority_id'], context=context))
    authority = operation.decode(operation.snapshot(authority_path))
    closed(authority, 'schema authority_id context', 'STAGE_AUTHORITY_FIELDS')
    require(authority['schema'] == RUN and authority['context'] == context, 'STAGE_AUTHORITY_BINDING')
    return operation.Journal(path, authority['authority_id'])


def stage_request(context, directory, phase, role, **extra):
    require(phase in ('train', 'evaluate') and role in
            (runtime.CONTROLS if phase == 'train' else PARTICIPANTS), 'STAGE_ROLE')
    stage_id = phase + '-' + role
    intent = runtime.identity(dict(schema=RUN, original_intent=context['original_intent_sha256'],
                                   profile=context['evaluation_profile_sha256'], stage=stage_id))
    request = dict(schema=RUN, phase=phase, role=role,
        original_authority_id=context['original_authority_id'], original_intent_sha256=context['original_intent_sha256'],
        evaluation_profile_sha256=context['evaluation_profile_sha256'],
        directory=str(directory / stage_id), output=str(directory / stage_id), **extra)
    return stage_id, intent, request


def candidate_readback(journal, context, profile, directory, *, dispatch):
    args = candidate_args(profile, directory, context['materials'])
    if dispatch:
        try:
            result = operation.run_once(journal, context['original_intent_sha256'], args)
        except Exception:
            # The original operation's reserved state decides whether anything
            # happened; an exception is neither NoUpdate nor a retry grant.
            reserved = journal.lookup(profile['operation_id'], context['original_intent_sha256'])
            if reserved is None or reserved['request'] != operation.invocation(args):
                raise
            result = operation.query(journal, profile['operation_id'], context['original_intent_sha256'])
    else:
        if journal.lookup(profile['operation_id'], context['original_intent_sha256']) is None:
            return dict(status='NOT_STARTED', dispatch_allowed=False)
        result = operation.query(journal, profile['operation_id'], context['original_intent_sha256'])
    require(result.get('evaluation_profile_sha256') == context['evaluation_profile_sha256'] and
            result.get('original_output') == args.output,
            'CANDIDATE_FREEZE_BINDING')
    require(journal.lookup(profile['operation_id'], context['original_intent_sha256'])['request'] ==
            operation.invocation(args), 'CANDIDATE_REQUEST_BINDING')
    if result['status'] == 'SUCCESS':
        record = journal.lookup(profile['operation_id'], context['original_intent_sha256'])
        require(record['plan']['runtime'] == profile['runtime'] and record['plan']['parent'] == profile['parent'],
                'CANDIDATE_PLAN_BINDING')
        receipt = operation.decode(operation.snapshot(directory / 'candidate/worker/actual-receipt.json'))
        supervisor = operation.decode(operation.snapshot(directory / 'candidate/supervisor.json'))
        budget_readback(supervisor, receipt, profile['runtime']['training_budget'])
        costs._training_receipt(profile['runtime'], 'candidate', receipt)
    return result


def validate_roster(roster, profile, profile_sha256):
    closed(roster, 'schema evaluation_profile_sha256 operation_id artifacts', 'ROSTER_FIELDS')
    require(roster['schema'] == ROSTER and roster['evaluation_profile_sha256'] == profile_sha256
            and roster['operation_id'] == profile['operation_id'] and
            type(roster['artifacts']) is dict and set(roster['artifacts']) == set(PARTICIPANTS), 'ROSTER')
    for role, spec in roster['artifacts'].items():
        if role in ('retained-parent', 'candidate'):
            closed(spec, 'kind descriptor artifact contract', 'ROSTER_INHERITED_FIELDS')
            descriptor = inherited.validate_parent(spec['descriptor'])
            require(spec['kind'] == 'inherited' and spec['artifact'] == descriptor['adapter'] and
                    spec['contract'] == descriptor['contract'] == profile['parent']['contract'], 'ROSTER_INHERITED')
            if role == 'retained-parent':
                require(descriptor == profile['parent'], 'RETAINED_PARENT_CHANGED')
            else:
                require(descriptor['generation'] == profile['parent']['generation'] + 1 and
                        descriptor['operation_id'] == profile['operation_id'], 'CANDIDATE_LINEAGE')
        else:
            closed(spec, 'kind directory artifact contract artifact_record_sha256', 'ROSTER_CONTROL_FIELDS')
            require(spec['kind'] == 'pilot' and Path(spec['directory']).is_absolute(), 'ROSTER_CONTROL')
            operation.digest(spec['artifact_record_sha256'])
        operation.digest(spec['artifact'])
        operation.digest(spec['contract'])
    return roster


def train_all(journal, profile, context, directory, *, dispatch):
    candidate = candidate_readback(journal, context, profile, directory, dispatch=dispatch)
    if candidate['status'] != 'SUCCESS':
        return dict(status=candidate['status'], candidate=candidate, controls={}, numerical_disposition=None)
    stages = child_journal(context, directory, create=dispatch)
    observations = {}
    try:
        for role in runtime.CONTROLS:
            name, intent, request = stage_request(context, directory, 'train', role)
            command = [sys.executable, str(Path(runtime.__file__).resolve()), '_child',
                '--materials', context['materials'], '--output', request['directory'],
                '--plan', str(directory / 'training-plan.json'), '--phase', 'train', '--role', role]
            callback = (lambda command=command, request=request: runtime.supervise(command,
                request['directory'], profile['runtime']['training_budget'])) if dispatch else None
            observations[role] = stage_once(stages, name, intent, request, profile, callback)
            if observations[role]['status'] != 'SUCCESS':
                return dict(status=observations[role]['status'], candidate=candidate, controls=observations,
                            numerical_disposition=None)
    finally:
        stages.close()
    receipt_paths = {'candidate': directory / 'candidate/worker/actual-receipt.json',
                     **{role: directory / ('train-' + role) / 'actual-receipt.json' for role in runtime.CONTROLS}}
    receipts = {'train-' + role: operation.decode(operation.snapshot(path)) for role, path in receipt_paths.items()}
    costs.validate_training_match(profile['runtime'], receipts)
    candidate_parent = operation.decode(operation.snapshot(directory / 'candidate/worker/parent-material.json'))
    artifacts = {}
    for role, descriptor in (('retained-parent', profile['parent']), ('candidate', candidate_parent)):
        artifacts[role] = dict(kind='inherited', descriptor=descriptor,
                               artifact=descriptor['adapter'], contract=descriptor['contract'])
    for role, observation in observations.items():
        artifacts[role] = dict(kind='pilot', directory=str(directory / ('train-' + role)),
            artifact=observation['artifact'], contract=observation['contract'],
            artifact_record_sha256=observation['pins']['artifact.json'])
    roster = dict(schema=ROSTER, evaluation_profile_sha256=context['evaluation_profile_sha256'],
                  operation_id=profile['operation_id'], artifacts=artifacts)
    validate_roster(roster, profile, context['evaluation_profile_sha256'])
    if dispatch:
        publish_json(directory / 'artifact-roster.json', roster)
    else:
        require(operation.decode(operation.snapshot(directory / 'artifact-roster.json')) == roster, 'ROSTER_CHANGED')
    return dict(status='TRAINED', candidate=candidate, controls=observations,
                artifact_roster_sha256=runtime.file_sha(directory / 'artifact-roster.json'),
                equal_training_caps=True, matched_observed_steps_and_token_totals=True,
                actual_per_step_token_trace_verified=False, numerical_disposition=None)


def load_evaluation_artifact(model, contract, raw, cid, shapes, plan, spec, role, torch, device):
    if spec['kind'] == 'inherited':
        parent, parent_raw, factors = inherited.read_parent(spec['descriptor'])
        require({k: v for k, v in contract.items() if k != 'registration'} ==
                {k: v for k, v in parent.items() if k != 'registration'}, 'TARGET_RUNTIME_MISMATCH')
        contract, raw, cid = parent, parent_raw, spec['descriptor']['contract']
        model = runtime.insert_lora(model, plan, 'candidate', torch)
        actual = inherited.load_factors(model, contract, cid, factors, spec['artifact'], torch, device)
    else:
        directory = Path(spec['directory'])
        read_pinned(directory / 'artifact.json', spec['artifact_record_sha256'])
        admitted, tensors, tensor_shapes = runtime.checked_evaluation_artifact(
            directory, plan, role, contract, cid, shapes)
        require(admitted['artifact'] == spec['artifact'] and admitted['contract'] == spec['contract'],
                'CONTROL_ROSTER_BINDING')
        if admitted['kind'] in ('lora', 'random-lora'):
            model = runtime.insert_lora(model, plan, role, torch)
            runtime.copy_tensor_material(runtime.adapter_tensors(model, contract['targets']),
                                         tensors, tensor_shapes, torch, device)
            _, actual, _ = runtime.wrap_adapter(model, contract, cid)
        elif admitted['kind'] == 'full-tune':
            target = runtime.backbone_tensors(model, shapes)
            runtime.copy_tensor_material(target, tensors, tensor_shapes, torch, device)
            actual = runtime.contract_module().H('llm-tensor-index-v1', runtime.contract_module().canonical(
                {name: runtime.tensor_descriptor(tensor) for name, tensor in target.items()})).hex()
        else:
            actual = contract['backbone']['index_root']
    require(actual == spec['artifact'] and cid == spec['contract'], 'ACTUAL_ARTIFACT_READBACK')
    return model, contract, cid, actual


def evaluation_child(args):
    profile, _ = read_pinned(args.profile, args.profile_sha256)
    validate_freeze(profile)
    inputs, _ = read_pinned(args.evaluation_input, profile['evaluation_input_sha256'])
    rows = evaluation_rows(inputs, profile)
    roster, _ = read_pinned(args.roster, args.roster_sha256)
    validate_roster(roster, profile, args.profile_sha256)
    require(args.role in PARTICIPANTS, 'EVALUATION_ROLE')
    plan, directory = profile['runtime'], Path(args.output)
    observer = runtime.Observer(directory, 'cpu')
    begin, cpu = time.monotonic_ns(), time.process_time_ns()
    report = dict(schema=CHILD, operation_id=profile['operation_id'], phase='evaluate', role=args.role,
        evaluation_profile_sha256=args.profile_sha256, roster_sha256=args.roster_sha256,
        evaluation_input_sha256=profile['evaluation_input_sha256'], source_pins=profile['source_pins'],
        authority=AUTHORITY.copy(), outcome='failed')
    try:
        manifest, _ = observer.stage('material-verification', lambda: runtime.verify_materials(args.materials))
        require(runtime.identity(manifest) == plan['snapshot'], 'MATERIALS_CHANGED')
        imports = observer.stage('runtime-import', lambda: runtime.runtime_import(plan))
        torch, device = imports[:2]
        model, tokenizer, shapes, _ = observer.stage('model-load',
            lambda: runtime.load_model(args.materials, plan, imports))
        contract, raw, cid = observer.stage('complete-base-contract',
            lambda: runtime.make_contract(model, tokenizer, shapes, args.materials, manifest, plan))
        model, contract, cid, actual = observer.stage('artifact-material-readback',
            lambda: load_evaluation_artifact(model, contract, raw, cid, shapes, plan,
                roster['artifacts'][args.role], args.role, torch, device))
        predictions = observer.stage('real-forward-greedy-decode', lambda: [runtime.decode(
            model, tokenizer, row, contract, cid, plan, torch, device, actual, args.role) for row in rows])
        runtime.save(directory / 'predictions.json', predictions)
        report.update(outcome='success', artifact=actual, contract=cid, actual_backend='cpu',
            actual_threads=torch.get_num_threads(), forward_executed=True, requests=len(predictions),
            predictions_sha256=runtime.file_sha(directory / 'predictions.json'),
            environment={name: importlib.metadata.version(name) for name in
                         ('torch', 'transformers', 'peft', 'safetensors', 'tokenizers', 'numpy', 'accelerate')})
    except BaseException as error:
        report['error_type'] = type(error).__name__
        raise
    finally:
        report.update(cost_events=observer.events, process_wall_ns=time.monotonic_ns() - begin,
            process_cpu_ns=time.process_time_ns() - cpu,
            process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)
        runtime.save(directory / 'actual-receipt.json', report)


def numerical_assessment(profile, rows, observations):
    validate_freeze(profile, current_sources=False)
    require(type(observations) is dict and set(observations) == set(PARTICIPANTS) and
            all(value.get('status') == 'SUCCESS' for value in observations.values()), 'COMPLETE_EVALUATION_REQUIRED')
    targets = {row['id']: row['target_output_sha256'] for row in rows}
    require(len(targets) == profile['evaluation']['rows'], 'EVALUATION_ROW_SET')
    correct = {}
    for role, observation in observations.items():
        outputs = observation.get('outputs')
        require(type(outputs) is dict and set(outputs) == set(targets), 'EVALUATION_OUTPUT_SET')
        for value in outputs.values():
            operation.digest(value)
        correct[role] = sum(outputs[key] == target for key, target in targets.items())
    strongest = max(correct[role] for role in runtime.CONTROLS)
    gain_parent, gain_control = (correct['candidate'] - correct['retained-parent'],
                                 correct['candidate'] - strongest)
    candidate = min(gain_parent, gain_control) >= profile['evaluation']['min_correct_gain']
    return dict(numerical_disposition='Candidate' if candidate else 'NoUpdate',
        rows=len(targets), correct=correct, strongest_control_correct=strongest,
        gain_correct_vs_retained_parent=gain_parent, gain_correct_vs_strongest_control=gain_control,
        min_correct_gain=profile['evaluation']['min_correct_gain'],
        retained_parent=None if candidate else profile['parent'],
        numerical_gate_passed=candidate, native_iteration_completed=False,
        all_required_controls_executed=True, equal_training_caps=True, equal_inference_caps=True,
        independent_custody_verified=False, improvement_bonus_authorized=False,
        base_service_fee_authorized=False, consensus_credit_authorized=False, authority=AUTHORITY.copy())


def evaluate_all(profile, context, directory, training, evaluation_input, *, dispatch):
    require(training['status'] == 'TRAINED', 'COMPLETE_TRAINING_REQUIRED')
    input_path = directory / 'held-out-input.json'
    if dispatch:
        inputs, raw = read_pinned(evaluation_input, profile['evaluation_input_sha256'])
        rows = evaluation_rows(inputs, profile)
        publish(input_path, raw)
    else:
        inputs, _ = read_pinned(input_path, profile['evaluation_input_sha256'])
        rows = evaluation_rows(inputs, profile)
    roster_path = directory / 'artifact-roster.json'
    stages = child_journal(context, directory, create=False)
    observations = {}
    try:
        for role in PARTICIPANTS:
            name, intent, request = stage_request(context, directory, 'evaluate', role,
                roster=str(roster_path), roster_sha256=training['artifact_roster_sha256'],
                evaluation_input=str(input_path))
            command = [sys.executable, str(Path(__file__).resolve()), '_child',
                '--profile', str(directory / 'evaluation-profile.json'),
                '--profile-sha256', context['evaluation_profile_sha256'],
                '--evaluation-input', str(input_path), '--roster', str(roster_path),
                '--roster-sha256', training['artifact_roster_sha256'], '--role', role,
                '--materials', context['materials'], '--output', request['directory']]
            callback = (lambda command=command, request=request: runtime.supervise(command,
                request['directory'], profile['runtime']['inference_budget'])) if dispatch else None
            observations[role] = stage_once(stages, name, intent, request, profile, callback)
            if observations[role]['status'] != 'SUCCESS':
                return dict(schema=RESULT, status=observations[role]['status'], numerical_disposition=None,
                    operation_id=profile['operation_id'], evaluation_profile_sha256=context['evaluation_profile_sha256'],
                    training=training, evaluation=observations, authority=AUTHORITY.copy())
    finally:
        stages.close()
    result = dict(schema=RESULT, status='COMPLETE', operation_id=profile['operation_id'],
        evaluation_profile_sha256=context['evaluation_profile_sha256'],
        artifact_roster_sha256=training['artifact_roster_sha256'], training=training,
        evaluation=observations, complete_economic_cost=False,
        **numerical_assessment(profile, rows, observations))
    if dispatch:
        publish_json(directory / 'result.json', result)
    else:
        require(operation.decode(operation.snapshot(directory / 'result.json')) == result, 'FINAL_RESULT_CHANGED')
    return result


def run_trial(args):
    train = args.action in ('train', 'run')
    profile, context, directory = prepare_context(args, create=train)
    journal = operation.Journal(args.journal, args.authority_id)
    try:
        training = train_all(journal, profile, context, directory, dispatch=train)
        if training['status'] != 'TRAINED' or args.action == 'train':
            return dict(schema=RESULT, operation_id=profile['operation_id'],
                evaluation_profile_sha256=context['evaluation_profile_sha256'],
                **training, authority=AUTHORITY.copy())
        if args.action == 'query' and not (directory / 'held-out-input.json').exists():
            return dict(schema=RESULT, operation_id=profile['operation_id'],
                evaluation_profile_sha256=context['evaluation_profile_sha256'],
                **training, authority=AUTHORITY.copy())
        return evaluate_all(profile, context, directory, training, getattr(args, 'evaluation_input', None),
                            dispatch=args.action != 'query')
    finally:
        journal.close()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    freeze = commands.add_parser('freeze')
    for name in ('materials', 'parent', 'parent-sha256', 'training-input', 'training-input-sha256',
                 'evaluation-input-sha256', 'operation-id', 'output'):
        freeze.add_argument('--' + name, required=True)
    freeze.add_argument('--evaluation-rows', type=int, required=True)
    freeze.add_argument('--min-correct-gain', type=int, default=1)
    freeze.add_argument('--threads', type=int, default=2)
    freeze.add_argument('--steps', type=int, default=10)
    for action in ('train', 'evaluate', 'run', 'query'):
        command = commands.add_parser(action)
        for name in ('profile', 'profile-sha256', 'materials', 'output', 'journal', 'authority-id', 'intent-sha256'):
            command.add_argument('--' + name, required=True)
        if action in ('train', 'run'):
            command.add_argument('--training-input', required=True)
        if action in ('evaluate', 'run'):
            command.add_argument('--evaluation-input', required=True)
    child = commands.add_parser('_child')
    for name in ('profile', 'profile-sha256', 'evaluation-input', 'roster', 'roster-sha256',
                 'role', 'materials', 'output'):
        child.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if args.action == '_child':
        evaluation_child(args)
        return 0
    result = create_profile(args) if args.action == 'freeze' else run_trial(args)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status') in (None, 'TRAINED', 'COMPLETE') else 2


if __name__ == '__main__':
    raise SystemExit(main())
