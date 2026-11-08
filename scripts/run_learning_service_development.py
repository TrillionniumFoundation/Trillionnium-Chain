#!/usr/bin/env python3
"""One auditable local-development training, evaluation and service-fee run.

Start requires a new output directory. It freezes the evaluation before training,
prepares a funded *development* native service contract, runs all actual model
participants, reads the original candidate operation and settles that same
service intent. Completed contracted training can earn the development base fee
even when evaluation fails; failure is never relabelled NoUpdate. Only a complete
numerical NoUpdate permits the supplied retained parent to answer the distinct
next input. Candidate selection/installation is left to the original owner.
Before that new input, a fresh native query must confirm the same paid contract
and no local revocation. This is an observation-time gate, not an atomic
revocation fence shared by the native and model owners.

Query invokes only the existing provider/evaluator/native query entry points.
It does not initialize an authority, resume training, settle, infer, or recreate
missing files. Every invocation, raw stdout/stderr and observed exit is retained.
An interrupted invocation remains uncertain until its original owners read it.

This driver does not attest original-owner installation, independent evaluation,
an independent customer, external custody, real-asset funding, or production
activation. Native fees are local-development units; bonuses and consensus
credit stay zero. The separate frozen backend supplies the model observations.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

import llm_frozen_evaluation as frozen
import llm_inherited_operation as operation
import llm_inherited_runtime as inherited
import llm_parent_material as material
import llm_runtime_pilot as runtime

SCHEMA = 'controlled-learning-service-development-run-v1'
NEXT_INTENT = 'controlled-learning-service-next-input-intent-v1'
MAX_BINARY = 512 * 1024**2
# Stable Linux UAPI, also used by the existing cell-host executable handoff.
# Some Python builds expose memfd_create but omit these fcntl names.
ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
GET_SEALS = getattr(fcntl, 'F_GET_SEALS', 1034)
EXECUTABLE_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008
SCOPE = dict(controlled_local_development=True, original_owner_installation_verified=False,
    independent_evaluation_accepted=False, independent_customer_verified=False,
    external_custody_verified=False, real_asset_funding_verified=False,
    production_activation=False, atomic_cross_owner_revocation_enforced=False,
    improvement_bonus=0, anti_sybil_consensus_credit=0)


def require(value, code):
    if not value:
        raise ValueError('LEARNING_DEVELOPMENT_' + code)


def document(path):
    return operation.decode(operation.snapshot(path))


def absolute(path, *, exists=True):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=exists) == path, 'CANONICAL_PATH')
    return path


@contextmanager
def pinned_native(path, expected):
    """Execute the exact SHA-pinned ELF snapshot, with Linux write seals."""
    operation.digest(expected)
    path = absolute(path)
    require(sys.platform.startswith('linux') and hasattr(os, 'memfd_create'), 'SEALED_ELF_UNAVAILABLE')
    source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    sealed = None
    try:
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_mode & 0o111 and
                0 < before.st_size <= MAX_BINARY, 'NATIVE_EXECUTABLE')
        sealed = os.memfd_create('learning-service-development', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        os.fchmod(sealed, 0o500)
        digest, count, prefix = hashlib.sha256(), 0, b''
        while block := os.read(source, 1024**2):
            count += len(block)
            require(count <= MAX_BINARY, 'NATIVE_BOUND')
            digest.update(block)
            if not prefix:
                prefix = block[:4]
            view = memoryview(block)
            while view:
                written = os.write(sealed, view)
                require(written > 0, 'NATIVE_COPY')
                view = view[written:]
        after = os.fstat(source)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        require(identity(before) == identity(after) and count == before.st_size and
                prefix == b'\x7fELF' and digest.hexdigest() == expected, 'NATIVE_PIN')
        fcntl.fcntl(sealed, ADD_SEALS, EXECUTABLE_SEALS)
        require(fcntl.fcntl(sealed, GET_SEALS) & EXECUTABLE_SEALS == EXECUTABLE_SEALS, 'NATIVE_SEALS')
        os.lseek(sealed, 0, os.SEEK_SET)
        yield '/proc/self/fd/' + str(sealed), (sealed,)
    finally:
        os.close(source)
        if sealed is not None:
            os.close(sealed)


def phase(logs, name, command, *, pass_fds=(), executable_pin=None):
    """Preserve original bytes and a dispatch intent before every process."""
    directory = logs / name
    directory.mkdir(mode=0o700)
    invocation = dict(schema=SCHEMA, phase=name, command=command, executable_sha256=executable_pin,
                      started_utc_ns=time.time_ns(), automatically_replayable=False)
    frozen.publish_json(directory / 'invocation.json', invocation)
    start = time.monotonic_ns()
    process = None
    try:
        with (directory / 'stdout.log').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, pass_fds=pass_fds)
            frozen.publish_json(directory / 'started.json', dict(pid=process.pid,
                started_utc_ns=invocation['started_utc_ns'], no_automatic_retry=True))
            code = process.wait()
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
    except BaseException as error:
        frozen.publish_json(directory / 'interrupted.json', dict(error_type=type(error).__name__,
            pid=None if process is None else process.pid,
            observed_exit_code=None if process is None else process.poll(),
            no_automatic_retry=True, original_owner_query_required=True))
        raise
    receipt = dict(schema=SCHEMA, phase=name, exit_code=code, pid=process.pid,
        observed_wall_ns=time.monotonic_ns() - start,
        stdout_sha256=runtime.file_sha(directory / 'stdout.log'),
        stderr_sha256=runtime.file_sha(directory / 'stderr.log'))
    data, parse_error = None, None
    try:
        data = operation.decode(material.read_regular(directory / 'stdout.log', frozen.MAX_DOCUMENT))
    except (ValueError, OSError) as error:
        parse_error = type(error).__name__
    receipt['stdout_json_error'] = parse_error
    frozen.publish_json(directory / 'exit.json', receipt)
    return dict(receipt=receipt, data=data, directory=str(directory))


def script(name):
    return str(Path(__file__).resolve().with_name(name))


def python_phase(logs, name, module, arguments):
    path = script(module)
    return phase(logs, name, [sys.executable, '-u', path, *arguments], executable_pin=runtime.file_sha(path))


def native_phase(logs, name, manifest, arguments, native_override=None):
    path = native_override or manifest['native_binary']['path']
    with pinned_native(path, manifest['native_binary']['sha256']) as (executable, descriptors):
        return phase(logs, name, [executable, *arguments], pass_fds=descriptors,
                     executable_pin=manifest['native_binary']['sha256'])


def successful(stage, schema, code):
    require(stage['receipt']['exit_code'] == 0 and type(stage['data']) is dict and
            stage['data'].get('schema') == schema, code)
    return stage['data']


def check_next_input(value, operation_id):
    frozen.closed(value, 'schema request_id prompt', 'NEXT_INPUT_FIELDS')
    require(value['schema'] == 'hepta-smollm-inference-input-v1', 'NEXT_INPUT_SCHEMA')
    operation.label(value['request_id'])
    require(value['request_id'] != operation_id and type(value['prompt']) is str and
            1 <= len(value['prompt'].encode()) <= 4096, 'DISTINCT_NEXT_INPUT')


def setup(args):
    output = absolute(args.output, exists=False)
    require(not output.exists(), 'NEW_OUTPUT_REQUIRED_USE_QUERY')
    absolute(output.parent)
    operation.label(args.operation_id)
    for name in ('parent_sha256', 'training_input_sha256', 'evaluation_input_sha256',
                 'next_input_sha256', 'native_bin_sha256'):
        operation.digest(getattr(args, name))
    if args.next_expected_output_sha256 is not None:
        operation.digest(args.next_expected_output_sha256)
    require(type(args.steps) is int and 1 <= args.steps <= 100 and
            type(args.threads) is int and 1 <= args.threads <= 4 and
            type(args.base_fee) is int and 1 <= args.base_fee <= 1_000_000, 'BOUNDS')
    output.mkdir(mode=0o700)
    operation.sync_directory(output.parent)
    (output / 'inputs').mkdir(mode=0o700)
    (output / 'logs').mkdir(mode=0o700)
    (output / 'trial').mkdir(mode=0o700)
    # Record the caller's concrete request even if a later preflight fails.
    frozen.publish_json(output / 'invocation.json', dict(schema=SCHEMA,
        arguments={key: value for key, value in vars(args).items()}, scope=SCOPE,
        driver_sha256=runtime.file_sha(__file__), created_utc_ns=time.time_ns()))
    inputs = {}
    values = {}
    for role, name in (('parent', 'parent'), ('training', 'training_input'),
                       ('evaluation', 'evaluation_input'), ('next', 'next_input')):
        source = absolute(getattr(args, name))
        expected = getattr(args, name + '_sha256')
        value, raw = frozen.read_pinned(source, expected)
        destination = output / 'inputs' / (role + '.json')
        frozen.publish(destination, raw)
        inputs[role] = dict(path=str(destination), sha256=expected, source=str(source))
        values[role] = value
    inherited.training_rows(values['training'])
    check_next_input(values['next'], args.operation_id)
    contract, _, _ = inherited.read_parent(values['parent'])
    runtime_source = runtime.file_sha(runtime.__file__)
    require(contract['numeric']['operator_contract'] == runtime.identity(dict(source=runtime_source,
                backend='cpu', matmul='highest-no-TF32-eager-attention')) and
            contract['tokenizer']['behavior_contract'] == runtime.identity(dict(source=runtime_source,
                special_token_decode='skip', cleanup=False, chat_template='apply-once-no-extra-bos')),
            'PARENT_RUNTIME_INCOMPATIBLE_NO_REBIND')
    require(type(values['evaluation']) is dict and type(values['evaluation'].get('records')) is list,
            'EVALUATION_INPUT')
    rows = len(values['evaluation']['records'])
    require(1 <= rows <= inherited.MAX_TASKS, 'EVALUATION_ROWS')
    materials = absolute(args.materials)
    # Validate the exact native executable before creating a funded dev task.
    with pinned_native(args.native_bin, args.native_bin_sha256):
        pass
    cpu_cap = (1800 * (args.threads + 1) * 10**9 if args.training_cpu_cap_ns is None
               else args.training_cpu_cap_ns)
    require(type(cpu_cap) is int and 1 <= cpu_cap <= 1 << 62 and
            type(args.parameter_byte_cap) is int and 1 <= args.parameter_byte_cap <= 16 * 1024**2,
            'CONTRACT_CAPS')
    manifest = dict(schema=SCHEMA, operation_id=args.operation_id, output=str(output),
        materials=str(materials), inputs=inputs, steps=args.steps, threads=args.threads,
        evaluation_rows=rows, min_correct_gain=args.min_correct_gain,
        next_expected_output_sha256=args.next_expected_output_sha256,
        native_binary=dict(path=str(absolute(args.native_bin)), sha256=args.native_bin_sha256),
        base_fee=args.base_fee, training_cpu_cap_ns=cpu_cap, parameter_byte_cap=args.parameter_byte_cap,
        scope=SCOPE, source_pins=dict(frozen.sources(), development_driver=runtime.file_sha(__file__)))
    frozen.publish_json(output / 'manifest.json', manifest)
    return output, manifest


def service_request(manifest, authority, profile_sha256):
    return dict(schema='native-learning-service-request-v1', provider_authority_id=authority,
        operation_id=manifest['operation_id'], output_directory=str(Path(manifest['output']) / 'trial/candidate'),
        base_fee=manifest['base_fee'], training_cpu_cap_ns=manifest['training_cpu_cap_ns'],
        parameter_byte_cap=manifest['parameter_byte_cap'], evaluation_protocol_sha256=profile_sha256)


def verify_native(value, manifest, binding, *, prepared=False):
    require(type(value) is dict and value.get('schema') == 'native-learning-service-round-v1', 'NATIVE_RESULT')
    for key, expected in dict(operation_id=manifest['operation_id'],
            provider_authority_id=binding['authority_id'], plan_sha256=binding['plan_sha256'],
            evaluation_profile_sha256=binding['evaluation_profile_sha256']).items():
        require(value.get(key) == expected, 'NATIVE_BINDING')
    operation.digest(value.get('intent_sha256'))
    if 'intent_sha256' in binding:
        require(value['intent_sha256'] == binding['intent_sha256'], 'NATIVE_INTENT_CHANGED')
    if prepared:
        require(value.get('status') == 'PREPARED' and value.get('dispatch_allowed') is True, 'NATIVE_PREPARE')
    else:
        require(value.get('dispatch_allowed') is False, 'NATIVE_QUERY_DISPATCH')
    require(value.get('improvement_bonus') == 0 and value.get('anti_sybil_consensus_credit') == 0 and
            value.get('production_activation') is False, 'NATIVE_SCOPE')


def provider_query(logs, name, output, binding, *, next_input=False):
    identity = document(output / 'next-intent.json') if next_input else binding
    return python_phase(logs, name, 'llm_inherited_operation.py', ['query',
        '--journal', str(output / 'provider.sqlite3'), '--authority-id', binding['authority_id'],
        '--intent-sha256', identity['intent_sha256'], '--operation-id', identity['operation_id']])


def frozen_arguments(output, manifest, binding, action):
    result = [action, '--profile', str(output / 'evaluation-profile.json'),
        '--profile-sha256', binding['evaluation_profile_sha256'], '--materials', manifest['materials'],
        '--output', str(output / 'trial'), '--journal', str(output / 'provider.sqlite3'),
        '--authority-id', binding['authority_id'], '--intent-sha256', binding['intent_sha256']]
    if action == 'run':
        result += ['--training-input', manifest['inputs']['training']['path'],
                   '--evaluation-input', manifest['inputs']['evaluation']['path']]
    return result


def numerical_no_update(value, manifest, binding):
    return (type(value) is dict and value.get('schema') == frozen.RESULT and value.get('status') == 'COMPLETE'
            and value.get('operation_id') == manifest['operation_id']
            and value.get('evaluation_profile_sha256') == binding['evaluation_profile_sha256']
            and value.get('numerical_disposition') == 'NoUpdate' and value.get('numerical_gate_passed') is False
            and value.get('all_required_controls_executed') is True
            and value.get('retained_parent') == document(Path(manifest['inputs']['parent']['path']))
            and type(value.get('authority')) is dict and set(value['authority']) == set(frozen.AUTHORITY)
            and all(flag is False for flag in value['authority'].values()))


def evaluation_result(stage, manifest, binding):
    value = stage['data']
    if not isinstance(value, dict):
        return None
    if not (value.get('schema') == frozen.RESULT and value.get('operation_id') == manifest['operation_id']
            and value.get('evaluation_profile_sha256') == binding['evaluation_profile_sha256']):
        return dict(schema=frozen.RESULT, status='EVALUATION_RESPONSE_BINDING_FAILED',
            operation_id=manifest['operation_id'], evaluation_profile_sha256=binding['evaluation_profile_sha256'],
            numerical_disposition=None, original_response=value)
    if value.get('status') == 'COMPLETE' and stage['receipt']['exit_code'] != 0:
        return dict(schema=frozen.RESULT, status='COMPLETE_RESPONSE_WITH_UNCONFIRMED_EXIT',
            operation_id=manifest['operation_id'], evaluation_profile_sha256=binding['evaluation_profile_sha256'],
            numerical_disposition=None, original_response=value)
    return value


def next_dispatch_gate(stage, manifest, binding):
    """A fresh native observation is necessary; no cross-owner atomicity claim."""
    reason = None
    value = None if not isinstance(stage, dict) else stage.get('data')
    if (not isinstance(stage, dict) or stage.get('receipt', {}).get('exit_code') != 0
            or not isinstance(value, dict)):
        reason = 'NATIVE_QUERY_UNCONFIRMED'
    else:
        try:
            verify_native(value, manifest, binding)
        except (ValueError, KeyError, TypeError):
            reason = 'NATIVE_QUERY_BINDING_FAILED'
        if reason is None:
            if value.get('locally_revoked') is True:
                reason = 'LOCALLY_REVOKED'
            elif value.get('locally_revoked') is not False:
                reason = 'LOCAL_REVOCATION_UNCONFIRMED'
            elif (value.get('status') != 'PAID_CURRENT_BRANCH' or
                    type(value.get('current_branch_base_fee')) is not int or
                    value['current_branch_base_fee'] != manifest['base_fee'] or
                    value.get('base_fee_contract') != manifest['base_fee']):
                reason = 'PAYMENT_NOT_CURRENT'
    return dict(allowed=reason is None, blocked_reason=reason,
        scope='fresh-local-native-observation-not-atomic-cross-owner-revocation',
        native_query_exit=None if not isinstance(stage, dict) else stage.get('receipt'))


def next_identity(manifest, binding):
    next_input = document(Path(manifest['inputs']['next']['path']))
    payload = dict(schema=NEXT_INTENT, source_operation_id=manifest['operation_id'],
        source_intent_sha256=binding['intent_sha256'], operation_id=next_input['request_id'],
        input_sha256=manifest['inputs']['next']['sha256'],
        retained_parent_sha256=manifest['inputs']['parent']['sha256'])
    return dict(payload, intent_sha256=runtime.identity(payload))


def next_arguments(output, manifest, binding, identity):
    return ['infer', '--journal', str(output / 'provider.sqlite3'),
        '--authority-id', binding['authority_id'], '--intent-sha256', identity['intent_sha256'],
        '--operation-id', identity['operation_id'], '--materials', manifest['materials'],
        '--output', str(output / 'next-input'), '--input', manifest['inputs']['next']['path'],
        '--input-sha256', manifest['inputs']['next']['sha256'], '--parent', manifest['inputs']['parent']['path'],
        '--parent-sha256', manifest['inputs']['parent']['sha256'],
        '--evaluation-freeze', str(output / 'evaluation-profile.json'),
        '--evaluation-profile-sha256', binding['evaluation_profile_sha256'],
        '--source-operation-id', manifest['operation_id'], '--source-intent-sha256', binding['intent_sha256'],
        '--threads', str(manifest['threads']), '--steps', str(manifest['steps'])]


def next_observation(output, manifest, binding, value):
    if type(value) is not dict:
        return dict(status=None, expected_output_match=None, owner_readback=value)
    identity = document(output / 'next-intent.json')
    require(identity == next_identity(manifest, binding), 'NEXT_SOURCE_INTENT_CHANGED')
    for key, expected in dict(schema=operation.OBSERVATION, authority_id=binding['authority_id'],
            operation_id=identity['operation_id'], intent_sha256=identity['intent_sha256'],
            evaluation_profile_sha256=binding['evaluation_profile_sha256'],
            original_output=str(output / 'next-input'), dispatch_allowed=False,
            reservation='RETAINED', no_update_decided=False, payment_authorized=False).items():
        require(value.get(key) == expected and
                (not isinstance(expected, bool) or value.get(key) is expected), 'NEXT_READBACK_BINDING')
    require(type(value.get('authority')) is dict and set(value['authority']) == set(frozen.AUTHORITY)
            and all(flag is False for flag in value['authority'].values()), 'NEXT_READBACK_AUTHORITY')
    require(value.get('status') in ('SUCCESS', 'FAILED', 'UNKNOWN'), 'NEXT_READBACK_STATUS')
    if value['status'] != 'SUCCESS':
        return dict(status=value['status'], expected_output_match=None, owner_readback=value)
    plan_raw = operation.snapshot(output / 'next-input/execution-plan.json')
    require(hashlib.sha256(plan_raw).hexdigest() == value['plan_sha256'] ==
            value['observation']['pins']['execution-plan.json']['sha256'], 'NEXT_PLAN_CHANGED')
    plan = operation.decode(plan_raw)
    parent = document(Path(manifest['inputs']['parent']['path']))
    require(plan.get('schema') == inherited.SCHEMA and plan.get('phase') == 'infer'
            and plan.get('operation_id') == identity['operation_id'] and plan.get('parent') == parent
            and type(plan.get('generation')) is int and plan['generation'] == parent['generation']
            and plan.get('inputs_sha256') == manifest['inputs']['next']['sha256']
            and plan.get('inputs') == document(Path(manifest['inputs']['next']['path']))
            and value['observation'].get('artifact') == parent['adapter'], 'NEXT_SOURCE_PLAN_BINDING')
    raw = operation.snapshot(output / 'next-input/worker/prediction.json')
    require(hashlib.sha256(raw).hexdigest() == value['observation']['pins']['worker/prediction.json']['sha256'],
            'NEXT_OUTPUT_CHANGED')
    prediction = operation.decode(raw)
    require(prediction.get('artifact') == parent['adapter'] and
            prediction.get('task') == runtime.identity(plan['inputs']), 'NEXT_PREDICTION_BINDING')
    expected = manifest['next_expected_output_sha256']
    return dict(status='SUCCESS', output_sha256=prediction['output_sha256'],
        decoded_outputs=prediction['response']['decoded_outputs'],
        expected_output_sha256=expected,
        expected_output_match=None if expected is None else prediction['output_sha256'] == expected,
        owner_readback=value)


def summary(manifest, binding, evaluation, candidate, settlement, next_use, stages):
    no_update = numerical_no_update(evaluation, manifest, binding)
    paid = type(settlement) is dict and settlement.get('status') == 'PAID_CURRENT_BRANCH'
    next_ok = type(next_use) is dict and next_use.get('status') == 'SUCCESS'
    if no_update:
        checked = next_ok and next_use.get('expected_output_match') is True
        status = ('COMPLETED_DEVELOPMENT_NO_UPDATE' if paid and checked else
                  'NO_UPDATE_WITH_INCOMPLETE_DEVELOPMENT_EFFECTS')
        if next_ok and next_use.get('expected_output_match') is False:
            status = 'NO_UPDATE_NEXT_INPUT_OUTPUT_MISMATCH'
        elif next_ok and next_use.get('expected_output_match') is None:
            status = 'NO_UPDATE_NEXT_INPUT_UNCHECKED'
    elif isinstance(evaluation, dict) and evaluation.get('status') == 'COMPLETE' and \
            evaluation.get('numerical_disposition') == 'Candidate':
        status = 'CANDIDATE_PENDING_ORIGINAL_OWNER_SELECTION'
    elif isinstance(candidate, dict) and candidate.get('status') == 'SUCCESS':
        status = 'TRAINING_SERVICE_COMPLETED_EVALUATION_INCOMPLETE'
    else:
        status = 'INCOMPLETE_OR_UNKNOWN'
    return dict(schema=SCHEMA, status=status, scope=SCOPE, operation_id=manifest['operation_id'],
        evaluation_profile_sha256=binding['evaluation_profile_sha256'], intent_sha256=binding['intent_sha256'],
        native_iteration_completed=False, numerical_no_update_completed=no_update,
        candidate_operation=candidate, evaluation=evaluation, development_settlement=settlement,
        next_input=next_use, stages=stages, complete_economic_cost=False,
        candidate_selected=False, candidate_installed=False,
        no_automatic_retry=True, original_owner_query_required_for_unknown=True)


def start(args):
    output, manifest = setup(args)
    logs, inputs = output / 'logs', manifest['inputs']
    stages = {}
    try:
        stages['freeze'] = python_phase(logs, '01-freeze', 'llm_frozen_evaluation.py', [
            'freeze', '--materials', manifest['materials'], '--parent', inputs['parent']['path'],
            '--parent-sha256', inputs['parent']['sha256'], '--training-input', inputs['training']['path'],
            '--training-input-sha256', inputs['training']['sha256'],
            '--evaluation-input-sha256', inputs['evaluation']['sha256'],
            '--evaluation-rows', str(manifest['evaluation_rows']), '--operation-id', manifest['operation_id'],
            '--output', str(output / 'evaluation-profile.json'), '--threads', str(manifest['threads']),
            '--steps', str(manifest['steps']), '--min-correct-gain', str(manifest['min_correct_gain'])])
        freeze = successful(stages['freeze'], frozen.PROFILE, 'FREEZE_FAILED')
        profile = document(output / 'evaluation-profile.json')
        frozen.evaluation_rows(document(Path(inputs['evaluation']['path'])), profile)
        stages['journal'] = python_phase(logs, '02-provider-authority', 'llm_inherited_operation.py',
                                         ['init', '--journal', str(output / 'provider.sqlite3')])
        authority = successful(stages['journal'], operation.SCHEMA, 'AUTHORITY_FAILED')
        plan = inherited.prepare_plan(SimpleNamespace(command='train', operation_id=manifest['operation_id'],
            materials=manifest['materials'], output=str(output / 'trial/candidate'),
            input=inputs['training']['path'], input_sha256=inputs['training']['sha256'],
            parent=inputs['parent']['path'], parent_sha256=inputs['parent']['sha256'], bootstrap=False,
            threads=manifest['threads'], steps=manifest['steps']))
        require(plan['runtime'] == profile['runtime'] and plan['parent'] == profile['parent'], 'EXACT_CANDIDATE_PLAN')
        frozen.publish_json(output / 'candidate-plan.json', plan)
        binding = dict(operation_id=manifest['operation_id'], authority_id=authority['authority_id'],
            plan_sha256=runtime.file_sha(output / 'candidate-plan.json'),
            evaluation_profile_sha256=freeze['evaluation_profile_sha256'])
        request = service_request(manifest, binding['authority_id'], binding['evaluation_profile_sha256'])
        frozen.publish_json(output / 'service-request.json', request)
        stages['prepare'] = native_phase(logs, '03-native-prepare', manifest,
            ['prepare', str(output / 'native-service'), str(output / 'service-request.json'),
             str(output / 'candidate-plan.json')])
        prepared = successful(stages['prepare'], 'native-learning-service-round-v1', 'NATIVE_PREPARE_FAILED')
        verify_native(prepared, manifest, binding, prepared=True)
        binding['intent_sha256'] = prepared['intent_sha256']
        frozen.publish_json(output / 'binding.json', binding)
        # The native request needs an existing output parent. Fill the exact
        # frozen backend context only after its original intent is known.
        context = dict(schema=frozen.RUN, operation_id=manifest['operation_id'],
            evaluation_profile_sha256=binding['evaluation_profile_sha256'],
            original_authority_id=binding['authority_id'], original_intent_sha256=binding['intent_sha256'],
            materials=manifest['materials'], output=str(output / 'trial'))
        frozen.publish_json(output / 'trial/context.json', context)
        identity = next_identity(manifest, binding)
        frozen.publish_json(output / 'next-intent.json', identity)
        stages['evaluation'] = python_phase(logs, '04-model-trial', 'llm_frozen_evaluation.py',
                                            frozen_arguments(output, manifest, binding, 'run'))
        evaluation = evaluation_result(stages['evaluation'], manifest, binding)
        # Training-service payment is read independently of evaluation success.
        stages['candidate_query'] = provider_query(logs, '05-candidate-query', output, binding)
        candidate = stages['candidate_query']['data']
        settlement = None
        if isinstance(candidate, dict) and candidate.get('schema') == operation.OBSERVATION:
            require(candidate.get('intent_sha256') == binding['intent_sha256'] and
                    candidate.get('plan_sha256') == binding['plan_sha256'], 'CANDIDATE_CONTRACT_BINDING')
            frozen.publish_json(output / 'candidate-readback.json', candidate)
            stages['settle'] = native_phase(logs, '06-native-settle', manifest,
                ['settle', str(output / 'native-service'), str(output / 'candidate-readback.json')])
            settlement = stages['settle']['data']
            if isinstance(settlement, dict):
                verify_native(settlement, manifest, binding)
        stages['native_query'] = native_phase(logs, '07-native-query', manifest,
                                               ['query', str(output / 'native-service')])
        gate = next_dispatch_gate(stages['native_query'], manifest, binding)
        settlement = stages['native_query']['data']
        if gate['blocked_reason'] in ('NATIVE_QUERY_UNCONFIRMED', 'NATIVE_QUERY_BINDING_FAILED'):
            settlement = None
        next_use = None
        if numerical_no_update(evaluation, manifest, binding):
            if gate['allowed']:
                stages['next_input'] = python_phase(logs, '08-retained-parent-next-input',
                    'llm_inherited_operation.py', next_arguments(output, manifest, binding, identity))
                stages['next_query'] = provider_query(logs, '09-next-input-query', output, binding, next_input=True)
                next_use = next_observation(output, manifest, binding, stages['next_query']['data'])
                next_use['dispatch_gate'] = gate
            else:
                next_use = dict(status='BLOCKED', blocked_reason=gate['blocked_reason'],
                                dispatch_gate=gate, new_operation_started=False)
        result = summary(manifest, binding, evaluation, candidate, settlement, next_use, stages)
        frozen.publish_json(output / 'result.json', result)
        return result
    except BaseException as error:
        frozen.publish_json(output / 'interrupted.json', dict(schema=SCHEMA, error_type=type(error).__name__,
            error=str(error)[:512], stages=stages, no_automatic_retry=True, scope=SCOPE))
        raise


def query(args):
    output = absolute(args.output)
    operation.private_directory(output)
    if not (output / 'manifest.json').is_file() or not (output / 'binding.json').is_file():
        return dict(schema=SCHEMA, status='INCOMPLETE_SETUP_QUERY_ORIGINAL_STAGE_FILES',
                    output=str(output), no_automatic_retry=True, scope=SCOPE)
    manifest, binding = document(output / 'manifest.json'), document(output / 'binding.json')
    require(manifest.get('schema') == SCHEMA and manifest.get('output') == str(output), 'MANIFEST')
    if args.native_bin_sha256 is not None:
        require(args.native_bin_sha256 == manifest['native_binary']['sha256'], 'QUERY_NATIVE_PIN_CHANGED')
    (output / 'queries').mkdir(mode=0o700, exist_ok=True)
    logs = output / 'queries' / (str(time.time_ns()) + '-' + uuid.uuid4().hex[:8])
    logs.mkdir(mode=0o700)
    stages = {}
    stages['candidate_query'] = provider_query(logs, '01-candidate-query', output, binding)
    candidate = stages['candidate_query']['data']
    stages['evaluation_query'] = python_phase(logs, '02-evaluation-query', 'llm_frozen_evaluation.py',
                                              frozen_arguments(output, manifest, binding, 'query'))
    evaluation = evaluation_result(stages['evaluation_query'], manifest, binding)
    stages['native_query'] = native_phase(logs, '03-native-query', manifest,
        ['query', str(output / 'native-service')], args.native_bin)
    settlement = stages['native_query']['data']
    if isinstance(settlement, dict):
        verify_native(settlement, manifest, binding)
    next_use = None
    if (output / 'logs/08-retained-parent-next-input/invocation.json').is_file():
        stages['next_query'] = provider_query(logs, '04-next-input-query', output, binding, next_input=True)
        next_use = next_observation(output, manifest, binding, stages['next_query']['data'])
    elif numerical_no_update(evaluation, manifest, binding):
        gate = next_dispatch_gate(stages['native_query'], manifest, binding)
        next_use = dict(status='NOT_STARTED', new_operation_started=False,
                        blocked_reason=gate['blocked_reason'] or 'QUERY_NEVER_DISPATCHES', dispatch_gate=gate)
    result = summary(manifest, binding, evaluation, candidate, settlement, next_use, stages)
    result['query_only'] = True
    frozen.publish_json(logs / 'result.json', result)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    run = commands.add_parser('run')
    for name in ('materials', 'parent', 'parent-sha256', 'training-input', 'training-input-sha256',
                 'evaluation-input', 'evaluation-input-sha256', 'next-input', 'next-input-sha256',
                 'native-bin', 'native-bin-sha256', 'output', 'operation-id'):
        run.add_argument('--' + name, required=True)
    run.add_argument('--steps', type=int, default=10)
    run.add_argument('--threads', type=int, default=2)
    run.add_argument('--min-correct-gain', type=int, default=1)
    run.add_argument('--base-fee', type=int, default=2000, help='local-development units only')
    run.add_argument('--training-cpu-cap-ns', type=int)
    run.add_argument('--parameter-byte-cap', type=int, default=16 * 1024**2)
    run.add_argument('--next-expected-output-sha256')
    inspect = commands.add_parser('query')
    inspect.add_argument('--output', required=True)
    inspect.add_argument('--native-bin', help='an identical SHA-pinned ELF may be supplied after relocation')
    inspect.add_argument('--native-bin-sha256')
    args = parser.parse_args()
    result = start(args) if args.action == 'run' else query(args)
    print(runtime.canonical(result).decode())
    return 0 if result.get('status') in ('COMPLETED_DEVELOPMENT_NO_UPDATE',
        'CANDIDATE_PENDING_ORIGINAL_OWNER_SELECTION') else 2


if __name__ == '__main__':
    raise SystemExit(main())
