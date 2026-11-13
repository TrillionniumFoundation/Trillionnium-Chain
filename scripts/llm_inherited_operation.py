#!/usr/bin/env python3
"""Once-only dispatch and readback for the existing inherited SmolLM executor.

The original owner must retain one authority ID, journal and intent for this
cooperative provider. A committed reservation is never dispatched again, even
after a crash before spawn. Query only reads the original supervisor and model
outputs; missing or uncertain observations remain UNKNOWN. This is not a payment
sender, installation owner, independent evaluator or external rollback witness.
Copying/rewinding the whole authority, or using another authority, is outside
this local guarantee. Neither SUCCESS nor FAILED releases an owner's resource
reservation or issues FinalUse. The original unfenced CLI remains available for
explicit research use and is not covered by this once-only contract.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys

import llm_inherited_runtime as inherited
import llm_runtime_pilot as runtime

SCHEMA = 'hepta-smollm-operation-journal-v1'
OBSERVATION = 'hepta-smollm-operation-readback-v1'
MAX_DOCUMENT = 2 * 1024**2
MAX_OPERATIONS = 64
MAX_DATABASE = 32 * 1024**2


def require(value, code):
    if not value:
        raise ValueError('INHERITED_OPERATION_' + code)


def digest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
            and value != '0' * 64, 'DIGEST')


def label(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value)
            is not None, 'ID')


def canonical(value):
    raw = runtime.canonical(value)
    require(len(raw) <= MAX_DOCUMENT, 'DOCUMENT_BOUND')
    return raw


def decode(raw):
    require(len(raw) <= MAX_DOCUMENT, 'DOCUMENT_BOUND')
    return json.loads(raw, object_pairs_hook=runtime.unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_JSON')))


def private_directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'DIRECTORY_PATH')
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'DIRECTORY_OWNER')
    return path


def private_file(path, maximum=MAX_DOCUMENT):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, 'FILE_PATH')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and not info.st_mode & 0o077 and 0 < info.st_size <= maximum, 'FILE_OWNER_BOUND')
        return fd
    except BaseException:
        os.close(fd)
        raise


def snapshot(path, maximum=MAX_DOCUMENT, *, durable=False):
    with os.fdopen(private_file(path, maximum), 'rb') as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'FILE_CHANGED')
        if durable:
            os.fsync(stream.fileno())
    return raw


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def initialize(path):
    path = Path(path)
    private_directory(path.parent)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    os.close(descriptor)
    authority = secrets.token_hex(32)
    try:
        with sqlite3.connect(path) as db:
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA max_page_count=8192')
            db.execute('CREATE TABLE authority (id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL, identity TEXT NOT NULL)')
            db.execute('INSERT INTO authority VALUES (1,?,?)', (SCHEMA, authority))
            db.execute('CREATE TABLE operations (operation TEXT PRIMARY KEY, intent TEXT UNIQUE NOT NULL, output TEXT UNIQUE NOT NULL, '
                       'request TEXT NOT NULL, plan TEXT NOT NULL, freeze TEXT NOT NULL, result TEXT)')
        sync_directory(path.parent)
    except BaseException:
        # Do not silently delete an uncertain authority or reuse its identity.
        raise
    return dict(schema=SCHEMA, authority_id=authority, journal=str(path))


class Journal:
    def __init__(self, path, authority):
        digest(authority)
        self.path = Path(path)
        private_directory(self.path.parent)
        with os.fdopen(private_file(self.path, MAX_DATABASE), 'rb'):
            pass
        for suffix in ('-journal', '-wal', '-shm'):
            side = Path(str(self.path) + suffix)
            require(not side.is_symlink(), 'SQLITE_SYMLINK')
        self.db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, timeout=5,
                                  isolation_level=None)
        self.db.execute('PRAGMA trusted_schema=OFF')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA max_page_count=8192')
        row = self.db.execute('SELECT schema, identity FROM authority WHERE id=1').fetchone()
        require(row == (SCHEMA, authority), 'AUTHORITY')
        self.authority = authority

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def lookup(self, operation, intent):
        label(operation); digest(intent)
        rows = self.db.execute('SELECT operation,intent,request,plan,freeze,result FROM operations '
                               'WHERE operation=? OR intent=? LIMIT 2', (operation, intent)).fetchall()
        if not rows:
            return None
        require(len(rows) == 1 and rows[0][:2] == (operation, intent), 'IDENTITY_REUSE')
        row = rows[0]
        return dict(operation=row[0], intent=row[1], request=decode(row[2]), plan=decode(row[3]),
                    freeze=decode(row[4]), result=decode(row[5]) if row[5] is not None else None)

    def reserve(self, operation, intent, request, plan, freeze):
        with self.transaction():
            previous = self.lookup(operation, intent)
            if previous is not None:
                require(previous['request'] == request, 'REQUEST_CHANGED')
                return False
            require(self.db.execute('SELECT count(*) FROM operations').fetchone()[0] < MAX_OPERATIONS,
                    'CAPACITY')
            require(self.db.execute('SELECT operation FROM operations WHERE output=?',
                                   (request['output'],)).fetchone() is None, 'OUTPUT_REUSE')
            self.db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,NULL)',
                            (operation, intent, request['output'], canonical(request).decode(), canonical(plan).decode(),
                             canonical(freeze).decode()))
        # FULL commits the reservation before any output directory or worker.
        sync_directory(self.path.parent)
        return True

    def complete(self, operation, intent, result):
        with self.transaction():
            previous = self.lookup(operation, intent)
            require(previous is not None, 'NOT_RESERVED')
            if previous['result'] is not None:
                require(previous['result'] == result, 'TERMINAL_CHANGED')
            else:
                self.db.execute('UPDATE operations SET result=? WHERE operation=?',
                                (canonical(result).decode(), operation))


def invocation(args):
    label(args.operation_id)
    for key in ('input_sha256', 'evaluation_profile_sha256'):
        digest(getattr(args, key))
    require(args.command in ('train', 'infer'), 'PHASE')
    request = {name: getattr(args, name) for name in
               ('command', 'operation_id', 'materials', 'output', 'input', 'input_sha256',
                'parent', 'parent_sha256', 'bootstrap', 'threads', 'steps',
                'evaluation_freeze', 'evaluation_profile_sha256')}
    request.update(source_operation_id=getattr(args, 'source_operation_id', None),
                   source_intent_sha256=getattr(args, 'source_intent_sha256', None))
    if args.command == 'infer':
        label(request['source_operation_id']); digest(request['source_intent_sha256'])
        require(request['source_operation_id'] != args.operation_id, 'NEXT_TASK_ID')
    else:
        require(request['source_operation_id'] is None and request['source_intent_sha256'] is None,
                'TRAINING_SOURCE_FIELDS')
    for name in ('materials', 'output', 'input', 'parent', 'evaluation_freeze'):
        if request[name] is not None:
            path = Path(request[name])
            require(path.is_absolute() and str(path) == str(path.resolve()), 'REQUEST_PATH')
            request[name] = str(path)
    if request['parent_sha256'] is not None:
        digest(request['parent_sha256'])
    require(type(args.bootstrap) is bool and type(args.threads) is int and type(args.steps) is int,
            'REQUEST_TYPES')
    canonical(request)
    return request


def evidence(record, *, durable=False):
    """Read original bounded files; no model, supervisor or subprocess is called."""
    directory = Path(record['request']['output'])
    if not directory.exists():
        return None
    private_directory(directory)
    pins = {}

    def read(name, maximum=MAX_DOCUMENT):
        path = directory / name
        raw = snapshot(path, maximum, durable=durable)
        pins[name] = dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        return raw

    try:
        plan_raw = read('execution-plan.json')
        plan = decode(plan_raw)
        require(plan == record['plan'], 'PLAN_CHANGED')
        supervisor = decode(read('supervisor.json'))
    except FileNotFoundError:
        return None
    require(type(supervisor) is dict and supervisor.get('outcome') in ('success', 'failed'),
            'SUPERVISOR')
    # Exit alone is insufficient: retain UNKNOWN until original owner cleanup is observed.
    if (supervisor.get('waited_child_reaped') is not True or
            supervisor.get('owned_child_reap_resolved') is not True or
            supervisor.get('waited_child_observation_error') is not None):
        return None
    require(type(supervisor.get('exit_code')) is int, 'EXIT')
    require(supervisor.get('budget') == plan['runtime'][
        'training_budget' if plan['phase'] == 'train' else 'inference_budget'], 'BUDGET_CHANGED')
    costs = {key: supervisor.get(key) for key in
             ('observed_wall_ns', 'child_cpu_ns', 'observer_cpu_ns', 'waited_child_peak_rss_bytes')}
    for value in costs.values():
        require(value is None or type(value) is int and 0 <= value < 2**63, 'COST')
    status = 'FAILED'
    artifact = None
    if supervisor['outcome'] == 'success':
        require(supervisor['exit_code'] == 0 and supervisor.get('stop_reason') is None, 'SUCCESS_EXIT')
        try:
            receipt = decode(read('worker/actual-receipt.json'))
        except FileNotFoundError:
            return None
        for key, expected in dict(schema=inherited.SCHEMA, operation_id=plan['operation_id'],
                phase=plan['phase'], generation=plan['generation'], parent=plan['parent'],
                input_sha256=plan['inputs_sha256'], plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
                source_pins=plan['source_pins'], outcome='success', authority=inherited.NO_AUTHORITY).items():
            require(receipt.get(key) == expected, 'RECEIPT_BINDING')
        if plan['parent'] is not None:
            require(receipt.get('actual_loaded_parent') == plan['parent']['adapter'], 'PARENT_LOAD')
        artifact = receipt.get('artifact'); digest(artifact)
        if plan['phase'] == 'train':
            parent_raw = read('worker/parent-material.json')
            parent = inherited.validate_parent(decode(parent_raw))
            require(parent['directory'] == str(directory / 'worker') and
                    parent['operation_id'] == plan['operation_id'] and
                    parent['generation'] == plan['generation'] and parent['adapter'] == artifact and
                    receipt.get('parent_material_sha256') == hashlib.sha256(parent_raw).hexdigest(),
                    'OUTPUT_PARENT')
            require(parent['contract'] == receipt.get('contract') and
                    (plan['parent'] is None or parent['contract'] == plan['parent']['contract']),
                    'OUTPUT_CONTRACT')
            captured = {name: read('worker/' + name, 16 * 1024**2) for name in
                        ('target-contract.json', 'wrapped-adapter.json', 'artifact.safetensors')}
            inherited.parent_material.verify_parent_bytes(captured['target-contract.json'],
                captured['wrapped-adapter.json'], captured['artifact.safetensors'],
                expected_contract=parent['contract'], expected_adapter=parent['adapter'],
                expected_file_sha256=parent['file_sha256'])
            require(parent['file_sha256'] == pins['worker/artifact.safetensors']['sha256'],
                    'OUTPUT_ARTIFACT_CHANGED')
        else:
            prediction = decode(read('worker/prediction.json'))
            require(receipt.get('forward_executed') is True and receipt.get('prediction') == prediction
                    and artifact == plan['parent']['adapter'], 'OUTPUT_FORWARD')
            runtime.verify_predictions([prediction], dict(plan['runtime'], tasks=[
                dict(id=runtime.identity(plan['inputs']), partition='evaluation')]),
                'installed-parent-input', artifact, plan['parent']['contract'])
        status = 'SUCCESS'
    else:
        require(supervisor['exit_code'] != 0 or supervisor.get('stop_reason') is not None,
                'FAILURE_EXIT')
    if durable:
        if (directory / 'worker').is_dir():
            sync_directory(directory / 'worker')
        sync_directory(directory)
    return dict(status=status, pins=pins, costs=costs, artifact=artifact)


def query(journal, operation, intent):
    record = journal.lookup(operation, intent)
    require(record is not None, 'NOT_RESERVED')
    freeze = record['freeze']
    require(type(freeze) is dict and set(freeze) == {'raw_utf8', 'sha256'} and
            hashlib.sha256(freeze['raw_utf8'].encode()).hexdigest() == freeze['sha256'] ==
            record['request']['evaluation_profile_sha256'], 'FROZEN_PROFILE_CHANGED')
    terminal = record['result']
    if terminal is None:
        terminal = evidence(record, durable=True)
        if terminal is not None:
            journal.complete(operation, intent, terminal)
    elif evidence(record) != terminal:
        raise ValueError('INHERITED_OPERATION_TERMINAL_EVIDENCE_CHANGED')
    return dict(schema=OBSERVATION, authority_id=journal.authority, operation_id=operation,
        intent_sha256=intent, status='UNKNOWN' if terminal is None else terminal['status'],
        evaluation_profile_sha256=freeze['sha256'],
        dispatch_allowed=False, reservation='RETAINED', original_output=record['request']['output'],
        plan_sha256=hashlib.sha256(canonical(record['plan']) + b'\n').hexdigest(),
        observation=terminal, no_update_decided=False, payment_authorized=False,
        authority=inherited.NO_AUTHORITY.copy())


def run_once(journal, intent, args):
    """Only the winner of the durable reservation can enter the real executor."""
    digest(intent)
    request = invocation(args)
    prior = journal.lookup(args.operation_id, intent)
    if prior is not None:
        require(prior['request'] == request, 'REQUEST_CHANGED')
        return query(journal, args.operation_id, intent)
    private_directory(Path(args.output).parent)
    require(not Path(args.output).exists(), 'OUTPUT_EXISTS')
    freeze_raw = snapshot(args.evaluation_freeze)
    require(hashlib.sha256(freeze_raw).hexdigest() == args.evaluation_profile_sha256,
            'FROZEN_PROFILE_IDENTITY')
    profile = decode(freeze_raw)
    require(type(profile) is dict and profile.get('schema') ==
            'hepta-smollm-frozen-evaluation-profile-v1', 'FROZEN_PROFILE_SCHEMA')
    # Import at the execution boundary, after module initialization: the
    # evaluator itself uses this journal. There is no permissive schema-only
    # fallback for a malformed or source-drifted freeze.
    from llm_frozen_evaluation import validate_freeze
    validate_freeze(profile)
    freeze = dict(raw_utf8=freeze_raw.decode('utf-8'), sha256=args.evaluation_profile_sha256)
    plan = inherited.prepare_plan(args)
    if plan['phase'] == 'train':
        require(profile.get('operation_id') == plan['operation_id'] and
                profile.get('parent') == plan['parent'] and
                profile.get('training_input_sha256') == plan['inputs_sha256'] and
                profile.get('runtime') == plan['runtime'], 'FROZEN_PROFILE_BINDING')
    else:
        source_op, source_intent = request['source_operation_id'], request['source_intent_sha256']
        source_result = query(journal, source_op, source_intent)
        source = journal.lookup(source_op, source_intent)
        require(source_result['status'] == 'SUCCESS' and source['plan']['phase'] == 'train'
                and source_result['evaluation_profile_sha256'] == args.evaluation_profile_sha256
                and profile.get('operation_id') == source_op, 'NEXT_TASK_SOURCE')
        produced_raw = snapshot(Path(source['request']['output']) / 'worker/parent-material.json')
        require(hashlib.sha256(produced_raw).hexdigest() ==
                source_result['observation']['pins']['worker/parent-material.json']['sha256'],
                'NEXT_TASK_SOURCE_CHANGED')
        produced = inherited.validate_parent(decode(produced_raw))
        # Transport may relocate identical verified material. Selection and
        # permission remain with the original owner; this only binds the bytes.
        identity = lambda value: {key: item for key, item in value.items() if key != 'directory'}
        allowed = [parent for parent in (source['plan']['parent'], produced) if parent is not None]
        require(any(identity(parent) == identity(plan['parent']) for parent in allowed),
                'NEXT_TASK_MODEL_LINEAGE')
    if journal.reserve(args.operation_id, intent, request, plan, freeze):
        # Any exception preserves the original pending reservation. The caller
        # can query exactly this operation; it must not invent a replacement ID.
        inherited.execute_plan(plan, args.materials, args.output)
    return query(journal, args.operation_id, intent)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    init = commands.add_parser('init'); init.add_argument('--journal', required=True)
    for name in ('query', 'train', 'infer'):
        command = commands.add_parser(name)
        for field in ('journal', 'authority-id', 'intent-sha256', 'operation-id'):
            command.add_argument('--' + field, required=True)
        if name != 'query':
            for field in ('materials', 'output', 'input', 'input-sha256',
                          'evaluation-freeze', 'evaluation-profile-sha256'):
                command.add_argument('--' + field, required=True)
            command.add_argument('--parent'); command.add_argument('--parent-sha256')
            command.add_argument('--bootstrap', action='store_true')
            command.add_argument('--threads', type=int, default=4)
            command.add_argument('--steps', type=int, default=10)
            command.add_argument('--source-operation-id')
            command.add_argument('--source-intent-sha256')
    args = parser.parse_args()
    if args.action == 'init':
        print(json.dumps(initialize(args.journal), sort_keys=True)); return 0
    journal = Journal(args.journal, args.authority_id)
    try:
        if args.action == 'query':
            result = query(journal, args.operation_id, args.intent_sha256)
        else:
            args.command = args.action
            result = run_once(journal, args.intent_sha256, args)
        print(json.dumps(result, sort_keys=True))
        return {'SUCCESS': 0, 'UNKNOWN': 2, 'FAILED': 3}[result['status']]
    finally:
        journal.close()


if __name__ == '__main__':
    raise SystemExit(main())
