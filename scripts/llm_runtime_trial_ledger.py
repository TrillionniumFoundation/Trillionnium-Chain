"""Durable trial spending for the existing, explicitly public local pilot.

This is an adapter around the pilot's one process owner, not an evaluator or a
global identity service. Cooperating processes must open the same pre-created
SQLite authority and pin its policy and last checkpoint. Copying an old database
and its old checkpoint, or choosing another authority, is outside this guarantee.
The public fixture is already exposed; an alpha allocation is not a p-value.
"""
from __future__ import annotations

from contextlib import contextmanager
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import time

import llm_runtime_pilot as runtime

SCHEMA = 'llm-runtime-family-trial-policy-v1'
SCOPE = 'cooperative-local-public-pilot-no-global-custody-or-qualification'
MAX_ATTEMPTS = 64
MAX_PAYLOAD = 256 * 1024
MAX_DATABASE_BYTES = 512 * 1024 * 1024
PHASES = ('loader-1thread', 'loader-reference',
          *('train-' + role for role in runtime.PARTICIPANTS),
          *('evaluate-' + role for role in runtime.PARTICIPANTS))
MAX_EVENTS = MAX_ATTEMPTS * (2 * len(PHASES) + 3)
POLICY_SQL = ('CREATE TABLE policy (singleton INTEGER PRIMARY KEY CHECK(singleton=1), '
              'value TEXT NOT NULL, identity TEXT NOT NULL)')
EVENTS_SQL = ('CREATE TABLE events (seq INTEGER PRIMARY KEY, trial TEXT NOT NULL, '
              'kind TEXT NOT NULL, payload TEXT NOT NULL, previous TEXT NOT NULL, root TEXT NOT NULL)')


def _require(condition, code):
    runtime.require(condition, 'TRIAL_' + code)


def _digest(value):
    _require(type(value) is str and len(value) == 64 and
             all(c in '0123456789abcdef' for c in value), 'DIGEST')
    return value


def _integer(value, minimum, maximum):
    _require(type(value) is int and minimum <= value <= maximum, 'INTEGER')


def _closed(value, keys):
    _require(type(value) is dict and set(value) == set(keys.split()), 'FIELDS')


def _payload(value):
    raw = runtime.canonical(value)
    _require(len(raw) <= MAX_PAYLOAD, 'PAYLOAD_BOUND')
    return raw.decode('ascii')


def _policy(policy):
    _closed(policy, 'schema scope authority_instance model_family max_attempts '
                    'family_alpha comparisons_per_attempt multiplicity')
    _require(policy['schema'] == SCHEMA and policy['scope'] == SCOPE and
             policy['model_family'] == runtime.MODEL and
             policy['multiplicity'] == 'bonferroni-allocation-only-no-significance-claim',
             'POLICY')
    _digest(policy['authority_instance'])
    _integer(policy['max_attempts'], 1, MAX_ATTEMPTS)
    _require(type(policy['family_alpha']) is list and len(policy['family_alpha']) == 2,
             'ALPHA')
    numerator, denominator = policy['family_alpha']
    _integer(numerator, 1, 10**9)
    _integer(denominator, numerator, 10**9)
    _require([Fraction(numerator, denominator).numerator,
              Fraction(numerator, denominator).denominator] == policy['family_alpha'],
             'ALPHA_CANONICAL')
    _require(type(policy['comparisons_per_attempt']) is int and
             policy['comparisons_per_attempt'] == len(runtime.CONTROLS), 'COMPARISONS')
    return policy


def _allocation(policy):
    value = Fraction(*policy['family_alpha']) / (
        policy['max_attempts'] * policy['comparisons_per_attempt'])
    return [value.numerator, value.denominator]


def _genesis(policy_id):
    return runtime.identity(dict(schema='llm-runtime-trial-genesis-v1', policy=policy_id))


def _event_root(seq, trial, kind, value, previous):
    return runtime.identity(dict(schema='llm-runtime-trial-event-v1', ordinal=seq,
                                 trial=trial, kind=kind, value=value, previous=previous))


def initialize(path, max_attempts, family_alpha=(1, 20)):
    """Explicit create-only bootstrap. Never called by run/open/recovery."""
    path = Path(path).absolute()
    _require(type(family_alpha) in (tuple, list) and len(family_alpha) == 2, 'ALPHA')
    for number in family_alpha:
        _integer(number, 1, 10**9)
    alpha = Fraction(*family_alpha)
    policy = _policy(dict(schema=SCHEMA, scope=SCOPE,
        authority_instance=hashlib.sha256(os.urandom(32)).hexdigest(),
        model_family=runtime.MODEL, max_attempts=max_attempts,
        family_alpha=[alpha.numerator, alpha.denominator],
        comparisons_per_attempt=len(runtime.CONTROLS),
        multiplicity='bonferroni-allocation-only-no-significance-claim'))
    policy_id = runtime.identity(policy)
    # A failed creation remains visible and cannot silently become a new budget.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    db = sqlite3.connect(str(path), timeout=2, isolation_level=None)
    try:
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=EXTRA')
        _require(db.execute('PRAGMA synchronous').fetchone() == (3,), 'SYNC_MODE')
        db.execute('BEGIN IMMEDIATE')
        db.execute(POLICY_SQL)
        db.execute(EVENTS_SQL)
        db.execute('INSERT INTO policy VALUES (1, ?, ?)', (_payload(policy), policy_id))
        db.execute('PRAGMA user_version=1')
        db.execute('COMMIT')
    finally:
        db.close()
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return dict(policy=policy, policy_id=policy_id, checkpoint=_genesis(policy_id),
                spent=0, scope=SCOPE)


class TrialLedger:
    """Serial durable debit, frozen roster and immutable terminal observations.

    There is deliberately no refund, reset, retry, automatic create or implicit
    pending-to-success transition. An uncertain COMMIT is not replayed. The
    caller can inspect the exact trial afterwards; it cannot rerun its effects.
    """

    def __init__(self, path, expected_policy):
        self.path = Path(path).absolute()
        self.expected_policy = _digest(expected_policy)

    @contextmanager
    def _transaction(self):
        before = self.path.lstat()  # Missing authority is a refusal, not bootstrap.
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'REGULAR_DATABASE')
        _require(0 < before.st_size <= MAX_DATABASE_BYTES, 'DATABASE_BOUND')
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                             timeout=2, isolation_level=None)
        try:
            after = self.path.lstat()
            _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                     'DATABASE_REPLACED')
            db.execute('PRAGMA synchronous=EXTRA')
            _require(db.execute('PRAGMA synchronous').fetchone() == (3,), 'SYNC_MODE')
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('BEGIN IMMEDIATE')
            policy, checkpoint, attempts, count = self._read(db)
            yield db, policy, checkpoint, attempts, count
            db.execute('COMMIT')
        except BaseException:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()

    def _read(self, db):
        _require(db.execute('PRAGMA user_version').fetchone() == (1,), 'SCHEMA')
        _require(db.execute("SELECT type, name, tbl_name, sql FROM sqlite_master "
                            "ORDER BY name").fetchall() == [
            ('table', 'events', 'events', EVENTS_SQL), ('table', 'policy', 'policy', POLICY_SQL)],
            'SCHEMA')
        _require(db.execute('PRAGMA journal_mode').fetchone() == ('delete',), 'JOURNAL_MODE')
        count = len(db.execute('SELECT seq FROM events ORDER BY seq LIMIT ?',
                               (MAX_EVENTS + 1,)).fetchall())
        _integer(count, 0, MAX_EVENTS)
        for table, column in (('policy', 'value'), ('events', 'payload')):
            # Identifiers above are constants. Bound bytes before fetching text.
            maximum = db.execute(f'SELECT max(length({column})) FROM {table}').fetchone()[0]
            _require(maximum is None or (type(maximum) is int and maximum <= MAX_PAYLOAD),
                     'PAYLOAD_BOUND')
        rows = db.execute('SELECT singleton, value, identity FROM policy').fetchall()
        _require(len(rows) == 1 and rows[0][0] == 1, 'POLICY_ROWS')
        raw, policy_id = rows[0][1:]
        _require(type(raw) is str and len(raw) <= MAX_PAYLOAD, 'POLICY_BOUND')
        policy = _policy(json.loads(raw, object_pairs_hook=runtime.unique))
        _require(_payload(policy) == raw and runtime.identity(policy) == policy_id ==
                 self.expected_policy, 'POLICY_BINDING')
        attempts, checkpoint = {}, _genesis(policy_id)
        for expected_seq, row in enumerate(db.execute(
                'SELECT seq, trial, kind, payload, previous, root FROM events ORDER BY seq'), 1):
            seq, trial, kind, raw, previous, root = row
            _digest(trial)
            _require(seq == expected_seq and previous == checkpoint and
                     type(raw) is str and len(raw) <= MAX_PAYLOAD, 'JOURNAL_LINK')
            value = json.loads(raw, object_pairs_hook=runtime.unique)
            _require(_payload(value) == raw and
                     _event_root(seq, trial, kind, value, previous) == root, 'JOURNAL_ROOT')
            self._apply(attempts, policy, trial, kind, value)
            checkpoint = root
        return policy, checkpoint, attempts, count

    @staticmethod
    def _apply(attempts, policy, trial, kind, value):
        if kind == 'reserve':
            _closed(value, 'plan plan_id related_identity host observed_at_ns alpha_per_comparison')
            _require(trial not in attempts and len(attempts) < policy['max_attempts'],
                     'ALLOWANCE_OR_REPLAY')
            plan = value['plan']
            _require(type(plan) is dict and plan.get('model') == policy['model_family'] and
                     runtime.identity(plan) == value['plan_id'], 'PLAN_BINDING')
            _require(all(type(value[k]) is str and 1 <= len(value[k]) <= 256
                         for k in ('related_identity', 'host')), 'OBSERVATION_METADATA')
            _integer(value['observed_at_ns'], 1, (1 << 63) - 1)
            _require(value['alpha_per_comparison'] == _allocation(policy), 'ALPHA_BINDING')
            attempts[trial] = dict(state='reserved', reservation=value, phases=[], receipts={},
                                   roster=None, terminal=None)
            return
        _require(trial in attempts, 'UNKNOWN_ATTEMPT')
        attempt = attempts[trial]
        _require(attempt['state'] in ('reserved', 'evaluating'), 'TERMINAL_IMMUTABLE')
        if kind == 'phase':
            _closed(value, 'name observation')
            n = len(attempt['phases'])
            _require(n < len(PHASES) and value['name'] == PHASES[n], 'PHASE_ORDER')
            _require(type(value['observation']) is dict and
                     value['observation'].get('outcome') in ('success', 'failed'), 'PHASE_OBSERVATION')
            _require(not attempt['phases'] or
                     attempt['phases'][-1]['observation']['outcome'] == 'success', 'FAILED_PREDECESSOR')
            _require(not attempt['phases'] or
                     attempt['phases'][-1]['name'] in attempt['receipts'], 'MISSING_CHILD_RECEIPT')
            _require((n < 7 and attempt['state'] == 'reserved') or
                     (n >= 7 and attempt['state'] == 'evaluating'), 'ROSTER_BEFORE_EVALUATION')
            attempt['phases'].append(value)
        elif kind == 'child-receipt':
            from llm_runtime_assessment import observe_phase
            _closed(value, 'name receipt')
            name = value['name']
            _require(attempt['phases'] and name == attempt['phases'][-1]['name'] and
                     name not in attempt['receipts'], 'CHILD_RECEIPT_ORDER')
            frozen = attempt['reservation']['plan']
            if name.startswith('loader-'):
                phase, role = 'loader', 'current-backbone'
            else:
                phase, role = name.split('-', 1)
            actual = dict(frozen, threads=1) if name == 'loader-1thread' else frozen
            observe_phase(actual, name, phase, role, attempt['phases'][-1]['observation'],
                          value['receipt'])
            if phase == 'evaluate':
                _require(value['receipt'].get('contract') == attempt['roster']['contract'] and
                         value['receipt'].get('artifact') == attempt['roster']['artifacts'][role],
                         'EVALUATED_ROSTER_BINDING')
            attempt['receipts'][name] = value['receipt']
        elif kind == 'freeze-roster':
            _closed(value, 'experiment contract artifacts frozen_before_evaluation scope')
            _require(attempt['state'] == 'reserved' and len(attempt['phases']) == 7 and
                     len(attempt['receipts']) == 7 and
                     all(v['observation']['outcome'] == 'success' for v in attempt['phases']),
                     'TRAINING_INCOMPLETE')
            _require(value['experiment'] == attempt['reservation']['plan_id'] and
                     value['frozen_before_evaluation'] is True and
                     value['scope'] == 'five-actual-local-artifacts-no-independent-authority',
                     'ROSTER_CONTEXT')
            _digest(value['contract'])
            _require(type(value['artifacts']) is dict and
                     set(value['artifacts']) == set(runtime.PARTICIPANTS) and
                     len(set(value['artifacts'].values())) == len(runtime.PARTICIPANTS), 'ROSTER_ARTIFACTS')
            for artifact in value['artifacts'].values():
                _digest(artifact)
            # The one-thread loader has a distinct plan-bound contract. It is
            # a loader control, not one of the five evaluated artifacts.
            _require(all(receipt.get('contract') == value['contract']
                         for name, receipt in attempt['receipts'].items() if name != 'loader-1thread') and
                     all(attempt['receipts']['train-' + role].get('artifact') == artifact
                         for role, artifact in value['artifacts'].items()), 'TRAINED_ROSTER_BINDING')
            attempt.update(state='evaluating', roster=value)
        elif kind == 'terminal':
            _closed(value, 'outcome record record_id')
            _require(value['outcome'] in ('aborted', 'complete-unqualified') and
                     type(value['record']) is dict and
                     runtime.identity(value['record']) == value['record_id'], 'TERMINAL_RECORD')
            record = value['record']
            _require(all(record.get(k) is False for k in runtime.QUALIFICATIONS) and
                     record.get('adoption') is False and record.get('reward') is False and
                     record.get('no_update') is False,
                     'TERMINAL_AUTHORITY')
            _require(record.get('experiment') == attempt['reservation']['plan_id'], 'TERMINAL_PLAN')
            expected_phases = [dict(name=p['name'], **p['observation']) for p in attempt['phases']]
            _require(record.get('phases') == expected_phases, 'TERMINAL_PHASES')
            if value['outcome'] == 'complete-unqualified':
                from llm_runtime_assessment import build_assessment
                _require(attempt['state'] == 'evaluating' and len(attempt['phases']) == len(PHASES) and
                         len(attempt['receipts']) == len(PHASES) and
                         all(p['observation']['outcome'] == 'success' for p in attempt['phases']) and
                         record.get('roster') == runtime.identity(attempt['roster']), 'TERMINAL_INCOMPLETE')
                checked = build_assessment(attempt['reservation']['plan'], attempt['roster'],
                                           record.get('scores'), expected_phases, attempt['receipts'])
                _require(runtime.canonical(record) == runtime.canonical(checked), 'TERMINAL_COST_BINDING')
            else:
                _require(record.get('outcome') == 'aborted', 'ABORT_OUTCOME')
            attempt.update(state=value['outcome'], terminal=value)
        else:
            raise ValueError('TRIAL_EVENT_KIND')

    def _append(self, db, policy, checkpoint, attempts, count, trial, kind, value):
        _require(count < MAX_EVENTS, 'CAPACITY')
        raw = _payload(value)
        self._apply(attempts, policy, trial, kind, value)
        root = _event_root(count + 1, trial, kind, value, checkpoint)
        db.execute('INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)',
                   (count + 1, trial, kind, raw, checkpoint, root))
        _require(db.execute('SELECT trial, kind, payload, previous, root FROM events WHERE seq=?',
                            (count + 1,)).fetchone() == (trial, kind, raw, checkpoint, root), 'WRITE_READBACK')
        return dict(schema='llm-runtime-trial-receipt-v1', scope=SCOPE,
                    policy=self.expected_policy, checkpoint=root, trial=trial,
                    spent=len(attempts), maximum=policy['max_attempts'],
                    state=attempts[trial]['state'], plan=attempts[trial]['reservation']['plan_id'],
                    alpha_per_comparison=_allocation(policy), statistical_acceptance=False)

    def reserve(self, plan, trial, expected_checkpoint, related_identity):
        runtime.validate_plan(plan)
        _digest(trial)
        _digest(expected_checkpoint)
        _require(plan.get('schema') == 'llm-runtime-registered-public-pilot-plan-v1' and
                 plan.get('trial_policy') == self.expected_policy and plan.get('trial_id') == trial,
                 'REGISTERED_PLAN')
        value = dict(plan=plan, plan_id=runtime.identity(plan), related_identity=related_identity,
                     host=socket.gethostname(), observed_at_ns=time.time_ns())
        with self._transaction() as (db, policy, checkpoint, attempts, count):
            _require(checkpoint == expected_checkpoint, 'STALE_CHECKPOINT')
            value['alpha_per_comparison'] = _allocation(policy)
            receipt = self._append(db, policy, checkpoint, attempts, count, trial, 'reserve', value)
        return receipt  # The successful durable COMMIT precedes disclosure.

    def _transition(self, trial, kind, value):
        _digest(trial)
        with self._transaction() as (db, policy, checkpoint, attempts, count):
            receipt = self._append(db, policy, checkpoint, attempts, count, trial, kind, value)
        return receipt

    def phase(self, trial, name, observation):
        return self._transition(trial, 'phase', dict(name=name, observation=observation))

    def child_receipt(self, trial, name, receipt):
        return self._transition(trial, 'child-receipt', dict(name=name, receipt=receipt))

    def freeze_roster(self, trial, roster):
        return self._transition(trial, 'freeze-roster', roster)

    def finish(self, trial, outcome, record):
        return self._transition(trial, 'terminal', dict(outcome=outcome, record=record,
                                                       record_id=runtime.identity(record)))

    def inspect(self):
        """Readback for reconciliation; returned checkpoint is not an external anchor."""
        with self._transaction() as (_, policy, checkpoint, attempts, _):
            return dict(policy=policy, policy_id=self.expected_policy, checkpoint=checkpoint,
                        spent=len(attempts), attempts=attempts, scope=SCOPE)
