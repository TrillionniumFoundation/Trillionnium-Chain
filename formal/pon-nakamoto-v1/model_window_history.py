"""Bounded, externally pinned continuation of reported model-evaluation windows.

This is an offline sidecar. It validates supplied history and the current complete
v1 operation record, not historical execution, wall time, custody or hidden uses.
The caller supplies both expected identities from outside the submitted records.
Every structurally valid current assessment consumes its window, including zero
gain and failed reported gates. Existing v1 contracts and chain rewards are unchanged.
"""
from __future__ import annotations

from contract_wire import H, canonical
from llm_adapter_contract import closed, decode, digest, integer, require
from model_acceptance import (DOMAIN as PREREG_DOMAIN, freeze_preregistration,
                              validate_preregistration, verify_acceptance)

HISTORY_DOMAIN = 'model-operations-window-history-v1'
WINDOW_DOMAIN = 'model-operations-window-preregistration-v1'
ENTRY_DOMAIN = 'model-operations-window-entry-v1'
CONTEXT_DOMAIN = 'model-operations-window-context-v1'
SCOPE = 'reported-window-continuity-no-independent-acceptance'
MAX_WINDOWS = 64
MAX_ITEMS = 131072
MAX_HISTORY_BYTES = 16 * 1024 * 1024
MAX_WINDOW_BYTES = 4096
MAX_TIME = (1 << 63) - 1


def _identity(domain, value):
    return H(domain, canonical(value)).hex()


def _context(value):
    closed(value, 'series owner governance', 'WINDOW_CONTEXT_FIELDS')
    for field in ('series', 'owner', 'governance'):
        digest(value[field])
    return _identity(CONTEXT_DOMAIN, value)


def _digests(value):
    require(type(value) is list and len(value) <= MAX_ITEMS, 'WINDOW_SET_BOUND')
    for item in value:
        digest(item)
    require(value == sorted(set(value)), 'WINDOW_SET_ORDER')


def _window(value):
    closed(value, 'schema scope context ordinal previous preregistration run_plan',
           'WINDOW_PREREGISTRATION_FIELDS')
    require(value['schema'] == 'pon-model-window-preregistration-v1' and
            value['scope'] == SCOPE, 'WINDOW_PREREGISTRATION_SCOPE')
    for field in ('context', 'previous', 'preregistration', 'run_plan'):
        digest(value[field])
    integer(value['ordinal'], 1, MAX_WINDOWS, 'WINDOW_ORDINAL')


def _tasks(value):
    require(type(value) is list and 1 <= len(value) <= MAX_ITEMS, 'WINDOW_TASK_BOUND')
    ids = []
    for task in value:
        closed(task, 'id prompt group partition', 'WINDOW_TASK_FIELDS')
        for field in ('id', 'prompt', 'group'):
            digest(task[field])
        require(type(task['partition']) is str and
                task['partition'] in ('calibration', 'evaluation'), 'WINDOW_PARTITION')
        ids.append(task['id'])
    require(ids == sorted(set(ids)), 'WINDOW_TASK_ORDER')
    require(len({t['prompt'] for t in value}) == len(value), 'WINDOW_TASK_PROMPT_ALIAS')
    require({t['partition'] for t in value} == {'calibration', 'evaluation'},
            'WINDOW_PARTITION_COVERAGE')


def _check_exposure(tasks, probes, training, seen):
    _tasks(tasks)
    _digests(probes)
    _digests(training)
    prompts = {t['prompt'] for t in tasks}
    require(not prompts & set(probes), 'WINDOW_CURRENT_PROBE_ALIAS')
    calibration_groups = {t['group'] for t in tasks if t['partition'] == 'calibration'}
    evaluation = [t for t in tasks if t['partition'] == 'evaluation']
    require(not {t['group'] for t in evaluation} & (set(training) | calibration_groups),
            'WINDOW_CURRENT_GROUP_ALIAS')
    require(not {t['id'] for t in evaluation} & seen['tasks'], 'WINDOW_REUSED_TASK')
    require(not {t['prompt'] for t in evaluation} & seen['prompts'], 'WINDOW_REUSED_PROMPT')
    require(not {t['group'] for t in evaluation} & seen['groups'], 'WINDOW_REUSED_GROUP')


def _consume(tasks, probes, training, seen):
    seen['tasks'].update(t['id'] for t in tasks)
    seen['prompts'].update(t['prompt'] for t in tasks)
    seen['prompts'].update(probes)
    seen['groups'].update(t['group'] for t in tasks)
    seen['groups'].update(training)


def _history(value):
    """Rebuild the ordered entry chain and contacted sets from all retained rows."""
    closed(value, 'schema scope context head entries', 'WINDOW_HISTORY_FIELDS')
    require(value['schema'] == 'pon-model-window-history-v1' and value['scope'] == SCOPE,
            'WINDOW_HISTORY_SCOPE')
    context = _context(value['context'])
    digest(value['head'])
    entries = value['entries']
    require(type(entries) is list and len(entries) <= MAX_WINDOWS, 'WINDOW_HISTORY_BOUND')
    previous = context
    seen = {'tasks': set(), 'prompts': set(), 'groups': set()}
    last_observed = 0
    items = 0
    for ordinal, row in enumerate(entries, 1):
        closed(row, 'window receipt registered_at observed_at closes_at reported_gates_passed '
               'tasks probe_prompts training_groups', 'WINDOW_ENTRY_FIELDS')
        _window(row['window'])
        require(row['window']['context'] == context and
                row['window']['ordinal'] == ordinal and
                row['window']['previous'] == previous, 'WINDOW_HISTORY_LINK')
        digest(row['receipt'])
        require(type(row['reported_gates_passed']) is bool, 'WINDOW_GATE_TYPE')
        for field in ('registered_at', 'observed_at', 'closes_at'):
            integer(row[field], 1, MAX_TIME, 'WINDOW_TIME')
        require(last_observed < row['registered_at'] < row['observed_at'] <= row['closes_at'],
                'WINDOW_CHRONOLOGY')
        # Bound cumulative work before sorting, hashing or traversing task fields.
        for field in ('tasks', 'probe_prompts', 'training_groups'):
            require(type(row[field]) is list, 'WINDOW_EXPOSURE_TYPE')
            items += len(row[field])
        require(items <= MAX_ITEMS, 'WINDOW_HISTORY_ITEM_BOUND')
        _check_exposure(row['tasks'], row['probe_prompts'], row['training_groups'], seen)
        _consume(row['tasks'], row['probe_prompts'], row['training_groups'], seen)
        last_observed = row['observed_at']
        previous = _identity(ENTRY_DOMAIN, row)
    require(value['head'] == previous, 'WINDOW_HISTORY_HEAD')
    return seen, last_observed, items


def freeze_history(value):
    _history(value)
    raw = canonical(value)
    require(len(raw) <= MAX_HISTORY_BYTES, 'WINDOW_HISTORY_BYTE_BOUND')
    return raw, H(HISTORY_DOMAIN, raw).hex()


def empty_history(series, owner, governance):
    value = dict(schema='pon-model-window-history-v1', scope=SCOPE,
                 context=dict(series=series, owner=owner, governance=governance), entries=[])
    value['head'] = _context(value['context'])
    freeze_history(value)
    return value


def _decode_history(raw, expected):
    require(type(raw) is bytes and len(raw) <= MAX_HISTORY_BYTES, 'WINDOW_HISTORY_BYTE_BOUND')
    return decode(raw, expected, _history, HISTORY_DOMAIN)


def _projection(prereg, plan):
    tasks = sorted((dict(id=t['id'], prompt=t['prompt_sha256'], group=t['source_group'],
                         partition=t['partition']) for t in plan['tasks']), key=lambda t: t['id'])
    probes = sorted(p['prompt'] for p in prereg['probes'])
    training = list(prereg['training_groups'])
    return tasks, probes, training


def _inputs(history_raw, expected_history, preregistration_raw, expected_preregistration,
            plan, expected_plan):
    history = _decode_history(history_raw, expected_history)
    require(len(history['entries']) < MAX_WINDOWS, 'WINDOW_HISTORY_FULL')
    prereg = decode(preregistration_raw, expected_preregistration,
                    validate_preregistration, PREREG_DOMAIN)
    require(freeze_preregistration(prereg, plan, expected_plan)[0] == preregistration_raw,
            'WINDOW_OPERATION_PREREGISTRATION')
    require(all(history['context'][key] == prereg[key] for key in ('owner', 'governance')),
            'WINDOW_OWNER_GOVERNANCE')
    seen, observed, items = _history(history)
    require(prereg['registered_at'] > observed, 'WINDOW_CHRONOLOGY')
    tasks, probes, training = _projection(prereg, plan)
    require(items + len(tasks) + len(probes) + len(training) <= MAX_ITEMS,
            'WINDOW_HISTORY_ITEM_BOUND')
    _check_exposure(tasks, probes, training, seen)
    return history, prereg, tasks, probes, training


def freeze_window(value, history_raw, expected_history, preregistration_raw,
                  expected_preregistration, plan, expected_plan):
    history, prereg, tasks, probes, training = _inputs(
        history_raw, expected_history, preregistration_raw, expected_preregistration, plan, expected_plan)
    _window(value)
    require(value['context'] == _context(history['context']) and
            value['ordinal'] == len(history['entries']) + 1 and
            value['previous'] == history['head'] and
            value['preregistration'] == expected_preregistration and
            value['run_plan'] == expected_plan, 'WINDOW_PREREGISTRATION_BINDING')
    raw = canonical(value)
    require(len(raw) <= MAX_WINDOW_BYTES, 'WINDOW_PREREGISTRATION_BYTE_BOUND')
    # Reserve the complete serialized append before an evaluation is admitted.
    # A receipt and head are fixed-width digests, False is longer than True, and
    # closes_at is the largest permitted observed_at. This is only a byte-size
    # envelope; it is neither returned nor retained as an observed assessment.
    envelope = dict(window=value, receipt='f' * 64, registered_at=prereg['registered_at'],
                    observed_at=prereg['closes_at'], closes_at=prereg['closes_at'],
                    reported_gates_passed=False, tasks=tasks, probe_prompts=probes,
                    training_groups=training)
    reservation = dict(history, entries=[*history['entries'], envelope],
                       head=_identity(ENTRY_DOMAIN, envelope))
    freeze_history(reservation)
    return raw, H(WINDOW_DOMAIN, raw).hex()


def verify_window(window_raw, expected_window, history_raw, expected_history,
                  preregistration_raw, expected_preregistration, plan, expected_plan,
                  record, receipt, material):
    """Return the new pinned history only after complete current v1 verification.

    A false reported gate is a retained outcome, not permission to retry its future
    tasks as a fresh window. A malformed current record raises without advancing.
    No files, roots, rewards or external state are mutated by this function.
    """
    require(type(window_raw) is bytes and len(window_raw) <= MAX_WINDOW_BYTES,
            'WINDOW_PREREGISTRATION_BYTE_BOUND')
    window = decode(window_raw, expected_window, _window, WINDOW_DOMAIN)
    require(freeze_window(window, history_raw, expected_history, preregistration_raw,
                          expected_preregistration, plan, expected_plan)[0] == window_raw,
            'WINDOW_PREREGISTRATION_BINDING')
    history, prereg, tasks, probes, training = _inputs(
        history_raw, expected_history, preregistration_raw, expected_preregistration, plan, expected_plan)
    assessment = verify_acceptance(preregistration_raw, expected_preregistration, plan,
                                   expected_plan, record, receipt, material)
    row = dict(window=window, receipt=assessment['receipt'], registered_at=prereg['registered_at'],
               observed_at=receipt['observed_at'], closes_at=prereg['closes_at'],
               reported_gates_passed=assessment['reported_gates_passed'], tasks=tasks,
               probe_prompts=probes, training_groups=training)
    history['entries'].append(row)
    history['head'] = _identity(ENTRY_DOMAIN, row)
    _, next_identity = freeze_history(history)
    return dict(schema='pon-model-window-assessment-v1', scope=SCOPE,
                window=expected_window, previous_history=expected_history,
                next_history=next_identity, history=history, assessment=assessment,
                window_consumed=True, historical_execution_verified=False,
                hidden_windows_excluded=False, physical_custody_verified=False,
                prospective_accepted=False, independent_accepted=False,
                public_reward_eligible=False, production_activation=False)
