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
    return decode(raw, expected, _history, HISTORY_DOMAIN, max_bytes=MAX_HISTORY_BYTES)


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


# Explicit successor: disclosure consumes exposure BEFORE an outcome is known.
# The existing evaluation owner must durably compare-and-set the returned pin
# before releasing prompts. These pure functions are not a second journal.
EXPOSURE_HISTORY_DOMAIN = 'model-operations-exposure-history-v2'
EXPOSURE_ANCHOR_DOMAIN = 'model-operations-exposure-anchor-v2'
EXPOSURE_ENTRY_DOMAIN = 'model-operations-exposure-entry-v2'
EXPOSURE_WINDOW_DOMAIN = 'model-operations-exposure-window-v2'
EXPOSURE_SCOPE = 'reported-disclosure-continuity-no-independent-acceptance'


def _exposure_window(value):
    closed(value, 'schema scope context ordinal previous preregistration run_plan',
           'EXPOSURE_WINDOW_FIELDS')
    require(value['schema'] == 'pon-model-exposure-window-v2' and
            value['scope'] == EXPOSURE_SCOPE, 'EXPOSURE_WINDOW_SCOPE')
    for name in ('context', 'previous', 'preregistration', 'run_plan'):
        digest(value[name])
    integer(value['ordinal'], 1, MAX_WINDOWS, 'WINDOW_ORDINAL')


def _exposure_history(value):
    closed(value, 'schema scope prior_history head entries', 'EXPOSURE_HISTORY_FIELDS')
    require(value['schema'] == 'pon-model-exposure-history-v2' and
            value['scope'] == EXPOSURE_SCOPE, 'EXPOSURE_HISTORY_SCOPE')
    # Preserve the complete old history, including all unsuccessful windows.
    # Conversion never relabels old completions as previously registered starts.
    prior = value['prior_history']
    seen, last_observed, items = _history(prior)
    context = _context(prior['context'])
    previous = _identity(EXPOSURE_ANCHOR_DOMAIN, prior)
    digest(value['head'])
    entries = value['entries']
    require(type(entries) is list and len(prior['entries']) + len(entries) <= MAX_WINDOWS,
            'WINDOW_HISTORY_BOUND')
    for index, row in enumerate(entries):
        closed(row, 'window status receipt registered_at observed_at closes_at '
               'reported_gates_passed tasks probe_prompts training_groups', 'EXPOSURE_ENTRY_FIELDS')
        _exposure_window(row['window'])
        require(row['window']['context'] == context and
                row['window']['ordinal'] == len(prior['entries']) + index + 1 and
                row['window']['previous'] == previous, 'WINDOW_HISTORY_LINK')
        integer(row['registered_at'], 1, MAX_TIME, 'WINDOW_TIME')
        integer(row['closes_at'], 1, MAX_TIME, 'WINDOW_TIME')
        require(last_observed < row['registered_at'] < row['closes_at'], 'WINDOW_CHRONOLOGY')
        require(type(row['status']) is str and row['status'] in ('pending', 'completed', 'aborted'),
                'EXPOSURE_STATUS')
        if row['status'] == 'pending':
            require(index + 1 == len(entries) and row['receipt'] is None and
                    row['observed_at'] is None and row['reported_gates_passed'] is None,
                    'EXPOSURE_PENDING')
        else:
            digest(row['receipt'])
            integer(row['observed_at'], 1, MAX_TIME, 'WINDOW_TIME')
            require(row['registered_at'] < row['observed_at'], 'WINDOW_CHRONOLOGY')
            if row['status'] == 'completed':
                require(row['observed_at'] <= row['closes_at'] and
                        type(row['reported_gates_passed']) is bool, 'EXPOSURE_COMPLETION')
            else:
                # A delayed failure still consumes its window. No successful
                # model assessment or retrospective positive gate is fabricated.
                require(row['reported_gates_passed'] is False, 'EXPOSURE_ABORT')
            last_observed = row['observed_at']
        for name in ('tasks', 'probe_prompts', 'training_groups'):
            require(type(row[name]) is list, 'WINDOW_EXPOSURE_TYPE')
            items += len(row[name])
        require(items <= MAX_ITEMS, 'WINDOW_HISTORY_ITEM_BOUND')
        _check_exposure(row['tasks'], row['probe_prompts'], row['training_groups'], seen)
        _consume(row['tasks'], row['probe_prompts'], row['training_groups'], seen)
        previous = _identity(EXPOSURE_ENTRY_DOMAIN, row)
    require(value['head'] == previous, 'WINDOW_HISTORY_HEAD')
    return seen, last_observed, items


def freeze_exposure_history(value):
    _exposure_history(value)
    raw = canonical(value)
    require(len(raw) <= MAX_HISTORY_BYTES, 'WINDOW_HISTORY_BYTE_BOUND')
    return raw, H(EXPOSURE_HISTORY_DOMAIN, raw).hex()


def _decode_exposure_history(raw, expected):
    require(type(raw) is bytes and len(raw) <= MAX_HISTORY_BYTES, 'WINDOW_HISTORY_BYTE_BOUND')
    return decode(raw, expected, _exposure_history, EXPOSURE_HISTORY_DOMAIN,
                  max_bytes=MAX_HISTORY_BYTES)


def upgrade_exposure_history(history_raw, expected_history):
    """Explicitly wrap a pinned v1 history, without rewriting any old record.

    The returned v2 identity needs its own owner-side durable CAS. No evaluator
    has been started and no historical disclosure claim has been upgraded.
    """
    prior = _decode_history(history_raw, expected_history)
    value = dict(schema='pon-model-exposure-history-v2', scope=EXPOSURE_SCOPE,
                 prior_history=prior, head=_identity(EXPOSURE_ANCHOR_DOMAIN, prior), entries=[])
    freeze_exposure_history(value)
    return value


def _exposure_result(history, previous, window_id, assessment=None):
    _, next_identity = freeze_exposure_history(history)
    return dict(schema='pon-model-exposure-transition-v2', scope=EXPOSURE_SCOPE,
                window=window_id, previous_history=previous, next_history=next_identity,
                history=history, assessment=assessment, window_consumed=True,
                owner_persistence_required=True, historical_execution_verified=False,
                hidden_windows_excluded=False, physical_custody_verified=False,
                prospective_accepted=False, independent_accepted=False,
                public_reward_eligible=False, production_activation=False)


def admit_exposure_window(history_raw, expected_history, preregistration_raw,
                          expected_preregistration, plan, expected_plan):
    """Consume all declared exposure, reserving both possible terminal records.

    Persist the returned history and pin before any prompt/probe is disclosed.
    A pending window blocks another admission; abort/finish keeps its exposure.
    This operation never runs a model, sends data, or grants permission to do so.
    """
    history = _decode_exposure_history(history_raw, expected_history)
    entries = history['entries']
    require(not entries or entries[-1]['status'] != 'pending', 'EXPOSURE_ALREADY_PENDING')
    require(len(history['prior_history']['entries']) + len(entries) < MAX_WINDOWS,
            'WINDOW_HISTORY_BOUND')
    prereg = decode(preregistration_raw, expected_preregistration, validate_preregistration, PREREG_DOMAIN)
    require(freeze_preregistration(prereg, plan, expected_plan)[0] == preregistration_raw,
            'WINDOW_OPERATION_PREREGISTRATION')
    context = history['prior_history']['context']
    require(prereg['owner'] == context['owner'] and prereg['governance'] == context['governance'],
            'WINDOW_OWNER_CONTEXT')
    seen, observed, items = _exposure_history(history)
    require(prereg['registered_at'] > observed, 'WINDOW_CHRONOLOGY')
    tasks, probes, training = _projection(prereg, plan)
    require(items + len(tasks) + len(probes) + len(training) <= MAX_ITEMS,
            'WINDOW_HISTORY_ITEM_BOUND')
    _check_exposure(tasks, probes, training, seen)
    declaration = dict(schema='pon-model-exposure-window-v2', scope=EXPOSURE_SCOPE,
        context=_context(context), ordinal=len(history['prior_history']['entries']) + len(entries) + 1,
        previous=history['head'], preregistration=expected_preregistration, run_plan=expected_plan)
    _exposure_window(declaration)
    require(len(canonical(declaration)) <= MAX_WINDOW_BYTES, 'WINDOW_PREREGISTRATION_BYTE_BOUND')
    row = dict(window=declaration, status='pending', receipt=None,
               registered_at=prereg['registered_at'], observed_at=None,
               closes_at=prereg['closes_at'], reported_gates_passed=None,
               tasks=tasks, probe_prompts=probes, training_groups=training)
    # Reserve canonical serialized space now, rather than discovering at abort
    # or completion that the already-exposed window cannot be retained. Abort
    # may happen after closes_at, so its envelope uses the largest valid time.
    for status, latest in [('completed', prereg['closes_at']), ('aborted', MAX_TIME)]:
        terminal = dict(row, status=status, receipt='f' * 64,
                        observed_at=latest, reported_gates_passed=False)
        envelope = dict(history, entries=[*entries, terminal],
                        head=_identity(EXPOSURE_ENTRY_DOMAIN, terminal))
        freeze_exposure_history(envelope)
    entries.append(row)
    history['head'] = _identity(EXPOSURE_ENTRY_DOMAIN, row)
    return _exposure_result(history, expected_history, _identity(EXPOSURE_WINDOW_DOMAIN, declaration))


def _pending_exposure(history_raw, expected_history, expected_window):
    history = _decode_exposure_history(history_raw, expected_history)
    digest(expected_window)
    require(history['entries'] and history['entries'][-1]['status'] == 'pending',
            'EXPOSURE_NOT_PENDING')
    row = history['entries'][-1]
    require(_identity(EXPOSURE_WINDOW_DOMAIN, row['window']) == expected_window,
            'EXPOSURE_WINDOW_IDENTITY')
    return history, row


def finish_exposure_window(history_raw, expected_history, expected_window,
                           preregistration_raw, expected_preregistration, plan, expected_plan,
                           record, receipt, material):
    """Settle only the exact pinned pending window using full v1 verification.

    Invalid or incomplete results leave the caller's pending bytes intact. They
    can be aborted explicitly, but cannot erase exposure or start a fresh retry.
    """
    history, row = _pending_exposure(history_raw, expected_history, expected_window)
    require(row['window']['preregistration'] == expected_preregistration and
            row['window']['run_plan'] == expected_plan, 'EXPOSURE_RESULT_BINDING')
    prereg = decode(preregistration_raw, expected_preregistration, validate_preregistration, PREREG_DOMAIN)
    require(freeze_preregistration(prereg, plan, expected_plan)[0] == preregistration_raw,
            'WINDOW_OPERATION_PREREGISTRATION')
    context = history['prior_history']['context']
    require(prereg['owner'] == context['owner'] and prereg['governance'] == context['governance'],
            'WINDOW_OWNER_CONTEXT')
    tasks, probes, training = _projection(prereg, plan)
    require((row['tasks'], row['probe_prompts'], row['training_groups']) == (tasks, probes, training)
            and row['registered_at'] == prereg['registered_at']
            and row['closes_at'] == prereg['closes_at'], 'EXPOSURE_RESULT_BINDING')
    assessment = verify_acceptance(preregistration_raw, expected_preregistration, plan,
                                   expected_plan, record, receipt, material)
    row.update(status='completed', receipt=assessment['receipt'],
               observed_at=receipt['observed_at'], reported_gates_passed=assessment['reported_gates_passed'])
    history['head'] = _identity(EXPOSURE_ENTRY_DOMAIN, row)
    return _exposure_result(history, expected_history, expected_window, assessment)


def abort_exposure_window(history_raw, expected_history, expected_window, observed_at, failure_digest):
    """Record failed/unknown execution without certifying its cause or refunding exposure."""
    history, row = _pending_exposure(history_raw, expected_history, expected_window)
    digest(failure_digest)
    integer(observed_at, 1, MAX_TIME, 'WINDOW_TIME')
    require(observed_at > row['registered_at'], 'WINDOW_CHRONOLOGY')
    row.update(status='aborted', receipt=failure_digest, observed_at=observed_at,
               reported_gates_passed=False)
    history['head'] = _identity(EXPOSURE_ENTRY_DOMAIN, row)
    return _exposure_result(history, expected_history, expected_window)

# Three-generation adoption-chain contract.  This validates only retained
# identities and chronology around already-consumed exposure windows.  It does
# not assert that a model was physically installed, independently controlled,
# useful to a consumer, or production-qualified.
PROSPECTIVE_LINEAGE_SCHEMA = 'pon-model-prospective-lineage-v1'
PROSPECTIVE_LINEAGE_SCOPE = 'three-generation-adoption-chain-no-benefit-acceptance'


def verify_prospective_generation_chain(history_raw, expected_history, generations):
    """Bind three completed exposure windows into one predecessor/adoption chain.

    Each candidate identity is externally pinned to the matching run-plan
    identity.  An adopted decision requires that window's reported gates to pass
    and makes the candidate the successor.  A no_update decision retains the
    predecessor.  The next row must name the prior adopted model exactly.

    This is an executable lineage/decision contract only.  It deliberately
    leaves prospective/independent/consumer-benefit/production acceptance false.
    """
    history = _decode_exposure_history(history_raw, expected_history)
    require(type(generations) is list and len(generations) == 3,
            'PROSPECTIVE_GENERATION_COUNT')
    require(len(history['entries']) >= 3, 'PROSPECTIVE_HISTORY_COUNT')
    rows = history['entries'][-3:]
    require(all(row['status'] == 'completed' for row in rows),
            'PROSPECTIVE_COMPLETED_WINDOWS')

    previous_adopted = None
    retained = []
    for ordinal, (row, generation) in enumerate(zip(rows, generations), 1):
        closed(generation,
               'window run_plan predecessor_model candidate_model adopted_model decision '
               'consumer_receipt',
               'PROSPECTIVE_GENERATION_FIELDS')
        for field in ('window', 'run_plan', 'predecessor_model', 'candidate_model',
                      'adopted_model', 'consumer_receipt'):
            digest(generation[field])
        require(generation['window'] == _identity(EXPOSURE_WINDOW_DOMAIN, row['window']) and
                generation['run_plan'] == row['window']['run_plan'],
                'PROSPECTIVE_WINDOW_BINDING')
        require(generation['decision'] in ('adopted', 'no_update'),
                'PROSPECTIVE_DECISION')
        if previous_adopted is not None:
            require(generation['predecessor_model'] == previous_adopted,
                    'PROSPECTIVE_PREDECESSOR')
        if generation['decision'] == 'adopted':
            require(row['reported_gates_passed'] is True,
                    'PROSPECTIVE_ADOPTION_GATE')
            require(generation['candidate_model'] != generation['predecessor_model'] and
                    generation['adopted_model'] == generation['candidate_model'],
                    'PROSPECTIVE_ADOPTION_IDENTITY')
        else:
            require(generation['adopted_model'] == generation['predecessor_model'],
                    'PROSPECTIVE_NO_UPDATE_IDENTITY')
        retained.append(dict(
            ordinal=ordinal,
            window=generation['window'],
            run_plan=generation['run_plan'],
            predecessor_model=generation['predecessor_model'],
            candidate_model=generation['candidate_model'],
            adopted_model=generation['adopted_model'],
            decision=generation['decision'],
            consumer_receipt=generation['consumer_receipt'],
            reported_gates_passed=row['reported_gates_passed']))
        previous_adopted = generation['adopted_model']

    value = dict(schema=PROSPECTIVE_LINEAGE_SCHEMA, scope=PROSPECTIVE_LINEAGE_SCOPE,
                 history=expected_history, generations=retained,
                 lineage_verified=True, exposure_consumption_verified=True,
                 candidate_identity_externally_pinned=True,
                 actual_model_installation_verified=False,
                 new_consumer_benefit_verified=False,
                 hidden_windows_excluded=False,
                 physical_custody_verified=False,
                 prospective_accepted=False, independent_accepted=False,
                 public_reward_eligible=False, production_activation=False)
    raw = canonical(value)
    return dict(value, id=H('model-prospective-lineage-v1', raw).hex())

