"""Durable trial spending for the existing, explicitly public local pilot.

This is an adapter around the pilot's one process owner, not an evaluator or a
global identity service. Cooperating processes must open the same pre-created
SQLite authority and pin its policy and last checkpoint. Copying an old database
and its old checkpoint, or choosing another authority, is outside this guarantee.
The public fixture is already exposed; an alpha allocation is not a p-value.
"""
from __future__ import annotations

from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import stat
import time


# Immutable interpretation of the already persisted v1 policy/event domains and
# v2/v3 assessment records. Admission may inspect the live runner; historical replay
# must never reinterpret old bytes using a later family file or assessment code.
# A changed model, phase inventory or assessment meaning requires a new namespace
# and its own interpreter. Keep this compatibility profile when adding one.
_MODEL_V1 = 'HuggingFaceTB/SmolLM2-135M-Instruct'
_REVISION_V1 = '12fd25f77366fa6b3b4b768ec3050bf629380bac'
_REGISTERED_PLAN_V1 = 'llm-runtime-registered-public-pilot-plan-v1'
_LEGACY_REPLAY = 'llm-runtime-public-history-legacy-v1'
_CONTAINED_REPLAY = 'llm-runtime-public-history-contained-v2'
_RESERVATION_V2 = 'llm-runtime-trial-reservation-v2'
# Legacy events had no replay selector. Recognize only the exact assessment
# implementation whose stored interpretation is retained below. Never compare
# a historical source hash to whichever source happens to be installed today.
_LEGACY_ASSESSMENT_SOURCES = {
    '133871703daf740c26cccb30e450cd90127d1ee206c75734929ddbf364602f5d': _LEGACY_REPLAY,
}
_COMPONENTS_V1 = frozenset(('llm_runtime_pilot.py', 'llm_runtime_trial_ledger.py',
                           'llm_runtime_assessment.py', 'llm_parent_material.py'))
_EXIT_PROFILES_V1 = dict(zip(('llm-runtime-public-pilot-plan-v' + str(n) for n in range(1, 5)),
    ('strict-v1', 'linux-owned-exit-cleanup-v2', 'linux-owned-exit-terminal-subset-v3',
     'linux-owned-exit-worker-pidfd-v4')))
_CONTROLS_V1 = ('current-backbone', 'fresh-budget-matched-lora',
                'budget-matched-full-tune', 'randomized-rank-matched-lora')
_PARTICIPANTS_V1 = ('candidate', *_CONTROLS_V1)
_PARTICIPANT_KINDS_V1 = dict(zip(_PARTICIPANTS_V1,
    ('lora', 'immutable-backbone', 'lora', 'full-tune', 'random-lora')))
_QUALIFICATIONS_V1 = ('public_network_ready', 'authenticated_inference_accepted',
                     'independent_accepted', 'prospective_accepted', 'public_reward_eligible')
# This SHA names the exact shipped source bytes, not a mutable path or a claim
# supplied by a receipt. Old v1 reservations did not embed the family source;
# unknown historical digests remain unsupported rather than guessed or rebound.
_FAMILY_CONTEXT_V1 = {
    '0837bbfb31f3f2b9a8731545c9f742aee1ebd32daed392a936a3ec9719537e52': (
        '5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c',
        'c320c094769446c21d7e4a33795d7f9310b5e4c8ca5a6fecca40207b1f735b7c',
        134515008),
}


def _runtime_require(condition, code):
    if not condition:
        raise ValueError(code)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode()


def _identity(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _runtime_require(key not in result, 'RUNTIME_DUPLICATE_JSON')
        result[key] = value
    return result


SCHEMA = 'llm-runtime-family-trial-policy-v1'
SCOPE = 'cooperative-local-public-pilot-no-global-custody-or-qualification'
MAX_ATTEMPTS = 64
MAX_PAYLOAD = 256 * 1024
MAX_DATABASE_BYTES = 512 * 1024 * 1024
PHASES = ('loader-1thread', 'loader-reference',
          *('train-' + role for role in _PARTICIPANTS_V1),
          *('evaluate-' + role for role in _PARTICIPANTS_V1))
MAX_EVENTS = MAX_ATTEMPTS * (2 * len(PHASES) + 3)
POLICY_SQL = ('CREATE TABLE policy (singleton INTEGER PRIMARY KEY CHECK(singleton=1), '
              'value TEXT NOT NULL, identity TEXT NOT NULL)')
EVENTS_SQL = ('CREATE TABLE events (seq INTEGER PRIMARY KEY, trial TEXT NOT NULL, '
              'kind TEXT NOT NULL, payload TEXT NOT NULL, previous TEXT NOT NULL, root TEXT NOT NULL)')


def _require(condition, code):
    _runtime_require(condition, 'TRIAL_' + code)


def _digest(value):
    _require(type(value) is str and len(value) == 64 and
             all(c in '0123456789abcdef' for c in value), 'DIGEST')
    return value


def _integer(value, minimum, maximum):
    _require(type(value) is int and minimum <= value <= maximum, 'INTEGER')


def _closed(value, keys):
    _require(type(value) is dict and set(value) == set(keys.split()), 'FIELDS')


def _payload(value):
    raw = _canonical(value)
    _require(len(raw) <= MAX_PAYLOAD, 'PAYLOAD_BOUND')
    return raw.decode('ascii')


def _policy(policy):
    _closed(policy, 'schema scope authority_instance model_family max_attempts '
                    'family_alpha comparisons_per_attempt multiplicity')
    _require(policy['schema'] == SCHEMA and policy['scope'] == SCOPE and
             policy['model_family'] == _MODEL_V1 and
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
             policy['comparisons_per_attempt'] == len(_CONTROLS_V1), 'COMPARISONS')
    return policy


def _stored_plan_v1(plan, policy, trial):
    """Validate the stored registered-plan structure, with no live source reads.

    Source digests are provenance, not an instruction to load today's files.
    The separate reservation replay selector fixes their interpretation. New
    writes also pass the current runner's stricter admission checks.
    """
    _require(type(plan) is dict and plan.get('schema') == _REGISTERED_PLAN_V1 and
             plan.get('trial_policy') == _identity(policy) and plan.get('trial_id') == trial,
             'REGISTERED_PLAN')
    _require(plan.get('model') == policy['model_family'] == _MODEL_V1 and
             plan.get('revision') == _REVISION_V1 and plan.get('dtype') == 'float32',
             'PLAN_CONTEXT')
    profile = _EXIT_PROFILES_V1.get(plan.get('pilot_schema'))
    _require(profile is not None, 'PILOT_SCHEMA')
    if profile == 'strict-v1':
        _require('exit_observation' not in plan, 'EXIT_PROFILE')
    else:
        observation = plan.get('exit_observation')
        fields = {'profile', 'maximum_drain_ns', 'observer_source_sha256', 'diagnostic_source_sha256'}
        if profile != 'linux-owned-exit-cleanup-v2':
            fields.add('base_observer_source_sha256')
        _require(type(observation) is dict and set(observation) == fields and
                 observation['profile'] == profile and
                 type(observation['maximum_drain_ns']) is int and
                 observation['maximum_drain_ns'] == 100_000_000, 'EXIT_PROFILE')
        for field in fields - {'profile', 'maximum_drain_ns'}:
            _digest(observation[field])
    for key in ('snapshot', 'runtime_source', 'model_family_configuration_sha256'):
        _digest(plan.get(key))
    _require(plan['model_family_configuration_sha256'] in _FAMILY_CONTEXT_V1, 'FAMILY_CONTEXT')
    components = plan.get('run_components')
    _require(type(components) is dict and _COMPONENTS_V1 <= set(components) and
             len(components) <= 64, 'COMPONENTS')
    for name, digest in components.items():
        _require(type(name) is str and 1 <= len(name) <= 128 and name.endswith('.py') and
                 all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_.' for c in name), 'COMPONENTS')
        _digest(digest)
    _require(components['llm_runtime_pilot.py'] == plan['runtime_source'], 'COMPONENT_SOURCE')
    _require(plan.get('backend') in ('cpu', 'cuda', 'rocm', 'mps') and
             type(plan.get('threads')) is int and 1 <= plan['threads'] <= 8 and
             type(plan.get('generation_tokens')) is int and 1 <= plan['generation_tokens'] <= 16 and
             type(plan.get('input_tokens_max')) is int and plan['input_tokens_max'] == 128 and
             type(plan.get('rank')) is int and plan['rank'] == 4 and
             type(plan.get('alpha')) is int and plan['alpha'] == 8, 'PLAN_LIMIT')
    for name, wall_limit, rss_limit in (('training_budget', 1800, 16 * 1024**3),
                                        ('inference_budget', 600, 8 * 1024**3)):
        budget = plan.get(name)
        _require(type(budget) is dict and set(budget) == {'wall_seconds', 'rss_bytes'} and
                 type(budget['wall_seconds']) is int and 1 <= budget['wall_seconds'] <= wall_limit and
                 type(budget['rss_bytes']) is int and 1 <= budget['rss_bytes'] <= rss_limit,
                 'PLAN_BUDGET')
    _require(plan.get('participants') == list(_PARTICIPANTS_V1) and
             type(plan.get('recipes')) is dict and set(plan['recipes']) == set(_PARTICIPANTS_V1),
             'PLAN_CONTROLS')
    for role, kind in _PARTICIPANT_KINDS_V1.items():
        recipe = plan['recipes'][role]
        _require(type(recipe) is dict and recipe.get('kind') == kind, 'PLAN_RECIPE')
        fields = {'kind'} if kind == 'immutable-backbone' else {
            'kind', 'initialization_seed', 'std' if kind == 'random-lora' else 'learning_rate'}
        _require(set(recipe) == fields, 'PLAN_RECIPE')
        if kind != 'immutable-backbone':
            _integer(recipe['initialization_seed'], -(1 << 63), (1 << 64) - 1)
            value = recipe['std' if kind == 'random-lora' else 'learning_rate']
            _require(type(value) is str and 0 < len(value) <= 64 and value.isascii() and
                     value == value.strip(), 'PLAN_RECIPE_NUMERIC')
            try:
                number = float(value)
            except ValueError as error:
                raise ValueError('TRIAL_PLAN_RECIPE_NUMERIC') from error
            _require(math.isfinite(number) and number > 0, 'PLAN_RECIPE_NUMERIC')
    _require(all(plan.get(name) is False for name in _QUALIFICATIONS_V1), 'PLAN_QUALIFICATION')
    _integer(plan.get('training_steps'), 1, 100)
    rows = plan.get('tasks')
    _require(type(rows) is list and all(type(row) is dict for row in rows), 'PLAN_TASKS')
    ids, prompts = set(), set()
    for row in rows:
        _require(type(row.get('prompt')) is str and type(row.get('expected_output')) is str,
                 'PLAN_TASKS')
        _digest(row.get('id')); _digest(row.get('prompt_sha256')); _digest(row.get('target_output_sha256'))
        _require(row['id'] not in ids and row['prompt_sha256'] not in prompts, 'PLAN_TASK_ALIAS')
        ids.add(row['id']); prompts.add(row['prompt_sha256'])
        _require(hashlib.sha256(row['prompt'].encode()).hexdigest() == row['prompt_sha256'] and
                 hashlib.sha256(row['expected_output'].encode()).hexdigest() == row['target_output_sha256'],
                 'PLAN_TASK_BYTES')
        _require(row['id'] == _identity({k: v for k, v in row.items() if k != 'id'}) and
                 row.get('partition') in ('training', 'calibration', 'evaluation'), 'PLAN_TASK_IDENTITY')


def _reservation_profile(kind, value):
    fields = 'plan plan_id related_identity host observed_at_ns alpha_per_comparison'
    if kind == 'reserve':
        _closed(value, fields)
        components = value['plan']['run_components']
        profile = _LEGACY_ASSESSMENT_SOURCES.get(components['llm_runtime_assessment.py'])
        _require(profile == _LEGACY_REPLAY, 'LEGACY_REPLAY_SOURCE')
        return profile
    _closed(value, fields + ' schema replay_profile')
    # New source hashes may change while this explicit immutable profile remains
    # supported. Its meaning is checked by pure code, not inferred from a digest.
    _require(value['schema'] == _RESERVATION_V2 and
             value['replay_profile'] == _CONTAINED_REPLAY, 'REPLAY_PROFILE')
    _require('llm_base_material.py' in value['plan']['run_components'], 'REPLAY_COMPONENTS')
    return value['replay_profile']


def _allocation(policy):
    value = Fraction(*policy['family_alpha']) / (
        policy['max_attempts'] * policy['comparisons_per_attempt'])
    return [value.numerator, value.denominator]


def _genesis(policy_id):
    return _identity(dict(schema='llm-runtime-trial-genesis-v1', policy=policy_id))


def _event_root(seq, trial, kind, value, previous):
    return _identity(dict(schema='llm-runtime-trial-event-v1', ordinal=seq,
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
        model_family=_MODEL_V1, max_attempts=max_attempts,
        family_alpha=[alpha.numerator, alpha.denominator],
        comparisons_per_attempt=len(_CONTROLS_V1),
        multiplicity='bonferroni-allocation-only-no-significance-claim'))
    policy_id = _identity(policy)
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


# Frozen v2 cost/assessment derivation. This intentionally retains its original
# caller-supplied score boundary and incomplete economic decision. Later runner
# changes must not retroactively rewrite or silently upgrade these stored facts.
_COST_LIMIT_V2 = (1 << 63) - 1
_COST_COMMON_V2 = ('material-verification', 'declared-family-check', 'runtime-import',
          'model-load', 'derived-material-check')
_MISSING_OBLIGATIONS_V2 = (
    'full-release-composition-and-serving-profile',
    'independent-prospective-and-family-multiplicity-evidence',
    'separate-routing-old-task-rare-cohort-calibration-and-cold-warm-metrics',
    'frozen-economic-tariffs-horizon-and-minimum-net-benefit',
    'complete-search-failures-download-activation-serving-storage-repair-rollback-and-future-selection-costs',
    'release-rate-and-retained-byte-owner-enforcement',
    'current-generation-final-use-and-accepted-no-update-owner',
)


def _cost_integer_v2(value, code, lower=0):
    _runtime_require(type(value) is int and lower <= value <= _COST_LIMIT_V2, code)
    return value


def _cost_sum_v2(values):
    value = sum(values)
    return _cost_integer_v2(value, 'RUNTIME_COST_OVERFLOW')


def _cost_material_v2(plan, receipt):
    contract = receipt.get('contract')
    _runtime_require(type(contract) is str and len(contract) == 64 and
                    all(c in '0123456789abcdef' for c in contract) and contract != '0' * 64,
                    'RUNTIME_COST_CONTRACT')
    context = _FAMILY_CONTEXT_V1.get(plan.get('model_family_configuration_sha256'))
    _runtime_require(context is not None, 'RUNTIME_COST_FAMILY_BINDING')
    source_weight, derived_root, parameter_count = context
    _runtime_require(receipt.get('source_weight_sha256') == source_weight and
                    receipt.get('derived_backbone_root') == derived_root and
                    type(receipt.get('parameter_count')) is int and
                    receipt['parameter_count'] == parameter_count, 'RUNTIME_COST_MATERIAL_BINDING')


def _cost_stages_v2(phase, role):
    stages = list(_COST_COMMON_V2)
    if phase in ('loader', 'evaluate'):
        return stages + ['real-forward-greedy-decode']
    kind = _PARTICIPANT_KINDS_V1[role]
    if kind in ('lora', 'random-lora'):
        stages.append('adapter-insertion')
    stages.append('training')
    if kind in ('lora', 'random-lora'):
        stages.append('adapter-material-check')
    if kind != 'immutable-backbone':
        stages += ['artifact-save', 'artifact-domain-hash']
    return stages


def _observe_phase_v2(plan, name, phase, role, supervisor, receipt):
    """Bind one child receipt to the monitored call; reject absent CPU/RSS.

    IO and GPU time are optional physical observations in the old runtime. Their
    absence is preserved with an incomplete-channel marker, never imputed as zero.
    Outer elapsed/CPU and child elapsed/CPU overlap and are reported separately.
    """
    _runtime_require(phase in ('loader', 'train', 'evaluate') and role in _PARTICIPANTS_V1,
                    'RUNTIME_COST_PHASE')
    _runtime_require(type(supervisor) is dict and type(receipt) is dict, 'RUNTIME_COST_RECORD')
    _runtime_require(type(supervisor.get('exit_code')) is int and supervisor['exit_code'] == 0 and
                    supervisor.get('outcome') == 'success' and supervisor.get('stop_reason') is None and
                    supervisor.get('waited_child_reaped') is True and
                    supervisor.get('owned_child_reap_resolved') is True and
                    supervisor.get('child_spawned') is True and
                    supervisor.get('waited_child_observation_error') is None,
                    'RUNTIME_COST_SUPERVISOR_INCOMPLETE')
    _runtime_require(receipt.get('schema') == 'llm-runtime-actual-child-v1' and
                    receipt.get('outcome') == 'success' and receipt.get('phase') == phase and
                    receipt.get('role') == role and receipt.get('experiment') == _identity(plan) and
                    receipt.get('runtime_source') == plan['runtime_source'] and
                    receipt.get('actual_backend') == plan['backend'] and
                    type(receipt.get('actual_threads')) is int and
                    receipt['actual_threads'] == plan['threads'] and
                    receipt.get('scope') == 'local-actual-runtime-no-native-admission' and
                    all(receipt.get(flag) is False for flag in _QUALIFICATIONS_V1),
                    'RUNTIME_COST_CHILD_BINDING')
    _cost_material_v2(plan, receipt)
    budget = plan['training_budget' if phase == 'train' else 'inference_budget']
    _runtime_require(supervisor.get('budget') == budget, 'RUNTIME_COST_BUDGET_BINDING')
    monitored_wall = _cost_integer_v2(supervisor.get('observed_wall_ns'), 'RUNTIME_COST_WALL', 1)
    waited_cpu = _cost_integer_v2(supervisor.get('child_cpu_ns'), 'RUNTIME_COST_CPU')
    observer_cpu = _cost_integer_v2(supervisor.get('observer_cpu_ns'), 'RUNTIME_COST_CPU')
    sampled_rss = _cost_integer_v2(supervisor.get('sampled_peak_rss_bytes'), 'RUNTIME_COST_RSS')
    waited_rss = _cost_integer_v2(supervisor.get('waited_child_peak_rss_bytes'), 'RUNTIME_COST_RSS', 1)
    child_wall = _cost_integer_v2(receipt.get('process_wall_ns'), 'RUNTIME_COST_WALL', 1)
    child_cpu = _cost_integer_v2(receipt.get('process_cpu_ns'), 'RUNTIME_COST_CPU')
    child_rss = _cost_integer_v2(receipt.get('process_peak_rss_bytes'), 'RUNTIME_COST_RSS', 1)
    _runtime_require(max(sampled_rss, waited_rss, child_rss) <= budget['rss_bytes'] and
                    monitored_wall <= budget['wall_seconds'] * 1_000_000_000,
                    'RUNTIME_COST_BUDGET_EXCEEDED')
    events = receipt.get('cost_events')
    expected = _cost_stages_v2(phase, role)
    _runtime_require(type(events) is list and len(events) == len(expected) and
                    [e.get('stage') if type(e) is dict else None for e in events] == expected,
                    'RUNTIME_COST_STAGE_SET')
    missing = []
    for event in events:
        _runtime_require(set(event) == {'stage', 'outcome', 'error_type', 'cpu_ns', 'wall_ns',
                                      'memory_peak_bytes', 'bytes_read', 'bytes_written', 'gpu_ns'} and
                        event['outcome'] == 'success' and event['error_type'] is None,
                        'RUNTIME_COST_STAGE_FAILED')
        for key in ('cpu_ns', 'wall_ns'):
            _cost_integer_v2(event[key], 'RUNTIME_COST_STAGE_NUMBER')
        _cost_integer_v2(event['memory_peak_bytes'], 'RUNTIME_COST_RSS', 1)
        _runtime_require(event['memory_peak_bytes'] <= budget['rss_bytes'], 'RUNTIME_COST_BUDGET_EXCEEDED')
        for key in ('bytes_read', 'bytes_written', 'gpu_ns'):
            if event[key] is None:
                missing.append(event['stage'] + ':' + key)
            else:
                _cost_integer_v2(event[key], 'RUNTIME_COST_STAGE_NUMBER')
        _runtime_require(plan['backend'] != 'cpu' or event['gpu_ns'] == 0,
                        'RUNTIME_COST_CPU_GPU_SCOPE')
    return dict(name=name, phase=phase, role=role, experiment=_identity(plan),
                contract=receipt['contract'], source_weight_sha256=receipt['source_weight_sha256'],
                derived_backbone_root=receipt['derived_backbone_root'], parameter_count=receipt['parameter_count'],
                child_receipt=_identity(receipt), supervisor=_identity(supervisor),
                observed_wall_ns=monitored_wall, waited_child_cpu_ns=waited_cpu,
                observer_cpu_ns=observer_cpu, child_reported_wall_ns=child_wall,
                child_reported_cpu_ns=child_cpu, sampled_peak_rss_bytes=sampled_rss,
                waited_child_peak_rss_bytes=waited_rss, child_reported_peak_rss_bytes=child_rss,
                stage_bytes_read=None if any(e['bytes_read'] is None for e in events)
                    else _cost_sum_v2(e['bytes_read'] for e in events),
                stage_bytes_written=None if any(e['bytes_written'] is None for e in events)
                    else _cost_sum_v2(e['bytes_written'] for e in events),
                stage_gpu_ns=None if any(e['gpu_ns'] is None for e in events)
                    else _cost_sum_v2(e['gpu_ns'] for e in events),
                missing_channels=missing, local_channels_complete=not missing)


# Frozen v3 training validation. The legacy v2 interpreter above never
# invokes these stricter checks or rewrites its original stored claims.
def _training_receipt_v3(plan, role, receipt):
    """Validate existing training observations without inventing a token trace.

    The child reports aggregate counts and one finite loss per training step.
    It does not record ordered token IDs or per-step task/token commitments.
    Equal reported totals therefore cannot verify the actual token schedule.
    """
    _runtime_require(type(receipt) is dict and type(receipt.get('training')) is dict,
                    'RUNTIME_TRAINING_FIELDS')
    training = receipt['training']
    _runtime_require(set(training) == {'steps', 'loss', 'tokens', 'supervised_tokens',
                                     'supported_profile_flops', 'flop_scope'} and
                    training['flop_scope'] == 'profiler-supported-operators-only-not-total-work',
                    'RUNTIME_TRAINING_FIELDS')
    numbers = {key: _cost_integer_v2(training[key], 'RUNTIME_TRAINING_NUMBER') for key in
               ('steps', 'tokens', 'supervised_tokens', 'supported_profile_flops')}
    steps, tokens, supervised = (numbers['steps'], numbers['tokens'], numbers['supervised_tokens'])
    _runtime_require(type(plan.get('training_steps')) is int and 1 <= plan['training_steps'] <= 100 and
                    type(plan.get('input_tokens_max')) is int and plan['input_tokens_max'] == 128 and
                    type(plan.get('tasks')) is list and
                    all(type(row) is dict for row in plan['tasks']) and
                    any(row.get('partition') == 'training' for row in plan['tasks']) and
                    role in _PARTICIPANT_KINDS_V1, 'RUNTIME_TRAINING_PLAN')
    trained = _PARTICIPANT_KINDS_V1[role] in ('lora', 'full-tune')
    _runtime_require(steps == (plan['training_steps'] if trained else 0), 'RUNTIME_TRAINING_STEPS')
    losses = training['loss']
    _runtime_require(type(losses) is list and len(losses) == steps, 'RUNTIME_TRAINING_LOSS')
    for value in losses:
        _runtime_require(type(value) is str and 0 < len(value) <= 64 and value.isascii() and
                        value == value.strip(), 'RUNTIME_TRAINING_LOSS')
        try:
            number = float(value)
            exact = Decimal(value)
        except (ValueError, InvalidOperation) as error:
            raise ValueError('RUNTIME_TRAINING_LOSS') from error
        # A negative decimal can underflow to binary64 -0.0. Check its exact
        # sign as well; the legitimate formatted '-0' still compares as zero.
        _runtime_require(math.isfinite(number) and exact.is_finite() and exact >= 0,
                        'RUNTIME_TRAINING_LOSS')
    if trained:
        # train() adds three supervised EOS tokens and requires a nonempty
        # prompt on every step. All tokens fit the same frozen per-step bound.
        _runtime_require(3 * steps <= supervised and supervised + steps <= tokens <=
                        steps * plan['input_tokens_max'], 'RUNTIME_TRAINING_TOKENS')
    else:
        _runtime_require(tokens == supervised == numbers['supported_profile_flops'] == 0,
                        'RUNTIME_TRAINING_ZERO_ROLE')
    return training


def _validate_training_match_v3(plan, receipts):
    """Match validated steps and reported totals across the three trained roles."""
    _runtime_require(type(receipts) is dict and
                    all('train-' + role in receipts for role in _PARTICIPANTS_V1),
                    'RUNTIME_TRAINING_RECEIPTS')
    training = {role: _training_receipt_v3(plan, role, receipts['train-' + role])
                for role in _PARTICIPANTS_V1}
    totals = {(row['steps'], row['tokens'], row['supervised_tokens'])
              for role, row in training.items()
              if _PARTICIPANT_KINDS_V1[role] in ('lora', 'full-tune')}
    _runtime_require(len(totals) == 1, 'RUNTIME_MATCHED_TRAINING_BUDGET')
    return True


def _observe_phase_contained_v2(plan, name, phase, role, supervisor, receipt):
    """Frozen current profile: physical containment and v3 training checks."""
    result = _observe_phase_v2(plan, name, phase, role, supervisor, receipt)
    child_wall, child_cpu, child_rss = (receipt['process_wall_ns'], receipt['process_cpu_ns'],
                                      receipt['process_peak_rss_bytes'])
    waited_cpu = supervisor['child_cpu_ns']
    slack = 2_000 + math.ceil(4 * math.ulp(2.0 * max(waited_cpu, 1))) + 1
    _runtime_require(child_wall <= supervisor['observed_wall_ns'], 'RUNTIME_COST_WALL_CONTAINMENT')
    _runtime_require(child_cpu - waited_cpu <= slack, 'RUNTIME_COST_CPU_CONTAINMENT')
    _runtime_require(child_rss <= supervisor['waited_child_peak_rss_bytes'], 'RUNTIME_COST_RSS_CONTAINMENT')
    events = receipt['cost_events']
    _runtime_require(all(event['memory_peak_bytes'] <= child_rss for event in events),
                     'RUNTIME_COST_STAGE_RSS_CONTAINMENT')
    _runtime_require(_cost_sum_v2(event['wall_ns'] for event in events) <= child_wall,
                     'RUNTIME_COST_STAGE_WALL_CONTAINMENT')
    _runtime_require(_cost_sum_v2(event['cpu_ns'] for event in events) <= child_cpu,
                     'RUNTIME_COST_STAGE_CPU_CONTAINMENT')
    if phase == 'train':
        _training_receipt_v3(plan, role, receipt)
    return result


def _profile_observer(profile):
    if profile == _LEGACY_REPLAY:
        return _observe_phase_v2
    _require(profile == _CONTAINED_REPLAY, 'REPLAY_PROFILE')
    return _observe_phase_contained_v2


def _cost_score_v2(value):
    _runtime_require(type(value) is list and len(value) == 2,
                    'RUNTIME_ASSESSMENT_SCORE')
    numerator = _cost_integer_v2(value[0], 'RUNTIME_ASSESSMENT_SCORE')
    denominator = _cost_integer_v2(value[1], 'RUNTIME_ASSESSMENT_SCORE', 1)
    _runtime_require(numerator <= denominator, 'RUNTIME_ASSESSMENT_SCORE')
    return Fraction(numerator, denominator)


def _build_assessment_v2(plan, roster, scores, records, receipts, *, observer=_observe_phase_v2):
    """Replay the immutable historical v2 assessment from all twelve observations.

    Caller supplies the already verified output scores. Their metric is still one
    public exact-output channel, so it cannot satisfy complete release assessment.
    """
    _runtime_require(type(roster) is dict and roster.get('experiment') == _identity(plan) and
                    roster.get('frozen_before_evaluation') is True and
                    type(roster.get('artifacts')) is dict and
                    set(roster['artifacts']) == set(_PARTICIPANTS_V1) and
                    len(set(roster['artifacts'].values())) == len(_PARTICIPANTS_V1),
                    'RUNTIME_ASSESSMENT_ROSTER')
    order = [('loader-1thread', 'loader', 'current-backbone'),
             ('loader-reference', 'loader', 'current-backbone')]
    order += [('train-' + r, 'train', r) for r in _PARTICIPANTS_V1]
    order += [('evaluate-' + r, 'evaluate', r) for r in _PARTICIPANTS_V1]
    names = [row[0] for row in order]
    _runtime_require(type(records) is list and len(records) == len(order) and
                    [r.get('name') if type(r) is dict else None for r in records] == names and
                    type(receipts) is dict and set(receipts) == set(names),
                    'RUNTIME_ASSESSMENT_PHASE_SET')
    observations = []
    for (name, phase, role), record in zip(order, records):
        actual_plan = dict(plan, threads=1) if name == 'loader-1thread' else plan
        supervisor = {k: v for k, v in record.items() if k != 'name'}
        receipt = receipts[name]
        row = observer(actual_plan, name, phase, role, supervisor, receipt)
        _runtime_require((name == 'loader-1thread' or receipt.get('contract') == roster.get('contract')) and
                        (phase == 'loader' or receipt.get('artifact') == roster['artifacts'][role]),
                        'RUNTIME_ASSESSMENT_ARTIFACT_BINDING')
        observations.append(row)
    _runtime_require(type(scores) is dict and set(scores) == set(_PARTICIPANTS_V1),
                    'RUNTIME_ASSESSMENT_SCORE_SET')
    values = {}
    for role, row in scores.items():
        _runtime_require(type(row) is dict and set(row) == {'calibration', 'evaluation'},
                        'RUNTIME_ASSESSMENT_SCORE_SET')
        values[role] = {partition: _cost_score_v2(value) for partition, value in row.items()}
    selected = max(_CONTROLS_V1, key=lambda r: (values[r]['calibration'], -_CONTROLS_V1.index(r)))
    gain = values['candidate']['evaluation'] - max(values[r]['evaluation'] for r in _CONTROLS_V1)
    aggregate = {
        'observed_sequential_phase_wall_ns': _cost_sum_v2(r['observed_wall_ns'] for r in observations),
        'waited_child_cpu_ns': _cost_sum_v2(r['waited_child_cpu_ns'] for r in observations),
        'observer_cpu_ns': _cost_sum_v2(r['observer_cpu_ns'] for r in observations),
        'max_waited_child_peak_rss_bytes': max(r['waited_child_peak_rss_bytes'] for r in observations),
        'max_sampled_child_peak_rss_bytes': max(r['sampled_peak_rss_bytes'] for r in observations),
    }
    for key in ('stage_bytes_read', 'stage_bytes_written', 'stage_gpu_ns'):
        aggregate[key] = None if any(r[key] is None for r in observations) else _cost_sum_v2(r[key] for r in observations)
    return dict(schema='llm-runtime-actual-pilot-assessment-v2',
                experiment=_identity(plan), roster=_identity(roster),
                source=plan['runtime_source'],
                scope='actual-local-short-LLM-pilot-no-future-independent-quality-or-native-admission',
                scores=scores, calibration_selected_control=selected,
                gain_vs_strongest_evaluation_control=[gain.numerator, gain.denominator],
                positive_vs_all_controls=gain > 0, all_required_controls_executed=True,
                training_budget_matched_by_steps_and_token_schedule=True,
                consumption_not_assumed_equal=True,
                output_byte_metric='equal-source-group-exact-output-bytes',
                phases=records, cost_observations=observations, aggregate_observed_costs=aggregate,
                local_process_channels_complete=all(r['local_channels_complete'] for r in observations),
                cost_scope='Sequential process-return observations; stage IO is partial; peaks are maxima, not sums. '
                           'No measured value is a full release-lifetime cost or monetary utility.',
                complete_economic_cost=False, complete_release_evaluation=False,
                net_benefit_lower_bound=None, decision='incomplete', no_update=False,
                adoption=False, reward=False, unresolved_obligations=list(_MISSING_OBLIGATIONS_V2),
                **{flag: False for flag in _QUALIFICATIONS_V1})


def _build_assessment_contained_v3(plan, roster, scores, records, receipts):
    record = _build_assessment_v2(plan, roster, scores, records, receipts,
                                  observer=_observe_phase_contained_v2)
    matched = _validate_training_match_v3(plan, receipts)
    record['schema'] = 'llm-runtime-actual-pilot-assessment-v3'
    del record['training_budget_matched_by_steps_and_token_schedule']
    record.update(training_steps_and_reported_token_counts_matched=matched,
                  actual_token_schedule_verified=False)
    record['unresolved_obligations'].append(
        'actual-per-step-token-schedule-commitments-and-cross-role-verification')
    return record


def _profile_assessment(profile):
    if profile == _LEGACY_REPLAY:
        return _build_assessment_v2
    _require(profile == _CONTAINED_REPLAY, 'REPLAY_PROFILE')
    return _build_assessment_contained_v3


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
        policy = _policy(json.loads(raw, object_pairs_hook=_unique))
        _require(_payload(policy) == raw and _identity(policy) == policy_id ==
                 self.expected_policy, 'POLICY_BINDING')
        attempts, checkpoint = {}, _genesis(policy_id)
        for expected_seq, row in enumerate(db.execute(
                'SELECT seq, trial, kind, payload, previous, root FROM events ORDER BY seq'), 1):
            seq, trial, kind, raw, previous, root = row
            _digest(trial)
            _require(seq == expected_seq and previous == checkpoint and
                     type(raw) is str and len(raw) <= MAX_PAYLOAD, 'JOURNAL_LINK')
            value = json.loads(raw, object_pairs_hook=_unique)
            _require(_payload(value) == raw and
                     _event_root(seq, trial, kind, value, previous) == root, 'JOURNAL_ROOT')
            self._apply(attempts, policy, trial, kind, value)
            checkpoint = root
        return policy, checkpoint, attempts, count

    @staticmethod
    def _apply(attempts, policy, trial, kind, value):
        if kind in ('reserve', 'reserve-v2'):
            _require(trial not in attempts and len(attempts) < policy['max_attempts'],
                     'ALLOWANCE_OR_REPLAY')
            _require(type(value) is dict and type(value.get('plan')) is dict, 'PLAN_BINDING')
            plan = value['plan']
            _stored_plan_v1(plan, policy, trial)
            profile = _reservation_profile(kind, value)
            _require(_identity(plan) == value['plan_id'], 'PLAN_BINDING')
            _require(all(type(value[k]) is str and 1 <= len(value[k]) <= 256
                         for k in ('related_identity', 'host')), 'OBSERVATION_METADATA')
            _integer(value['observed_at_ns'], 1, (1 << 63) - 1)
            _require(value['alpha_per_comparison'] == _allocation(policy), 'ALPHA_BINDING')
            attempts[trial] = dict(state='reserved', reservation=value, replay_profile=profile,
                                   phases=[], receipts={}, roster=None, terminal=None)
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
            _profile_observer(attempt['replay_profile'])(actual, name, phase, role,
                attempt['phases'][-1]['observation'], value['receipt'])
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
                     set(value['artifacts']) == set(_PARTICIPANTS_V1) and
                     len(set(value['artifacts'].values())) == len(_PARTICIPANTS_V1), 'ROSTER_ARTIFACTS')
            for artifact in value['artifacts'].values():
                _digest(artifact)
            # The one-thread loader has a distinct plan-bound contract. It is
            # a loader control, not one of the five evaluated artifacts.
            _require(all(receipt.get('contract') == value['contract']
                         for name, receipt in attempt['receipts'].items() if name != 'loader-1thread') and
                     all(attempt['receipts']['train-' + role].get('artifact') == artifact
                         for role, artifact in value['artifacts'].items()), 'TRAINED_ROSTER_BINDING')
            if attempt['replay_profile'] == _CONTAINED_REPLAY:
                _validate_training_match_v3(attempt['reservation']['plan'], attempt['receipts'])
            attempt.update(state='evaluating', roster=value)
        elif kind == 'terminal':
            _closed(value, 'outcome record record_id')
            _require(value['outcome'] in ('aborted', 'complete-unqualified') and
                     type(value['record']) is dict and
                     _identity(value['record']) == value['record_id'], 'TERMINAL_RECORD')
            record = value['record']
            _require(all(record.get(k) is False for k in _QUALIFICATIONS_V1) and
                     record.get('adoption') is False and record.get('reward') is False and
                     record.get('no_update') is False,
                     'TERMINAL_AUTHORITY')
            _require(record.get('experiment') == attempt['reservation']['plan_id'], 'TERMINAL_PLAN')
            expected_phases = [dict(name=p['name'], **p['observation']) for p in attempt['phases']]
            _require(record.get('phases') == expected_phases, 'TERMINAL_PHASES')
            if value['outcome'] == 'complete-unqualified':
                _require(attempt['state'] == 'evaluating' and len(attempt['phases']) == len(PHASES) and
                         len(attempt['receipts']) == len(PHASES) and
                         all(p['observation']['outcome'] == 'success' for p in attempt['phases']) and
                         record.get('roster') == _identity(attempt['roster']), 'TERMINAL_INCOMPLETE')
                checked = _profile_assessment(attempt['replay_profile'])(
                    attempt['reservation']['plan'], attempt['roster'], record.get('scores'),
                    expected_phases, attempt['receipts'])
                _require(_canonical(record) == _canonical(checked), 'TERMINAL_COST_BINDING')
            else:
                _require(record.get('outcome') == 'aborted', 'ABORT_OUTCOME')
            attempt.update(state=value['outcome'], terminal=value)
        else:
            raise ValueError('TRIAL_EVENT_KIND')

    def _append(self, db, policy, checkpoint, attempts, count, trial, kind, value):
        _require(count < MAX_EVENTS, 'CAPACITY')
        raw = _payload(value)
        self._apply(attempts, policy, trial, kind, value)
        self._validate_new_event(attempts[trial], kind, value)
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

    @staticmethod
    def _validate_new_event(attempt, kind, value):
        # A pure historical read must not import today's runner dependencies.
        # New effects, however, must use the exact currently admitted components
        # and satisfy current cost checks as well as their stored-format rules.
        # An old pending attempt may still be marked aborted after an upgrade.
        if kind in ('reserve', 'reserve-v2') or (kind == 'terminal' and value['outcome'] == 'aborted'):
            return
        import llm_runtime_pilot as runtime
        plan = attempt['reservation']['plan']
        runtime.validate_plan(plan)
        if kind == 'child-receipt':
            from llm_runtime_assessment import observe_phase
            name = value['name']
            phase, role = ('loader', 'current-backbone') if name.startswith('loader-') else name.split('-', 1)
            actual = dict(plan, threads=1) if name == 'loader-1thread' else plan
            observe_phase(actual, name, phase, role, attempt['phases'][-1]['observation'], value['receipt'])
        elif kind == 'freeze-roster':
            from llm_runtime_assessment import validate_training_match
            validate_training_match(plan, attempt['receipts'])
        elif kind == 'terminal':
            from llm_runtime_assessment import build_assessment
            records = [dict(name=p['name'], **p['observation']) for p in attempt['phases']]
            checked = build_assessment(plan, attempt['roster'], value['record'].get('scores'),
                                       records, attempt['receipts'])
            _require(_canonical(checked) == _canonical(value['record']), 'CURRENT_ASSESSMENT_BINDING')

    def reserve(self, plan, trial, expected_checkpoint, related_identity):
        import llm_runtime_pilot as runtime
        runtime.validate_plan(plan)
        _digest(trial)
        _digest(expected_checkpoint)
        _require(plan.get('schema') == 'llm-runtime-registered-public-pilot-plan-v1' and
                 plan.get('trial_policy') == self.expected_policy and plan.get('trial_id') == trial,
                 'REGISTERED_PLAN')
        _require(plan.get('model_family_configuration_sha256') in _FAMILY_CONTEXT_V1,
                 'FAMILY_CONTEXT')
        value = dict(schema=_RESERVATION_V2, replay_profile=_CONTAINED_REPLAY,
                     plan=plan, plan_id=_identity(plan), related_identity=related_identity,
                     host=socket.gethostname(), observed_at_ns=time.time_ns())
        with self._transaction() as (db, policy, checkpoint, attempts, count):
            _require(checkpoint == expected_checkpoint, 'STALE_CHECKPOINT')
            value['alpha_per_comparison'] = _allocation(policy)
            receipt = self._append(db, policy, checkpoint, attempts, count, trial, 'reserve-v2', value)
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
                                                       record_id=_identity(record)))

    def reconcile(self, trial, expected_plan, minimum_checkpoint):
        """Observe one uncertain trial without retrying any of its effects.

        The caller must retain minimum_checkpoint outside a database rollback.
        A current journal may extend that checkpoint, but must contain it. A
        missing trial only means that this journal has no committed reservation;
        it cannot settle external effects or authorize a new attempt. Restoring
        both the database and the caller's anchor remains outside this guarantee.
        """
        for value in (trial, expected_plan, minimum_checkpoint):
            _digest(value)
        with self._transaction() as (db, policy, checkpoint, attempts, count):
            # _transaction has already replayed every immutable event and checked
            # its policy, schema and hash links under this same SQLite snapshot.
            if minimum_checkpoint == _genesis(self.expected_policy):
                minimum_sequence = 0
            else:
                anchored = db.execute('SELECT seq FROM events WHERE root=?',
                                      (minimum_checkpoint,)).fetchall()
                _require(len(anchored) == 1, 'RECONCILE_CHECKPOINT_NOT_RETAINED')
                minimum_sequence = anchored[0][0]
            attempt = attempts.get(trial)
            if attempt is not None:
                _require(attempt['reservation']['plan_id'] == expected_plan,
                         'RECONCILE_PLAN_BINDING')
            events = [dict(sequence=seq, kind=kind, checkpoint=root)
                      for seq, kind, root in db.execute(
                          'SELECT seq, kind, root FROM events WHERE trial=? ORDER BY seq', (trial,))]
            terminal = attempt['terminal'] if attempt else None
            return dict(schema='llm-runtime-trial-reconciliation-v1', scope=SCOPE,
                policy=self.expected_policy, trial=trial, plan=expected_plan,
                minimum_checkpoint=minimum_checkpoint, minimum_sequence=minimum_sequence,
                checkpoint=checkpoint, event_count=count,
                spent=len(attempts), maximum=policy['max_attempts'],
                target_observed=attempt is not None,
                state=attempt['state'] if attempt else 'not-observed',
                committed_events=events,
                child_receipt_ids={name: _identity(receipt) for name, receipt in
                                   attempt['receipts'].items()} if attempt else {},
                roster_id=_identity(attempt['roster']) if attempt and attempt['roster'] else None,
                terminal_record_id=terminal['record_id'] if terminal else None,
                external_effects_state='UNKNOWN', retry_authorized=False,
                refund_authorized=False, installation_verified=False,
                final_use_verified=False, statistical_acceptance=False)

    def inspect(self):
        """Unanchored readback; use reconcile for exact trial and retained-checkpoint checks."""
        with self._transaction() as (_, policy, checkpoint, attempts, _):
            return dict(policy=policy, policy_id=self.expected_policy, checkpoint=checkpoint,
                        spent=len(attempts), attempts=attempts, scope=SCOPE)
