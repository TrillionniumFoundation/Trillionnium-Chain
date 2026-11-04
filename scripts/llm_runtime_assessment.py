"""Validate actual pilot costs before writing its observation-only assessment.

This is the existing pilot's return boundary, not an economic selector. Missing
physical channels stay missing. A complete local process observation does not
supply a release closure, prospective cohort, tariff, horizon or FinalUse owner.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json

import llm_runtime_pilot as runtime

LIMIT = (1 << 63) - 1
COMMON = ('material-verification', 'declared-family-check', 'runtime-import',
          'model-load', 'derived-material-check')
MISSING_OBLIGATIONS = (
    'full-release-composition-and-serving-profile',
    'independent-prospective-and-family-multiplicity-evidence',
    'separate-routing-old-task-rare-cohort-calibration-and-cold-warm-metrics',
    'frozen-economic-tariffs-horizon-and-minimum-net-benefit',
    'complete-search-failures-download-activation-serving-storage-repair-rollback-and-future-selection-costs',
    'release-rate-and-retained-byte-owner-enforcement',
    'current-generation-final-use-and-accepted-no-update-owner',
)


def _integer(value, code, lower=0):
    runtime.require(type(value) is int and lower <= value <= LIMIT, code)
    return value


def _sum(values):
    value = sum(values)
    return _integer(value, 'RUNTIME_COST_OVERFLOW')


def _material_context(plan, receipt):
    # A thread-count-specific plan has a different target_admission and contract
    # digest. Both loader plans must still observe exactly the frozen material.
    contract = receipt.get('contract')
    runtime.require(type(contract) is str and len(contract) == 64 and
                    all(c in '0123456789abcdef' for c in contract) and contract != '0' * 64,
                    'RUNTIME_COST_CONTRACT')
    raw = runtime.FAMILY_PATH.read_bytes()
    runtime.require(hashlib.sha256(raw).hexdigest() == plan.get('model_family_configuration_sha256'),
                    'RUNTIME_COST_FAMILY_BINDING')
    family = runtime.verify_family(json.loads(raw, object_pairs_hook=runtime.unique))
    runtime.require(receipt.get('source_weight_sha256') == runtime.WEIGHT_SHA and
                    receipt.get('derived_backbone_root') == family['material_pins']['fp32_backbone_index_root'] and
                    type(receipt.get('parameter_count')) is int and
                    receipt['parameter_count'] == 134515008, 'RUNTIME_COST_MATERIAL_BINDING')


def _stages(phase, role):
    stages = list(COMMON)
    if phase in ('loader', 'evaluate'):
        return stages + ['real-forward-greedy-decode']
    kind = runtime.PARTICIPANT_KINDS[role]
    if kind in ('lora', 'random-lora'):
        stages.append('adapter-insertion')
    stages.append('training')
    if kind in ('lora', 'random-lora'):
        stages.append('adapter-material-check')
    if kind != 'immutable-backbone':
        stages += ['artifact-save', 'artifact-domain-hash']
    return stages


def observe_phase(plan, name, phase, role, supervisor, receipt):
    """Bind one child receipt to the monitored call; reject absent CPU/RSS.

    IO and GPU time are optional physical observations in the old runtime. Their
    absence is preserved with an incomplete-channel marker, never imputed as zero.
    Outer elapsed/CPU and child elapsed/CPU overlap and are reported separately.
    """
    runtime.require(phase in ('loader', 'train', 'evaluate') and role in runtime.PARTICIPANTS,
                    'RUNTIME_COST_PHASE')
    runtime.require(type(supervisor) is dict and type(receipt) is dict, 'RUNTIME_COST_RECORD')
    runtime.require(type(supervisor.get('exit_code')) is int and supervisor['exit_code'] == 0 and
                    supervisor.get('outcome') == 'success' and supervisor.get('stop_reason') is None and
                    supervisor.get('waited_child_reaped') is True and
                    supervisor.get('owned_child_reap_resolved') is True and
                    supervisor.get('child_spawned') is True and
                    supervisor.get('waited_child_observation_error') is None,
                    'RUNTIME_COST_SUPERVISOR_INCOMPLETE')
    runtime.require(receipt.get('schema') == 'llm-runtime-actual-child-v1' and
                    receipt.get('outcome') == 'success' and receipt.get('phase') == phase and
                    receipt.get('role') == role and receipt.get('experiment') == runtime.identity(plan) and
                    receipt.get('runtime_source') == plan['runtime_source'] and
                    receipt.get('actual_backend') == plan['backend'] and
                    type(receipt.get('actual_threads')) is int and
                    receipt['actual_threads'] == plan['threads'] and
                    receipt.get('scope') == 'local-actual-runtime-no-native-admission' and
                    all(receipt.get(flag) is False for flag in runtime.QUALIFICATIONS),
                    'RUNTIME_COST_CHILD_BINDING')
    _material_context(plan, receipt)
    budget = plan['training_budget' if phase == 'train' else 'inference_budget']
    runtime.require(supervisor.get('budget') == budget, 'RUNTIME_COST_BUDGET_BINDING')
    monitored_wall = _integer(supervisor.get('observed_wall_ns'), 'RUNTIME_COST_WALL', 1)
    waited_cpu = _integer(supervisor.get('child_cpu_ns'), 'RUNTIME_COST_CPU')
    observer_cpu = _integer(supervisor.get('observer_cpu_ns'), 'RUNTIME_COST_CPU')
    sampled_rss = _integer(supervisor.get('sampled_peak_rss_bytes'), 'RUNTIME_COST_RSS')
    waited_rss = _integer(supervisor.get('waited_child_peak_rss_bytes'), 'RUNTIME_COST_RSS', 1)
    child_wall = _integer(receipt.get('process_wall_ns'), 'RUNTIME_COST_WALL', 1)
    child_cpu = _integer(receipt.get('process_cpu_ns'), 'RUNTIME_COST_CPU')
    child_rss = _integer(receipt.get('process_peak_rss_bytes'), 'RUNTIME_COST_RSS', 1)
    runtime.require(max(sampled_rss, waited_rss, child_rss) <= budget['rss_bytes'] and
                    monitored_wall <= budget['wall_seconds'] * 1_000_000_000,
                    'RUNTIME_COST_BUDGET_EXCEEDED')
    events = receipt.get('cost_events')
    expected = _stages(phase, role)
    runtime.require(type(events) is list and len(events) == len(expected) and
                    [e.get('stage') if type(e) is dict else None for e in events] == expected,
                    'RUNTIME_COST_STAGE_SET')
    missing = []
    for event in events:
        runtime.require(set(event) == {'stage', 'outcome', 'error_type', 'cpu_ns', 'wall_ns',
                                      'memory_peak_bytes', 'bytes_read', 'bytes_written', 'gpu_ns'} and
                        event['outcome'] == 'success' and event['error_type'] is None,
                        'RUNTIME_COST_STAGE_FAILED')
        for key in ('cpu_ns', 'wall_ns'):
            _integer(event[key], 'RUNTIME_COST_STAGE_NUMBER')
        _integer(event['memory_peak_bytes'], 'RUNTIME_COST_RSS', 1)
        runtime.require(event['memory_peak_bytes'] <= budget['rss_bytes'], 'RUNTIME_COST_BUDGET_EXCEEDED')
        for key in ('bytes_read', 'bytes_written', 'gpu_ns'):
            if event[key] is None:
                missing.append(event['stage'] + ':' + key)
            else:
                _integer(event[key], 'RUNTIME_COST_STAGE_NUMBER')
        runtime.require(plan['backend'] != 'cpu' or event['gpu_ns'] == 0,
                        'RUNTIME_COST_CPU_GPU_SCOPE')
    return dict(name=name, phase=phase, role=role, experiment=runtime.identity(plan),
                contract=receipt['contract'], source_weight_sha256=receipt['source_weight_sha256'],
                derived_backbone_root=receipt['derived_backbone_root'], parameter_count=receipt['parameter_count'],
                child_receipt=runtime.identity(receipt), supervisor=runtime.identity(supervisor),
                observed_wall_ns=monitored_wall, waited_child_cpu_ns=waited_cpu,
                observer_cpu_ns=observer_cpu, child_reported_wall_ns=child_wall,
                child_reported_cpu_ns=child_cpu, sampled_peak_rss_bytes=sampled_rss,
                waited_child_peak_rss_bytes=waited_rss, child_reported_peak_rss_bytes=child_rss,
                stage_bytes_read=None if any(e['bytes_read'] is None for e in events)
                    else _sum(e['bytes_read'] for e in events),
                stage_bytes_written=None if any(e['bytes_written'] is None for e in events)
                    else _sum(e['bytes_written'] for e in events),
                stage_gpu_ns=None if any(e['gpu_ns'] is None for e in events)
                    else _sum(e['gpu_ns'] for e in events),
                missing_channels=missing, local_channels_complete=not missing)


def _score(value):
    runtime.require(type(value) is list and len(value) == 2,
                    'RUNTIME_ASSESSMENT_SCORE')
    numerator = _integer(value[0], 'RUNTIME_ASSESSMENT_SCORE')
    denominator = _integer(value[1], 'RUNTIME_ASSESSMENT_SCORE', 1)
    runtime.require(numerator <= denominator, 'RUNTIME_ASSESSMENT_SCORE')
    return Fraction(numerator, denominator)


def build_assessment(plan, roster, scores, records, receipts):
    """Build v2 at the actual runner return after all twelve phase observations.

    Caller supplies the already verified output scores. Their metric is still one
    public exact-output channel, so it cannot satisfy complete release assessment.
    """
    runtime.require(type(roster) is dict and roster.get('experiment') == runtime.identity(plan) and
                    roster.get('frozen_before_evaluation') is True and
                    type(roster.get('artifacts')) is dict and
                    set(roster['artifacts']) == set(runtime.PARTICIPANTS) and
                    len(set(roster['artifacts'].values())) == len(runtime.PARTICIPANTS),
                    'RUNTIME_ASSESSMENT_ROSTER')
    order = [('loader-1thread', 'loader', 'current-backbone'),
             ('loader-reference', 'loader', 'current-backbone')]
    order += [('train-' + r, 'train', r) for r in runtime.PARTICIPANTS]
    order += [('evaluate-' + r, 'evaluate', r) for r in runtime.PARTICIPANTS]
    names = [row[0] for row in order]
    runtime.require(type(records) is list and len(records) == len(order) and
                    [r.get('name') if type(r) is dict else None for r in records] == names and
                    type(receipts) is dict and set(receipts) == set(names),
                    'RUNTIME_ASSESSMENT_PHASE_SET')
    observations = []
    for (name, phase, role), record in zip(order, records):
        actual_plan = dict(plan, threads=1) if name == 'loader-1thread' else plan
        supervisor = {k: v for k, v in record.items() if k != 'name'}
        receipt = receipts[name]
        row = observe_phase(actual_plan, name, phase, role, supervisor, receipt)
        runtime.require((name == 'loader-1thread' or receipt.get('contract') == roster.get('contract')) and
                        (phase == 'loader' or receipt.get('artifact') == roster['artifacts'][role]),
                        'RUNTIME_ASSESSMENT_ARTIFACT_BINDING')
        observations.append(row)
    runtime.require(type(scores) is dict and set(scores) == set(runtime.PARTICIPANTS),
                    'RUNTIME_ASSESSMENT_SCORE_SET')
    values = {}
    for role, row in scores.items():
        runtime.require(type(row) is dict and set(row) == {'calibration', 'evaluation'},
                        'RUNTIME_ASSESSMENT_SCORE_SET')
        values[role] = {partition: _score(value) for partition, value in row.items()}
    selected = max(runtime.CONTROLS, key=lambda r: (values[r]['calibration'], -runtime.CONTROLS.index(r)))
    gain = values['candidate']['evaluation'] - max(values[r]['evaluation'] for r in runtime.CONTROLS)
    aggregate = {
        'observed_sequential_phase_wall_ns': _sum(r['observed_wall_ns'] for r in observations),
        'waited_child_cpu_ns': _sum(r['waited_child_cpu_ns'] for r in observations),
        'observer_cpu_ns': _sum(r['observer_cpu_ns'] for r in observations),
        'max_waited_child_peak_rss_bytes': max(r['waited_child_peak_rss_bytes'] for r in observations),
        'max_sampled_child_peak_rss_bytes': max(r['sampled_peak_rss_bytes'] for r in observations),
    }
    for key in ('stage_bytes_read', 'stage_bytes_written', 'stage_gpu_ns'):
        aggregate[key] = None if any(r[key] is None for r in observations) else _sum(r[key] for r in observations)
    return dict(schema='llm-runtime-actual-pilot-assessment-v2',
                experiment=runtime.identity(plan), roster=runtime.identity(roster),
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
                adoption=False, reward=False, unresolved_obligations=list(MISSING_OBLIGATIONS),
                **{flag: False for flag in runtime.QUALIFICATIONS})
