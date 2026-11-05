"""Validate actual pilot costs before writing its observation-only assessment.

This is the existing pilot's return boundary, not an economic selector. Missing
physical channels stay missing. A complete local process observation does not
supply a release closure, prospective cohort, tariff, horizon or FinalUse owner.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from fractions import Fraction
import hashlib
import json
import math

import llm_runtime_pilot as runtime

LIMIT = (1 << 63) - 1
WAIT4_CPU_TRUNCATION_NS = 2_000
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
    'actual-per-step-token-schedule-commitments-and-cross-role-verification',
)


def _integer(value, code, lower=0):
    runtime.require(type(value) is int and lower <= value <= LIMIT, code)
    return value


def _sum(values):
    value = sum(values)
    return _integer(value, 'RUNTIME_COST_OVERFLOW')


def _wait4_cpu_slack_ns(waited_cpu):
    # Linux wait4 exposes two timeval channels, each truncated below 1us. The
    # runner then rounds (user_seconds + system_seconds) * 1e9 from binary64.
    # Four ulps at twice the total cover input conversion, addition and scaling;
    # the final integer rounding gets one more ns. This is at most 18,385ns for
    # the entire accepted integer range, not a workload-dependent percentage.
    roundoff = math.ceil(4 * math.ulp(2.0 * max(waited_cpu, 1))) + 1
    return WAIT4_CPU_TRUNCATION_NS + roundoff


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


def _training_receipt(plan, role, receipt):
    """Validate existing training observations without inventing a token trace.

    The child reports aggregate counts and one finite loss per training step.
    It does not record ordered token IDs or per-step task/token commitments.
    Equal reported totals therefore cannot verify the actual token schedule.
    """
    runtime.require(type(receipt) is dict and type(receipt.get('training')) is dict,
                    'RUNTIME_TRAINING_FIELDS')
    training = receipt['training']
    runtime.require(set(training) == {'steps', 'loss', 'tokens', 'supervised_tokens',
                                     'supported_profile_flops', 'flop_scope'} and
                    training['flop_scope'] == 'profiler-supported-operators-only-not-total-work',
                    'RUNTIME_TRAINING_FIELDS')
    numbers = {key: _integer(training[key], 'RUNTIME_TRAINING_NUMBER') for key in
               ('steps', 'tokens', 'supervised_tokens', 'supported_profile_flops')}
    steps, tokens, supervised = (numbers['steps'], numbers['tokens'], numbers['supervised_tokens'])
    runtime.require(type(plan.get('training_steps')) is int and 1 <= plan['training_steps'] <= 100 and
                    type(plan.get('input_tokens_max')) is int and plan['input_tokens_max'] == 128 and
                    type(plan.get('tasks')) is list and
                    all(type(row) is dict for row in plan['tasks']) and
                    any(row.get('partition') == 'training' for row in plan['tasks']) and
                    role in runtime.PARTICIPANT_KINDS, 'RUNTIME_TRAINING_PLAN')
    trained = runtime.PARTICIPANT_KINDS[role] in ('lora', 'full-tune')
    runtime.require(steps == (plan['training_steps'] if trained else 0), 'RUNTIME_TRAINING_STEPS')
    losses = training['loss']
    runtime.require(type(losses) is list and len(losses) == steps, 'RUNTIME_TRAINING_LOSS')
    for value in losses:
        runtime.require(type(value) is str and 0 < len(value) <= 64 and value.isascii() and
                        value == value.strip(), 'RUNTIME_TRAINING_LOSS')
        try:
            number = float(value)
            exact = Decimal(value)
        except (ValueError, InvalidOperation) as error:
            raise ValueError('RUNTIME_TRAINING_LOSS') from error
        # A negative decimal can underflow to binary64 -0.0. Check its exact
        # sign as well; the legitimate formatted '-0' still compares as zero.
        runtime.require(math.isfinite(number) and exact.is_finite() and exact >= 0,
                        'RUNTIME_TRAINING_LOSS')
    if trained:
        # train() adds three supervised EOS tokens and requires a nonempty
        # prompt on every step. All tokens fit the same frozen per-step bound.
        runtime.require(3 * steps <= supervised and supervised + steps <= tokens <=
                        steps * plan['input_tokens_max'], 'RUNTIME_TRAINING_TOKENS')
    else:
        runtime.require(tokens == supervised == numbers['supported_profile_flops'] == 0,
                        'RUNTIME_TRAINING_ZERO_ROLE')
    return training


def validate_training_match(plan, receipts):
    """Match validated steps and reported totals across the three trained roles."""
    runtime.require(type(receipts) is dict and
                    all('train-' + role in receipts for role in runtime.PARTICIPANTS),
                    'RUNTIME_TRAINING_RECEIPTS')
    training = {role: _training_receipt(plan, role, receipts['train-' + role])
                for role in runtime.PARTICIPANTS}
    totals = {(row['steps'], row['tokens'], row['supervised_tokens'])
              for role, row in training.items()
              if runtime.PARTICIPANT_KINDS[role] in ('lora', 'full-tune')}
    runtime.require(len(totals) == 1, 'RUNTIME_MATCHED_TRAINING_BUDGET')
    return True


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
    # The child's interval is inside supervision. Its high-water RSS is no
    # later than the same child's terminal wait4; neither relation uses slack.
    runtime.require(child_wall <= monitored_wall, 'RUNTIME_COST_WALL_CONTAINMENT')
    runtime.require(child_cpu - waited_cpu <= _wait4_cpu_slack_ns(waited_cpu),
                    'RUNTIME_COST_CPU_CONTAINMENT')
    runtime.require(child_rss <= waited_rss, 'RUNTIME_COST_RSS_CONTAINMENT')
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
        runtime.require(event['memory_peak_bytes'] <= child_rss, 'RUNTIME_COST_STAGE_RSS_CONTAINMENT')
        for key in ('bytes_read', 'bytes_written', 'gpu_ns'):
            if event[key] is None:
                missing.append(event['stage'] + ':' + key)
            else:
                _integer(event[key], 'RUNTIME_COST_STAGE_NUMBER')
        runtime.require(plan['backend'] != 'cpu' or event['gpu_ns'] == 0,
                        'RUNTIME_COST_CPU_GPU_SCOPE')
    # Observer.stage calls are sequential, non-nested and inside the reported
    # child interval. These use the same respective nanosecond clocks, so their
    # sums have no wait4 quantization allowance and cannot exceed that interval.
    runtime.require(_sum(event['wall_ns'] for event in events) <= child_wall,
                    'RUNTIME_COST_STAGE_WALL_CONTAINMENT')
    runtime.require(_sum(event['cpu_ns'] for event in events) <= child_cpu,
                    'RUNTIME_COST_STAGE_CPU_CONTAINMENT')
    if phase == 'train':
        _training_receipt(plan, role, receipt)
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
    """Build v3 at the actual runner return after all twelve phase observations.

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
    training_matched = validate_training_match(plan, receipts)
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
    return dict(schema='llm-runtime-actual-pilot-assessment-v3',
                experiment=runtime.identity(plan), roster=runtime.identity(roster),
                source=plan['runtime_source'],
                scope='actual-local-short-LLM-pilot-no-future-independent-quality-or-native-admission',
                scores=scores, calibration_selected_control=selected,
                gain_vs_strongest_evaluation_control=[gain.numerator, gain.denominator],
                positive_vs_all_controls=gain > 0, all_required_controls_executed=True,
                training_steps_and_reported_token_counts_matched=training_matched,
                actual_token_schedule_verified=False,
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
