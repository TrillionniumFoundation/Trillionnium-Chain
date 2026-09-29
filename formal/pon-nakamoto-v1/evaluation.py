"""Bounded, cluster-weighted evaluation. No data-owner or future-window authority."""
from __future__ import annotations
from fractions import Fraction
import math
from contract_wire import canonical, H

CONTROL_ORDER = ('current', 'best_single', 'mean_merge', 'pooled')
MAX_ROWS = 32768
MAX_GROUPS = 4096
MINIMUM_GROUPS = 20
COMPARISONS = 4


def _aligned(rows, *predictions):
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_ROWS:
        raise ValueError('EVALUATION_LIMIT')
    if any(not isinstance(p, list) or len(p) != len(rows) for p in predictions):
        raise ValueError('SAMPLE_ALIGNMENT')
    seen = set()
    groups = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError('TASK_SHAPE')
        identity = row.get('id')
        if not isinstance(identity, str) or not 0 < len(identity) <= 256:
            raise ValueError('TASK_ID')
        if identity in seen:
            raise ValueError('DUPLICATE_TASK')
        seen.add(identity)
        label = row.get('label')
        if type(label) is not int or not 0 <= label < 3:
            raise ValueError('LABEL')
        group = row.get('source_group', row.get('file'))
        if not isinstance(group, str) or not 0 < len(group) <= 1024:
            raise ValueError('SOURCE_GROUP')
        if 'file' in row and row['file'] != group:
            raise ValueError('SOURCE_GROUP_BINDING')
        for prediction in predictions:
            if type(prediction[i]) is not int or not 0 <= prediction[i] < 3:
                raise ValueError('PREDICTION')
        groups.setdefault(group, []).append(i)
    if len(groups) > MAX_GROUPS:
        raise ValueError('EVALUATION_LIMIT')
    return groups


def macro_accuracy(rows, predictions):
    """Equal weight per source group, never per correlated snippet."""
    groups = _aligned(rows, predictions)
    return sum((Fraction(sum(predictions[i] == rows[i]['label'] for i in indices),
                         len(indices)) for indices in groups.values()), Fraction(0)) / len(groups)


def select_reference(calibration, controls):
    if not isinstance(controls, dict) or set(controls) != set(CONTROL_ORDER):
        raise ValueError('CONTROL_SET')
    _aligned(calibration, *(controls[name] for name in CONTROL_ORDER))
    scored = {name: macro_accuracy(calibration, controls[name]) for name in CONTROL_ORDER}
    name = max(CONTROL_ORDER, key=lambda k: (scored[k], -CONTROL_ORDER.index(k)))
    record = {'policy': 'source-group-macro-v3', 'tasks': calibration,
              'controls': controls, 'selected': name}
    return name, H('reference-lock-v3', canonical(record)).hex()


def assess(rows, candidate, reference, *, comparisons=COMPARISONS,
           minimum_clusters=MINIMUM_GROUPS, future_window=False):
    if type(comparisons) is not int or not COMPARISONS <= comparisons <= 64:
        raise ValueError('MULTIPLICITY')
    if type(minimum_clusters) is not int or not MINIMUM_GROUPS <= minimum_clusters <= MAX_GROUPS:
        raise ValueError('MINIMUM_CLUSTERS')
    if type(future_window) is not bool:
        raise ValueError('TIME_OBSERVATION')
    groups = _aligned(rows, candidate, reference)
    differences = [Fraction(sum(int(candidate[i] == rows[i]['label']) -
                                int(reference[i] == rows[i]['label']) for i in indices),
                            len(indices)) for indices in groups.values()]
    wins = sum(d > 0 for d in differences)
    losses = sum(d < 0 for d in differences)
    decisive = wins + losses
    mean = sum(differences, Fraction(0)) / len(differences)
    # A majority of tiny improvements may coexist with worse macro accuracy. Both
    # positive mean and the precommitted directional test are required for any score.
    passes = bool(len(groups) >= minimum_clusters and mean > 0 and wins > losses and
                  20 * comparisons * sum(math.comb(decisive, k)
                                         for k in range(wins, decisive + 1)) <= 1 << decisive)
    return {'clusters': len(groups), 'wins': wins, 'losses': losses,
            'comparisons': comparisons, 'cluster_gate': passes,
            'mean_gain_numerator': mean.numerator, 'mean_gain_denominator': mean.denominator,
            'exploratory_score': int(mean * 1000000) if passes else 0,
            'future_window_observed': False, 'caller_future_window_claim': future_window,
            'public_reward_eligible': False,
            'reason': 'independent time/source-owner receipts must be verified by the accepting owner'}


def freeze_plan(*, source, train_ids, calibration_ids, eligible_future_after, model_hash):
    if set(train_ids) & set(calibration_ids):
        raise ValueError('PARTITION_OVERLAP')
    if len(train_ids) != len(set(train_ids)) or len(calibration_ids) != len(set(calibration_ids)):
        raise ValueError('DUPLICATE_TASK')
    if not source or not model_hash or type(eligible_future_after) is not int or eligible_future_after < 0:
        raise ValueError('PLAN')
    return {'schema': 'pon-strong-reference-plan-v3', 'source': source,
            'train_ids': sorted(train_ids), 'calibration_ids': sorted(calibration_ids),
            'eligible_future_after': eligible_future_after, 'candidate': model_hash,
            'controls': list(CONTROL_ORDER), 'minimum_clusters': MINIMUM_GROUPS,
            'comparisons': COMPARISONS, 'statistical_unit': 'authorized-source-group',
            'adaptation_after_plan_forbidden': True}
