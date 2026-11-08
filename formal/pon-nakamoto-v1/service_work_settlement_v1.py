"""Separate a fulfilled evaluation service from improvement and chain credit.

This adapter reuses RewardBudgetPlanner and the complete integer Cell evaluator.
It is process-local conditional accounting: owner identity, real escrow, data
independence, physical cost and external payment are not certified here. There is
no work-qualification input and no path that emits consensus credit.
"""
from __future__ import annotations

import copy
import json
from fractions import Fraction

from contract_wire import H, canonical, unique
from evaluation import CONTROL_ORDER, assess
from model_contract import load_model_bytes
from reward_budget_oracle import RewardBudgetPlanner, identity, resources, units
from useful_cell_numeric_v1 import NUMERIC_PROFILE, evaluate_exact

SCHEMA = 'pon-service-work-contract-v1'
PROGRAM = 'frozen-int257-evaluation-service-v1'
SCOPE = 'conditional-reference-accounting-no-native-payment-or-work-authority'
MAX_BYTES = 1024 * 1024
FIELDS = {
    'schema', 'program', 'scope', 'context', 'task', 'consumer', 'service_provider',
    'improvement_beneficiary', 'material', 'numeric_profile', 'base_budget',
    'bonus_budget', 'base_fee', 'bonus_fee', 'contribution_root',
    'base_reservation', 'bonus_reservation', 'issued_height', 'deadline_height',
    'minimum_gain_ppm', 'max_retention_regressions',
}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def _object(raw, code):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, code + '_BYTES')
    try:
        value = json.loads(raw, object_pairs_hook=unique)
        require(canonical(value) == raw, code + '_CANONICAL')
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(code + '_JSON') from error
    return value


def _bounded_copy(value, code):
    try:
        return _object(canonical(value), code)
    except (TypeError, OverflowError, RecursionError) as error:
        raise ValueError(code + '_VALUE') from error


def material_identity(material):
    """Commit to all models, labels, task order, groups and actual feature values."""
    value = _bounded_copy(material, 'SERVICE_MATERIAL')
    require(type(value) is dict and set(value) ==
            {'candidate', 'controls', 'evaluation', 'retention'},
            'SERVICE_MATERIAL_FIELDS')
    require(type(value['controls']) is dict and
            set(value['controls']) == set(CONTROL_ORDER), 'SERVICE_CONTROL_SET')
    for model in [value['candidate'], *value['controls'].values()]:
        load_model_bytes(canonical(model))
    seen_ids, seen_groups = set(), set()
    for partition in ('evaluation', 'retention'):
        rows = value[partition]
        require(type(rows) is list and 1 <= len(rows) <= 64, 'SERVICE_TASK_LIMIT')
        ids, groups = set(), set()
        for row in rows:
            require(type(row) is dict and set(row) ==
                    {'id', 'source_group', 'label', 'x'}, 'SERVICE_TASK_FIELDS')
            identity(row['id']); identity(row['source_group'])
            require(row['id'] not in ids, 'SERVICE_TASK_REPLAY')
            require(type(row['label']) is int and 0 <= row['label'] < 3,
                    'SERVICE_LABEL')
            x = row['x']
            require(type(x) is list and len(x) == 257 and x[-1] == 8 and
                    all(type(v) is int and -8 <= v <= 8 for v in x),
                    'SERVICE_FEATURES')
            ids.add(row['id']); groups.add(row['source_group'])
        require(not (seen_ids & ids or seen_groups & groups),
                'SERVICE_PARTITION_OVERLAP')
        seen_ids.update(ids); seen_groups.update(groups)
    return H('service-work-material-v1', canonical(value)).hex()


def _validate_contract(value):
    require(type(value) is dict and set(value) == FIELDS, 'SERVICE_CONTRACT_FIELDS')
    require(value['schema'] == SCHEMA and value['program'] == PROGRAM and
            value['scope'] == SCOPE and
            value['numeric_profile'] == NUMERIC_PROFILE['id'],
            'SERVICE_CONTRACT_SCOPE')
    for field in ('context', 'task', 'consumer', 'service_provider',
                  'improvement_beneficiary', 'material', 'base_budget',
                  'bonus_budget', 'contribution_root'):
        identity(value[field])
    require(value['base_budget'] != value['bonus_budget'], 'SERVICE_BUDGET_ALIAS')
    # Declared identity separation is necessary, not proof of hidden-control independence.
    require(value['service_provider'] != value['improvement_beneficiary'],
            'SERVICE_EVALUATOR_AUTHOR_ALIAS')
    for field in ('base_fee', 'bonus_fee', 'issued_height', 'deadline_height',
                  'minimum_gain_ppm', 'max_retention_regressions'):
        units(value[field])
    require(value['base_fee'] > 0 and value['bonus_fee'] > 0,
            'SERVICE_FEE')
    require(value['issued_height'] < value['deadline_height'], 'SERVICE_WINDOW')
    require(1 <= value['minimum_gain_ppm'] <= 1000000 and
            value['max_retention_regressions'] <= 64, 'SERVICE_GAIN_POLICY')
    resources('evaluation', value['base_reservation'])
    resources('contribution', value['bonus_reservation'])
    return value


def freeze_contract(*, material, context, task, consumer, service_provider,
                    improvement_beneficiary, base_budget, bonus_budget,
                    base_fee, bonus_fee, contribution_root, base_reservation,
                    bonus_reservation, issued_height, deadline_height,
                    minimum_gain_ppm=1, max_retention_regressions=0):
    """The admitting owner retains the returned digest before accepting a result.

    This is a finite contract to evaluate the exact candidate and four frozen
    controls. Completing that evaluation can earn a base service fee even when
    its correct decision is NoUpdate. It is not a promise of model improvement.
    """
    value = dict(schema=SCHEMA, program=PROGRAM, scope=SCOPE, context=context,
        task=task, consumer=consumer, service_provider=service_provider,
        improvement_beneficiary=improvement_beneficiary,
        material=material_identity(material), numeric_profile=NUMERIC_PROFILE['id'],
        base_budget=base_budget, bonus_budget=bonus_budget, base_fee=base_fee,
        bonus_fee=bonus_fee, contribution_root=contribution_root,
        base_reservation=base_reservation, bonus_reservation=bonus_reservation,
        issued_height=issued_height, deadline_height=deadline_height,
        minimum_gain_ppm=minimum_gain_ppm,
        max_retention_regressions=max_retention_regressions)
    raw = canonical(_validate_contract(value))
    _object(raw, 'SERVICE_CONTRACT')
    return raw, H('service-work-contract-v1', raw).hex()


def read_contract(raw, expected):
    identity(expected)
    value = _object(raw, 'SERVICE_CONTRACT')
    require(H('service-work-contract-v1', raw).hex() == expected,
            'SERVICE_EXPECTED_CONTEXT')
    return _validate_contract(value)


def execute_service(raw, expected, material):
    """Recompute every product, route, logit and prediction for all five models.

    The task is evaluation, not training or installation. Labels and declared
    groups are frozen inputs, not independently established ground truth. Full
    replay establishes this finite relation, not actual use by a Hepta owner.
    """
    contract = read_contract(raw, expected)
    material = _bounded_copy(material, 'SERVICE_MATERIAL')
    require(material_identity(material) == contract['material'],
            'SERVICE_MATERIAL_BINDING')
    models = {'candidate': material['candidate'], **material['controls']}
    outputs = {
        partition: {name: evaluate_exact(model, [r['x'] for r in material[partition]])
                    for name, model in models.items()}
        for partition in ('evaluation', 'retention')
    }
    comparisons = {
        name: assess(material['evaluation'],
                     outputs['evaluation']['candidate']['predictions'],
                     outputs['evaluation'][name]['predictions'])
        for name in CONTROL_ORDER
    }
    required_gain = Fraction(contract['minimum_gain_ppm'], 1000000)
    gain_ok = all(result['cluster_gate'] and
                  Fraction(result['mean_gain_numerator'], result['mean_gain_denominator'])
                  >= required_gain for result in comparisons.values())
    retention = outputs['retention']
    regressions = sum(
        retention['candidate']['predictions'][i] != row['label'] and
        any(retention[name]['predictions'][i] == row['label'] for name in CONTROL_ORDER)
        for i, row in enumerate(material['retention'])
    )
    retention_ok = regressions <= contract['max_retention_regressions']
    decision = 'MeasuredImprovement' if gain_ok and retention_ok else 'NoUpdate'
    return canonical(dict(schema='pon-service-work-complete-result-v1',
        contract=expected, task=contract['task'], material=contract['material'],
        outputs=outputs, comparisons=comparisons, retention_regressions=regressions,
        decision=decision, base_service='complete-evaluation',
        model_adoption_authorized=False, independent_evaluation_certified=False))


def _claims(contract):
    return {lane: H('service-work-claim-v1', bytes.fromhex(contract['context']),
                    bytes.fromhex(contract['task']), lane.encode()).hex()
            for lane in ('evaluation', 'contribution')}


def _book_binding(book, contract):
    require(type(book) is RewardBudgetPlanner and book.context == contract['context'],
            'SERVICE_BOOK_CONTEXT')
    base = book.branch.budgets.get(contract['base_budget'])
    bonus = book.branch.budgets.get(contract['bonus_budget'])
    require(base is not None and bonus is not None, 'SERVICE_BUDGET_ABSENT')
    require(base.lane == 'evaluation' and bonus.lane == 'contribution' and
            base.source != bonus.source, 'SERVICE_FUNDING_LANES')
    require(max(base.maturity, bonus.maturity) <= contract['issued_height'],
            'SERVICE_BUDGET_IMMATURE_AT_ISSUE')
    require(contract['deadline_height'] <= min(base.deadline, bonus.deadline),
            'SERVICE_BUDGET_WINDOW')
    return _claims(contract)


def _bound_reservations(book, contract):
    claims = _book_binding(book, contract)
    for lane, prefix, payee in (
            ('evaluation', 'base', 'service_provider'),
            ('contribution', 'bonus', 'improvement_beneficiary')):
        claim = book.branch.claims.get(claims[lane])
        require(claim is not None and claim.budget == contract[prefix + '_budget'] and
                claim.subject == contract['task'] and claim.beneficiary == contract[payee] and
                claim.amount == contract[prefix + '_fee'] and
                claim.reserved == contract[prefix + '_reservation'] and
                claim.contribution_root == (contract['contribution_root']
                    if lane == 'contribution' else None), 'SERVICE_RESERVATION_BINDING')
        require(claim.status == 'reserved', 'SERVICE_ALREADY_RESOLVED')
    return claims


def _contract_pins(book, claims, expected):
    # Extend the existing monotonic resource jobs, not branch state or another
    # journal. A task cannot acquire a different policy/material commitment on
    # retry, even when the caller mistakenly passes that replacement as expected.
    require(all(book._resource_jobs.get(claim, {}).get('service_work_contract_v1')
                == expected for claim in claims.values()), 'SERVICE_ORIGINAL_CONTRACT')


def _check_height(book, claims, height):
    for claim in claims.values():
        job = book._resource_jobs[claim]
        previous = job.get('service_work_last_height_v1')
        require(previous is None or height >= previous, 'SERVICE_HEIGHT_REWIND')


def _observe_height(book, claims, height):
    # This updates a private transition copy, not a clock or persistent observer.
    # A successful reservation/settlement (including UNKNOWN) retains this height
    # only if the caller keeps the returned planner. Failed attempts and read-only
    # supply queries record no new height; the real owner must separately persist
    # valid height observations. Retries cannot rewind below a retained height.
    _check_height(book, claims, height)
    for claim in claims.values():
        book._resource_jobs[claim]['service_work_last_height_v1'] = height


def reserve_contract(book, raw, expected, *, height):
    """Return a new planner with both reservations, or leave the input untouched."""
    contract = read_contract(raw, expected)
    claims = _book_binding(book, contract)
    units(height)
    require(contract['issued_height'] <= height < contract['deadline_height'],
            'SERVICE_WINDOW')
    updated = copy.deepcopy(book)
    for lane, prefix, payee in (
            ('evaluation', 'base', 'service_provider'),
            ('contribution', 'bonus', 'improvement_beneficiary')):
        if claims[lane] in updated._resource_jobs:
            require(updated._resource_jobs[claims[lane]].get('service_work_contract_v1')
                    == expected, 'SERVICE_ORIGINAL_CONTRACT')
        updated.reserve(claim=claims[lane], budget=contract[prefix + '_budget'],
            subject=contract['task'], beneficiary=contract[payee],
            amount=contract[prefix + '_fee'],
            resource_reservation=contract[prefix + '_reservation'], height=height,
            contribution_root=contract['contribution_root'] if lane == 'contribution' else None)
        updated._resource_jobs[claims[lane]]['service_work_contract_v1'] = expected
    _observe_height(updated, claims, height)
    updated.summary()
    return updated


def settle_contract(book, raw, expected, *, height, outcome, material=None,
                    result=None, base_consumed=None, bonus_consumed=None):
    """Return a new planner and a conditional allocation report, never a payment.

    Unknown keeps both reservations outstanding. A correct complete evaluation
    pays the contractual base fee in reference accounting even for NoUpdate.
    Invalid/cancelled service consumes reported resources and earns neither fee.
    Caller reports of resource consumption remain unverified physical premises.
    """
    contract = read_contract(raw, expected)
    claims = _bound_reservations(book, contract)
    _contract_pins(book, claims, expected)
    units(height)
    require(height >= contract['issued_height'], 'SERVICE_WINDOW')
    require(type(outcome) is str and outcome in {'complete', 'invalid', 'cancelled', 'unknown'},
            'SERVICE_OUTCOME')
    updated = copy.deepcopy(book)
    _observe_height(updated, claims, height)
    base_paid = bonus_paid = 0
    decision = None
    if outcome == 'unknown':
        require(all(v is None for v in (material, result, base_consumed, bonus_consumed)),
                'SERVICE_UNKNOWN_NOT_TERMINAL')
        status = 'PENDING_UNKNOWN'
    else:
        base_cost = resources('evaluation', base_consumed)
        bonus_cost = resources('contribution', bonus_consumed)
        if outcome == 'complete':
            require(height < contract['deadline_height'], 'SERVICE_WINDOW')
            observed = _object(result, 'SERVICE_RESULT')
            replay = execute_service(raw, expected, material)
            require(result == replay, 'SERVICE_COMPLETE_REPLAY')
            decision = observed['decision']
            base_paid = contract['base_fee']
            bonus_paid = contract['bonus_fee'] if decision == 'MeasuredImprovement' else 0
            base_outcome = 'positive'
            bonus_outcome = 'positive' if bonus_paid else 'no-gain'
            status = 'CONDITIONAL_ACCOUNTING_COMPLETE'
        else:
            require(material is None and result is None, 'SERVICE_FAILED_RESULT')
            base_outcome = bonus_outcome = outcome
            status = 'SERVICE_' + outcome.upper()
        updated.resolve(claim=claims['evaluation'], height=height, paid=base_paid,
                        consumed=base_cost, outcome=base_outcome)
        updated.resolve(claim=claims['contribution'], height=height, paid=bonus_paid,
                        consumed=bonus_cost, outcome=bonus_outcome)
    totals = updated.summary()
    report = dict(schema='pon-service-work-settlement-reference-v1',
        contract=expected, task=contract['task'], status=status, decision=decision,
        conditional_base_fee_units=base_paid, conditional_improvement_bonus_units=bonus_paid,
        additional_consensus_credit=0, work_profile_qualified=False,
        native_funding_verified=False, resource_cost_certified=False,
        independent_evaluation_certified=False, public_reward_eligible=False,
        external_payment_executed=False, model_adoption_authorized=False,
        production_activation=False, qualification='HOLD',
        original_reservations_retained=outcome == 'unknown',
        evaluation_lane=totals['lanes']['evaluation'],
        contribution_lane=totals['lanes']['contribution'])
    return updated, report


def supply_observation(book, contracts, *, height):
    """Finite supplied contracts do not establish real demand or long-run supply."""
    units(height)
    require(type(contracts) is list and len(contracts) <= 64, 'SERVICE_SUPPLY_LIMIT')
    seen = set()
    pending = funded = 0
    for raw, expected in contracts:
        contract = read_contract(raw, expected)
        require(contract['task'] not in seen, 'SERVICE_SUPPLY_REPLAY')
        seen.add(contract['task'])
        claims = _book_binding(book, contract)
        base = book.branch.claims.get(claims['evaluation'])
        if (base is not None and base.status == 'reserved' and
                contract['issued_height'] <= height < contract['deadline_height']):
            _bound_reservations(book, contract)
            _contract_pins(book, claims, expected)
            _check_height(book, claims, height)
            pending += 1
            funded += base.amount
    return dict(schema='pon-service-work-supply-observation-v1',
        supplied_contracts=len(contracts), pending_contracts=pending,
        conditional_base_reservations=funded, no_pending_contracts=pending == 0,
        actual_demand_verified=False, native_funding_verified=False,
        synthetic_fill_authorized=False, liveness_qualified=False,
        additional_consensus_credit=0, qualification='HOLD')


def demo_case(kind='no-update'):
    """Synthetic complete-arithmetic fixture; no training/efficacy/demand evidence."""
    from ledger import FAMILY
    from model_contract import CLASSES, DIM, SCALE

    def key(label):
        return H('service-work-demo-v1', label.encode()).hex()

    model = dict(schema='hepta-source-owner-linear-256-v1', family=FAMILY.hex(),
        scale=SCALE, source='synthetic-settlement-control-only',
        base=[[0] * DIM for _ in range(3)], router=[[0] * DIM for _ in range(3)],
        deltas=[[[0] * DIM for _ in range(3)] for _ in range(3)],
        feature='signed-token-hash-256-clipped8-plus-bias-v1', classes=CLASSES[:])
    candidate = copy.deepcopy(model)
    require(kind in {'no-update', 'improved', 'retention-regression'}, 'SERVICE_DEMO_KIND')
    if kind != 'no-update':
        candidate['base'][1][-1] = 1

    def rows(partition, label):
        return [dict(id=key(partition + str(i)), source_group=key(partition + '-group-' + str(i)),
            label=label, x=[i % 8] + [0] * (DIM - 2) + [8]) for i in range(20)]

    material = dict(candidate=candidate,
        controls={name: copy.deepcopy(model) for name in CONTROL_ORDER},
        evaluation=rows('eval', 1),
        retention=rows('retention', 0 if kind == 'retention-regression' else 1))
    book = RewardBudgetPlanner(context=key('context'),
        contribution_root_caps={key('contribution-root'): 100}, max_records=32)
    for lane, budget in (('evaluation', 'base-budget'), ('contribution', 'bonus-budget')):
        book.register_funding(source=key(lane + '-escrow'), lane=lane, amount=100, height=1)
        cap = ({'evaluation_cpu_ns': 1000, 'evaluated_examples': 1000} if lane == 'evaluation'
               else {'training_cpu_ns': 1000, 'parameter_bytes': 1000})
        book.open_budget(budget=key(budget), source=key(lane + '-escrow'), lane=lane,
                         cap=100, maturity=1, deadline=50, resource_cap=cap)
    raw, expected = freeze_contract(material=material, context=book.context,
        task=key('one-original-task'), consumer=key('consumer'),
        service_provider=key('evaluator'), improvement_beneficiary=key('author'),
        base_budget=key('base-budget'), bonus_budget=key('bonus-budget'),
        base_fee=7, bonus_fee=11, contribution_root=key('contribution-root'),
        base_reservation={'evaluation_cpu_ns': 50, 'evaluated_examples': 200},
        bonus_reservation={'training_cpu_ns': 50, 'parameter_bytes': 100},
        issued_height=1, deadline_height=40)
    return book, raw, expected, material


def run_demo():
    reports = {}
    for kind in ('no-update', 'improved', 'retention-regression'):
        book, raw, expected, material = demo_case(kind)
        book = reserve_contract(book, raw, expected, height=2)
        _, reports[kind] = settle_contract(book, raw, expected, height=3, outcome='complete',
            material=material, result=execute_service(raw, expected, material),
            base_consumed={'evaluation_cpu_ns': 30, 'evaluated_examples': 200},
            bonus_consumed={'training_cpu_ns': 20, 'parameter_bytes': 100})
    book, raw, expected, _ = demo_case()
    book = reserve_contract(book, raw, expected, height=2)
    _, reports['unknown'] = settle_contract(book, raw, expected, height=3, outcome='unknown')
    _, reports['invalid'] = settle_contract(book, raw, expected, height=3, outcome='invalid',
        base_consumed={'evaluation_cpu_ns': 30, 'evaluated_examples': 0},
        bonus_consumed={'training_cpu_ns': 20, 'parameter_bytes': 100})
    return dict(schema='pon-service-work-separation-demo-v1',
        fixture='synthetic-complete-integer-evaluation-not-trained-Hepta', scenarios=reports,
        empty_supply=supply_observation(book, [], height=3), qualification='HOLD')


if __name__ == '__main__':
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
