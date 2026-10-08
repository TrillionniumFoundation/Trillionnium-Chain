"""Stricter offline sequence qualification using the existing model evidence owner.

V1/V2 receipt bytes and verifiers remain unchanged. This explicit additional gate
checks reported chronology, the externally pinned initial model and actual run
plan identities. It neither installs models nor writes a second owner journal.
"""
from contract_wire import H, canonical
from llm_adapter_contract import digest, freeze, require, validate_run_plan
from model_window_history import (
    _decode_exposure_history,
    verify_signed_prospective_consumer_decisions_v2,
)

SEQUENCE_DOMAIN = 'model-consumer-generation-sequence-v1'
PLAN_DOMAIN = 'target-decoder-evaluation-run-plan-v1'


def verify_generation_sequence(history_raw, expected_history, generations,
                               receipts, attestations, run_plans,
                               expected_initial_model):
    """Qualify supplied signed decisions, not actual independent model evolution.

    The consumer-use receipt of each predecessor must predate registration of
    the next window. A re-signed late receipt cannot repair an already registered
    chronology. A legitimate no_update or owner hold keeps the predecessor.
    The initial-model pin must come from the caller's existing admitted owner,
    not be derived from the submitted first row. Current authority/withdrawal,
    physical installation and independently controlled tasks remain external.
    """
    digest(expected_initial_model)
    require(type(run_plans) is list and len(run_plans) == 3,
            'GENERATION_SEQUENCE_PLAN_COUNT')
    verified = verify_signed_prospective_consumer_decisions_v2(
        history_raw, expected_history, generations, receipts, attestations)
    history = _decode_exposure_history(history_raw, expected_history)
    rows = history['entries'][-3:]
    require(generations[0]['predecessor_model'] == expected_initial_model,
            'GENERATION_SEQUENCE_INITIAL_MODEL')

    boundaries = []
    for index, (generation, receipt, row, plan) in enumerate(
            zip(generations, receipts, rows, run_plans)):
        _, plan_id = freeze(plan, validate_run_plan, PLAN_DOMAIN)
        require(plan_id == generation['run_plan'] == row['window']['run_plan'],
                'GENERATION_SEQUENCE_PLAN_BINDING')
        require(plan['candidate'] == generation['candidate_model'],
                'GENERATION_SEQUENCE_CANDIDATE_BINDING')
        next_registration = rows[index + 1]['registered_at'] if index < 2 else None
        if next_registration is not None:
            require(receipt['used_at'] < next_registration,
                    'GENERATION_SEQUENCE_PREDECESSOR_USE')
        boundaries.append(dict(
            ordinal=row['window']['ordinal'], run_plan=plan_id,
            observed_at=row['observed_at'], used_at=receipt['used_at'],
            next_registered_at=next_registration))

    value = dict(verified)
    value.pop('id')
    value.update(
        schema='pon-model-generation-sequence-v1',
        scope='signed-reported-sequence-not-physical-evolution',
        verified_decisions=verified['id'],
        initial_model=expected_initial_model,
        terminal_model=generations[-1]['adopted_model'],
        boundaries=boundaries,
        supplied_run_plans_verified=True,
        reported_cross_generation_chronology_verified=True,
        ordinary_hepta_generation_verified=False)
    # Existing independent/prospective/model-install/reward/production flags
    # are retained verbatim from the original signed decision verification.
    return dict(value, id=H(SEQUENCE_DOMAIN, canonical(value)).hex())
