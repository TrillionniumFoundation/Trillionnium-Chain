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


CONTEXT_SEQUENCE_DOMAIN = 'model-context-bound-generation-sequence-v2'


def verify_context_bound_generation_sequence(
        history_raw, expected_history, generations, receipts, attestations,
        run_plans, expected_initial_model, contexts):
    """Join the existing sequence and context owners without upgrading old bytes.

    All original V1 sequence checks and signed V2 consumer decisions still run.
    Context signatures must additionally bind each window, assessment and plan.
    The actual plans must disclose exactly the task identities, prompt hashes,
    source groups and partitions retained by the existing exposure-history owner.
    Otherwise a caller could report fresh exposure while supplying a reused plan.

    This explicit V2 entry is offline qualification only. It neither replaces
    the caller's trusted history pin nor proves real installation, complete hidden
    exposure, independent control, current permission or future model benefit.
    Callers must keep supplied Python objects immutable for the whole call.
    """
    from model_consumer_context import verify_context_bound_prospective_decisions

    require(type(contexts) is list and len(contexts) == 3,
            'CONSUMER_CONTEXT_COUNT')
    sequence = verify_generation_sequence(
        history_raw, expected_history, generations, receipts, attestations,
        run_plans, expected_initial_model)
    context = verify_context_bound_prospective_decisions(
        history_raw, expected_history, generations, receipts, attestations, contexts)
    require(context['consumer_decisions'] == sequence['verified_decisions'],
            'GENERATION_SEQUENCE_CONTEXT_DECISIONS')
    history = _decode_exposure_history(history_raw, expected_history)
    exposure_bindings = []
    for row, plan in zip(history['entries'][-3:], run_plans):
        # Same task projection as model_window_history._projection. Labels are
        # not interchangeable: calibration cannot conceal evaluation exposure.
        tasks = sorted((dict(id=task['id'], prompt=task['prompt_sha256'],
                             group=task['source_group'], partition=task['partition'])
                        for task in plan['tasks']), key=lambda task: task['id'])
        require(tasks == row['tasks'], 'GENERATION_SEQUENCE_EXPOSURE_BINDING')
        exposure_bindings.append(dict(
            ordinal=row['window']['ordinal'], run_plan=row['window']['run_plan'],
            task_projection=H('model-generation-plan-exposure-v2', canonical(tasks)).hex()))

    value = dict(sequence)
    value.pop('id')
    value.update(
        schema='pon-model-context-bound-generation-sequence-v2',
        scope='signed-plan-exposure-context-not-physical-evolution',
        verified_sequence=sequence['id'], verified_context=context['id'],
        context_signatures_verified=True, supplied_plan_exposure_verified=True,
        exposure_bindings=exposure_bindings, hidden_windows_excluded=False,
        physical_custody_verified=False)
    return dict(value, id=H(CONTEXT_SEQUENCE_DOMAIN, canonical(value)).hex())


PARENT_SEQUENCE_DOMAIN = 'model-parent-bound-generation-sequence-v3'


def verify_parent_bound_generation_sequence(
        history_raw, expected_history, generations, receipts, attestations,
        run_plans, expected_initial_model, contexts):
    """Bind the evaluated parent control to the already selected predecessor.

    V2 establishes signatures, exposure, plans and reported use chronology. It
    deliberately does not assert that a plan's current-backbone control is the
    adopted predecessor named in the consumer receipt. This explicit V3 entry
    additionally requires that exact artifact identity in every supplied plan.
    Re-signing a plan containing a weaker or stale parent cannot satisfy V3.

    Here current-backbone denotes the current adopted snapshot evaluated without
    additional control training, not necessarily the immutable family backbone.
    The plan's separate backbone/tokenizer/contract identities are not recast as
    installed model identities. A no_update decision keeps the previous model.

    This is still an offline supplied-evidence relation. No install, current
    authorization, independent custody, run execution, score truth or consensus
    weight follows. All V1/V2 output bytes and existing acceptance flags remain
    unchanged. Supplied Python objects must remain immutable during the call.
    """
    verified = verify_context_bound_generation_sequence(
        history_raw, expected_history, generations, receipts, attestations,
        run_plans, expected_initial_model, contexts)
    bindings = []
    for generation, plan, boundary in zip(
            generations, run_plans, verified['boundaries']):
        # validate_run_plan already checked exact control count, labels, order,
        # uniqueness and digest shape. Never accept another control's artifact
        # merely because it happens to equal the claimed predecessor.
        control = plan['controls'][0]
        require(control['id'] == 'current-backbone'
                and control['artifact'] == generation['predecessor_model'],
                'GENERATION_SEQUENCE_PARENT_CONTROL_BINDING')
        bindings.append(dict(
            ordinal=boundary['ordinal'], run_plan=generation['run_plan'],
            predecessor_model=generation['predecessor_model'],
            evaluated_parent_control=control['artifact'],
            adopted_model=generation['adopted_model'],
            decision=generation['decision']))
    value = dict(verified)
    value.pop('id')
    value.update(
        schema='pon-model-parent-bound-generation-sequence-v3',
        scope='signed-plan-parent-exposure-context-not-physical-evolution',
        verified_context_sequence=verified['id'],
        parent_control_bindings=bindings,
        supplied_parent_control_identities_verified=True)
    return dict(value, id=H(PARENT_SEQUENCE_DOMAIN, canonical(value)).hex())
