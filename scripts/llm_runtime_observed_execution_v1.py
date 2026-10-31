"""Explicit observation contract for the original V2 parent-step owner.

The model plan and target contract remain the original exact bytes. This separate
execution plan chooses an existing supervisor profile and has its own identity;
it is not a relabelled v4 model plan, qualification, or installation credential.
"""
import hashlib
import json
from pathlib import Path

import llm_runtime_parent_step as step
import llm_runtime_pilot as runtime

SCHEMA = 'llm-runtime-parent-step-observed-input-v1'
PROFILE = 'canonical-parent-original-task-observed-execution-v1'
PLAN = 'llm-runtime-parent-observation-plan-v1'
OBSERVER = 'linux-owned-exit-worker-pidfd-v4'
SCOPE = 'explicit-supervisor-observation-original-model-contract-no-qualification'


def is_observed(value):
    return type(value) is dict and value.get('schema') == SCHEMA


def plan_record(value):
    """Freeze observation policy separately; never edit the registered model plan."""
    plan = runtime.validate_plan(step.read_object(value['files']['plan'], 1024 * 1024))
    runtime.require(runtime.plan_exit_profile(plan) == 'strict-v1', 'OBSERVED_ORIGINAL_MODEL_PLAN')
    return dict(schema=PLAN, scope=SCOPE, model_plan=dict(identity=runtime.identity(plan),
        sha256=runtime.file_sha(value['files']['plan']), source=plan['runtime_source']),
        parent=value['parent'], parent_material=value['initial_setup']['parent_material'],
        recipe=value['initial_setup']['recipe'], source=value['source'],
        observer=runtime.exit_observation_profile(OBSERVER),
        training_budget=plan['training_budget'], inference_budget=plan['inference_budget'],
        model_plan_unchanged=True, target_contract_unchanged=True,
        installation=False, product_qualification=False, reward=False)


def checked_plan(value):
    role = value['initial_setup']['observation_plan']
    step.closed(role, 'path sha256')
    runtime.require(type(role['path']) is str and 0 < len(role['path']) <= 4096 and
                    Path(role['path']).is_absolute(), 'OBSERVED_PLAN_PATH')
    step.digest(role['sha256'])
    raw = step.parent.read_regular(role['path'], step.MAX_INPUT)
    runtime.require(hashlib.sha256(raw).hexdigest() == role['sha256'], 'OBSERVED_PLAN_PIN')
    record = json.loads(raw, object_pairs_hook=runtime.unique)
    runtime.require(runtime.canonical(record) == runtime.canonical(plan_record(value)),
                    'OBSERVED_EXACT_PLAN')
    runtime.validate_exit_observation_profile(record['observer'])
    return record


def context(value):
    record = checked_plan(value)
    return dict(plan_sha256=value['initial_setup']['observation_plan']['sha256'],
        profile=PROFILE, observer=runtime.identity(record['observer']),
        model_plan=record['model_plan']['identity'])


def preflight(value):
    from llm_runtime_parent_step_v2 import SCHEMA as old_schema, PROFILE as old_profile, sources, preflight as original
    step.closed(value, 'schema scope attempt_id operation experiment source files parent candidate output flags initial_setup')
    runtime.require(is_observed(value) and value['scope'] == step.SCOPE and
        value['source'] == sources(PROFILE) and value['flags'] == step.FALSES and
        all(v is False for v in value['flags'].values()), 'OBSERVED_SCOPE_SOURCE')
    request = value['initial_setup']
    step.closed(request, 'profile recipe parent_material observation_plan')
    runtime.require(request['profile'] == PROFILE, 'OBSERVED_PROFILE')
    # Validation-only projection into the unchanged model/parent checks. It is
    # never saved as an old request or used as an execution/completion receipt.
    base = dict(value, schema=old_schema, source=sources(old_profile),
        initial_setup={k: v for k, v in request.items() if k != 'observation_plan'})
    base['initial_setup']['profile'] = old_profile
    result = original(base)
    record = checked_plan(value)
    runtime.require(record['training_budget'] == result[0]['training_budget'] and
        record['inference_budget'] == result[0]['inference_budget'], 'OBSERVED_ORIGINAL_BUDGETS')
    return result


def verify_supervisor(value, result):
    """Keep exact owned-child terminal checks in the original caller as well."""
    record = checked_plan(value)
    runtime.require(result.get('exit_observation_profile') == record['observer'] and
        result.get('terminal_reconciliation_profile') == 'explicit-' + OBSERVER and
        result.get('budget') == record['training_budget'], 'OBSERVED_SUPERVISOR_BINDING')
