"""Exact task-admission link for an explicitly different V2 request profile.

No parent contract is rewritten. This checks one allowed field difference and
keeps the old material identity distinct from the actual execution contract.
"""
from pathlib import Path

import llm_inherited_runtime as inherited
import llm_initial_trainable_setup_v2 as setup
import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as v2
import llm_runtime_pilot as runtime


def derive(value, contract, plan, manifest, config):
    tokenizer = runtime.read_json(Path(value['files']['materials']) / 'tokenizer_config.json')
    return runtime.contract_from_inventory(contract['backbone']['index'], tokenizer['chat_template'],
                                           config, manifest, plan)


def request_link(value):
    """Compile request facts only; preflight and actual loaded model recheck them."""
    plan = runtime.validate_plan(step.read_object(value['files']['plan'], 1024 * 1024))
    contract = step.read_object(value['files']['parent_contract'], runtime.contract_module().MAX_MANIFEST_BYTES)
    manifest, config = runtime.verify_materials(value['files']['materials'])
    _, _, cid = derive(value, contract, plan, manifest, config)
    return dict(parent_admission=contract['registration']['target_admission'],
                training_plan=runtime.identity(plan), derived_contract=cid)


def verify_link(value, parent_contract, current_contract, current_raw, current_id, plan):
    link = value['initial_setup']['task_link']
    step.closed(link, 'parent_admission training_plan derived_contract')
    for pin in link.values(): step.digest(pin)
    parent_id = runtime.contract_module().freeze_target_contract(parent_contract)[1]
    raw, cid = runtime.contract_module().freeze_target_contract(current_contract)
    plan_id = runtime.identity(plan)
    admission = parent_contract['registration']['target_admission']
    expected = dict(parent_contract, registration=dict(parent_contract['registration'], target_admission=plan_id))
    runtime.require(parent_id == value['parent']['contract'] and raw == current_raw and cid == current_id and
        runtime.canonical(current_contract) == runtime.canonical(expected) and admission != plan_id and
        parent_id != cid, 'PARENT_V2_TASK_CONTRACT_DIFFERENCE')
    observed = dict(parent_admission=admission, training_plan=plan_id, derived_contract=cid)
    runtime.require(runtime.canonical(link) == runtime.canonical(observed), 'PARENT_V2_TASK_LINK')
    return observed


def preflight(value):
    step.closed(value, 'schema scope attempt_id operation experiment source files parent candidate output flags initial_setup')
    runtime.require(value['schema'] == v2.SCHEMA and value['scope'] == step.SCOPE and
        value['source'] == v2.sources(v2.NEW_TASK_PROFILE) and value['flags'] == step.FALSES and
        all(v is False for v in value['flags'].values()), 'PARENT_V2_SCOPE_SOURCE')
    runtime.require(value['operation'] == 'train', 'PARENT_V2_OPERATION_UNIMPLEMENTED')
    request = value['initial_setup']
    step.closed(request, 'profile recipe parent_material task_link')
    step.closed(request['parent_material'], 'path sha256')
    runtime.require(request['profile'] == v2.NEW_TASK_PROFILE and request['recipe'] == setup.RECIPE and
                    type(request['recipe']['initialization_seed']) is int, 'PARENT_V2_RECIPE')
    step.digest(value['attempt_id']); step.digest(value['experiment'])
    step.closed(value['files'], 'materials plan parent_contract parent_adapter parent_artifact candidate_directory')
    runtime.require(value['candidate'] is None and value['files']['candidate_directory'] is None,
                    'PARENT_STEP_CANDIDATE_ROLE')
    for name in ('materials', 'plan', 'parent_contract', 'parent_adapter', 'parent_artifact'):
        path = value['files'][name]
        runtime.require(type(path) is str and 0 < len(path) <= 4096 and Path(path).is_absolute(), 'PARENT_STEP_FILE_ROLE')
    runtime.require(type(value['output']) is str and 0 < len(value['output']) <= 4096 and
                    Path(value['output']).is_absolute(), 'PARENT_STEP_OUTPUT_ROLE')
    role = request['parent_material']
    runtime.require(type(role['path']) is str and 0 < len(role['path']) <= 4096 and
                    Path(role['path']).is_absolute(), 'PARENT_V2_ORIGIN_PATH')
    step.digest(role['sha256'])
    origin = inherited.validate_parent(inherited.checked_json(role['path'], role['sha256']))
    step.closed(value['parent'], 'contract adapter file_sha256')
    runtime.require(origin['generation'] == 1 and origin['file_sha256'] == setup.PARENT_SHA256 and
        {k: origin[k] for k in ('contract', 'adapter', 'file_sha256')} == value['parent'], 'PARENT_V2_ORIGIN')
    runtime.require(all(value['files'][key] == str(Path(origin['directory']) / name) for key, name in
        [('parent_contract', 'target-contract.json'), ('parent_adapter', 'wrapped-adapter.json'),
         ('parent_artifact', 'artifact.safetensors')]), 'PARENT_V2_ORIGIN_ROLES')
    plan = runtime.validate_plan(step.read_object(value['files']['plan'], 1024 * 1024))
    runtime.require(runtime.identity(plan) == value['experiment'] and plan['runtime_source'] == value['source']['runtime'] and
                    plan['backend'] == 'cpu', 'PARENT_STEP_EXPERIMENT')
    manifest, config = runtime.verify_materials(value['files']['materials'])
    runtime.require(plan == runtime.experiment_plan(manifest, backend='cpu', threads=plan['threads'],
        steps=plan['training_steps'], exit_observation=runtime.plan_exit_profile(plan)), 'PARENT_STEP_EXACT_PLAN')
    factors, summary = step.parent.verify_parent(value['files']['parent_contract'], value['files']['parent_adapter'],
        value['files']['parent_artifact'], expected_contract=value['parent']['contract'],
        expected_adapter=value['parent']['adapter'], expected_file_sha256=value['parent']['file_sha256'])
    raw = step.parent.read_regular(value['files']['parent_contract'], runtime.contract_module().MAX_MANIFEST_BYTES)
    contract = runtime.contract_module().verify_target_contract(raw, value['parent']['contract'],
        expected_backbone_root=summary['backbone'], expected_tokenizer_root=summary['tokenizer'])
    current, current_raw, current_id = derive(value, contract, plan, manifest, config)
    verify_link(value, contract, current, current_raw, current_id, plan)
    runtime.require(step.parent.read_regular(value['files']['parent_artifact'], len(setup.canonical_zero_parent())) ==
                    setup.canonical_zero_parent(), 'PARENT_V2_CANONICAL_PARENT')
    return plan, manifest, contract, raw, factors, None, summary


def verify_report(value, observed):
    step.closed(observed, 'parent_admission training_plan derived_contract')
    runtime.require(runtime.canonical(observed) == runtime.canonical(value['initial_setup']['task_link']),
                    'PARENT_V2_TASK_LINK_REPORT')
