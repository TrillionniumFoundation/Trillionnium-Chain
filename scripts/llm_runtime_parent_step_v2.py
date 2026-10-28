"""Explicit initial working-copy train adapter under the original supervisor.

Unsigned local execution evidence only. V1 schemas and material authority do not
change; setup is not learning. Evaluation/readback V2 are deliberately closed.
The explicit V3 research arm shares this lifecycle, with separate namespaces and
a pinned objective; it grants none of the missing product qualifications.
"""
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import struct
import sys
import time

import llm_inherited_runtime as inherited
import llm_initial_trainable_setup_v2 as setup
import llm_runtime_parent_step as step
import llm_runtime_pilot as runtime
import llm_answer_eos_research_v3 as research
import llm_answer_eos_task_research_v4 as task_research
import llm_runtime_observed_execution_v1 as observed

SCHEMA = 'llm-runtime-parent-step-input-v2'
PROFILE = 'canonical-positive-zero-to-caller-peft-A-v2'
NEW_TASK_PROFILE = 'canonical-positive-zero-to-caller-peft-A-new-task-v2'
ACTUAL = 'llm-runtime-parent-step-actual-v2'
CANDIDATE = 'llm-runtime-parent-candidate-v2'
RESULT = 'llm-runtime-parent-step-result-v2'


def sources(profile=PROFILE):
    result = dict(step.sources(), initial_setup=runtime.file_sha(setup.__file__),
        parent_step_v2=runtime.file_sha(__file__), inherited=runtime.file_sha(inherited.__file__),
        family=runtime.file_sha(runtime.FAMILY_PATH), research_objective=runtime.file_sha(research.__file__))
    if profile in (NEW_TASK_PROFILE, task_research.PROFILE):
        result['task_link'] = runtime.file_sha(Path(__file__).with_name('llm_runtime_parent_step_task_v2.py'))
    if profile == task_research.PROFILE:
        result['research_task'] = runtime.file_sha(task_research.__file__)
    if profile == observed.PROFILE:
        result['observation_execution'] = runtime.file_sha(observed.__file__)
    return result


def version(value):
    if observed.is_observed(value):
        return 'observed-v1'
    if task_research.is_research(value):
        return 'v4'
    return 'v3' if research.is_research(value) else 'v2'


def research_module(value):
    if task_research.is_research(value):
        return task_research
    return research if research.is_research(value) else None


def named(value, prefix):
    return prefix + '-' + version(value)


def new_task(value):
    return (type(value) is dict and type(value.get('initial_setup')) is dict and
            value['initial_setup'].get('profile') in (NEW_TASK_PROFILE, task_research.PROFILE))


def binding(value):
    return runtime.identity(dict(schema=named(value, 'llm-runtime-parent-attempt'),
        attempt_id=value['attempt_id'], experiment=value['experiment'],
        source=value['source'], parent=value['parent'], initial_setup=value['initial_setup']))


def preflight(value):
    if observed.is_observed(value):
        return observed.preflight(value)
    if task_research.is_research(value):
        return task_research.preflight(value)
    if research.is_research(value):
        return research.preflight(value)
    if new_task(value):
        from llm_runtime_parent_step_task_v2 import preflight as task_preflight
        return task_preflight(value)
    step.closed(value, 'schema scope attempt_id operation experiment source files parent candidate output flags initial_setup')
    runtime.require(value['schema'] == SCHEMA and value['scope'] == step.SCOPE and
        value['source'] == sources() and value['flags'] == step.FALSES and
        all(v is False for v in value['flags'].values()), 'PARENT_V2_SCOPE_SOURCE')
    runtime.require(value['operation'] == 'train', 'PARENT_V2_OPERATION_UNIMPLEMENTED')
    request = value['initial_setup']
    step.closed(request, 'profile recipe parent_material')
    step.closed(request['parent_material'], 'path sha256')
    runtime.require(request['profile'] == PROFILE and request['recipe'] == setup.RECIPE and
                    type(request['recipe']['initialization_seed']) is int,
                    'PARENT_V2_RECIPE')
    role = request['parent_material']
    runtime.require(type(role['path']) is str and 0 < len(role['path']) <= 4096 and
                    Path(role['path']).is_absolute(), 'PARENT_V2_ORIGIN_PATH')
    step.digest(role['sha256'])
    origin = inherited.validate_parent(inherited.checked_json(role['path'], role['sha256']))
    runtime.require(origin['generation'] == 1 and origin['file_sha256'] == setup.PARENT_SHA256 and
        {k: origin[k] for k in ('contract', 'adapter', 'file_sha256')} == value['parent'],
        'PARENT_V2_ORIGIN')
    runtime.require(all(value['files'][key] == str(Path(origin['directory']) / name) for key, name in
        [('parent_contract', 'target-contract.json'), ('parent_adapter', 'wrapped-adapter.json'),
         ('parent_artifact', 'artifact.safetensors')]), 'PARENT_V2_ORIGIN_ROLES')
    # This validation frame is never persisted/executed as V1 or used as a receipt.
    base = {k: v for k, v in value.items() if k != 'initial_setup'}
    base.update(schema=step.SCHEMA, source=step.sources())
    checked = step.preflight(base)
    raw = step.parent.read_regular(value['files']['parent_artifact'], len(setup.canonical_zero_parent()))
    runtime.require(raw == setup.canonical_zero_parent(), 'PARENT_V2_CANONICAL_PARENT')
    return checked


def _material(value, directory, prefix, pins):
    step.closed(pins, 'adapter file_sha256')
    for pin in pins.values(): step.digest(pin)
    return step.parent.verify_parent(value['files']['parent_contract'],
        directory / (prefix + 'wrapped-adapter.json'), directory / (prefix + 'artifact.safetensors'),
        expected_contract=value['parent']['contract'], expected_adapter=pins['adapter'],
        expected_file_sha256=pins['file_sha256'])[0]


def verify_setup(value, descriptor, contract, original):
    step.closed(descriptor, 'adapter file_sha256 receipt_sha256')
    for pin in descriptor.values(): step.digest(pin)
    directory = Path(value['output'])
    raw = step.parent.read_regular(directory / 'initial-setup-v2.json', step.MAX_INPUT)
    runtime.require(hashlib.sha256(raw).hexdigest() == descriptor['receipt_sha256'], 'PARENT_V2_SETUP_PIN')
    report = json.loads(raw, object_pairs_hook=runtime.unique)
    step.closed(report, 'schema operation_id original_parent original_parent_readback setup_adapter recipe source_pins '
        'old_factor_sha256 setup_factor_sha256 B_positive_zero function_equivalence full_model_numeric_preservation '
        'trainability capture_cost setup_cost flags')
    factors = _material(value, directory, 'setup-', {k: descriptor[k] for k in ('adapter', 'file_sha256')})
    runtime.require(report['schema'] == setup.SCHEMA and report['operation_id'] == value['attempt_id'] and
        report['original_parent'] == dict(generation=1, **value['parent']) and
        report['original_parent_readback'] == value['parent']['adapter'] and
        report['setup_adapter'] == descriptor['adapter'] and report['recipe'] == setup.RECIPE and
        report['source_pins'] == setup._sources() and report['B_positive_zero'] is True and
        report['function_equivalence'] == 'algebraic-B-zero-only' and
        report['full_model_numeric_preservation'] == report['trainability'] == 'NOT_RUN' and
        report['flags'] == dict.fromkeys(('trained', 'learned_change', 'gain', 'selected',
            'installed', 'ordinary', 'reward'), False) and
        all(v is False for v in report['flags'].values()), 'PARENT_V2_SETUP_CONTEXT')
    for field, values in [('old_factor_sha256', original), ('setup_factor_sha256', factors)]:
        runtime.require(report[field] == {n: hashlib.sha256(v).hexdigest() for n, v in values.items()},
                        'PARENT_V2_FACTOR_HASHES')
    for name, raw in factors.items():
        if name.endswith('.B'): runtime.require(not any(raw), 'PARENT_V2_SETUP_B')
        else:
            numbers = [v[0] for v in struct.iter_unpack('<f', raw)]
            runtime.require(all(math.isfinite(v) and abs(v) <= 1 for v in numbers) and
                            any(v != 0 for v in numbers), 'PARENT_V2_SETUP_A')
    for field in ('capture_cost', 'setup_cost'):
        step.closed(report[field], 'wall_ns cpu_ns')
        runtime.require(all(type(v) is int and v >= 0 for v in report[field].values()), 'PARENT_V2_COST')
    return factors


def candidate_record(value, descriptor, candidate, changed, task_link=None):
    record = dict(schema=named(value, 'llm-runtime-parent-candidate'), scope=step.SCOPE, operation='train',
        attempt_binding=binding(value), input=runtime.identity(value), source=value['source'],
        contract=value['parent']['contract'], parent=value['parent'], parent_generation=1,
        candidate_generation=2, setup=descriptor, candidate=candidate,
        training_changed_from_setup=changed, flags=step.FALSES)
    if new_task(value):
        record['task_link'] = task_link if task_link is not None else value['initial_setup']['task_link']
    if research_module(value):
        record['research'] = research_module(value).context(value)
    if observed.is_observed(value):
        record['observation_execution'] = observed.context(value)
    return record


def verify_completion(value):
    plan, _, contract, _, original, _, summary = preflight(value)
    directory = Path(value['output'])
    raw = step.parent.read_regular(directory / 'actual-receipt.json', step.MAX_INPUT)
    report = json.loads(raw, object_pairs_hook=runtime.unique)
    step.closed(report, 'schema scope operation attempt_id attempt_binding input source experiment parent '
        'parent_preflight parent_readback actual_backend actual_device actual_threads torch_cuda environment '
        'outcome observed_wall_ns training setup candidate setup_changed_from_parent training_changed_from_setup ' +
        ' '.join(step.FALSES) + (' task_link' if new_task(value) else '') +
        (' research' if research_module(value) else '') +
        (' observation_execution' if observed.is_observed(value) else ''))
    if observed.is_observed(value):
        runtime.require(report['observation_execution'] == observed.context(value), 'OBSERVED_REPORT_CONTEXT')
    if new_task(value):
        from llm_runtime_parent_step_task_v2 import verify_report
        verify_report(value, report['task_link'])
    if research_module(value):
        runtime.require(report['research'] == research_module(value).context(value),
                        'RESEARCH_V4_REPORT_CONTEXT' if task_research.is_research(value) else 'RESEARCH_V3_REPORT_CONTEXT')
    runtime.require(report['schema'] == named(value, 'llm-runtime-parent-step-actual') and report['scope'] == step.SCOPE and report['operation'] == 'train' and
        report['attempt_id'] == value['attempt_id'] and report['attempt_binding'] == binding(value) and
        report['input'] == runtime.identity(value) and report['source'] == value['source'] and
        report['experiment'] == value['experiment'] and report['parent'] == value['parent'] and
        report['parent_preflight'] == summary and report['parent_readback'] == value['parent']['adapter'] and
        report['actual_backend'] == report['actual_device'] == 'cpu' and
        type(report['actual_threads']) is int and report['actual_threads'] == plan['threads'] and
        report['outcome'] == 'success' and all(report[n] is False for n in step.FALSES), 'PARENT_V2_COMPLETION')
    step.closed(report['environment'], 'torch transformers peft safetensors tokenizers numpy accelerate')
    runtime.require(all(type(v) is str and 0 < len(v) <= 128 for v in report['environment'].values()) and
        type(report['observed_wall_ns']) is int and report['observed_wall_ns'] >= 0, 'PARENT_V2_OBSERVATIONS')
    training = report['training']
    step.closed(training, 'steps loss tokens supervised_tokens supported_profile_flops flop_scope' +
                (' objective' if research_module(value) else ''))
    runtime.require(type(training['steps']) is int and training['steps'] == plan['training_steps'] and
        type(training['loss']) is list and len(training['loss']) == training['steps'] and
        all(type(v) is str and 0 < len(v) <= 128 and math.isfinite(float(v)) for v in training['loss']) and
        all(type(training[n]) is int and training[n] >= 0 for n in
            ('tokens', 'supervised_tokens', 'supported_profile_flops')) and
        0 < training['supervised_tokens'] <= training['tokens'] <= training['steps'] * plan['input_tokens_max'] and
        training['flop_scope'] == 'profiler-supported-operators-only-not-total-work', 'PARENT_V2_TRAINING')
    if research_module(value):
        research.verify_training(training)
    prepared = verify_setup(value, report['setup'], contract, original)
    candidate = _material(value, directory, '', report['candidate'])
    changed = candidate != prepared
    record = step.read_object(directory / (named(value, 'parent-candidate') + '.json'))
    step.closed(record, 'schema scope operation attempt_binding input source contract parent parent_generation '
        'candidate_generation setup candidate training_changed_from_setup flags' + (' task_link' if new_task(value) else '') +
        (' research' if research_module(value) else '') +
        (' observation_execution' if observed.is_observed(value) else ''))
    runtime.require(type(record['parent_generation']) is int and type(record['candidate_generation']) is int and
        type(record['training_changed_from_setup']) is bool and all(v is False for v in record['flags'].values()) and
        type(report['training_changed_from_setup']) is bool and
        report['training_changed_from_setup'] == changed and report['setup_changed_from_parent'] is True and
        report['setup_changed_from_parent'] == (prepared != original) and
        record == candidate_record(value, report['setup'], report['candidate'], changed,
                                   report.get('task_link')), 'PARENT_V2_LINEAGE')
    runtime.require(step.parent.read_regular(directory / 'target-contract.json',
        runtime.contract_module().MAX_MANIFEST_BYTES) == step.parent.read_regular(
            value['files']['parent_contract'], runtime.contract_module().MAX_MANIFEST_BYTES), 'PARENT_V2_CONTRACT')
    return hashlib.sha256(raw).hexdigest()


def child(args, value):
    runtime.require(runtime.identity(value) == step.digest(args.expected_parent_step_input), 'PARENT_STEP_INPUT_PIN')
    runtime.require(str(Path(args.materials).absolute()) == value['files']['materials'] and
        str(Path(args.plan).absolute()) == value['files']['plan'] and
        str(Path(args.output).absolute()) == value['output'] and args.role == 'candidate', 'PARENT_STEP_CHILD_ROLES')
    plan, manifest, contract, raw, original, _, summary = preflight(value)
    directory = Path(args.output)
    observer = runtime.Observer(directory, plan['backend'])
    report = dict(schema=named(value, 'llm-runtime-parent-step-actual'), scope=step.SCOPE, operation='train', attempt_id=value['attempt_id'],
        attempt_binding=binding(value), input=runtime.identity(value), source=value['source'],
        experiment=value['experiment'], parent=value['parent'], parent_preflight=summary, **step.FALSES)
    if research_module(value):
        report['research'] = research_module(value).context(value)
    if observed.is_observed(value):
        report['observation_execution'] = observed.context(value)
    begin = time.monotonic_ns()
    try:
        imports = observer.stage('runtime-import', lambda: runtime.runtime_import(plan))
        torch, device, _, _, _, save_file, _ = imports
        model, tokenizer, shapes, _ = observer.stage('model-load',
            lambda: runtime.load_model(Path(value['files']['materials']), plan, imports))
        loaded, loaded_raw, cid = observer.stage('derived-material-check', lambda: runtime.make_contract(
            model, tokenizer, shapes, Path(value['files']['materials']), manifest, plan))
        if new_task(value):
            from llm_runtime_parent_step_task_v2 import verify_link
            report['task_link'] = verify_link(value, contract, loaded, loaded_raw, cid, plan)
            cid = value['parent']['contract']
        else:
            runtime.require(loaded == contract and loaded_raw == raw and cid == value['parent']['contract'],
                            'PARENT_STEP_LOADED_CONTRACT')
        model = observer.stage('adapter-insertion', lambda: runtime.insert_lora(model, plan, 'candidate', torch))
        captured = observer.stage('caller-A-capture', lambda: setup.capture_seeded_a(model, contract, torch, setup.RECIPE))
        prepared, setup_raw, setup_report = observer.stage('initial-working-copy-setup', lambda:
            setup.prepare_working_copy(model, contract, cid, dict(generation=1, **value['parent']),
                step.parent.read_regular(value['files']['parent_artifact'], len(setup.canonical_zero_parent())),
                captured, torch, value['attempt_id']))
        (directory / 'setup-wrapped-adapter.json').write_bytes(setup_raw)
        observer.stage('setup-artifact-save', lambda: save_file({n: p.detach().cpu().contiguous() for n, p in
            runtime.adapter_tensors(model, contract['targets']).items()}, str(directory / 'setup-artifact.safetensors')))
        runtime.save(directory / 'initial-setup-v2.json', setup_report)
        descriptor = dict(adapter=setup_report['setup_adapter'],
            file_sha256=runtime.file_sha(directory / 'setup-artifact.safetensors'),
            receipt_sha256=runtime.file_sha(directory / 'initial-setup-v2.json'))
        readback = observer.stage('setup-complete-readback', lambda: verify_setup(value, descriptor, contract, original))
        runtime.require(readback == prepared, 'PARENT_V2_SETUP_READBACK')
        report.update(setup=descriptor, parent_readback=setup_report['original_parent_readback'], actual_backend='cpu',
            actual_device=str(device), actual_threads=torch.get_num_threads(), torch_cuda=torch.version.cuda,
            environment={n: importlib.metadata.version(n) for n in
                ('torch', 'transformers', 'peft', 'safetensors', 'tokenizers', 'numpy', 'accelerate')})
        report['training'] = observer.stage('training', lambda:
            research.train(model, tokenizer, plan, torch, device) if research_module(value) else
            runtime.train(model, tokenizer, plan, 'candidate', torch, device))
        index = {n: runtime.tensor_descriptor(t) for n, t in runtime.backbone_tensors(model, shapes).items()}
        runtime.require(runtime.contract_module().H('llm-tensor-index-v1', runtime.canonical(index)).hex() ==
                        contract['backbone']['index_root'], 'PARENT_STEP_BACKBONE_MUTATION')
        adapter_raw, aid, tensors = observer.stage('adapter-material-check', lambda: runtime.wrap_adapter(model, contract, cid))
        (directory / 'wrapped-adapter.json').write_bytes(adapter_raw)
        observer.stage('artifact-save', lambda: save_file({n: t.detach().cpu().contiguous() for n, t in tensors.items()},
                                                         str(directory / 'artifact.safetensors')))
        candidate = dict(adapter=aid, file_sha256=runtime.file_sha(directory / 'artifact.safetensors'))
        changed = {n: runtime.tensor_bytes(t) for n, t in tensors.items()} != prepared
        runtime.save(directory / (named(value, 'parent-candidate') + '.json'), candidate_record(value, descriptor, candidate, changed,
                                                                            report.get('task_link')))
        (directory / 'target-contract.json').write_bytes(raw)
        preflight(value)
        report.update(candidate=candidate, setup_changed_from_parent=prepared != original,
                      training_changed_from_setup=changed, outcome='success')
    except BaseException as error:
        report.update(outcome='failed', error_type=type(error).__name__, error=str(error)[:128])
        raise
    finally:
        report['observed_wall_ns'] = time.monotonic_ns() - begin
        runtime.save(directory / 'actual-receipt.json', report)


def run(args):
    runtime.require(args.operation == 'train', 'PARENT_V2_OPERATION_UNIMPLEMENTED')
    runtime.require(args.initial_setup_profile in (PROFILE, NEW_TASK_PROFILE, research.PROFILE, task_research.PROFILE, observed.PROFILE) and args.parent_material and args.parent_material_sha256,
                    'PARENT_V2_ARGUMENTS')
    selected_research = (task_research if args.initial_setup_profile == task_research.PROFILE else
                         research if args.initial_setup_profile == research.PROFILE else None)
    is_research = selected_research is not None
    is_observed = args.initial_setup_profile == observed.PROFILE
    observation_role = (getattr(args, 'observation_plan', None), getattr(args, 'observation_plan_sha256', None))
    runtime.require(all(observation_role) if is_observed else not any(observation_role), 'OBSERVED_PLAN_ARGUMENTS')
    plan_role = (getattr(args, 'research_plan', None), getattr(args, 'research_plan_sha256', None))
    runtime.require(all(plan_role) if is_research else not any(plan_role), 'RESEARCH_V3_ARGUMENTS')
    runtime.require(not any(getattr(args, n) for n in ('candidate_directory', 'expected_candidate_adapter',
        'expected_candidate_file_sha256', 'expected_candidate_record_sha256', 'expected_candidate_result_sha256')),
        'PARENT_STEP_CANDIDATE_ARGUMENTS')
    files = {n: str(Path(getattr(args, n)).absolute()) for n in
        ('materials', 'plan', 'parent_contract', 'parent_adapter', 'parent_artifact')}
    files['candidate_directory'] = None
    directory = Path(args.output).absolute()
    value = dict(schema=observed.SCHEMA if is_observed else selected_research.SCHEMA if is_research else SCHEMA, scope=step.SCOPE, attempt_id=args.attempt_id, operation='train',
        experiment=args.expected_plan, source=sources(args.initial_setup_profile), files=files,
        parent=dict(contract=args.expected_contract, adapter=args.expected_parent_adapter,
                    file_sha256=args.expected_parent_file_sha256), candidate=None,
        output=str(directory / 'execution'), flags=step.FALSES,
        initial_setup=dict(profile=args.initial_setup_profile, recipe=dict(setup.RECIPE), parent_material=dict(
            path=str(Path(args.parent_material).absolute()), sha256=args.parent_material_sha256)))
    if is_research:
        value['initial_setup']['research_plan'] = dict(path=str(Path(plan_role[0]).absolute()), sha256=plan_role[1])
    if is_observed:
        value['initial_setup']['observation_plan'] = dict(path=str(Path(observation_role[0]).absolute()), sha256=observation_role[1])
    if new_task(value):
        from llm_runtime_parent_step_task_v2 import request_link
        value['initial_setup']['task_link'] = request_link(value)
    plan, *_ = preflight(value)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    frozen = directory / (named(value, 'parent-step-input') + '.json')
    runtime.save(frozen, value)
    command = [sys.executable, str(Path(runtime.__file__).resolve()), '_child', '--materials', files['materials'],
        '--plan', files['plan'], '--output', value['output'], '--phase', 'parent-step', '--role', 'candidate',
        '--parent-step-input', str(frozen), '--expected-parent-step-input', runtime.identity(value)]
    observer_profile = observed.checked_plan(value)['observer'] if is_observed else plan.get('exit_observation')
    result = runtime.supervise(command, value['output'], plan['training_budget'], exit_observation=observer_profile)
    completion = dict(schema=named(value, 'llm-runtime-parent-step-result'), scope=step.SCOPE, input=runtime.identity(value), attempt_binding=binding(value),
        supervisor=result, outcome='failed', completion_verified=False, actual_receipt_sha256=None, flags=step.FALSES)
    try:
        if is_observed:
            completion['observation_execution'] = observed.context(value)
        runtime.require(result['outcome'] == 'success' and type(result['exit_code']) is int and result['exit_code'] == 0 and
            result['stop_reason'] is None and result['budget'] == plan['training_budget'] and
            result['waited_child_reaped'] is True and result['owned_child_reap_resolved'] is True and
            result['owned_child_echild_observed'] is False and result['waited_child_observation_error'] is None,
            'PARENT_STEP_CHILD_FAILED')
        if is_observed:
            observed.verify_supervisor(value, result)
        completion['actual_receipt_sha256'] = verify_completion(value)
        completion.update(outcome='success', completion_verified=True)
    finally:
        runtime.save(directory / (named(value, 'parent-step-result') + '.json'), completion)


def add_arguments(parser):
    parser.add_argument('--initial-setup-profile', choices=(PROFILE, NEW_TASK_PROFILE, research.PROFILE, task_research.PROFILE, observed.PROFILE))
    parser.add_argument('--parent-material')
    parser.add_argument('--parent-material-sha256')
    parser.add_argument('--research-plan')
    parser.add_argument('--research-plan-sha256')
    parser.add_argument('--observation-plan')
    parser.add_argument('--observation-plan-sha256')
