"""Explicit parent consumption for the existing pilot, without installation authority.

This is one engineering operation, not the five-participant experiment or a
selection decision. The caller retains pins and unique attempt identities. No
registry, CURRENT writer, generation counter or additional supervisor is owned
here. Old-source artifacts deliberately fail the same-source contract check.
"""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
import time

import llm_parent_material as parent
import llm_runtime_pilot as runtime

SCHEMA = 'llm-runtime-parent-step-input-v1'
SCOPE = 'engineering-parent-consumption-no-installation-selection-or-quality-qualification'
FALSES = dict.fromkeys(runtime.QUALIFICATIONS + [
    'adoption', 'reward', 'installation_accepted', 'all_required_controls_executed'], False)
MAX_INPUT = 64 * 1024


def closed(value, fields):
    runtime.require(type(value) is dict and set(value) == set(fields.split()), 'PARENT_STEP_FIELDS')


def digest(value):
    runtime.contract_module().digest(value)
    runtime.require(value != '0' * 64, 'PARENT_STEP_ZERO_IDENTITY')
    return value


def sources():
    return {name: runtime.file_sha(path) for name, path in {
        'runtime': Path(runtime.__file__), 'parent_step': Path(__file__),
        'preflight': Path(parent.__file__),
        'contract': Path(runtime.contract_module().__file__),
    }.items()}


def read_object(path, maximum=MAX_INPUT):
    return json.loads(parent.read_regular(path, maximum), object_pairs_hook=runtime.unique)


def attempt_binding(value):
    return runtime.identity(dict(schema='llm-runtime-parent-attempt-v1',
        attempt_id=value['attempt_id'], experiment=value['experiment'],
        source=value['source'], parent=value['parent']))


def preflight(value):
    """All exact-context/byte checks precede model imports and output creation."""
    closed(value, 'schema scope attempt_id operation experiment source files parent candidate output flags')
    runtime.require(value['schema'] == SCHEMA and value['scope'] == SCOPE and
                    value['flags'] == FALSES and all(v is False for v in value['flags'].values()),
                    'PARENT_STEP_SCOPE')
    digest(value['attempt_id']); digest(value['experiment'])
    runtime.require(value['operation'] in ('train', 'evaluate', 'readback'), 'PARENT_STEP_OPERATION')
    runtime.require(value['source'] == sources(), 'PARENT_STEP_SOURCE')
    closed(value['files'], 'materials plan parent_contract parent_adapter parent_artifact candidate_directory')
    for role, path in value['files'].items():
        if role == 'candidate_directory' and value['operation'] != 'evaluate':
            runtime.require(path is None, 'PARENT_STEP_CANDIDATE_ROLE')
        else:
            runtime.require(type(path) is str and 0 < len(path) <= 4096 and Path(path).is_absolute(),
                            'PARENT_STEP_FILE_ROLE')
    runtime.require(type(value['output']) is str and 0 < len(value['output']) <= 4096 and
                    Path(value['output']).is_absolute(), 'PARENT_STEP_OUTPUT_ROLE')
    closed(value['parent'], 'contract adapter file_sha256')
    for pin in value['parent'].values(): digest(pin)
    plan = runtime.validate_plan(read_object(value['files']['plan'], 1024 * 1024))
    runtime.require(runtime.identity(plan) == value['experiment'] and
                    plan['runtime_source'] == value['source']['runtime'], 'PARENT_STEP_EXPERIMENT')
    runtime.require(plan['backend'] == 'cpu', 'PARENT_STEP_CPU_ONLY')
    manifest, config = runtime.verify_materials(value['files']['materials'])
    profile = 'linux-owned-exit-cleanup-v2' if 'exit_observation' in plan else 'strict-v1'
    expected_plan = runtime.experiment_plan(manifest, backend='cpu', threads=plan['threads'],
        steps=plan['training_steps'], exit_observation=profile)
    runtime.require(plan == expected_plan, 'PARENT_STEP_EXACT_PLAN')
    pins, files = value['parent'], value['files']
    factors, summary = parent.verify_parent(files['parent_contract'], files['parent_adapter'],
        files['parent_artifact'], expected_contract=pins['contract'],
        expected_adapter=pins['adapter'], expected_file_sha256=pins['file_sha256'])
    c = runtime.contract_module()
    raw = parent.read_regular(files['parent_contract'], c.MAX_MANIFEST_BYTES)
    contract = c.verify_target_contract(raw, pins['contract'],
        expected_backbone_root=summary['backbone'], expected_tokenizer_root=summary['tokenizer'])
    tokenizer_config = runtime.read_json(Path(files['materials']) / 'tokenizer_config.json')
    _, expected_raw, cid = runtime.contract_from_inventory(contract['backbone']['index'],
        tokenizer_config['chat_template'], config, manifest, plan)
    runtime.require(cid == pins['contract'] and raw == expected_raw, 'PARENT_STEP_CURRENT_CONTRACT')
    candidate_factors = None
    if value['operation'] == 'evaluate':
        closed(value['candidate'], 'adapter file_sha256 record_sha256 result_sha256')
        for pin in value['candidate'].values(): digest(pin)
        directory = Path(files['candidate_directory'])
        record_raw = parent.read_regular(directory / 'parent-candidate.json', MAX_INPUT)
        runtime.require(hashlib.sha256(record_raw).hexdigest() == value['candidate']['record_sha256'],
                        'PARENT_STEP_CANDIDATE_RECORD_PIN')
        record = json.loads(record_raw, object_pairs_hook=runtime.unique)
        closed(record, 'schema scope operation attempt_binding input contract parent candidate flags')
        digest(record['input'])
        runtime.require(record['schema'] == 'llm-runtime-parent-candidate-v1' and
            record['scope'] == SCOPE and record['operation'] == 'train' and
            record['attempt_binding'] == attempt_binding(value) and record['parent'] == pins and
            record['contract'] == cid and record['flags'] == FALSES and
            all(v is False for v in record['flags'].values()) and
            record['candidate'] == {k: value['candidate'][k] for k in ('adapter', 'file_sha256')},
            'PARENT_STEP_CANDIDATE_CONTEXT')
        training_input = read_object(directory.parent / 'parent-step-input.json')
        runtime.require(runtime.identity(training_input) == record['input'] and
            training_input['operation'] == 'train' and training_input['output'] == str(directory) and
            attempt_binding(training_input) == attempt_binding(value), 'PARENT_STEP_TRAINING_INPUT')
        result_raw = parent.read_regular(directory.parent / 'parent-step-result.json', 1024 * 1024)
        runtime.require(hashlib.sha256(result_raw).hexdigest() == value['candidate']['result_sha256'],
                        'PARENT_STEP_TRAINING_RESULT_PIN')
        result = json.loads(result_raw, object_pairs_hook=runtime.unique)
        closed(result, 'schema scope input attempt_binding supervisor outcome completion_verified actual_receipt_sha256 flags')
        runtime.require(result['schema'] == 'llm-runtime-parent-step-result-v1' and
            result['scope'] == SCOPE and result['input'] == record['input'] and
            result['attempt_binding'] == attempt_binding(value) and result['outcome'] == 'success' and
            result['completion_verified'] is True and result['flags'] == FALSES and
            all(v is False for v in result['flags'].values()) and
            result['supervisor']['outcome'] == 'success' and result['supervisor']['stop_reason'] is None,
            'PARENT_STEP_TRAINING_NOT_COMPLETED')
        runtime.require(verify_completion(training_input) == result['actual_receipt_sha256'],
                        'PARENT_STEP_TRAINING_RECEIPT_PIN')
        candidate_factors, _ = parent.verify_parent(files['parent_contract'],
            directory / 'wrapped-adapter.json', directory / 'artifact.safetensors',
            expected_contract=cid, expected_adapter=value['candidate']['adapter'],
            expected_file_sha256=value['candidate']['file_sha256'])
    else:
        runtime.require(value['candidate'] is None, 'PARENT_STEP_CANDIDATE_ROLE')
    return plan, manifest, contract, raw, factors, candidate_factors, summary


def verify_completion(value):
    """Check fixed-child local readback; this is not independent execution proof."""
    plan, _, _, _, _, _, summary = preflight(value)
    directory = Path(value['output'])
    raw = parent.read_regular(directory / 'actual-receipt.json', MAX_INPUT)
    report = json.loads(raw, object_pairs_hook=runtime.unique)
    fields = ('schema scope operation attempt_id attempt_binding input source experiment parent '
              'parent_preflight parent_readback actual_backend actual_device actual_threads torch_cuda '
              'environment outcome observed_wall_ns ' + ' '.join(FALSES))
    fields += (' training candidate unchanged_parent' if value['operation'] == 'train' else
               ' artifact forward_executed greedy_decode_executed requests predictions_sha256 task_scope')
    closed(report, fields)
    closed(report['environment'], 'torch transformers peft safetensors tokenizers numpy accelerate')
    runtime.require(all(type(version) is str and 0 < len(version) <= 128
                        for version in report['environment'].values()) and
                    type(report['observed_wall_ns']) is int and report['observed_wall_ns'] >= 0,
                    'PARENT_STEP_COMPLETION_OBSERVATIONS')
    runtime.require(report['schema'] == 'llm-runtime-parent-step-actual-v1' and report['scope'] == SCOPE and
        report['operation'] == value['operation'] and report['attempt_id'] == value['attempt_id'] and
        report['attempt_binding'] == attempt_binding(value) and report['input'] == runtime.identity(value) and
        report['source'] == value['source'] and report['experiment'] == value['experiment'] and
        report['parent'] == value['parent'] and report['parent_preflight'] == summary and
        report['parent_readback'] == value['parent']['adapter'] and report['outcome'] == 'success' and
        report['actual_backend'] == 'cpu' and report['actual_device'] == 'cpu' and
        type(report['actual_threads']) is int and report['actual_threads'] == plan['threads'] and
        all(report[name] is False for name in FALSES), 'PARENT_STEP_COMPLETION_CONTEXT')
    if value['operation'] == 'train':
        runtime.require(type(report['training']['steps']) is int and
            report['training']['steps'] == plan['training_steps'], 'PARENT_STEP_TRAINING_STEPS')
        candidate = report['candidate']
        closed(candidate, 'adapter file_sha256')
        for pin in candidate.values(): digest(pin)
        record = read_object(directory / 'parent-candidate.json')
        expected = dict(schema='llm-runtime-parent-candidate-v1', scope=SCOPE, operation='train',
            attempt_binding=attempt_binding(value), input=runtime.identity(value),
            contract=value['parent']['contract'], parent=value['parent'], candidate=candidate, flags=FALSES)
        runtime.require(record == expected and type(report['unchanged_parent']) is bool and
            report['unchanged_parent'] == (candidate['adapter'] == value['parent']['adapter']),
            'PARENT_STEP_COMPLETION_CANDIDATE')
        parent.verify_parent(value['files']['parent_contract'], directory / 'wrapped-adapter.json',
            directory / 'artifact.safetensors', expected_contract=value['parent']['contract'],
            expected_adapter=candidate['adapter'], expected_file_sha256=candidate['file_sha256'])
    else:
        expected_artifact = (value['candidate']['adapter'] if value['operation'] == 'evaluate'
                             else value['parent']['adapter'])
        runtime.require(report['artifact'] == expected_artifact and report['forward_executed'] is True and
            report['greedy_decode_executed'] is True and
            report['task_scope'] == 'existing-public-fixture-not-untouched-future-evaluation',
            'PARENT_STEP_COMPLETION_READBACK')
        predictions_raw = parent.read_regular(directory / 'predictions.json', MAX_INPUT)
        runtime.require(hashlib.sha256(predictions_raw).hexdigest() == report['predictions_sha256'],
                        'PARENT_STEP_COMPLETION_PREDICTIONS')
        predictions = json.loads(predictions_raw, object_pairs_hook=runtime.unique)
        checked_plan = plan
        if value['operation'] == 'readback':
            # Reuse the reported-record checker on this explicitly selected one
            # training task. This local projection is not a new evaluation plan.
            checked_plan = dict(plan, tasks=[dict(row, partition='readback')
                for row in plan['tasks'] if row['partition'] == 'training'][:1])
        runtime.verify_predictions(predictions, checked_plan, 'candidate', expected_artifact,
                                   value['parent']['contract'])
        runtime.require(type(report['requests']) is int and report['requests'] == len(predictions),
                        'PARENT_STEP_COMPLETION_REQUESTS')
    runtime.require(parent.read_regular(directory / 'target-contract.json',
        runtime.contract_module().MAX_MANIFEST_BYTES) == parent.read_regular(
            value['files']['parent_contract'], runtime.contract_module().MAX_MANIFEST_BYTES),
        'PARENT_STEP_COMPLETION_CONTRACT')
    return hashlib.sha256(raw).hexdigest()


def copy_factors(model, contract, factors, expected_adapter, torch):
    """Copy absolute A/B once; byte readback and wrapper identity must both agree."""
    target = runtime.adapter_tensors(model, contract['targets'])
    runtime.require(set(target) == set(factors), 'PARENT_STEP_FACTOR_SET')
    with torch.no_grad():
        for name, parameter in target.items():
            runtime.require(parameter.dtype == torch.float32, 'PARENT_STEP_FACTOR_DTYPE')
            tensor = torch.frombuffer(bytearray(factors[name]), dtype=torch.float32).clone()
            runtime.require(tensor.numel() == parameter.numel(), 'PARENT_STEP_FACTOR_SHAPE')
            parameter.copy_(tensor.reshape(parameter.shape).to(parameter.device))
            runtime.require(runtime.tensor_bytes(parameter) == factors[name], 'PARENT_STEP_FACTOR_READBACK')
    cid = runtime.contract_module().freeze_target_contract(contract)[1]
    _, observed, _ = runtime.wrap_adapter(model, contract, cid)
    runtime.require(observed == expected_adapter, 'PARENT_STEP_ADAPTER_READBACK')
    return observed


def child(args):
    value = read_object(args.parent_step_input)
    runtime.require(runtime.identity(value) == digest(args.expected_parent_step_input),
                    'PARENT_STEP_INPUT_PIN')
    runtime.require(str(Path(args.materials).absolute()) == value['files']['materials'] and
        str(Path(args.plan).absolute()) == value['files']['plan'] and
        str(Path(args.output).absolute()) == value['output'] and args.role == 'candidate',
        'PARENT_STEP_CHILD_ROLES')
    plan, manifest, contract, raw, factors, candidate_factors, summary = preflight(value)
    directory = Path(args.output)
    observer = runtime.Observer(directory, plan['backend'])
    report = dict(schema='llm-runtime-parent-step-actual-v1', scope=SCOPE,
        operation=value['operation'], attempt_id=value['attempt_id'], attempt_binding=attempt_binding(value),
        input=runtime.identity(value), source=value['source'], experiment=value['experiment'],
        parent=value['parent'], parent_preflight=summary, **FALSES)
    begin = time.monotonic_ns()
    try:
        imports = observer.stage('runtime-import', lambda: runtime.runtime_import(plan))
        torch, device, _, _, _, save_file, _ = imports
        model, tokenizer, shapes, _ = observer.stage('model-load',
            lambda: runtime.load_model(Path(value['files']['materials']), plan, imports))
        loaded_contract, loaded_raw, cid = observer.stage('derived-material-check',
            lambda: runtime.make_contract(model, tokenizer, shapes, Path(value['files']['materials']), manifest, plan))
        runtime.require(loaded_raw == raw and loaded_contract == contract and cid == value['parent']['contract'],
                        'PARENT_STEP_LOADED_CONTRACT')
        model = observer.stage('adapter-insertion', lambda: runtime.insert_lora(model, plan, 'candidate', torch))
        parent_readback = observer.stage('parent-byte-readback',
            lambda: copy_factors(model, contract, factors, value['parent']['adapter'], torch))
        report.update(parent_readback=parent_readback, actual_backend='cpu', actual_device=str(device),
            actual_threads=torch.get_num_threads(), torch_cuda=torch.version.cuda,
            environment={name: importlib.metadata.version(name) for name in
                ('torch', 'transformers', 'peft', 'safetensors', 'tokenizers', 'numpy', 'accelerate')})
        if value['operation'] == 'train':
            report['training'] = observer.stage('training',
                lambda: runtime.train(model, tokenizer, plan, 'candidate', torch, device))
            index = {name: runtime.tensor_descriptor(t) for name, t in runtime.backbone_tensors(model, shapes).items()}
            runtime.require(runtime.contract_module().H('llm-tensor-index-v1', runtime.canonical(index)).hex() ==
                            contract['backbone']['index_root'], 'PARENT_STEP_BACKBONE_MUTATION')
            adapter_raw, aid, tensors = observer.stage('adapter-material-check',
                lambda: runtime.wrap_adapter(model, contract, cid))
            (directory / 'wrapped-adapter.json').write_bytes(adapter_raw)
            observer.stage('artifact-save', lambda: save_file(
                {n: t.detach().cpu().contiguous() for n, t in tensors.items()}, str(directory / 'artifact.safetensors')))
            candidate = dict(adapter=aid, file_sha256=runtime.file_sha(directory / 'artifact.safetensors'))
            runtime.save(directory / 'parent-candidate.json', dict(schema='llm-runtime-parent-candidate-v1',
                scope=SCOPE, operation='train', attempt_binding=attempt_binding(value), input=runtime.identity(value),
                contract=cid, parent=value['parent'], candidate=candidate, flags=FALSES))
            report.update(candidate=candidate, unchanged_parent=aid == value['parent']['adapter'])
        else:
            aid = parent_readback
            if value['operation'] == 'evaluate':
                aid = observer.stage('candidate-byte-readback', lambda: copy_factors(model, contract,
                    candidate_factors, value['candidate']['adapter'], torch))
            rows = [row for row in plan['tasks'] if row['partition'] != 'training']
            if value['operation'] == 'readback':
                rows = [row for row in plan['tasks'] if row['partition'] == 'training'][:1]
            predictions = observer.stage('real-forward-greedy-decode', lambda: [runtime.decode(
                model, tokenizer, row, contract, cid, plan, torch, device, aid, 'candidate') for row in rows])
            runtime.save(directory / 'predictions.json', predictions)
            report.update(artifact=aid, forward_executed=True, greedy_decode_executed=True,
                requests=len(predictions), predictions_sha256=runtime.file_sha(directory / 'predictions.json'),
                task_scope='existing-public-fixture-not-untouched-future-evaluation')
        # Recheck the original input files after use. No operation writes them.
        preflight(value)
        (directory / 'target-contract.json').write_bytes(raw)
        report['outcome'] = 'success'
    except BaseException as error:
        report.update(outcome='failed', error_type=type(error).__name__, error=str(error)[:128])
        raise
    finally:
        report['observed_wall_ns'] = time.monotonic_ns() - begin
        runtime.save(directory / 'actual-receipt.json', report)


def run(args):
    files = {name: str(Path(getattr(args, name)).absolute()) for name in
        ('materials', 'plan', 'parent_contract', 'parent_adapter', 'parent_artifact')}
    files['candidate_directory'] = str(Path(args.candidate_directory).absolute()) if args.candidate_directory else None
    candidate_args = (args.expected_candidate_adapter, args.expected_candidate_file_sha256,
                      args.expected_candidate_record_sha256, args.expected_candidate_result_sha256)
    runtime.require(all(candidate_args) if args.operation == 'evaluate' else not any(candidate_args),
                    'PARENT_STEP_CANDIDATE_ARGUMENTS')
    candidate = dict(zip(('adapter', 'file_sha256', 'record_sha256', 'result_sha256'), candidate_args)) if args.operation == 'evaluate' else None
    directory = Path(args.output).absolute()
    value = dict(schema=SCHEMA, scope=SCOPE, attempt_id=args.attempt_id, operation=args.operation,
        experiment=args.expected_plan, source=sources(), files=files,
        parent=dict(contract=args.expected_contract, adapter=args.expected_parent_adapter,
                    file_sha256=args.expected_parent_file_sha256), candidate=candidate,
        output=str(directory / 'execution'), flags=FALSES)
    plan, *_ = preflight(value)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    frozen = directory / 'parent-step-input.json'
    runtime.save(frozen, value)
    command = [sys.executable, str(Path(runtime.__file__).resolve()), '_child',
        '--materials', files['materials'], '--plan', files['plan'], '--output', value['output'],
        '--phase', 'parent-step', '--role', 'candidate', '--parent-step-input', str(frozen),
        '--expected-parent-step-input', runtime.identity(value)]
    result = runtime.supervise(command, value['output'],
        plan['training_budget' if args.operation == 'train' else 'inference_budget'],
        exit_observation=plan.get('exit_observation'))
    completion = dict(schema='llm-runtime-parent-step-result-v1', scope=SCOPE,
        input=runtime.identity(value), attempt_binding=attempt_binding(value), supervisor=result,
        outcome='failed', completion_verified=False, actual_receipt_sha256=None, flags=FALSES)
    try:
        runtime.require(result['outcome'] == 'success', 'PARENT_STEP_CHILD_FAILED')
        completion['actual_receipt_sha256'] = verify_completion(value)
        completion.update(outcome='success', completion_verified=True)
    finally:
        runtime.save(directory / 'parent-step-result.json', completion)


def add_parser(commands):
    parser = commands.add_parser('parent-step', description=__doc__)
    for name in ('materials', 'plan', 'expected-plan', 'output', 'attempt-id', 'parent-contract',
                 'parent-adapter', 'parent-artifact', 'expected-contract', 'expected-parent-adapter',
                 'expected-parent-file-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--operation', choices=('train', 'evaluate', 'readback'), required=True)
    for name in ('candidate-directory', 'expected-candidate-adapter', 'expected-candidate-file-sha256',
                 'expected-candidate-record-sha256', 'expected-candidate-result-sha256'):
        parser.add_argument('--' + name)
