"""Unsigned candidate evaluation through the unchanged pilot supervisor.

This separate observation entry never edits a producer source or receipt. It
does not select/install a candidate, supply an ordinary route or issue an
independent evaluation receipt. Readback is deliberately not implemented here.
"""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
import time

import llm_runtime_parent_step as step
import llm_runtime_parent_step_v2 as producer
import llm_runtime_pilot as runtime

INPUT = 'llm-runtime-v2-candidate-observation-input-v1'
ACTUAL = 'llm-runtime-v2-candidate-observation-actual-v1'
RESULT = 'llm-runtime-v2-candidate-observation-result-v1'
INPUT_V4 = 'llm-runtime-v4-candidate-observation-input-v1'
ACTUAL_V4 = 'llm-runtime-v4-candidate-observation-actual-v1'
RESULT_V4 = 'llm-runtime-v4-candidate-observation-result-v1'
SCOPE = 'unsigned-candidate-evaluation-not-independent-qualification-or-ordinary-use'
REQUESTS, DECODE_STEPS = 8, 64


def _version(value):
    runtime.require(value.get('schema') in (INPUT, INPUT_V4), 'CANDIDATE_OBSERVATION_SCOPE')
    return 'v4' if value['schema'] == INPUT_V4 else 'v2'


def _actual_schema(value):
    return ACTUAL_V4 if _version(value) == 'v4' else ACTUAL


def _sources(profile):
    return dict(observer=runtime.file_sha(__file__), producer=producer.sources(profile))


def _terminal(result, budget):
    runtime.require(type(result) is dict and result['outcome'] == 'success' and
        type(result['exit_code']) is int and result['exit_code'] == 0 and
        result['stop_reason'] is None and result['budget'] == budget and
        result['waited_child_reaped'] is True and result['owned_child_reap_resolved'] is True and
        result['owned_child_echild_observed'] is False and result['waited_child_observation_error'] is None,
        'CANDIDATE_OBSERVATION_TERMINAL')


def _producer(value):
    directory = Path(value['training_directory'])
    version = _version(value)
    training = step.read_object(directory / ('parent-step-input-' + version + '.json'))
    profile = training['initial_setup']['profile']
    allowed = ((producer.task_research.PROFILE,) if version == 'v4' else
               (producer.PROFILE, producer.NEW_TASK_PROFILE))
    runtime.require(profile in allowed and producer.version(training) == version and
        value['source'] == _sources(profile), 'CANDIDATE_OBSERVATION_SOURCE')
    checked = producer.preflight(training)
    plan, _, _, _, _, _, _ = checked
    raw = step.parent.read_regular(directory / ('parent-step-result-' + version + '.json'), step.MAX_INPUT)
    runtime.require(hashlib.sha256(raw).hexdigest() == value['training_result_sha256'],
                    'CANDIDATE_OBSERVATION_RESULT_PIN')
    result = json.loads(raw, object_pairs_hook=runtime.unique)
    step.closed(result, 'schema scope input attempt_binding supervisor outcome completion_verified actual_receipt_sha256 flags')
    runtime.require(result['schema'] == producer.named(training, 'llm-runtime-parent-step-result') and result['scope'] == step.SCOPE and
        result['input'] == value['training_input_digest'] == runtime.identity(training) and
        result['attempt_binding'] == producer.binding(training) and result['outcome'] == 'success' and
        result['completion_verified'] is True and result['flags'] == step.FALSES and
        all(v is False for v in result['flags'].values()) and training['parent'] == value['parent'] and
        training['output'] == str(directory / 'execution') and
        training['experiment'] == value['plan_digest'] and training['attempt_id'] != value['attempt_id'],
        'CANDIDATE_OBSERVATION_TRAINING_CONTEXT')
    saved = step.read_object(directory / 'execution/supervisor.json', step.MAX_INPUT)
    runtime.require(type(saved) is dict and runtime.canonical(saved) == runtime.canonical(result['supervisor']),
                    'CANDIDATE_OBSERVATION_SUPERVISOR_DOCUMENT')
    _terminal(result['supervisor'], plan['training_budget'])
    runtime.require(producer.verify_completion(training) == result['actual_receipt_sha256'] ==
        value['actual_training_receipt_sha256'], 'CANDIDATE_OBSERVATION_TRAINING_RECEIPT')
    record = step.parent.read_regular(directory / ('execution/parent-candidate-' + version + '.json'), step.MAX_INPUT)
    runtime.require(hashlib.sha256(record).hexdigest() == value['candidate_record_sha256'],
                    'CANDIDATE_OBSERVATION_RECORD_PIN')
    actual = step.parent.read_regular(directory / 'execution/actual-receipt.json', step.MAX_INPUT)
    runtime.require(hashlib.sha256(actual).hexdigest() == value['actual_training_receipt_sha256'],
                    'CANDIDATE_OBSERVATION_TRAINING_RECEIPT')
    report = json.loads(actual, object_pairs_hook=runtime.unique)
    runtime.require(report['candidate'] == value['candidate'] and json.loads(record, object_pairs_hook=runtime.unique) ==
        producer.candidate_record(training, report['setup'], report['candidate'],
                                  report['training_changed_from_setup'], report.get('task_link')),
        'CANDIDATE_OBSERVATION_CANDIDATE')
    factors = step.parent.verify_parent(training['files']['parent_contract'],
        directory / 'execution/wrapped-adapter.json', directory / 'execution/artifact.safetensors',
        expected_contract=value['parent']['contract'], expected_adapter=value['candidate']['adapter'],
        expected_file_sha256=value['candidate']['file_sha256'])[0]
    return training, checked, factors


def _preflight(value):
    step.closed(value, 'schema scope operation attempt_id source training_directory training_input_digest '
        'training_result_sha256 candidate_record_sha256 actual_training_receipt_sha256 parent candidate plan_digest output flags')
    runtime.require(value['schema'] in (INPUT, INPUT_V4) and value['scope'] == SCOPE and value['operation'] == 'evaluate' and
        value['flags'] == step.FALSES and all(v is False for v in value['flags'].values()),
        'CANDIDATE_OBSERVATION_SCOPE')
    for name in ('training_directory', 'output'):
        runtime.require(type(value[name]) is str and 0 < len(value[name]) <= 4096 and Path(value[name]).is_absolute() and
                        str(Path(value[name]).resolve()) == value[name],
                        'CANDIDATE_OBSERVATION_PATH')
    for name in ('attempt_id', 'training_input_digest', 'training_result_sha256', 'candidate_record_sha256',
                 'actual_training_receipt_sha256', 'plan_digest'): step.digest(value[name])
    for name, fields in [('parent', 'contract adapter file_sha256'), ('candidate', 'adapter file_sha256')]:
        step.closed(value[name], fields)
        for pin in value[name].values(): step.digest(pin)
    training, checked, factors = _producer(value)
    runtime.require(len([r for r in checked[0]['tasks'] if r['partition'] != 'training']) == REQUESTS and
                    checked[0]['generation_tokens'] == 8, 'CANDIDATE_OBSERVATION_FIXED_COUNTS')
    runtime.require(Path(value['output']).parent != Path(value['training_directory']) and
        Path(value['training_directory']) not in Path(value['output']).parents,
        'CANDIDATE_OBSERVATION_OUTPUT_ROLE')
    return training, checked, factors


def _child(args):
    value = step.read_object(args.input)
    runtime.require(runtime.identity(value) == step.digest(args.expected_input), 'CANDIDATE_OBSERVATION_INPUT_PIN')
    training, checked, factors = _preflight(value)
    plan, manifest, contract, _, parent_factors, _, _ = checked
    directory = Path(value['output'])
    runtime.require(directory.is_dir() and all(entry.name == 'process.log' and not entry.is_symlink()
        for entry in directory.iterdir()), 'CANDIDATE_OBSERVATION_ALREADY_USED')
    observer = runtime.Observer(directory, plan['backend'])
    report = dict(schema=_actual_schema(value), scope=SCOPE, input=runtime.identity(value), source=value['source'],
        training_input_digest=value['training_input_digest'], parent=value['parent'], candidate=value['candidate'],
        plan_digest=value['plan_digest'], **step.FALSES)
    begin = time.monotonic_ns()
    try:
        imports = observer.stage('runtime-import', lambda: runtime.runtime_import(plan))
        torch, device, *_ = imports
        model, tokenizer, shapes, _ = observer.stage('model-load', lambda: runtime.load_model(
            Path(training['files']['materials']), plan, imports))
        loaded, loaded_raw, loaded_id = observer.stage('derived-material-check', lambda: runtime.make_contract(
            model, tokenizer, shapes, Path(training['files']['materials']), manifest, plan))
        link = None
        if producer.new_task(training):
            from llm_runtime_parent_step_task_v2 import verify_link
            link = verify_link(training, contract, loaded, loaded_raw, loaded_id, plan)
        else:
            runtime.require(loaded == contract and loaded_raw == checked[3] and
                            loaded_id == value['parent']['contract'], 'CANDIDATE_OBSERVATION_LOADED_CONTRACT')
        model = observer.stage('adapter-insertion', lambda: runtime.insert_lora(model, plan, 'candidate', torch))
        parent_readback = observer.stage('parent-byte-readback', lambda: step.copy_factors(
            model, contract, parent_factors, value['parent']['adapter'], torch))
        candidate_readback = observer.stage('candidate-byte-readback', lambda: step.copy_factors(
            model, contract, factors, value['candidate']['adapter'], torch))
        rows = [row for row in plan['tasks'] if row['partition'] != 'training']
        predictions = observer.stage('real-forward-greedy-decode', lambda: [runtime.decode(
            model, tokenizer, row, contract, value['parent']['contract'], plan, torch, device,
            value['candidate']['adapter'], 'candidate') for row in rows])
        runtime.verify_predictions(predictions, plan, 'candidate', value['candidate']['adapter'], value['parent']['contract'])
        index = {name: runtime.tensor_descriptor(t) for name, t in runtime.backbone_tensors(model, shapes).items()}
        runtime.require(runtime.contract_module().H('llm-tensor-index-v1', runtime.canonical(index)).hex() ==
                        contract['backbone']['index_root'], 'CANDIDATE_OBSERVATION_BACKBONE_MUTATION')
        runtime.require(runtime.wrap_adapter(model, contract, value['parent']['contract'])[1] ==
                        value['candidate']['adapter'], 'CANDIDATE_OBSERVATION_PARAMETER_MUTATION')
        runtime.save(directory / 'predictions.json', predictions)
        _preflight(value)
        report.update(outcome='success', actual_loaded_contract=loaded_id, task_link=link,
            parent_readback=parent_readback, candidate_readback=candidate_readback,
            predictions_sha256=runtime.file_sha(directory / 'predictions.json'), requests=len(predictions),
            completed_decode_steps=sum(row['generated_tokens'] for row in predictions),
            actual_backend='cpu', actual_device=str(device), actual_threads=torch.get_num_threads(),
            torch_cuda=torch.version.cuda, environment={name: importlib.metadata.version(name) for name in
                ('torch', 'transformers', 'peft', 'safetensors', 'tokenizers', 'numpy', 'accelerate')})
    except BaseException as error:
        report.update(outcome='failed', error_type=type(error).__name__, error=str(error)[:128])
        raise
    finally:
        report['observed_wall_ns'] = time.monotonic_ns() - begin
        runtime.save(directory / 'actual-observation.json', report)


def _verify_observation(value):
    training, checked, _ = _preflight(value)
    plan = checked[0]
    raw = step.parent.read_regular(Path(value['output']) / 'actual-observation.json', step.MAX_INPUT)
    report = json.loads(raw, object_pairs_hook=runtime.unique)
    step.closed(report, 'schema scope input source training_input_digest parent candidate plan_digest outcome '
        'actual_loaded_contract task_link parent_readback candidate_readback predictions_sha256 requests '
        'completed_decode_steps actual_backend actual_device actual_threads torch_cuda environment observed_wall_ns ' +
        ' '.join(step.FALSES))
    expected_link = training['initial_setup'].get('task_link')
    expected_loaded = expected_link['derived_contract'] if expected_link else value['parent']['contract']
    runtime.require(report['schema'] == _actual_schema(value) and report['scope'] == SCOPE and
        report['input'] == runtime.identity(value) and report['source'] == value['source'] and
        all(report[name] == value[name] for name in ('training_input_digest', 'parent', 'candidate', 'plan_digest')) and
        report['outcome'] == 'success' and report['actual_loaded_contract'] == expected_loaded and
        report['task_link'] == expected_link and report['parent_readback'] == value['parent']['adapter'] and
        report['candidate_readback'] == value['candidate']['adapter'] and
        report['actual_backend'] == report['actual_device'] == 'cpu' and
        type(report['actual_threads']) is int and report['actual_threads'] == plan['threads'] and
        all(report[name] is False for name in step.FALSES), 'CANDIDATE_OBSERVATION_CONTEXT')
    step.closed(report['environment'], 'torch transformers peft safetensors tokenizers numpy accelerate')
    runtime.require(all(type(v) is str and 0 < len(v) <= 128 for v in report['environment'].values()) and
        type(report['observed_wall_ns']) is int and report['observed_wall_ns'] >= 0,
        'CANDIDATE_OBSERVATION_OBSERVED_FIELDS')
    predictions = step.parent.read_regular(Path(value['output']) / 'predictions.json', step.MAX_INPUT)
    runtime.require(hashlib.sha256(predictions).hexdigest() == report['predictions_sha256'],
                    'CANDIDATE_OBSERVATION_PREDICTIONS_PIN')
    rows = json.loads(predictions, object_pairs_hook=runtime.unique)
    runtime.verify_predictions(rows, plan, 'candidate', value['candidate']['adapter'], value['parent']['contract'])
    c, contract, cid = runtime.contract_module(), checked[2], value['parent']['contract']
    for row in rows:
        step.closed(row, 'task request request_id response artifact role output_sha256 logits_sha256 '
                    'input_tokens generated_tokens actual_device numeric_dtype snapshot')
        runtime.require(c.validate_decoder_request(row['request'], contract, cid) == row['request_id'] and
            c.validate_decoder_response(row['response'], row['request'], contract, cid) == [row['output_sha256']] and
            type(row['input_tokens']) is int and row['input_tokens'] == len(row['request']['input_ids'][0]) and
            type(row['generated_tokens']) is int, 'CANDIDATE_OBSERVATION_DECODER_FIELDS')
        step.digest(row['logits_sha256'])
    runtime.require(type(report['requests']) is int and report['requests'] == len(rows) == REQUESTS and
        type(report['completed_decode_steps']) is int and report['completed_decode_steps'] ==
        len(rows) * plan['generation_tokens'] == DECODE_STEPS, 'CANDIDATE_OBSERVATION_COUNTS')
    return hashlib.sha256(raw).hexdigest()


def _run(args):
    directory = Path(args.training_directory).resolve()
    version = getattr(args, 'producer_version', 'v2')
    runtime.require(version in ('v2', 'v4'), 'CANDIDATE_OBSERVATION_SOURCE')
    training = step.read_object(directory / ('parent-step-input-' + version + '.json'))
    result = step.read_object(directory / ('parent-step-result-' + version + '.json'))
    output = Path(args.output).resolve()
    value = dict(schema=INPUT_V4 if version == 'v4' else INPUT, scope=SCOPE, operation='evaluate', attempt_id=args.attempt_id,
        source=_sources(training['initial_setup']['profile']), training_directory=str(directory),
        training_input_digest=runtime.identity(training), training_result_sha256=args.expected_training_result_sha256,
        candidate_record_sha256=args.expected_candidate_record_sha256,
        actual_training_receipt_sha256=result['actual_receipt_sha256'], plan_digest=training['experiment'],
        parent=dict(contract=args.expected_contract, adapter=args.expected_parent_adapter,
                    file_sha256=args.expected_parent_file_sha256),
        candidate=dict(adapter=args.expected_candidate_adapter, file_sha256=args.expected_candidate_file_sha256),
        output=str(output / 'execution'), flags=step.FALSES)
    _, checked, _ = _preflight(value)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    frozen = output / 'candidate-observation-input.json'
    runtime.save(frozen, value)
    result = runtime.supervise([sys.executable, str(Path(__file__).resolve()), '_child', '--input', str(frozen),
        '--expected-input', runtime.identity(value)], value['output'], checked[0]['inference_budget'],
        exit_observation=checked[0].get('exit_observation'))
    completion = dict(schema=RESULT_V4 if version == 'v4' else RESULT, scope=SCOPE, input=runtime.identity(value), supervisor=result,
        outcome='failed', completion_verified=False, actual_observation_sha256=None, flags=step.FALSES)
    try:
        _terminal(result, checked[0]['inference_budget'])
        completion['actual_observation_sha256'] = _verify_observation(value)
        completion.update(outcome='success', completion_verified=True)
    finally:
        runtime.save(output / 'candidate-observation-result.json', completion)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    observe = commands.add_parser('evaluate')
    observe.add_argument('--producer-version', choices=('v2', 'v4'), default='v2')
    for name in ('training-directory', 'expected-training-result-sha256', 'expected-candidate-record-sha256',
                 'expected-contract', 'expected-parent-adapter', 'expected-parent-file-sha256',
                 'expected-candidate-adapter', 'expected-candidate-file-sha256', 'output', 'attempt-id'):
        observe.add_argument('--' + name, required=True)
    child = commands.add_parser('_child')
    child.add_argument('--input', required=True)
    child.add_argument('--expected-input', required=True)
    args = parser.parse_args()
    if args.operation == 'evaluate': _run(args)
    else: _child(args)


if __name__ == '__main__':
    main()
