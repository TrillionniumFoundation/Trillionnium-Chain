#!/usr/bin/env python3
"""Execute an explicitly pinned SmolLM parent through the existing pilot backend.

This is an execution adapter, not a trainer owner, selector or installation store.
The original runtime owns AdamW, forward, decoding and child resource accounting.
Caller-supplied operation/data/parent identities are retained exactly. Public smoke
tasks remain public smoke tasks; three inherited executions are not three qualified
or installed beneficial releases. Product admission remains with the Hepta owners.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time

import llm_parent_material as parent_material
import llm_runtime_pilot as runtime

SCHEMA = 'hepta-smollm-inherited-execution-v1'
PARENT_SCHEMA = 'hepta-smollm-parent-material-v1'
MAX_INPUT_BYTES = 65536
MAX_TASKS = 128
NO_AUTHORITY = dict(installation_authorized=False, selection_authorized=False,
                    independent_accepted=False, prospective_accepted=False,
                    public_reward_eligible=False, hepta_final_use=False)


def checked_json(path, expected, maximum=MAX_INPUT_BYTES):
    runtime.contract_module().digest(expected)
    raw = parent_material.read_regular(path, maximum)
    runtime.require(hashlib.sha256(raw).hexdigest() == expected, 'INHERITED_INPUT_IDENTITY')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=runtime.unique)


def source_pins():
    return {path.name: runtime.file_sha(path) for path in
            (Path(__file__), Path(runtime.__file__), Path(parent_material.__file__),
             Path(runtime.contract_module().__file__), runtime.FAMILY_PATH)}


def validate_parent(value):
    runtime.require(type(value) is dict and set(value) ==
        {'schema', 'generation', 'operation_id', 'directory', 'contract', 'adapter', 'file_sha256'},
        'INHERITED_PARENT_FIELDS')
    runtime.require(value['schema'] == PARENT_SCHEMA and type(value['generation']) is int and
                    1 <= value['generation'] < (1 << 63), 'INHERITED_PARENT_GENERATION')
    runtime.require(type(value['operation_id']) is str and
                    1 <= len(value['operation_id'].encode()) <= 128, 'INHERITED_OPERATION')
    root = Path(value['directory'])
    runtime.require(root.is_absolute(), 'INHERITED_PARENT_PATH')
    for key in ('contract', 'adapter', 'file_sha256'):
        runtime.contract_module().digest(value[key])
    return value


def read_parent(value):
    value = validate_parent(value)
    directory = Path(value['directory'])
    factors, _ = parent_material.verify_parent(
        directory/'target-contract.json', directory/'wrapped-adapter.json',
        directory/'artifact.safetensors', expected_contract=value['contract'],
        expected_adapter=value['adapter'], expected_file_sha256=value['file_sha256'])
    raw = parent_material.read_regular(directory/'target-contract.json',
                                       runtime.contract_module().MAX_MANIFEST_BYTES)
    # Recheck the exact bytes captured for later use, rather than trusting a path.
    family = runtime.verify_family(runtime.read_json(runtime.FAMILY_PATH))
    contract = runtime.contract_module().verify_target_contract(raw, value['contract'],
        expected_backbone_root=family['material_pins']['fp32_backbone_index_root'],
        expected_tokenizer_root=family['material_pins']['tokenizer_files_root'])
    return contract, raw, factors


def load_factors(model, contract, cid, factors, expected_adapter, torch, device):
    """Load the already checked immutable byte snapshot, never reopen a tensor path."""
    target = runtime.adapter_tensors(model, contract['targets'])
    runtime.require(set(target) == set(factors), 'INHERITED_FACTOR_SET')
    with torch.no_grad():
        for name, parameter in target.items():
            tensor = torch.frombuffer(bytearray(factors[name]), dtype=torch.float32)
            runtime.require(tensor.numel() == parameter.numel() and
                            torch.isfinite(tensor).all().item(), 'INHERITED_FACTOR_VALUES')
            parameter.copy_(tensor.reshape(parameter.shape).to(device))
    _, actual, _ = runtime.wrap_adapter(model, contract, cid)
    runtime.require(actual == expected_adapter, 'INHERITED_LOADED_PARENT')
    return actual


def training_rows(value):
    runtime.require(type(value) is dict and set(value) == {'schema', 'scope', 'records'} and
        value['schema'] == 'hepta-smollm-training-input-v1' and
        value['scope'] in ('operator-authorized-inputs', 'public-smoke-fixtures'),
        'INHERITED_TRAINING_FIELDS')
    records = value['records']
    runtime.require(type(records) is list and 1 <= len(records) <= MAX_TASKS,
                    'INHERITED_TRAINING_LIMIT')
    rows, prompts = [], set()
    for record in records:
        runtime.require(type(record) is dict and set(record) == {'prompt', 'expected_output'},
                        'INHERITED_TRAINING_RECORD')
        for field, limit in (('prompt', 4096), ('expected_output', 1024)):
            runtime.require(type(record[field]) is str and
                            1 <= len(record[field].encode()) <= limit,
                            'INHERITED_TRAINING_TEXT')
        digest = hashlib.sha256(record['prompt'].encode()).hexdigest()
        runtime.require(digest not in prompts, 'INHERITED_TRAINING_DUPLICATE')
        prompts.add(digest)
        row = dict(record, partition='training', source_group=runtime.identity(value['scope']),
                   prompt_sha256=digest,
                   target_output_sha256=hashlib.sha256(record['expected_output'].encode()).hexdigest())
        row['id'] = runtime.identity(row)
        rows.append(row)
    return rows


def validate_plan(plan):
    runtime.require(type(plan) is dict and set(plan) == {'schema', 'phase', 'operation_id',
        'generation', 'parent', 'runtime', 'inputs', 'inputs_sha256', 'source_pins', 'authority'},
        'INHERITED_PLAN_FIELDS')
    runtime.require(plan['schema'] == SCHEMA and plan['phase'] in ('train', 'infer') and
                    type(plan['authority']) is dict and set(plan['authority']) == set(NO_AUTHORITY) and
                    all(value is False for value in plan['authority'].values()), 'INHERITED_PLAN_PROFILE')
    runtime.require(type(plan['operation_id']) is str and
                    1 <= len(plan['operation_id'].encode()) <= 128, 'INHERITED_OPERATION')
    runtime.require(type(plan['generation']) is int and 1 <= plan['generation'] < (1 << 63),
                    'INHERITED_GENERATION')
    runtime.require(plan['source_pins'] == source_pins(), 'INHERITED_SOURCE_CHANGED')
    pilot = runtime.validate_plan(plan['runtime'])
    runtime.require(pilot['backend'] == 'cpu' and pilot['threads'] <= 4, 'INHERITED_CPU_PROFILE')
    runtime.contract_module().digest(plan['inputs_sha256'])
    if plan['parent'] is None:
        runtime.require(plan['phase'] == 'train' and plan['generation'] == 1,
                        'INHERITED_BOOTSTRAP_ONLY')
    else:
        previous = validate_parent(plan['parent'])
        expected = previous['generation'] + (1 if plan['phase'] == 'train' else 0)
        runtime.require(plan['generation'] == expected, 'INHERITED_GENERATION_LINK')
    if plan['phase'] == 'train':
        runtime.require(pilot['tasks'] == training_rows(plan['inputs']), 'INHERITED_DATASET_BINDING')
    else:
        value = plan['inputs']
        runtime.require(type(value) is dict and set(value) == {'schema', 'request_id', 'prompt'} and
            value['schema'] == 'hepta-smollm-inference-input-v1' and
            value['request_id'] == plan['operation_id'] and type(value['prompt']) is str and
            1 <= len(value['prompt'].encode()) <= 4096, 'INHERITED_INFERENCE_INPUT')
    return plan


def child(args):
    plan = validate_plan(checked_json(args.plan, args.plan_sha256, 512 * 1024))
    pilot, directory, materials = plan['runtime'], Path(args.output), Path(args.materials)
    observer = runtime.Observer(directory, 'cpu')
    start = time.monotonic_ns()
    report = dict(schema=SCHEMA, operation_id=plan['operation_id'], phase=plan['phase'],
        generation=plan['generation'], parent=plan['parent'], input_sha256=plan['inputs_sha256'],
        plan_sha256=args.plan_sha256, scope='actual-inherited-execution-no-owner-admission',
        authority=NO_AUTHORITY, outcome='failed')
    try:
        manifest, _ = observer.stage('material-verification', lambda: runtime.verify_materials(materials))
        runtime.require(runtime.identity(manifest) == pilot['snapshot'], 'INHERITED_SNAPSHOT_CHANGED')
        imports = observer.stage('runtime-import', lambda: runtime.runtime_import(pilot))
        torch, device, _, _, _, save_file, _ = imports
        model, tokenizer, shapes, _ = observer.stage('model-load',
            lambda: runtime.load_model(materials, pilot, imports))
        contract, raw, cid = observer.stage('complete-backbone-tokenizer-verification',
            lambda: runtime.make_contract(model, tokenizer, shapes, materials, manifest, pilot))
        if plan['parent'] is not None:
            inherited, inherited_raw, factors = observer.stage('parent-material-verification',
                lambda: read_parent(plan['parent']))
            # The registration records the original target admission. New operation
            # and training scopes live in this plan; immutable target semantics agree.
            runtime.require({k:v for k,v in contract.items() if k != 'registration'} ==
                            {k:v for k,v in inherited.items() if k != 'registration'},
                            'INHERITED_TARGET_RUNTIME_MISMATCH')
            contract, raw, cid = inherited, inherited_raw, plan['parent']['contract']
        model = observer.stage('adapter-insertion',
            lambda: runtime.insert_lora(model, pilot, 'candidate', torch))
        if plan['parent'] is not None:
            before = observer.stage('actual-parent-reload', lambda: load_factors(model, contract,
                cid, factors, plan['parent']['adapter'], torch, device))
        else:
            _, before, _ = runtime.wrap_adapter(model, contract, cid)
        report.update(contract=cid, actual_loaded_parent=before,
            actual_backend='cpu', backbone=contract['backbone']['index_root'],
            tokenizer=contract['tokenizer']['files_root'], source_pins=source_pins())
        if plan['phase'] == 'train':
            training = observer.stage('training',
                lambda: runtime.train(model, tokenizer, pilot, 'candidate', torch, device))
            after = runtime.contract_module().H('llm-tensor-index-v1',
                runtime.contract_module().canonical({name: runtime.tensor_descriptor(t)
                    for name,t in runtime.backbone_tensors(model, shapes).items()})).hex()
            runtime.require(after == contract['backbone']['index_root'], 'INHERITED_BACKBONE_MUTATION')
            adapter_raw, adapter, tensors = runtime.wrap_adapter(model, contract, cid)
            (directory/'target-contract.json').write_bytes(raw)
            (directory/'wrapped-adapter.json').write_bytes(adapter_raw)
            observer.stage('artifact-save', lambda: save_file({name: value.detach().cpu().contiguous()
                for name,value in tensors.items()}, str(directory/'artifact.safetensors')))
            descriptor = dict(schema=PARENT_SCHEMA, generation=plan['generation'],
                operation_id=plan['operation_id'], directory=str(directory.resolve()),
                contract=cid, adapter=adapter,
                file_sha256=runtime.file_sha(directory/'artifact.safetensors'))
            read_parent(descriptor)
            runtime.save(directory/'parent-material.json', descriptor)
            report.update(artifact=adapter, training=training,
                parameter_change=adapter != before, parent_material_sha256=runtime.file_sha(directory/'parent-material.json'),
                disposition='candidate-produced' if adapter != before else 'no-parameter-change')
        else:
            row = dict(id=runtime.identity(plan['inputs']), prompt=plan['inputs']['prompt'])
            prediction = observer.stage('ordinary-input-forward', lambda: runtime.decode(model,
                tokenizer, row, contract, cid, pilot, torch, device, before, 'installed-parent-input'))
            runtime.save(directory/'prediction.json', prediction)
            report.update(artifact=before, prediction=prediction, forward_executed=True,
                          disposition='observed-output')
        report['outcome'] = 'success'
    except BaseException as error:
        report.update(error_type=type(error).__name__)
        raise
    finally:
        report.update(cost_events=observer.events, process_wall_ns=time.monotonic_ns()-start,
            process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024)
        runtime.save(directory/'actual-receipt.json', report)


def run(args):
    runtime.require(Path(args.output).is_absolute(), 'INHERITED_OUTPUT_PATH')
    manifest, _ = runtime.verify_materials(args.materials)
    inputs = checked_json(args.input, args.input_sha256)
    previous = None
    if args.parent:
        runtime.require(args.parent_sha256 is not None and not args.bootstrap, 'INHERITED_PARENT_REQUIRED')
        previous = validate_parent(checked_json(args.parent, args.parent_sha256))
        read_parent(previous)
    else:
        runtime.require(args.bootstrap and args.command == 'train' and args.parent_sha256 is None,
                        'INHERITED_EXPLICIT_BOOTSTRAP_REQUIRED')
    pilot = runtime.experiment_plan(manifest, threads=args.threads, steps=args.steps)
    if args.command == 'train':
        pilot['tasks'] = training_rows(inputs)
    plan = dict(schema=SCHEMA, phase=args.command, operation_id=args.operation_id,
        generation=(previous['generation'] + (1 if args.command == 'train' else 0)) if previous else 1,
        parent=previous, runtime=pilot, inputs=inputs, inputs_sha256=args.input_sha256,
        source_pins=source_pins(), authority=NO_AUTHORITY)
    validate_plan(plan)
    directory = Path(args.output)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    plan_path = directory/'execution-plan.json'
    runtime.save(plan_path, plan)
    process = directory/'worker'
    result = runtime.supervise([sys.executable, str(Path(__file__).resolve()), '_child',
        '--materials', args.materials, '--output', str(process), '--plan', str(plan_path),
        '--plan-sha256', runtime.file_sha(plan_path)], process,
        pilot['training_budget' if args.command == 'train' else 'inference_budget'])
    runtime.save(directory/'supervisor.json', result)
    runtime.require(result['outcome'] == 'success', 'INHERITED_CHILD_FAILED')
    receipt = runtime.read_json(process/'actual-receipt.json')
    runtime.require(receipt['outcome'] == 'success' and
                    receipt['operation_id'] == args.operation_id, 'INHERITED_CHILD_RECEIPT')
    print(json.dumps(dict(outcome='success', operation_id=args.operation_id,
        generation=plan['generation'], artifact=receipt['artifact'], receipt=str(process/'actual-receipt.json'),
        authority=NO_AUTHORITY), sort_keys=True))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('train', 'infer'):
        runner = commands.add_parser(command)
        for name in ('materials', 'output', 'operation-id', 'input', 'input-sha256'):
            runner.add_argument('--'+name, required=True)
        runner.add_argument('--parent'); runner.add_argument('--parent-sha256')
        runner.add_argument('--bootstrap', action='store_true')
        runner.add_argument('--threads', type=int, default=4)
        runner.add_argument('--steps', type=int, default=10)
    worker = commands.add_parser('_child')
    for name in ('materials', 'output', 'plan', 'plan-sha256'):
        worker.add_argument('--'+name, required=True)
    args = parser.parse_args()
    child(args) if args.command == '_child' else run(args)


if __name__ == '__main__':
    main()
