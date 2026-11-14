#!/usr/bin/env python3
"""Fresh two-generation SmolLM research work using unchanged pinned owners.

The explicit bootstrap creates a research parent; it does not replace the
historical all-zero parent or claim an installed incumbent. Both actual AdamW
runs use the original frozen CLI. Production selection/FinalUse stay closed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

SOURCE_PINS = {
    'scripts/llm_runtime_pilot.py': '65ccc6454befd96fa5ce1f5bdde2c56cb6cbb741cf495b8d24a758039f99f755',
    'scripts/llm_inherited_runtime.py': '1c356c4e8e9a114ac7b6348cac4bed9a6fc72d53ce71ce00139c3deed8733596',
    'scripts/llm_parent_material.py': '5396d72c4730aea2d271b55a8404f6eaba64dc57f91343537710c28f7686b43c',
    'scripts/llm_neural_read_worker.py': '791fbe67ae7d2b2e0551e5f9f6fd77797ed9f8c210e7ca47f9acb6ac02895769',
    'formal/pon-nakamoto-v1/llm_adapter_contract.py': 'e46311a08584ad7becfc56cd0b699d9bc6921adcfe39319e50aa14faa984ced5',
    'formal/pon-nakamoto-v1/contract_wire.py': 'cbe45d72ad20ed5683d50dceaa97b93bc74cdafced7d0896386edf9cbe9f98f6',
    'config/pon/model-family-smollm2-135m-v1.json': '0837bbfb31f3f2b9a8731545c9f742aee1ebd32daed392a936a3ec9719537e52',
}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    return dict(path=str(path), sha256=sha(path))


def inventory(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--research-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--operation', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    assert args.output.is_absolute() and not args.output.exists()
    args.output.mkdir(mode=0o700)
    original = args.research_root / 'inputs/source/chain'
    actual = inventory(original)
    assert all(actual.get(name) == value for name, value in SOURCE_PINS.items())
    materials = args.research_root / 'pinned-base'
    model_config = json.loads((args.research_root / 'configs/parent-model.json').read_bytes())
    result = dict(schema='trnm-smollm-same-run-training-v1', operation=args.operation,
                  original_chain_source='c96022b897c1235fdbdbfcfa32764403511c6aab',
                  result='FAIL', parent_scope='fresh-explicit-research-bootstrap-not-installed-incumbent',
                  model_training_observed=False, native_learning_owner_join=False,
                  current_selection_authorized=False, independent_evaluation=False,
                  hepta_final_use_accepted=False, production_activation=False, qualification='HOLD_NO_GO')
    try:
        source_before = save(args.output / 'source-before.json', actual)
        records = [
            [('Answer with only yes or no. Is 35 greater than 34?', 'yes'),
             ('Answer with only yes or no. Is 38 greater than 39?', 'no'),
             ('Answer with only yes or no. Is 73 greater than 72?', 'yes'),
             ('Answer with only yes or no. Is 88 greater than 89?', 'no')],
            [('Answer with only yes or no. Is 135 greater than 134?', 'yes'),
             ('Answer with only yes or no. Is 138 greater than 139?', 'no'),
             ('Answer with only yes or no. Is 173 greater than 172?', 'yes'),
             ('Answer with only yes or no. Is 188 greater than 189?', 'no')],
        ]
        inputs = []
        for index, rows in enumerate(records, 1):
            value = dict(schema='hepta-smollm-training-input-v1', scope='public-smoke-fixtures',
                         records=[dict(prompt=p, expected_output=e) for p, e in rows])
            inputs.append(save(args.output / f'training-input-{index}.json', value))
        evaluation = [dict(request_id=f'{args.operation}-evaluation-{i}',
                           prompt=f'Answer with only yes or no. Is {a} greater than {b}?',
                           expected_output='yes' if a > b else 'no')
                      for i, (a, b) in enumerate([(4807,4806),(5208,5209),(6311,6310),(7402,7403)])]
        next_task = dict(mode='conditional_binary', request_id=args.operation + '-next-task',
                         prompt='Answer with only yes or no. Is 8517 greater than 8516?')
        frozen = dict(schema='trnm-smollm-same-run-research-plan-v1', operation=args.operation,
                      inputs=inputs, source_before=source_before, generation_count=2,
                      training_steps_per_generation=10, threads=4, evaluation=evaluation, next_task=next_task,
                      evaluation_profile='original-conditional-binary-raw-logit-q32-v1',
                      evaluation_is_public_controlled=True, independent_custody=False,
                      production_adoption_rule='none-research-load-only',
                      original_zero_parent_is_reinitialized=False,
                      source_hashes=SOURCE_PINS, python=str(Path(sys.executable).resolve()),
                      python_sha256=sha(Path(sys.executable).resolve()),
                      start_unix_ns=time.time_ns(), authority='DENY_ALL', qualification='HOLD_NO_GO')
        result['frozen_plan'] = save(args.output / 'frozen-plan.json', frozen)
        parent, parent_pin, stages = None, None, []
        for generation, material in enumerate(inputs, 1):
            output = args.output / f'generation-{generation}'
            command = [sys.executable, str(original / 'scripts/llm_inherited_runtime.py'), 'train',
                       '--materials', str(materials), '--output', str(output),
                       '--operation-id', args.operation + f'-train-{generation}',
                       '--input', material['path'], '--input-sha256', material['sha256'],
                       '--threads', '4', '--steps', '10']
            command += ['--bootstrap'] if parent is None else ['--parent', str(parent), '--parent-sha256', parent_pin]
            started = time.monotonic()
            with (args.output / f'generation-{generation}.log').open('xb') as log:
                completed = subprocess.run(command, env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1',
                    'HF_HUB_OFFLINE':'1', 'TRANSFORMERS_OFFLINE':'1', 'TOKENIZERS_PARALLELISM':'false'},
                    stdout=log, stderr=subprocess.STDOUT, check=False)
            stage = dict(generation=generation, command=command, returncode=completed.returncode,
                         elapsed_seconds=time.monotonic()-started)
            save(args.output / f'generation-{generation}-command.json', stage)
            assert completed.returncode == 0, 'original training refused; preserve original log'
            receipt_path = output / 'worker/actual-receipt.json'
            receipt = json.loads(receipt_path.read_bytes())
            assert receipt['outcome'] == 'success' and receipt['training']['steps'] == 10
            assert receipt['parameter_change'] is True
            if parent is not None:
                assert receipt['actual_loaded_parent'] == json.loads(parent.read_bytes())['adapter']
            parent = output / 'worker/parent-material.json'
            parent_pin = sha(parent)
            descriptor = json.loads(parent.read_bytes())
            assert descriptor['generation'] == generation and descriptor['file_sha256'] == sha(parent.parent / 'artifact.safetensors')
            stage.update(parent_material=dict(path=str(parent),sha256=parent_pin),
                         actual_receipt=dict(path=str(receipt_path),sha256=sha(receipt_path)),
                         actual_adapter=receipt['artifact'], actual_loaded_parent=receipt['actual_loaded_parent'])
            stages.append(stage)
            config = dict(model_config, parent_dir=str(parent.parent), generation=generation,
                          parent_contract=descriptor['contract'], parent_adapter=descriptor['adapter'],
                          parent_file_sha256=descriptor['file_sha256'])
            save(args.output / f'model-generation-{generation}.json', config)
            print(json.dumps(dict(generation=generation, artifact=receipt['artifact'], parameter_change=True)),flush=True)
        assert inventory(original) == actual
        save(args.output / 'source-after.json', inventory(original))
        result.update(result='PASS_TWO_ACTUAL_RESEARCH_TRAINING_GENERATIONS', model_training_observed=True,
                      optimizer_steps=20, stages=stages, end_unix_ns=time.time_ns())
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        save(args.output / 'training-result.json', result)
        print(json.dumps(result,sort_keys=True),flush=True)


if __name__ == '__main__':
    main()
