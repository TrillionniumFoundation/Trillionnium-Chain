#!/usr/bin/env python3
"""Run one frozen public six-arm diagnostic from exact existing parent bytes.

Uses original training, observation, inference and terminal owners. The source
parent is not represented as an admitted CURRENT. No product gates, signatures,
installation credentials or model selection are constructed by this caller.
"""
import argparse
from fractions import Fraction
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import llm_answer_eos_task_research_v4 as research
import llm_inherited_runtime as inherited
import llm_runtime_candidate_observation_v1 as observation
import llm_runtime_parent_step as step
import llm_runtime_parent_step_task_v2 as task
import llm_runtime_parent_step_v2 as producer
import llm_runtime_pilot as runtime

ROOT = Path(__file__).resolve().parents[1]
CONTROL_ARTIFACT_MAX = 600 * 1024**2
DISK_RESERVE = 128 * 1024**2
LABEL = 'actual-source-parent'


def source_map():
    names = subprocess.check_output(['git', 'ls-files', '-z', '--', 'scripts',
        'formal/pon-nakamoto-v1', 'config/pon'], cwd=ROOT).split(b'\0')
    paths = {n.decode() for n in names if n}
    paths.update(str(p.relative_to(ROOT)) for p in ROOT.joinpath('scripts').glob('*research_v4.py'))
    return {name: runtime.file_sha(ROOT / name) for name in sorted(paths)
            if (ROOT / name).is_file() and not (ROOT / name).is_symlink()}


def disk_check(output, before_full=False):
    needed = DISK_RESERVE + (CONTROL_ARTIFACT_MAX if before_full else 0)
    runtime.require(shutil.disk_usage(output).free >= needed, 'RESEARCH_V4_DISK_ADMISSION')
    artifacts = list(output.glob('train-*/artifact.safetensors'))
    runtime.require(all(path.stat().st_size <= CONTROL_ARTIFACT_MAX for path in artifacts),
                    'RESEARCH_V4_CONTROL_ARTIFACT_BOUND')


def run(args):
    runtime.require(1 <= args.threads <= 2, 'RESEARCH_V4_LOCAL_THREADS')
    runtime.require(sys.flags.no_user_site == 1, 'RESEARCH_V4_NO_USER_SITE')
    for key in ('materials', 'parent', 'output'):
        runtime.require(getattr(args, key).is_absolute(), 'RESEARCH_V4_ABSOLUTE_PATH')
    parent_raw = step.parent.read_regular(args.parent, step.MAX_INPUT)
    runtime.require(hashlib.sha256(parent_raw).hexdigest() == args.parent_sha256, 'RESEARCH_V4_PARENT_PIN')
    parent = inherited.validate_parent(json.loads(parent_raw, object_pairs_hook=runtime.unique))
    contract, _, _ = inherited.read_parent(parent)
    materials, _ = runtime.verify_materials(args.materials)
    plan = runtime.validate_plan(runtime.experiment_plan(materials, threads=args.threads, steps=10))
    output = args.output
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    disk_check(output, before_full=True)
    pins = source_map()
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    plan_path = output / 'experiment-plan.json'
    runtime.save(plan_path, plan)
    directory = Path(parent['directory'])
    value = dict(files=dict(materials=str(args.materials), plan=str(plan_path),
                           parent_contract=str(directory / 'target-contract.json')),
        parent={k: parent[k] for k in ('contract', 'adapter', 'file_sha256')},
        initial_setup=dict(parent_material=dict(path=str(args.parent), sha256=args.parent_sha256)))
    value['initial_setup']['task_link'] = task.request_link(value)
    research_path = output / 'research-plan-v4.json'
    runtime.save(research_path, research.plan_record(value))
    freeze = dict(schema='llm-task-research-six-arm-freeze-v4', source_commit=source,
        source=pins, parent=parent, parent_descriptor_sha256=args.parent_sha256,
        source_parent_is_admitted_current=False, plan=runtime.identity(plan),
        research_plan_sha256=runtime.file_sha(research_path),
        participants=list(runtime.PARTICIPANTS) + [LABEL],
        order=['train-candidate', 'evaluate-candidate'] +
            [stage + '-' + role for role in runtime.CONTROLS for stage in ('train', 'evaluate')] +
            ['evaluate-' + LABEL],
        original_controls_unchanged=True, original_public_tasks=True,
        independent_future_holdout=False, installation_authorized=False,
        artifact_limit_bytes=CONTROL_ARTIFACT_MAX, disk_reserve_bytes=DISK_RESERVE,
        python_executable=str(Path(sys.executable).resolve()),
        python_executable_sha256=runtime.file_sha(sys.executable),
        packages={name: importlib.metadata.version(name) for name in
            ('torch', 'transformers', 'peft', 'safetensors', 'tokenizers', 'numpy', 'accelerate')})
    runtime.save(output / 'freeze.json', freeze)
    phases, predictions, training, artifacts = [], {}, {}, {}
    summary = dict(schema='llm-task-research-six-arm-result-v4', outcome='running',
        freeze_sha256=runtime.file_sha(output / 'freeze.json'), phases=phases,
        all_required_controls_executed=False, ordinary_installation=False,
        source_parent_is_admitted_current=False, independent_evaluation=False,
        product_qualification=False, reward_eligible=False)

    def save_phase(name, result):
        phases.append(dict(name=name, **result))
        runtime.save(output / 'result.json', summary)
        print(json.dumps(dict(phase=name, outcome=result['outcome'],
            stop_reason=result.get('stop_reason'))), flush=True)
        runtime.require(source_map() == pins, 'RESEARCH_V4_SOURCE_CHANGED')

    def control_phase(stage, role):
        disk_check(output, before_full=(stage == 'train' and role == 'budget-matched-full-tune'))
        dest = output / (stage + '-' + role)
        command = [sys.executable, str(ROOT / 'scripts/llm_runtime_pilot.py'), '_child',
            '--materials', str(args.materials), '--plan', str(plan_path), '--output', str(dest),
            '--phase', stage, '--role', role]
        if stage == 'evaluate': command += ['--artifact', str(output / ('train-' + role))]
        budget = plan['training_budget' if stage == 'train' else 'inference_budget']
        result = runtime.supervise(command, dest, budget, exit_observation=plan.get('exit_observation'))
        save_phase(dest.name, result)
        observation._terminal(result, budget)
        actual = runtime.read_json(dest / 'actual-receipt.json')
        runtime.require(actual['outcome'] == 'success' and actual['experiment'] == runtime.identity(plan),
                        'RESEARCH_V4_CONTROL_CONTEXT')
        return actual

    try:
        train_dir = output / 'train-candidate'
        producer.run(SimpleNamespace(operation='train', initial_setup_profile=research.PROFILE,
            parent_material=str(args.parent), parent_material_sha256=args.parent_sha256,
            materials=str(args.materials), plan=str(plan_path), output=str(train_dir),
            attempt_id=runtime.identity(freeze), expected_plan=runtime.identity(plan),
            parent_contract=str(directory / 'target-contract.json'),
            parent_adapter=str(directory / 'wrapped-adapter.json'),
            parent_artifact=str(directory / 'artifact.safetensors'),
            expected_contract=parent['contract'], expected_parent_adapter=parent['adapter'],
            expected_parent_file_sha256=parent['file_sha256'], candidate_directory=None,
            expected_candidate_adapter=None, expected_candidate_file_sha256=None,
            expected_candidate_record_sha256=None, expected_candidate_result_sha256=None,
            research_plan=str(research_path), research_plan_sha256=runtime.file_sha(research_path)))
        result_path = train_dir / 'parent-step-result-v4.json'
        result = runtime.read_json(result_path)
        save_phase('train-candidate', result['supervisor'])
        runtime.require(result['outcome'] == 'success' and result['completion_verified'] is True,
                        'RESEARCH_V4_TRAIN_COMPLETION')
        actual = runtime.read_json(train_dir / 'execution/actual-receipt.json')
        runtime.require(actual['parent_readback'] == parent['adapter'] and
                        actual['training_changed_from_setup'] is True, 'RESEARCH_V4_ACTUAL_PARENT')
        candidate = actual['candidate']
        training['candidate'] = actual['training']
        artifacts['candidate'] = candidate['adapter']
        candidate_parent = dict(parent, generation=parent['generation'] + 1,
            operation_id=runtime.identity(freeze), directory=str(train_dir / 'execution'), **candidate)
        inherited.read_parent(candidate_parent)
        runtime.save(output / 'candidate-parent.json', candidate_parent)
        observe_dir = output / 'evaluate-candidate'
        observation._run(SimpleNamespace(producer_version='v4', training_directory=str(train_dir),
            expected_training_result_sha256=runtime.file_sha(result_path),
            expected_candidate_record_sha256=runtime.file_sha(train_dir / 'execution/parent-candidate-v4.json'),
            expected_contract=parent['contract'], expected_parent_adapter=parent['adapter'],
            expected_parent_file_sha256=parent['file_sha256'],
            expected_candidate_adapter=candidate['adapter'], expected_candidate_file_sha256=candidate['file_sha256'],
            output=str(observe_dir), attempt_id=runtime.identity(dict(freeze=runtime.identity(freeze), phase='observe'))))
        observed = runtime.read_json(observe_dir / 'candidate-observation-result.json')
        save_phase('evaluate-candidate', observed['supervisor'])
        runtime.require(observed['outcome'] == 'success' and observed['completion_verified'] is True,
                        'RESEARCH_V4_OBSERVATION')
        predictions['candidate'] = runtime.verify_predictions(runtime.read_json(
            observe_dir / 'execution/predictions.json'), plan, 'candidate', candidate['adapter'], parent['contract'])
        for role in runtime.CONTROLS:
            trained = control_phase('train', role)
            artifacts[role], training[role] = trained['artifact'], trained['training']
            evaluated = control_phase('evaluate', role)
            runtime.require(evaluated['artifact'] == trained['artifact'], 'RESEARCH_V4_CONTROL_ARTIFACT')
            predictions[role] = runtime.verify_predictions(runtime.read_json(
                output / ('evaluate-' + role) / 'predictions.json'), plan, role, trained['artifact'], trained['contract'])
        runtime.require(len(set(artifacts.values())) == 5, 'RESEARCH_V4_ARTIFACT_ALIAS')
        counts = ('steps', 'tokens', 'supervised_tokens')
        runtime.require(all(tuple(training[r][k] for k in counts) == (10, 526, 40) for r in
            ('candidate', 'fresh-budget-matched-lora', 'budget-matched-full-tune')),
            'RESEARCH_V4_TRAINING_SCHEDULE')
        predictions[LABEL] = {}
        for index, row in enumerate(r for r in plan['tasks'] if r['partition'] != 'training'):
            dest = output / (LABEL + '-' + str(index))
            request = output / (LABEL + '-' + str(index) + '.input.json')
            request_id = runtime.identity(dict(freeze=runtime.identity(freeze), task=row['id']))
            runtime.save(request, dict(schema='hepta-smollm-inference-input-v1',
                request_id=request_id, prompt=row['prompt']))
            inherited.run(SimpleNamespace(command='infer', materials=str(args.materials), parent=str(args.parent),
                parent_sha256=args.parent_sha256, input=str(request), input_sha256=runtime.file_sha(request),
                operation_id=request_id, output=str(dest), threads=args.threads, steps=10, bootstrap=False))
            actual = runtime.read_json(dest / 'worker/actual-receipt.json')
            terminal = runtime.read_json(dest / 'supervisor.json')
            save_phase(LABEL + '-' + str(index), terminal)
            runtime.require(actual['outcome'] == 'success' and actual['actual_loaded_parent'] == parent['adapter']
                and actual['forward_executed'] is True and all(v is False for v in actual['authority'].values()),
                'RESEARCH_V4_SOURCE_PARENT_READBACK')
            predictions[LABEL][row['id']] = actual['prediction']['output_sha256']
        scores = {}
        for role, values in predictions.items():
            scores[role] = {}
            for partition in ('calibration', 'evaluation'):
                groups = {}
                for row in plan['tasks']:
                    if row['partition'] == partition:
                        groups.setdefault(row['source_group'], []).append(
                            int(values[row['id']] == row['target_output_sha256']))
                score = sum((Fraction(sum(g), len(g)) for g in groups.values()), Fraction()) / len(groups)
                scores[role][partition] = [score.numerator, score.denominator]
        gain = Fraction(*scores['candidate']['evaluation']) - max(
            Fraction(*scores[role]['evaluation']) for role in runtime.CONTROLS)
        parent_gain = Fraction(*scores['candidate']['evaluation']) - Fraction(*scores[LABEL]['evaluation'])
        summary.update(outcome='completed', scores=scores, artifacts=artifacts, training=training,
            gain_vs_strongest_control=[gain.numerator, gain.denominator],
            gain_vs_actual_source_parent=[parent_gain.numerator, parent_gain.denominator],
            all_required_controls_executed=True, training_schedule_matched=True,
            actual_costs_assumed_equal=False,
            decision='nonpositive-gain-no-installation' if min(gain, parent_gain) <= 0 else
                     'positive-public-diagnostic-independent-qualification-still-missing')
    except BaseException as error:
        summary.update(outcome='failed', error_type=type(error).__name__, error=str(error)[:512])
        # Preserve terminal failure receipts even when their owner raises before
        # returning. These paths are independent of a passing phase roster.
        summary['retained_failure_records'] = [str(p.relative_to(output)) for p in
            sorted(output.rglob('*.json')) if p.name in
            ('supervisor.json', 'parent-step-result-v4.json', 'candidate-observation-result.json')]
        raise
    finally:
        summary['source_unchanged'] = source_map() == pins
        summary['parent_unchanged'] = runtime.file_sha(args.parent) == args.parent_sha256
        runtime.save(output / 'result.json', summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('materials', 'parent', 'output'): parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--parent-sha256', required=True)
    parser.add_argument('--threads', type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    os.environ.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
        HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', OMP_NUM_THREADS=str(args.threads),
        MKL_NUM_THREADS=str(args.threads), OPENBLAS_NUM_THREADS=str(args.threads))
    run(args)


if __name__ == '__main__':
    main()
