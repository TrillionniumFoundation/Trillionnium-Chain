"""Real public-source training/replay plus exact-factor/copy/complementarity attacks.

Uses the existing trainer and integer inference owner. All data are retrospective;
the small controlled complementary case is an attack experiment, not model efficacy.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import platform
import resource
import subprocess
import sys
import time
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'formal/pon-nakamoto-v1'))
from contract_wire import H, canonical, unique
from evaluation_bundle import verify_bundle, read_bounded, write_new, MAX_BUNDLE_BYTES, MAX_TASK_BYTES, predict_rows
from model_attribution import (integer_linear_contract, contract_id, normalize_adapter, freeze_attribution_plan,
    verify_attribution_plan, evaluate_attribution_plan, _subset_model)
from work_utility import UniqueUsefulOutputAccounting, measured_cost


def identity(value):
    return H('attribution-campaign-identity-v1', value.encode()).hex()


def factor_adapter(contract, delta, alternate=False):
    sign = -1 if alternate else 1
    return dict(schema='pon-integer-linear-adapter-v1', contract=contract_id(contract),
                A=[[sign*v for v in row] for row in delta],
                B=[[sign if i == j else 0 for j in range(3)] for i in range(3)])


def timed(call, operations=0, bytes_read=0):
    cpu, wall = time.process_time_ns(), time.perf_counter_ns()
    value = call()
    return value, measured_cost(cpu_ns=time.process_time_ns()-cpu,
        wall_ns=time.perf_counter_ns()-wall, operations=operations, bytes_read=bytes_read,
        memory_peak_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024)


def content_roots(rows, predictions):
    # IDs, split labels and report wrappers never establish new task/output work.
    values = sorted((dict(content=row['source_content_sha256'], x=row['x'], label=row['label'], prediction=p)
                     for row, p in zip(rows, predictions)), key=lambda value: value['content'])
    task = [{k: v for k, v in row.items() if k != 'prediction'} for row in values]
    output = [dict(content=row['content'], prediction=row['prediction']) for row in values]
    return H('useful-public-task-content-v1', canonical(task)).hex(), H('useful-public-output-content-v1', canonical(output)).hex()


def observe(out, name, raw, digest, rows, observer, branch, *, adopt=False):
    outer_cpu, outer_wall = time.process_time_ns(), time.perf_counter_ns()
    child_wall = 0
    read, intake_cost = timed(lambda: canonical(rows), bytes_read=len(raw)+len(canonical(rows)))
    plan, plan_cost = timed(lambda: verify_attribution_plan(raw, digest))
    plan_cost['operations'] = sum(3*257*len(s['adapter']['A']) for s in plan['submissions'])
    _, normalization_cost = timed(lambda: [normalize_adapter(s['adapter'], plan['contract']) for s in plan['submissions']],
        operations=sum(3*257*len(s['adapter']['A']) for s in plan['submissions']))
    result, quality_cost = timed(lambda: evaluate_attribution_plan(raw, digest, rows))
    # The finite optimizer is allowed to select only from this pre-frozen set.
    mask = result['bounded_optimum']['winner_mask']; model = _subset_model(plan, mask)
    predictions, output_cost = timed(lambda: predict_rows(model, rows), operations=len(rows)*9*257)
    task_root, output_root = content_roots(rows, predictions)
    function = H('declared-composed-linear-update-v1', canonical({'contract': contract_id(plan['contract']),
        'delta': model['deltas'][plan['contract']['slot']]})).hex()
    attempt = identity(name)
    observer.begin_attempt(attempt=attempt, branch=branch, task_content=task_root, output_content=output_root,
        function_fingerprint=function, source=identity('one-controlled-development-operator'), partition=name)
    quality_cost['operations'] = (result['verification_cost']['inference_multiplications']+
                                  2*result['verification_cost']['adapter_product_multiplications'])
    for stage, cost in [('intake', intake_cost), ('normalization', normalization_cost),
                         ('plan_verification', plan_cost), ('quality', quality_cost), ('output_normalization', output_cost)]:
        observer.record_cost(attempt, stage, observer='local-process-monotonic-clock', cost=cost)
    optimum = Fraction(*map(int, result['bounded_optimum']['maximum']))
    baseline = Fraction(*map(int, result['baseline_value']))
    observer.finish_verification(attempt, accepted=True, quality_gain=optimum-baseline, outcome='recomputed-finite-subset-objective')
    write_new(out/(name+'-result.json'), canonical(result))
    if adopt and optimum > baseline:
        model_path = out/(name+'-consumer-model.json'); tasks_path = out/(name+'-consumer-tasks.json')
        result_path = out/(name+'-consumer-observation.json')
        write_new(model_path, canonical(model)); write_new(tasks_path, read)
        before = resource.getrusage(resource.RUSAGE_CHILDREN); wall = time.perf_counter_ns()
        subprocess.run([sys.executable, str(Path(__file__).parent/'model_loop.py'), '--mode', 'infer',
            '--model', str(model_path), '--tasks', str(tasks_path), '--out', str(result_path)], check=True, timeout=60)
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        child_wall = time.perf_counter_ns()-wall
        actual = json.loads(result_path.read_text())['predictions']
        if actual != predictions:
            raise ValueError('CONSUMER_PARITY')
        observer.record_cost(attempt, 'consumer_inference', observer='actual-child-process-rusage',
            cost=measured_cost(cpu_ns=round(((after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime))*10**9),
                wall_ns=child_wall, operations=len(rows)*9*257,
                bytes_read=len(model_path.read_bytes())+len(tasks_path.read_bytes()), bytes_written=len(result_path.read_bytes()),
                memory_peak_bytes=after.ru_maxrss*1024))
        observer.adopt_output(attempt, consumer_operation=identity('consumer-operation-'+name),
            consumer=identity('controlled-separate-inference-process'), observed_output=output_root)
    counted = [intake_cost, normalization_cost, plan_cost, quality_cost, output_cost]
    elapsed_cpu = time.process_time_ns()-outer_cpu
    elapsed_wall = time.perf_counter_ns()-outer_wall
    # Normal-form digesting, model materialization, output checks and recording
    # overhead are retained too; child CPU stays separately reported above.
    observer.record_cost(attempt, 'other_verifier_overhead', observer='inclusive-process-clock-minus-recorded-stages',
        cost=measured_cost(cpu_ns=max(0, elapsed_cpu-sum(c['cpu_ns'] for c in counted)),
            wall_ns=max(0, elapsed_wall-sum(c['wall_ns'] for c in counted)-child_wall), operations=0))
    return result


def run(inputs, expected_bundle, out, train_steps):
    out = Path(out); out.mkdir(parents=True, exist_ok=False); inputs = Path(inputs)
    raw = read_bounded(inputs/'evaluation-bundle.json', MAX_BUNDLE_BYTES)
    bundle = verify_bundle(raw, expected_bundle)
    datasets = {name: json.loads(read_bounded(inputs/(name+'.json'), MAX_TASK_BYTES), object_pairs_hook=unique)
                for name in ('train', 'evaluation_a', 'evaluation_b')}
    from experiments.model_loop import train, quantize
    import numpy as np
    import cryptography
    parent = bundle['controls']['current']; contract = integer_linear_contract(parent)
    submissions = []; sources = {}; caps = {}; producer_costs = []
    base = np.asarray(parent['base'], dtype=np.float64)/1024
    for index in range(3):
        shard = [row for row in datasets['train'] if row['label'] == index or int(row['id'][:8], 16)%3 == index]
        trained, cost = timed(lambda: quantize(train([row['x'] for row in shard], [row['label'] for row in shard], train_steps, base)))
        delta = (trained-np.asarray(parent['base'], dtype=np.int64)).clip(-32767, 32767).tolist()
        item = factor_adapter(contract, delta); sid = identity('trained-adapter-'+str(index))
        source = H('controlled-training-shard-v1', canonical(sorted(row['source_content_sha256'] for row in shard))).hex()
        submissions.append(dict(id=sid, adapter=item)); sources[sid] = source; caps[source] = 100
        producer_costs.append(dict(shard=index, rows=len(shard), steps=train_steps, cost=cost))
        write_new(out/('trained-adapter-'+str(index)+'.json'), canonical(item))
    alias = identity('same-BA-different-factors'); alternate = factor_adapter(contract, submissions[0]['adapter']['A'], True)
    submissions.append(dict(id=alias, adapter=alternate)); sources[alias] = sources[submissions[0]['id']]
    perturb = copy.deepcopy(submissions[0]['adapter']); perturb['A'][0][0] += -1 if perturb['A'][0][0] == 32767 else 1
    alias2 = identity('bounded-one-coordinate-copy'); submissions.append(dict(id=alias2, adapter=perturb)); sources[alias2] = sources[alias]
    plans = {}
    for partition in ('evaluation_a', 'evaluation_b'):
        plans[partition] = freeze_attribution_plan(parent=parent, evaluation_bundle=expected_bundle, partition=partition,
            rows=datasets[partition], submissions=submissions, admitted_sources=sources, source_caps=caps, perturbation_linf=1)
        write_new(out/(partition+'-plan.json'), plans[partition][0])
    stages = ('intake', 'normalization', 'plan_verification', 'quality')
    branch = identity('accepted-controlled-branch')
    observer = UniqueUsefulOutputAccounting(context=contract_id(contract), current_branch=branch, required_stages=stages)
    for partition in ('evaluation_a', 'evaluation_b'):
        observe(out, partition, *plans[partition], datasets[partition], observer, branch, adopt=True)
    observe(out, 'evaluation_b_repeated_A_content', *plans['evaluation_a'], datasets['evaluation_a'], observer, branch, adopt=True)
    observe(out, 'stale_retry_A', *plans['evaluation_a'], datasets['evaluation_a'], observer, identity('stale-branch'))
    new_branch = identity('reorganized-controlled-branch')
    observer.reorganize(new_branch=new_branch, active_branches=[new_branch])
    observe(out, 'reexecuted_A', *plans['evaluation_a'], datasets['evaluation_a'], observer, new_branch, adopt=True)
    write_new(out/'useful-output-events.json', canonical(observer.events))
    write_new(out/'useful-output-accounting.json', canonical(observer.snapshot()))
    # A separate finite attack model exercises genuine complementarity. These
    # fabricated labels are clearly identified; they are never efficacy evidence.
    attack_parent = copy.deepcopy(parent)
    attack_parent['source'] = 'controlled-complementarity-attack-fixture'
    attack_parent['base'] = [[0]*257 for _ in range(3)]; attack_parent['base'][0][-1] = 1
    attack_parent['router'] = [[0]*257 for _ in range(3)]
    attack_parent['deltas'] = [[[0]*257 for _ in range(3)] for _ in range(3)]
    attack_rows = [dict(id=identity('controlled-task-'+str(i)), file='controlled-attack/'+str(i)+'.rs',
        label=1, source_content_sha256=identity('controlled-content-'+str(i)), x=[1,1]+[0]*254+[8]) for i in range(24)]
    attack_contract = integer_linear_contract(attack_parent)
    attack_submissions = []
    for i in range(2):
        delta = [[0]*257 for _ in range(3)]; delta[1][i] = 5
        attack_submissions.append(dict(id=identity('complement-'+str(i)), adapter=factor_adapter(attack_contract, delta)))
    attack_sources = {s['id']: identity('complement-source-'+str(i)) for i, s in enumerate(attack_submissions)}
    attack_plan = freeze_attribution_plan(parent=attack_parent, evaluation_bundle=identity('controlled-attack-bundle'),
        partition='evaluation', rows=attack_rows, submissions=attack_submissions,
        admitted_sources=attack_sources, source_caps={source: 100 for source in attack_sources.values()})
    write_new(out/'complementarity-plan.json', attack_plan[0])
    attack_observer = UniqueUsefulOutputAccounting(context=contract_id(attack_contract), current_branch=branch, required_stages=stages)
    observed = observe(out, 'controlled_complementarity', *attack_plan, attack_rows, attack_observer, branch, adopt=True)
    write_new(out/'complementarity-accounting.json', canonical(attack_observer.snapshot()))
    source_files = [ROOT/'formal/pon-nakamoto-v1'/name for name in ('model_attribution.py', 'work_utility.py',
        'evaluation.py', 'evaluation_bundle.py', 'model_contract.py', 'contract_wire.py', 'ledger.py', 'strict_signature.py')]
    source_files += [Path(__file__), Path(__file__).parent/'model_loop.py']
    source_files += list(sorted((ROOT/'config/pon').glob('*.json')))
    report = dict(schema='pon-bounded-model-attribution-campaign-v1', source_commit=subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip(),
        source_clean=not bool(subprocess.check_output(['git','status','--porcelain'], cwd=ROOT, text=True).strip()),
        source_files_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in source_files},
        input_files_sha256={name: hashlib.sha256((inputs/name).read_bytes()).hexdigest()
            for name in ('evaluation-bundle.json', 'train.json', 'evaluation_a.json', 'evaluation_b.json')},
        bundle=expected_bundle, producer_costs=producer_costs, python=sys.version,
        numpy=np.__version__, cryptography=cryptography.__version__, platform=platform.platform(),
        completed_utc_ns=time.time_ns(), controlled_complementarity=observed['complementarity'],
        useful_output_observation=observer.snapshot(), prospective_accepted=False, independent_accepted=False,
        ordinary_hepta_entry=False, llm_runtime_executed=False, public_reward_eligible=False,
        scope='actual-existing-trainer-public-retrospective-data; separate-synthetic-complementarity-attack; no-LLM-quality-or-work-hardness-claim')
    write_new(out/'report.json', canonical(report))
    print(json.dumps({'output': str(out), 'actual_public_training_steps_per_shard': train_steps,
                      'complementarity': observed['complementarity'], 'scope': report['scope']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputs', required=True); parser.add_argument('--bundle-hash', required=True)
    parser.add_argument('--out', required=True); parser.add_argument('--train-steps', type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.train_steps <= 10000: raise ValueError('TRAINING_STEP_LIMIT')
    run(args.inputs, args.bundle_hash, args.out, args.train_steps)
