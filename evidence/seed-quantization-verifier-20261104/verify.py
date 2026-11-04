"""Independent stored-weight audit. No training imports or held-out data reads."""
import gzip
import hashlib
import json
import math
import os
from fractions import Fraction
from pathlib import Path

os.environ.setdefault('OPENBLAS_NUM_THREADS', '1')
os.environ.setdefault('OMP_NUM_THREADS', '1')
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'evidence/seed-final-quantization-20261103'
TRAIN = ROOT / 'evidence/pon-evaluation-bundle-v1/model/train.json'
CONTROL = ROOT / 'evidence/train-only-quantization-20261103/report.json'
ARMS = ('FF', 'FQ', 'QF', 'QQ')
PAIRS = {'seed_before_final': ('FF', 'QF'), 'seed_after_final': ('FQ', 'QQ'),
         'final_from_float_seed': ('FF', 'FQ'), 'final_from_quantized_seed': ('QF', 'QQ')}


def require(condition, name):
    if not condition:
        raise ValueError(name)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


MANIFEST_SHA256 = 'd6bf8b9cf451eac5a4a9e6a512b01f223a5f32ab4e96ef112c558bfb1d97c73b'
MANIFEST_FILES = {'PLAN.json', 'README.md', 'decoded-hashes.json', 'report.json.gz', 'reproduce.py', 'run.py', 'run.stderr', 'verification.json', 'verify.py', 'verify.stderr', 'weights.json.gz'}


def load(package=PACKAGE):
    # Pin the original manifest, not merely a possibly rewritten self-consistent set.
    manifest = (package / 'SHA256SUMS').read_bytes()
    require(digest(manifest) == MANIFEST_SHA256, 'frozen manifest hash')
    lines = manifest.decode().splitlines()
    names = [line.split('  ', 1)[1] for line in lines]
    require(len(names) == len(set(names)) and set(names) == MANIFEST_FILES, 'manifest coverage')
    for line in lines:
        expected, name = line.split('  ', 1)
        require(Path(name).name == name, 'unsafe manifest path')
        require(digest((package / name).read_bytes()) == expected, 'package hash: ' + name)
    decoded = json.loads((package / 'decoded-hashes.json').read_bytes())
    data = {}
    for name in ('report.json', 'weights.json'):
        require(not (package / name).exists(), 'uncompressed shadow: ' + name)
        raw = gzip.decompress((package / (name + '.gz')).read_bytes())
        require(digest(raw) == decoded[name], 'decoded hash: ' + name)
        data[name] = json.loads(raw)
    plan_raw = (package / 'PLAN.json').read_bytes()
    plan = json.loads(plan_raw)
    require(plan['input'] == str(TRAIN.relative_to(ROOT)), 'TRAIN path')
    require(plan['fold_reference'] == str(CONTROL.relative_to(ROOT)), 'control path')
    raw = TRAIN.read_bytes()
    control_raw = CONTROL.read_bytes()
    r = data['report.json']
    require(digest(raw) == plan['input_sha256'] == r['input_sha256'], 'TRAIN hash')
    require(digest(plan_raw) == r['plan_sha256'], 'plan hash')
    require(digest(control_raw) == r['old_control_report_sha256'], 'control hash')
    return r, data['weights.json'], json.loads(raw), json.loads(control_raw)


def equal(actual, expected, name):
    require(actual == expected, name)


def change(a, b, reported, name):
    # Scalar summation independently checks the runner's BLAS/numpy norm reduction.
    delta = [float(x) - float(y) for x, y in zip(a.flat, b.flat)]
    equal(set(reported), {'max_abs', 'l2', 'nonzero_entries'}, name + ' keys')
    equal(max(map(abs, delta)), reported['max_abs'], name + ' max_abs')
    equal(sum(v != 0 for v in delta), reported['nonzero_entries'], name + ' nonzero')
    norm = math.sqrt(math.fsum(v * v for v in delta))
    require(math.isfinite(reported['l2']) and math.isclose(norm, reported['l2'], rel_tol=1e-13, abs_tol=1e-15), name + ' l2')


def validate(r, weights, rows, control):
    equal(r['schema'], 'chain-seed-final-quantization-2x2-result-v1', 'schema')
    equal(len(rows), 1005, 'row count')
    require(all(row['split'] == 'train' for row in rows), 'TRAIN only')
    equal(len({row['id'] for row in rows}), len(rows), 'unique TRAIN IDs')
    files = {}
    for i, row in enumerate(rows):
        files.setdefault(row['file'], []).append(i)
        require(row['label'] in range(3), 'label')
        require(len(row['x']) == 257 and all(type(v) is int and abs(v) <= 8 for v in row['x']), 'features')
    equal(len(files), 150, 'file count')
    folds = {}
    for label in range(3):
        group = [f for f, indices in files.items() if rows[indices[0]]['label'] == label]
        for f in group:
            require(all(rows[i]['label'] == label for i in files[f]), 'single owner per file')
        for j, f in enumerate(sorted(group, key=lambda f: hashlib.sha256(f.encode()).digest())):
            folds[f] = j % 5
    oof = r['out_of_fold']
    equal(len(oof), len(rows), 'OOF coverage')
    equal([v['id'] for v in oof], [v['id'] for v in rows], 'OOF ordered IDs')
    old = {v['id']: v for v in control['out_of_fold']}
    equal(len(old), len(control['out_of_fold']), 'unique control IDs')
    equal(set(old), {v['id'] for v in rows}, 'control coverage')
    equal(len(weights), 5, 'weight fold count')
    equal(sorted(w['fold'] for w in weights), list(range(5)), 'weight fold IDs')
    equal(len(r['folds']), 5, 'report fold count')
    equal([f['fold'] for f in r['folds']], list(range(5)), 'report fold IDs')
    for row, out in zip(rows, oof):
        equal(out['fold'], folds[row['file']], 'OOF fold')
        equal(out['true'], row['label'], 'OOF truth')
        equal(old[row['id']]['fold'], out['fold'], 'control fold')
        equal(old[row['id']]['true'], row['label'], 'control truth')
    aggregate = {key: 0 for key in PAIRS}
    for w in weights:
        fold = w['fold']
        f = r['folds'][fold]
        test = [i for i, row in enumerate(rows) if folds[row['file']] == fold]
        fit = [row for row in rows if folds[row['file']] != fold]
        for key, val in {'fit_rows': len(fit), 'test_rows': len(test), 'fit_files': len({x['file'] for x in fit}), 'test_files': len({rows[i]['file'] for i in test})}.items():
            equal(f[key], val, key)
        equal(f['seed_row_ids'], [x['id'] for label in range(3) for x in [x for x in fit if x['label'] == label][:20]], 'seed identities')
        arrays = {}
        for key in ('seed_float', 'seed_quantized_integer', 'pooled_float_seed', 'pooled_quantized_seed', 'final_float_seed_integer', 'final_quantized_seed_integer'):
            a = np.asarray(w[key])
            require(a.shape == (3, 257) and np.isfinite(a).all(), 'weight shape/finite: ' + key)
            if key.endswith('integer'):
                require(a.dtype.kind in 'iu' and np.all(a >= -32767) and np.all(a <= 32767), 'integer range: ' + key)
                a = a.astype(np.int64)
            else:
                a = a.astype(np.float64)
            arrays[key] = a
        sf, si, wf, wq, qf, qq = [arrays[k] for k in ('seed_float', 'seed_quantized_integer', 'pooled_float_seed', 'pooled_quantized_seed', 'final_float_seed_integer', 'final_quantized_seed_integer')]
        for source, integer, key in ((sf, si, 'seed'), (wf, qf, 'float_seed_final'), (wq, qq, 'quantized_seed_final')):
            rounded = np.rint(source * 1024)
            require(np.array_equal(np.maximum(-32767, np.minimum(32767, rounded)), integer), 'quantization: ' + key)
            equal(f['clipped_weights'][key], int(np.count_nonzero((rounded < -32767) | (rounded > 32767))), 'clipping: ' + key)
        x = np.asarray([rows[i]['x'] for i in test], dtype=np.int64)
        scores = {'FF': x @ wf.T, 'FQ': (x @ qf.T) / 1024, 'QF': x @ wq.T, 'QQ': (x @ qq.T) / 1024}
        predictions = {}
        for arm, scores_arm in scores.items():
            predictions[arm] = np.argmax(scores_arm, axis=1).tolist()
            ordered = np.sort(scores_arm, axis=1)
            margins = ordered[:, 2] - ordered[:, 1]
            equal(f['margins'][arm], {'minimum': float(min(margins)), 'exact_top_ties': int(np.count_nonzero(margins == 0))}, 'fold margin: ' + arm)
            for j, i in enumerate(test):
                equal(oof[i]['predictions'][arm], predictions[arm][j], 'prediction: ' + arm)
                equal(oof[i]['logits_common_units'][arm], scores_arm[j].tolist(), 'logits: ' + arm)
                equal(oof[i]['top_margins_common_units'][arm], float(margins[j]), 'margin: ' + arm)
                if arm in ('QF', 'QQ'):
                    equal(predictions[arm][j], old[rows[i]['id']]['float' if arm == 'QF' else 'integer'], 'old control: ' + arm)
        for key, (a, b) in PAIRS.items():
            n = sum(u != v for u, v in zip(predictions[a], predictions[b]))
            equal(f['prediction_disagreements'][key], n, 'fold disagreement: ' + key)
            aggregate[key] += n
        change(sf, si.astype(np.float64) / 1024, f['seed_weight_change'], 'seed weights')
        change(wf, wq, f['pooled_weight_change'], 'pooled weights')
        change(scores['FF'], scores['QF'], f['seed_logit_shift_before_final'], 'logits before')
        change(scores['FQ'], scores['QQ'], f['seed_logit_shift_after_final'], 'logits after')
        interaction = (scores['QQ'] - scores['QF']) - (scores['FQ'] - scores['FF'])
        equal(f['logit_interaction_max_abs'], max(abs(float(v)) for v in interaction.flat), 'interaction')
        equal(f['both_old_controls_exact_match'], True, 'fold control flag')
    equal(r['disagreements'], aggregate, 'aggregate disagreements')
    equal(r['primary_seed_before_final_prediction_disagreements'], aggregate['seed_before_final'], 'primary')
    for arm in ARMS:
        pred = [v['predictions'][arm] for v in oof]
        confusion = [[sum(row['label'] == a and p == b for row, p in zip(rows, pred)) for b in range(3)] for a in range(3)]
        macro = sum((Fraction(sum(pred[i] == rows[i]['label'] for i in ids), len(ids)) for ids in files.values()), Fraction()) / len(files)
        equal(r['metrics'][arm], {'correct': sum(confusion[i][i] for i in range(3)), 'confusion': confusion, 'file_macro': float(macro)}, 'metrics: ' + arm)
    for key, val in {'rows': len(rows), 'files': len(files), 'all_original_rows_scored': True, 'controls_exact_match': True, 'new_independent_data': False, 'model_adopted': False, 'public_reward': 0}.items():
        equal(r[key], val, key)
    return {'result': 'PASS', 'rows': len(rows), 'files': len(files), 'folds': 5, 'arms': 4, 'all_fold_measurements_checked': True, 'disagreements': aggregate, 'training_run': False, 'held_out_task_data_read': False, 'l2_relative_tolerance': 1e-13, 'l2_absolute_tolerance': 1e-15}


if __name__ == '__main__':
    print(json.dumps(validate(*load()), indent=2))
