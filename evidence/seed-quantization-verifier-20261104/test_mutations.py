"""Synthetic in-memory and temporary-copy corruption tests; originals never edited."""
import copy
import json
import shutil
import tempfile
from pathlib import Path
import verify


def changed(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if isinstance(value, str):
        return value + '-mutated'
    raise TypeError(type(value))


def main():
    base = verify.load()
    verify.validate(*base)
    outcomes = []

    def reject(name, mutation):
        args = copy.deepcopy(base)
        mutation(args)
        try:
            verify.validate(*args)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            outcomes.append({'case': name, 'rejected': True, 'reason': str(exc)})
        else:
            raise RuntimeError('MUTATION ACCEPTED: ' + name)

    def leaf(name, arg, path):
        def mutate(args):
            target = args[arg]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = changed(target[path[-1]])
        reject(name, mutate)

    reject('empty weights', lambda a: a[1].clear())
    reject('missing weight fold', lambda a: a[1].pop())
    reject('duplicate weight fold', lambda a: a[1].__setitem__(4, copy.deepcopy(a[1][0])))
    reject('empty fold reports', lambda a: a[0]['folds'].clear())
    reject('missing OOF row', lambda a: a[0]['out_of_fold'].pop())
    reject('duplicate OOF row', lambda a: a[0]['out_of_fold'].__setitem__(1, copy.deepcopy(a[0]['out_of_fold'][0])))
    reject('weight shape', lambda a: a[1][0]['seed_float'].pop())
    reject('nonfinite weight', lambda a: a[1][0]['seed_float'][0].__setitem__(0, float('nan')))
    reject('fractional integer weight', lambda a: a[1][0]['seed_quantized_integer'][0].__setitem__(0, 0.5))
    reject('int64 minimum integer weight', lambda a: a[1][0]['seed_quantized_integer'][0].__setitem__(0, -(1 << 63)))
    reject('out of range integer weight', lambda a: a[1][0]['seed_quantized_integer'][0].__setitem__(0, 32768))
    for fold in range(5):
        f = base[0]['folds'][fold]
        for key in ('fold', 'fit_rows', 'test_rows', 'fit_files', 'test_files', 'logit_interaction_max_abs', 'both_old_controls_exact_match'):
            leaf(f'fold {fold} {key}', 0, ['folds', fold, key])
        leaf(f'fold {fold} seed identity', 0, ['folds', fold, 'seed_row_ids', 0])
        for key in ('seed_weight_change', 'pooled_weight_change', 'seed_logit_shift_before_final', 'seed_logit_shift_after_final', 'clipped_weights', 'prediction_disagreements'):
            for subkey in f[key]:
                leaf(f'fold {fold} {key}.{subkey}', 0, ['folds', fold, key, subkey])
        for arm in verify.ARMS:
            for key in ('minimum', 'exact_top_ties'):
                leaf(f'fold {fold} margin {arm}.{key}', 0, ['folds', fold, 'margins', arm, key])
        for key in base[1][fold]:
            if key != 'fold':
                leaf(f'fold {fold} weight {key}', 1, [fold, key, 0, 0])
    for arm in verify.ARMS:
        leaf('OOF prediction ' + arm, 0, ['out_of_fold', 0, 'predictions', arm])
        leaf('OOF logit ' + arm, 0, ['out_of_fold', 0, 'logits_common_units', arm, 0])
        leaf('OOF margin ' + arm, 0, ['out_of_fold', 0, 'top_margins_common_units', arm])
        for key in ('correct', 'file_macro'):
            leaf('aggregate ' + arm + key, 0, ['metrics', arm, key])
        leaf('confusion ' + arm, 0, ['metrics', arm, 'confusion', 0, 0])
    for key in ('fold', 'true', 'id'):
        leaf('OOF ' + key, 0, ['out_of_fold', 0, key])
    for key in base[0]['disagreements']:
        leaf('aggregate disagreement ' + key, 0, ['disagreements', key])
    for key in ('rows', 'files', 'primary_seed_before_final_prediction_disagreements', 'all_original_rows_scored', 'controls_exact_match', 'new_independent_data', 'model_adopted', 'public_reward'):
        leaf(key, 0, [key])
    leaf('TRAIN split', 2, [0, 'split'])
    leaf('TRAIN feature bound', 2, [0, 'x', 256])
    leaf('control prediction', 3, ['out_of_fold', 0, 'float'])
    for case in ('report.json', 'weights.json', 'report.json.gz', 'weights.json.gz', 'PLAN.json', 'empty manifest', 'missing manifest entry', 'duplicate manifest entry'):
        with tempfile.TemporaryDirectory(prefix='chain-verifier-negative-') as d:
            target = Path(d) / 'package'
            shutil.copytree(verify.PACKAGE, target)
            if 'manifest' in case:
                p = target / 'SHA256SUMS'
                lines = p.read_bytes().splitlines(keepends=True)
                raw = b'' if case == 'empty manifest' else b''.join(lines[:-1] if case == 'missing manifest entry' else lines + lines[:1])
                p.write_bytes(raw)
            else:
                p = target / case
                p.write_bytes(p.read_bytes() + b'corruption' if p.exists() else b'[]')
            try:
                verify.load(target)
            except (ValueError, OSError) as exc:
                outcomes.append({'case': 'package ' + case, 'rejected': True, 'reason': str(exc)})
            else:
                raise RuntimeError('PACKAGE MUTATION ACCEPTED: ' + case)
    # The original package still satisfies every published checksum after all tests.
    verify.validate(*verify.load())
    print(json.dumps({'result': 'PASS', 'negative_cases': len(outcomes), 'all_rejected': True, 'original_package_reverified': True, 'cases': outcomes}, indent=2))


if __name__ == '__main__':
    main()
