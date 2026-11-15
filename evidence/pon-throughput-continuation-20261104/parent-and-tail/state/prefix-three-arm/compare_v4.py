"""Read exactly the preregistered v4 experiment; no cell/sample exclusions."""
from pathlib import Path
from fractions import Fraction
from statistics import median
import hashlib
import json
import sys

REGISTRATION_PATH = Path(__file__).with_name('comparison-preregistration.json')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(strict_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(strict_equal(a, b) for a, b in zip(left, right))
    return left == right


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('invalid JSON constant: ' + value)


def strict_loads(text):
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


def parse_rows(text):
    rows = []
    for line in text.splitlines():
        if '{' not in line:
            continue
        row = strict_loads(line[line.index('{'):])
        require(type(row) is dict, 'JSON-like line must contain an object')
        if row.get('schema') == 'unchanged-snapshot-full-binding-cost-v4':
            rows.append(row)
    return rows


def evaluate(rows, registration, readback, provenance):
    require(registration['schema'] == 'unchanged-snapshot-v4-preregistration-v1', 'pre-registration schema differs')
    require(strict_equal(registration['common_inputs'], [[128, 64], [1024, 512], [4096, 512]]), 'pre-registered input sizes differ')
    require(registration['cases'] == ['unchanged', 'same_root_hint_first_value_changed', 'same_root_hint_last_value_changed'], 'pre-registered cases differ')
    require(registration['arms'] == ['original_full_map_ns', 'parent_40a_shared_map_ns', 'checked_shared_map_ns'], 'pre-registered arms differ')
    require(strict_equal(registration['six_permutation_order'], [[0, 1, 2], [2, 1, 0], [1, 2, 0], [0, 2, 1], [2, 0, 1], [1, 0, 2]]), 'pre-registered permutations differ')
    require(strict_equal(registration['permutation_repetitions'], 2), 'pre-registered repetitions differ')
    decision = registration['decision']
    require(decision['candidate'] == 'checked_shared_map_ns', 'pre-registered candidate differs')
    require(strict_equal(decision['primary_targets'], [
        {'reference':'parent_40a_shared_map_ns', 'case':'same_root_hint_last_value_changed', 'state_keys':[128,1024,4096], 'minimum_paired_median_improvement_fraction':0.05},
        {'reference':'original_full_map_ns', 'case':'unchanged', 'state_keys':[128,1024,4096], 'minimum_paired_median_improvement_fraction':0.05},
    ]), 'pre-registered primary targets differ')
    require(strict_equal(decision['maximum_paired_median_regression_fraction'], 0.10) and strict_equal(decision['maximum_p95_regression_fraction'], 0.10), 'pre-registered margins differ')
    require(decision['all_nine_cells_against_each_reference_required'] is True and decision['no_cell_aggregation_or_sample_exclusion'] is True, 'pre-registered completeness differs')
    require(strict_equal(decision['maximum_missing_or_unexpected_result_bindings'], 0), 'pre-registered result requirement differs')
    require(decision['public_business_gate_replaced'] is False and decision['physical_memory_qualification'] is False, 'pre-registered scope differs')
    arms = registration['arms']
    candidate_name = registration['decision']['candidate']
    required = {(n, width, case) for n, width in registration['common_inputs'] for case in registration['cases']}
    require(len(rows) == len(required) == 9, 'exactly nine v4 cells required')
    seen = set()
    findings = []
    identity = None
    for row in rows:
        require(type(row['state_keys']) is int and type(row['value_width']) is int, 'cell dimensions must be integers')
        cell = (row['state_keys'], row['value_width'], row['case'])
        require(cell in required and cell not in seen, 'unexpected or duplicate cell')
        seen.add(cell)
        require(row['schema'] == 'unchanged-snapshot-full-binding-cost-v4', 'v4 schema required')
        require(strict_equal(row['decision'], registration['decision']), 'decision differs from pre-registration')
        require(strict_equal(row['arm_names'], arms), 'arm identities/order differ')
        require(strict_equal(row['arm_order_per_six_rounds'], registration['six_permutation_order']), 'permutation schedule differs')
        require(row['order'] == 'fixed six-permutation rotation repeated twice', 'schedule identity differs')
        require(strict_equal(row['samples_per_arm'], 12) and strict_equal(registration['samples_per_arm'], 12), 'sample count differs')
        require(strict_equal(row['bindings_per_sample'], 8) and strict_equal(registration['bindings_per_sample'], 8), 'binding count differs')
        require(strict_equal(row['expected_returns_per_arm'], [96, 96, 96]), 'missing or noninteger expected returns')
        require(strict_equal(row['unexpected_returns_per_arm'], [0, 0, 0]), 'unexpected or noninteger returns')
        require(row['equal_result'] is True, 'results differ')
        require(row['complete_actual_state_compared'] is True and row['expected_root_checked'] is True and row['tree_empty_delta_check_retained'] is True, 'semantic checks absent')
        require(row['public_tps_measured'] is False and row['node_owner_measured'] is False and row['physical_memory_bound'] is False, 'component scope changed')
        source = row['source_identity']
        require(source['original_full_map_commit'] == registration['original_commit'], 'original source commit differs')
        require(source['parent_shared_map_commit'] == registration['actual_parent_commit'], 'actual parent source commit differs')
        require(source['original_reference_source_sha256'] == provenance['original_full_map']['file_sha256'], 'original reference source differs')
        require(source['parent_reference_source_sha256'] == provenance['actual_parent_shared_map']['file_sha256'], 'parent reference source differs')
        require(source['compiled_production_source_sha256'] == registration['candidate_production_sha256'], 'candidate production source differs')
        require(source['compiled_test_source_sha256'] == readback['source_sha256'], 'compiled experiment source differs')
        if identity is None:
            identity = source
        require(strict_equal(source, identity), 'mixed source identities')
        for arm in arms:
            require(isinstance(row[arm], list) and len(row[arm]) == 12, 'missing arm samples')
            require(all(type(value) is int and value > 0 for value in row[arm]), 'nonpositive or noninteger timing')
        current = row[candidate_name]
        for reference_name in arms[:2]:
            reference = row[reference_name]
            paired_improvement = median([Fraction(old-new, old) for old, new in zip(reference, current)])
            p95_regression = Fraction(max(current), max(reference)) - 1
            targets = [target for target in registration['decision']['primary_targets'] if target['reference'] == reference_name and target['case'] == row['case'] and row['state_keys'] in target['state_keys']]
            primary_required = bool(targets)
            primary_pass = not primary_required or paired_improvement >= Fraction(1, 20)
            median_pass = paired_improvement >= -Fraction(1, 10)
            tail_pass = p95_regression <= Fraction(1, 10)
            findings.append({
                'state_keys': row['state_keys'], 'value_width': row['value_width'], 'case': row['case'],
                'reference': reference_name,
                'paired_median_improvement_fraction': float(paired_improvement),
                'paired_median_improvement_exact': str(paired_improvement),
                'p95_regression_fraction': float(p95_regression),
                'p95_regression_exact': str(p95_regression),
                'reference_median_ns_per_binding': float(median(reference)/8),
                'candidate_median_ns_per_binding': float(median(current)/8),
                'primary_target_required': primary_required,
                'primary_target_pass': primary_pass,
                'median_nonregression_pass': median_pass,
                'p95_nonregression_pass': tail_pass,
                'pass': primary_pass and median_pass and tail_pass,
            })
    require(seen == required, 'missing cells')
    return {
        'schema': 'unchanged-snapshot-v4-preregistered-readback-v1',
        'status': 'PASS_COMPONENT_ONLY' if all(row['pass'] for row in findings) else 'HOLD',
        'source_identity': identity,
        'decision': registration['decision'],
        'planned_bindings': 2592,
        'expected_ok_bindings': 864,
        'expected_commitment_root_error_bindings': 1728,
        'unexpected_or_missing_bindings': 0,
        'comparisons': findings,
        'p95_is_twelve_sample_maximum': True,
        'statistical_confidence_established': False,
        'public_business_gate_replaced': False,
        'native_execution_verified': False,
        'requires_separate_source_binary_and_native_exit_verification': True,
    }


def main(path):
    registration = strict_loads(REGISTRATION_PATH.read_text())
    readback = {'source_sha256': registration['compiled_test_source_sha256']}
    provenance = registration['reference_provenance']
    raw = Path(path).read_bytes()
    rows = parse_rows(raw.decode())
    result = evaluate(rows, registration, readback, provenance)
    result['raw_log_sha256'] = hashlib.sha256(raw).hexdigest()
    result['preregistration_sha256'] = hashlib.sha256(REGISTRATION_PATH.read_bytes()).hexdigest()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'PASS_COMPONENT_ONLY' else 1


if __name__ == '__main__':
    try:
        code = main(sys.argv[1])
    except (ValueError, KeyError, TypeError, IndexError, UnicodeError) as error:
        print(json.dumps({'schema':'unchanged-snapshot-v4-preregistered-readback-v1','status':'HOLD','error':str(error),'public_business_gate_replaced':False,'native_execution_verified':False,'requires_separate_source_binary_and_native_exit_verification':True}))
        code = 1
    raise SystemExit(code)
