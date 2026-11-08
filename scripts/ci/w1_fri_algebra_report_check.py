#!/usr/bin/env python3
"""Independent count and claim boundary for the fixed algebra observation."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from w1_fri_algebra_controls import read_json, require

RECEIPT_SHA256 = '6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee'
PROFILE = 'trnm-w1-risc0-3.0.6-poseidon2-join-v2'
TRUE_FLAGS = (
    'fixed_mixed_air_validity_equation_checked',
    'fixed_deep_ali_evaluations_checked',
    'fixed_fri_folding_equations_checked',
    'fixed_terminal_polynomial_evaluations_checked',
)
FALSE_FLAGS = (
    'complete_receipt_verified', 'accepted_language_equivalence_proved',
    'source_guest_vm_air_semantics_proved', 'all_recursive_program_semantics_verified',
    'round_by_round_knowledge_extractor_supplied', 'qrom_instantiated',
    'post_quantum_soundness_qualified', 'complete_w1_soundness_qualified',
    'quantum_work_qualified', 'production_qualified', 'consensus_admission',
)
NULL_FLAGS = ('unconditional_project_security_bits', 'full_security_bound')


def canonical_field(value):
    return (type(value) is list and len(value) == 4
            and all(type(word) is int and 0 <= word < 2013265921 for word in value))


def validate(report):
    require(type(report) is dict and report.get('schema') == 'TRNM-W1-FRI-ALGEBRA-REPLAY1',
            'algebra report schema')
    require(report.get('profile_id') == PROFILE
            and report['receipt']['sha256'] == RECEIPT_SHA256,
            'fixed profile or receipt identity')
    expected = dict.fromkeys(TRUE_FLAGS, True)
    expected.update(dict.fromkeys(FALSE_FLAGS, False))
    expected.update(dict.fromkeys(NULL_FLAGS, None))
    flags = report['qualification']
    require(type(flags) is dict and set(flags) == set(expected)
            and all(flags[key] is value for key, value in expected.items()),
            'missing, promoted or mistyped qualification')
    algebra = report['algebra']
    counts = {
        'mixed_air_operations': algebra['mixed_air']['operations'],
        'deep_goals': algebra['deep']['query_values_checked_against_first_fri_leaf'],
        'fri_incoming_goal_equalities': algebra['fri']['incoming_goal_equalities'],
        'terminal_equalities': algebra['fri']['terminal_equalities'],
    }
    require(all(type(value) is int for value in counts.values()) and counts == {
        'mixed_air_operations': 12359, 'deep_goals': 50,
        'fri_incoming_goal_equalities': 150, 'terminal_equalities': 50},
        'incomplete algebra evaluation')
    return {'schema': 'TRNM-W1-FRI-ALGEBRA-SCOPE1', 'result': 'PASS',
            'receipt_sha256': RECEIPT_SHA256, 'counts': counts,
            'qualification': expected}


def compare_review(report, review):
    """Compare register-expanded results with the separate combo-batched replay."""
    require(review['schema'] == 'TRNM-W1-INDEPENDENT-REGISTER-DEEP-REVIEW1'
            and review['receipt']['sha256'] == RECEIPT_SHA256,
            'independent review identity')
    for key, expected in (
            ('imports_new_algebra_replay', False), ('generated_air_program_evaluated', False),
            ('native_sdk_executed', False), ('full_receipt_verified', False),
            ('sdk_general_language_equivalence_proved', False), ('qrom_instantiated', False),
            ('security_bits_quantum', None), ('whole_chain_pq_qualified', False),
            ('production_qualified', False)):
        require(review['scope'][key] is expected, 'independent review scope')
    expected_counts = {
        'merkle_openings_replayed_by_pinned_predecessor': 350,
        'registers_expanded_per_query': 163, 'deep_to_first_leaf_equalities': 50,
        'selected_fri_component_equalities': 150, 'folds_recomputed': 150,
        'terminal_equalities': 50, 'distinct_symbolic_denominators_per_query': 6,
        'nonzero_denominator_inverse_products': 300,
    }
    require(review['checks'] == expected_counts
            and all(type(v) is int for v in review['checks'].values()), 'independent review counts')
    air = report['algebra']['mixed_air']
    require(air['equality_checked'] is True
            and all(canonical_field(value) for value in (
                air['returned_total'], air['check_polynomial_times_zerofier'],
                review['air_check_side_normal_words']))
            and air['returned_total'] == air['check_polynomial_times_zerofier']
            == review['air_check_side_normal_words'], 'mixed AIR value disagreement')
    rows = report['algebra']['fri']['queries']
    independent = review['queries']
    require(len(rows) == len(independent) == 50, 'independent query coverage')
    divisors_by_key = {}
    for number, (row, other) in enumerate(zip(rows, independent)):
        require(type(row['query_number']) is int and row['query_number'] == number
                and type(other['query']) is int and other['query'] == number,
                'query identity disagreement')
        require(all(type(value) is int for value in (
                    row['initial_index'], other['initial_index'],
                    row['terminal_index'], other['terminal_index']))
                and row['initial_index'] == other['initial_index']
                and row['terminal_index'] == other['terminal_index']
                and len(row['rounds']) == 3 and len(row['deep_divisors']) == 6,
                'query geometry disagreement')
        goals = [row['deep_goal']] + [item['outgoing_goal'] for item in row['rounds']]
        other_goals = other['deep_and_three_fold_goals_normal']
        require(type(other_goals) is list and len(other_goals) == 4
                and all(canonical_field(value) for value in goals + other_goals)
                and goals == other_goals, 'independent DEEP/fold disagreement')
        for index, item in enumerate(row['rounds']):
            require(item['incoming_equality_checked'] is True
                    and canonical_field(item['incoming_goal'])
                    and canonical_field(item['selected_opened_value'])
                    and item['incoming_goal'] == item['selected_opened_value'] == goals[index],
                    'unverified incoming fold equality')
        require(row['terminal_equality_checked'] is True and other['terminal_equality'] is True
                and canonical_field(row['terminal_goal']) and canonical_field(row['terminal_value'])
                and row['terminal_goal'] == row['terminal_value'] == goals[-1],
                'unverified terminal equality')
        require(row['deep_denominators_nonzero'] is True, 'zero-divisor scope changed')
        for combo, divisor in enumerate(row['deep_divisors']):
            require(type(divisor) is list and len(divisor) == 4
                    and all(type(x) is int and 0 <= x < 2013265921 for x in divisor)
                    and any(divisor), 'noncanonical or zero DEEP divisor')
            divisors_by_key[number, 'check' if combo == 5 else combo] = struct.pack('<4I', *divisor)
    # Register order encounters combo 1 before combo 0. Compare named groups,
    # then hash in the reviewer's declared traversal order, not numeric order.
    require(len(review['denominators']) == 300, 'independent denominator coverage')
    divisor_bytes, seen = bytearray(), set()
    for item in review['denominators']:
        require(type(item['query']) is int and 0 <= item['query'] < 50,
                'nonintegral or out-of-range denominator query identity')
        combo = item['combo']
        require((type(combo) is int and 0 <= combo < 5)
                or (type(combo) is str and combo == 'check'),
                'noncanonical denominator combo identity')
        key = item['query'], item['combo']
        require(key in divisors_by_key and key not in seen, 'missing or duplicate denominator identity')
        seen.add(key)
        encoded = divisors_by_key[key]
        require(hashlib.sha256(encoded).hexdigest() == item['normal_words_le_sha256'],
                'independent named denominator disagreement')
        divisor_bytes.extend(encoded)
    require(seen == set(divisors_by_key), 'independent denominator identity coverage')
    require(hashlib.sha256(divisor_bytes).hexdigest()
            == review['denominators_ordered_normal_le_sha256'], 'independent denominator disagreement')
    return {'register_expansion_agrees_with_combo_batching': True,
            'deep_goals_compared': 50, 'fold_results_compared': 150,
            'terminal_results_compared': 50, 'nonzero_divisors_compared': 300,
            'independent_air_left_hand_side_evaluation': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--review', type=Path, help='Fresh independent register-expanded observation')
    args = parser.parse_args()
    try:
        raw, report = read_json(args.report)
        result = validate(report)
        result['report_sha256'] = hashlib.sha256(raw).hexdigest()
        if args.review is not None:
            review_raw, review = read_json(args.review)
            result['independent_review'] = compare_review(report, review)
            result['review_sha256'] = hashlib.sha256(review_raw).hexdigest()
        with args.output.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write('\n')
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('algebra scope refused: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
