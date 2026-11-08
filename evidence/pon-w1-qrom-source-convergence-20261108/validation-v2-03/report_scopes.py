from fractions import Fraction
import json
from pathlib import Path
import re
import sys

out = Path(sys.argv[1])
def require(condition, message):
    if not condition:
        raise ValueError(message)

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result

def refuse_constant(value):
    raise ValueError('nonfinite JSON number: ' + value)

def read(name):
    return json.loads((out / name).read_bytes(), object_pairs_hook=strict_object,
                      parse_constant=refuse_constant)

def fields(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), label + ': exact fields required')

def exact_qualification(observed, expected):
    return (type(observed) is dict and set(observed) == set(expected)
            and all(observed[key] is value for key, value in expected.items()))

implementation = read('implementation.json')
expected_implementation = {
    'post_quantum_soundness_qualified': False,
    'complete_w1_soundness_qualified': False,
    'quantum_work_qualified': False,
    'pq_signature_qualification_inferred': False,
    'production_qualified': False,
    'consensus_admission': False,
    'security_bits_quantum': None,
}
expected_source_review = {
    'schema': 'TRNM-W1-QROM-SOURCE-TRANSITION1',
    'review_sha256': '988a67862cff06d2d6d580dc65db84f9d177a7bbbdb9e79c96c3dc4f81d9491b',
    'historical_contract_sha256': '7761787fca9ea92c7b678186ccb302900bfabc974460b7f6793c7a0aabb6cf22',
    'historical_engine_sha256': 'c6fc6c36e4c2ce198c1dad465a7d36495253f844438f46df652715ea6dc8b354',
    'historical_report_sha256': 'eebf074f5f4a77cb7277035300294ef9308cb5ec5d0441336665bafcb6647c8b',
    'selected_project_file_count': 16,
    'unchanged_project_file_count': 14,
    'changed_paths': [
        'formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs',
        'trillionnium/crates/trnm-protocol/src/pon_wire.rs',
    ],
    'historical_route_byte_projection_reproduced': True,
    'historical_semantic_report_fields_reproduced': True,
    'new_native_once_route_qualified': False,
    'funded_service_decoder_qualified': False,
    'whole_source_and_build_equivalence_proved': False,
}
source_review = implementation.get('source_review') if type(implementation) is dict else None
require(type(source_review) is dict
        and set(source_review) == set(expected_source_review)
        and all(type(source_review[key]) is type(value) and source_review[key] == value
                for key, value in expected_source_review.items()),
        'implementation source transition scope or provenance differs')
require(type(implementation) is dict
        and implementation.get('schema') == 'TRNM-W1-QROM-IMPLEMENTATION-AUDIT2'
        and implementation.get('result') == 'MAPPING_REPRODUCED_SECURITY_HOLD'
        and implementation.get('contract_sha256') == 'bed7e925b5c02f896ea0f6ada378a346080d044a8c7c3879f7d47c034fb86280'
        and implementation.get('source_base_commit') == 'bb026697a972521009bc133ae6ed2b653e18e931'
        and exact_qualification(implementation.get('qualification'), expected_implementation),
        'implementation observation widened its qualification scope')
expected_budget = {
    'unconditional_project_security_bits': None,
    'quantum_security_bits': None,
    'full_recursive_security_bits': None,
    'qrom_theorem_instantiated': False,
    'post_quantum_soundness_qualified': False,
    'whole_recursive_proof_soundness_qualified': False,
    'complete_w1_attack_established': False,
    'production_qualified': False,
    'consensus_admission': False,
}
pqsr_fields = {'t', 'k', 'w', 'r_min', 'kappa_rrbr', 'target_error'}
merkle_fields = {'t', 'k', 'w_vc', 'sigma', 'ell_max', 'n', 'q_s', 'target_error'}
component_names = {
    'commutativity', 'extraction_correctness',
    'offline_extractability', 'online_indistinguishability',
}
pqsr_numbers = (
    'rrbr_coefficient', 'finite_randomness_addend',
    'rrbr_addend', 'conditional_upper_expression',
)
target_fields = {
    'finite_randomness_addend_exceeds_target',
    'some_nonnegative_rrbr_bound_can_meet_target_by_this_expression',
    'kappa_rrbr_required_at_most',
}
budget_fields = {
    'schema', 'status', 'source', 'inputs', 'pqsr_component', 'merkle_components',
    'theorem_11_3_full_bound', 'theorem_10_6_composed_bound',
    'qualification', 'unresolved_obligations',
}
def input_fields(inputs):
    fields(inputs, {'schema', 'input_kind', 'pqsr', 'merkle'}, 'inputs')
    require(inputs['schema'] == 'TRNM-W1-QROM-CONDITIONAL-INPUT1'
            and inputs['input_kind'] == 'hypothetical', 'hypothetical input schema required')
    fields(inputs['pqsr'], pqsr_fields, 'inputs.pqsr')
    fields(inputs['merkle'], merkle_fields, 'inputs.merkle')

def report_shape(report):
    fields(report, budget_fields, 'component report')
    require(report['schema'] == 'TRNM-W1-QROM-CONDITIONAL-COMPONENTS1'
            and report['status'] == 'hypothetical_component_arithmetic_only'
            and report['theorem_11_3_full_bound'] is None
            and report['theorem_10_6_composed_bound'] is None
            and exact_qualification(report['qualification'], expected_budget),
            'conditional component report widened its theorem or project scope')
    source = report['source']
    fields(source, {'paper', 'indexed_copy', 'indexed_manuscript_date',
                   'latest_revision_date_observed_in_metadata',
                   'latest_revision_full_text_equivalence_verified', 'scope'}, 'source')
    require(source['indexed_manuscript_date'] == '2026-01-01'
            and source['latest_revision_full_text_equivalence_verified'] is False,
            'component arithmetic must retain the selected January statement boundary')
    require(type(report['unresolved_obligations']) is list and report['unresolved_obligations']
            and all(type(item) is str and item for item in report['unresolved_obligations']),
            'unresolved obligations must remain explicit')
    input_fields(report['inputs'])
    pqsr = report['pqsr_component']
    fields(pqsr, set(pqsr_numbers) | {'theorem', 'conditional_expression_meets_target',
           'target_analysis', 'unknown_inputs', 'boundary'}, 'pqsr_component')
    require(pqsr['theorem'] == '2026-01-01 manuscript, Theorem 6.10, page 46'
            and type(pqsr['boundary']) is str and pqsr['boundary'], 'PQSR theorem boundary missing')
    fields(pqsr['target_analysis'], target_fields, 'PQSR target analysis')
    merkle = report['merkle_components']
    fields(merkle, {'theorem', 'conditional_expressions', 'each_expression_meets_component_target',
                    'unknown_inputs', 'boundary'}, 'merkle_components')
    require(merkle['theorem'] == '2026-01-01 manuscript, Theorem 8.3, page 53'
            and type(merkle['boundary']) is str and merkle['boundary'], 'Merkle theorem boundary missing')
    fields(merkle['conditional_expressions'], component_names, 'Merkle expressions')
    fields(merkle['each_expression_meets_component_target'], component_names, 'Merkle comparisons')

unknown = read('budget-unknown.json')
example = read('budget-hypothetical.json')
for report in (unknown, example):
    report_shape(report)
for group in ('pqsr', 'merkle'):
    require(all(value is None for value in unknown['inputs'][group].values()),
            'unknown inputs must remain null with the complete field set')
unknown_pqsr = unknown['pqsr_component']
require(all(unknown_pqsr[key] is None for key in pqsr_numbers)
        and unknown_pqsr['conditional_expression_meets_target'] is None
        and all(value is None for value in unknown_pqsr['target_analysis'].values())
        and unknown_pqsr['unknown_inputs'] == sorted(pqsr_fields),
        'every unknown PQSR derived value, comparison and threshold must remain null')
unknown_merkle = unknown['merkle_components']
require(all(value is None for value in unknown_merkle['conditional_expressions'].values())
        and all(value is None for value in unknown_merkle['each_expression_meets_component_target'].values())
        and unknown_merkle['unknown_inputs'] == sorted(merkle_fields),
        'every unknown named Merkle expression and comparison must remain null')

# Independent stdlib Fraction arithmetic for the retained hypothetical input.
# Do not import or call the calculator to validate its own derived values.
def integer_text(value, label, minimum=0, maximum=None):
    require(type(value) is str and len(value) <= 617
            and re.fullmatch(r'0|[1-9][0-9]*', value) is not None,
            label + ': canonical exact integer string required')
    number = int(value)
    require(number.bit_length() <= 2048 and number >= minimum
            and (maximum is None or number <= maximum), label + ': input outside evaluator bounds')
    return number

def fraction_value(value, label, reported):
    if not reported and type(value) is str:
        return Fraction(integer_text(value, label))
    fields(value, {'numerator', 'denominator'}, label)
    numerator = integer_text(value['numerator'], label + '.numerator')
    denominator = integer_text(value['denominator'], label + '.denominator', 1)
    number = Fraction(numerator, denominator)
    require(value == {'numerator': str(number.numerator), 'denominator': str(number.denominator)},
            label + ': reduced exact fraction required')
    return number

def parse_known_inputs(inputs, reported):
    input_fields(inputs)
    pqsr_raw, merkle_raw = inputs['pqsr'], inputs['merkle']
    pqsr = {key: integer_text(pqsr_raw[key], 'pqsr.' + key, int(key != 't'),
                             4096 if key == 'r_min' else None)
            for key in ('t', 'k', 'r_min')}
    pqsr.update({key: fraction_value(pqsr_raw[key], 'pqsr.' + key, reported)
                 for key in ('w', 'kappa_rrbr', 'target_error')})
    merkle = {key: integer_text(merkle_raw[key], 'merkle.' + key,
                               int(key in ('k', 'sigma', 'ell_max')),
                               4096 if key == 'sigma' else None)
              for key in ('t', 'k', 'sigma', 'ell_max', 'n', 'q_s')}
    merkle.update({key: fraction_value(merkle_raw[key], 'merkle.' + key, reported)
                   for key in ('w_vc', 'target_error')})
    require(pqsr['w'] <= pqsr['t'] and pqsr['kappa_rrbr'] <= 1
            and 0 < pqsr['target_error'] <= 1, 'PQSR query mass or probability domain invalid')
    length = merkle['ell_max']
    require(merkle['w_vc'] <= merkle['t'] and 0 < merkle['target_error'] <= 1
            and length & (length - 1) == 0 and merkle['n'] <= merkle['k']
            and merkle['q_s'] <= merkle['k'] * length, 'Merkle lengths, query mass or probability domain invalid')
    return pqsr, merkle

retained_input = read('budget-hypothetical-input.json')
pqsr, merkle = parse_known_inputs(retained_input, reported=False)
require(parse_known_inputs(example['inputs'], reported=True) == (pqsr, merkle),
        'hypothetical report must preserve every exact retained illustrative input')
def exact_fraction(observed, expected, label):
    if expected is None:
        require(observed is None, label + ': expected an unavailable threshold')
        return
    require(type(observed) is dict
            and set(observed) == {'numerator', 'denominator'}
            and all(type(value) is str for value in observed.values())
            and observed == {'numerator': str(expected.numerator), 'denominator': str(expected.denominator)},
            label + ': derived fraction differs from independent arithmetic')

t, k, w = pqsr['t'], pqsr['k'], pqsr['w']
coefficient = 80 * (t + k + 1) * (w + k)
finite = Fraction((t + k + 1) * k, 1 << pqsr['r_min'])
rrbr = coefficient * pqsr['kappa_rrbr']
upper = rrbr + finite
expected_pqsr = {
    'rrbr_coefficient': coefficient,
    'finite_randomness_addend': finite,
    'rrbr_addend': rrbr,
    'conditional_upper_expression': upper,
}
observed_pqsr = example['pqsr_component']
require(type(observed_pqsr['unknown_inputs']) is list and observed_pqsr['unknown_inputs'] == [],
        'fully specified hypothetical PQSR inputs cannot remain unknown')
for key, value in expected_pqsr.items():
    exact_fraction(observed_pqsr[key], value, 'pqsr_component.' + key)
target = pqsr['target_error']
require(observed_pqsr['conditional_expression_meets_target'] is (upper <= target),
        'PQSR target comparison must be the exact boolean result')
analysis = observed_pqsr['target_analysis']
feasible = finite <= target
require(analysis['finite_randomness_addend_exceeds_target'] is (finite > target)
        and analysis['some_nonnegative_rrbr_bound_can_meet_target_by_this_expression'] is feasible,
        'PQSR finite-addend comparisons must be exact booleans')
required_rrbr = min(Fraction(1), (target - finite) / coefficient) if feasible else None
exact_fraction(analysis['kappa_rrbr_required_at_most'], required_rrbr, 'PQSR required RRBR threshold')

t, w_vc, length = merkle['t'], merkle['w_vc'], merkle['ell_max']
denominator = 1 << merkle['sigma']
expected_merkle = {
    'commutativity': Fraction(240 * (t + 1), denominator),
    'extraction_correctness': Fraction(8 * merkle['n'] * length, denominator),
    'offline_extractability': (160 * w_vc * t * t
        + 16 * merkle['q_s'] * (length.bit_length() - 1)) / denominator,
    'online_indistinguishability': 240 * w_vc * t * t / denominator,
}
observed_merkle = example['merkle_components']
require(type(observed_merkle['unknown_inputs']) is list and observed_merkle['unknown_inputs'] == [],
        'fully specified hypothetical Merkle inputs cannot remain unknown')
for key, value in expected_merkle.items():
    exact_fraction(observed_merkle['conditional_expressions'][key], value, 'Merkle component ' + key)
    require(observed_merkle['each_expression_meets_component_target'][key] is (value <= merkle['target_error']),
            'Merkle target comparison must be the exact boolean result: ' + key)
print('Complete unknown fields and independently recomputed hypothetical components verified; project qualification remains false.')
