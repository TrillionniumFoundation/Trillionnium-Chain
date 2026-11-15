"""Independent adversarial controls for declared lifetime-budget arithmetic.

The fixtures below are invented probability models, not Trillionnium security
estimates. A theorem label, exact arithmetic, or a successful test never turns
one of these fixtures into an actual PQ128 claim.
"""
from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pq_lifetime_budget as budget
import pq_lifetime_current_v2 as current_budget


EVENTS = ('signature', 'commitment', 'proof', 'ledger', 'transport', 'recovery',
          'release', 'application')
COVERAGE = ['online', 'offline', 'preprocessing', 'failed', 'unpublished',
            'recursive', 'shared-primitive']
SOURCE = 'test-input/declared-boundary.txt'
MANIFEST = 'config/pon/pq128-lifetime-budget-v1.json'
SOURCE_LOCK = 'config/pon/pq128-source-lock-v1.json'
TARGET = Fraction(1, 1 << 128)


def ratio(value):
    value = Fraction(value)
    return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}


def decode(value):
    return Fraction(int(value['numerator']), int(value['denominator']))


def example():
    """The user's eight-class arithmetic example, with unproved hypotheses."""
    experiment = {
        'id': 'synthetic-adaptive-game',
        'profile': 'synthetic-profile-with-no-crypto-qualification',
        'model': 'quantum-adaptive-lifetime',
        'horizon': 'One explicitly bounded synthetic lifetime',
        'source_revision': 'illustrative',
    }
    return {
        'schema': 'trnm-pq128-lifetime-budget-v1',
        'purpose': 'arithmetic-example',
        'target_bits': 128,
        'experiment': experiment,
        'assumptions': [{
            'id': 'external-resource-assumption',
            'statement': 'The full coalition, including retained advice, is externally bounded; no node log establishes this.',
            'status': 'assumed',
        }],
        'primitives': [{
            'id': 'same-public-oracle',
            'construction': 'synthetic-public-oracle',
            'public_parameter_id': 'one-fixed-public-instance',
            'fixed_across_epochs': True,
            'reset_at_epoch': False,
            'query_budget': {
                'basis': 'external-adversary-assumption',
                'maximum': str(1 << 64),
                'coverage': list(COVERAGE),
                'assumption_id': 'external-resource-assumption',
            },
        }],
        'events': [{
            'id': name,
            'definition': 'Synthetic bad event for ' + name + '; no project probability is asserted.',
            'source_paths': [SOURCE],
            'allocation': ratio(Fraction(1, 1 << 131)),
        } for name in EVENTS],
        'terms': [{
            'id': name + '-term',
            'covers': [name],
            'experiment_id': experiment['id'],
            'profile': experiment['profile'],
            'model': experiment['model'],
            'status': 'illustrative',
            'bound': ratio(Fraction(1, 1 << 163)),
            'scope': 'per-invocation',
            'opportunities': {
                'maximum': str(1 << 32),
                'cap_kind': 'almost-sure',
                'conditioning': 'uniform-adaptive-history',
            },
            'theorem': {
                'reference': 'Synthetic hypothesis, not a proved project theorem',
                'locator': 'Test fixture only',
                'applicability': 'Assume the bound uniformly over every reachable adaptive history and legal quantum side information; applicability is unproved.',
            },
            'loss_ids': [name + '-synthetic-loss'],
            'primitive_ids': ['same-public-oracle'],
            'assumption_ids': ['external-resource-assumption'],
            'obligations': [],
        } for name in EVENTS],
    }


def lifetime_example():
    data = example()
    for term in data['terms']:
        term['scope'] = 'whole-lifetime'
        term['opportunities'] = None
        term['bound'] = ratio(Fraction(1, 1 << 131))
    return data


def make_unknown(term):
    term['status'] = 'unknown'
    term['bound'] = None
    term['theorem'] = None
    term['obligations'] = ['Prove the missing reduction and its concrete constants.']


class ContractCase(unittest.TestCase):
    def refused(self, data):
        with self.assertRaises(budget.BudgetError):
            budget.evaluate(data)

    def remains_unqualified(self, report):
        self.assertEqual(report['status'], 'HOLD')
        self.assertIsNone(report['actual_lifetime_failure_bound'])
        for field in ('whole_chain_pq_qualified', 'pq_128_qualified',
                      'production_activation', 'composition_coverage_proved',
                      'theorem_applicability_verified'):
            self.assertIs(report[field], False, field)
        self.assertTrue(all(row['proof_verified'] is False for row in report['term_results']))


class ExactArithmeticTests(ContractCase):
    def test_eight_class_example_is_exact_and_never_an_attestation(self):
        report = budget.evaluate(example())
        self.assertEqual(decode(report['allocated_sum']), TARGET)
        self.assertEqual(decode(report['partial_arithmetic_sum']), TARGET)
        self.assertEqual(decode(report['model_arithmetic_sum']), TARGET)
        self.assertIs(report['target_met_under_declared_bounds'], True)
        for term in report['term_results']:
            self.assertEqual(decode(term['declared_lifetime_term']), Fraction(1, 1 << 131))
            self.assertEqual(term['multiplier'], str(1 << 32))
        self.remains_unqualified(report)

    def test_single_invocation_128_bit_label_leaves_only_93_in_example(self):
        data = example()
        for term in data['terms']:
            term['bound'] = ratio(TARGET)
        report = budget.evaluate(data)
        self.assertEqual(decode(report['model_arithmetic_sum']), Fraction(1, 1 << 93))
        self.assertIs(report['target_met_under_declared_bounds'], False)
        self.remains_unqualified(report)

    def test_positive_increment_beyond_boundary_has_no_float_tolerance(self):
        data = lifetime_example()
        increment = Fraction(1, 1 << 512)
        data['terms'][0]['bound'] = ratio(Fraction(1, 1 << 131) + increment)
        report = budget.evaluate(data)
        self.assertEqual(decode(report['model_arithmetic_sum']), TARGET + increment)
        self.assertIs(report['target_met_under_declared_bounds'], False)
        self.assertIs(report['term_results'][0]['within_allocation'], False)

    def test_allocations_cannot_exceed_target_even_by_tiny_fraction(self):
        data = example()
        data['events'][0]['allocation'] = ratio(Fraction(1, 1 << 131) + Fraction(1, 1 << 512))
        self.refused(data)

    def test_union_works_for_correlated_and_disjoint_finite_events(self):
        data = lifetime_example()
        for term in data['terms']:
            term['bound'] = ratio(Fraction(1, 16))
        report = budget.evaluate(data)
        declared_sum = decode(report['model_arithmetic_sum'])
        correlated = [{0} for _ in EVENTS]
        disjoint = [{i} for i in range(len(EVENTS))]
        correlated_actual = Fraction(len(set().union(*correlated)), 16)
        disjoint_actual = Fraction(len(set().union(*disjoint)), 16)
        self.assertEqual(declared_sum, disjoint_actual)
        self.assertLessEqual(correlated_actual, declared_sum)
        self.assertGreater(correlated_actual, Fraction(1, 16) ** len(EVENTS))
        self.remains_unqualified(report)

    def test_zero_declared_error_does_not_verify_the_theorem(self):
        data = lifetime_example()
        for term in data['terms']:
            term['bound'] = ratio(0)
            term['status'] = 'declared-model-bound'
            term['theorem']['reference'] = 'A caller can type an arbitrary theorem title'
        report = budget.evaluate(data)
        self.assertEqual(decode(report['model_arithmetic_sum']), 0)
        self.assertIs(report['target_met_under_declared_bounds'], True)
        self.remains_unqualified(report)


class ProbabilityScopeTests(ContractCase):
    def test_marginal_event_bound_fails_after_adaptive_event_selection(self):
        # Public history reveals Z, uniform on 16 values, then chooses E_Z.
        # Each fixed E_i has mass 1/16; the adaptively selected event is certain.
        fixed_marginal = Fraction(1, 16)
        chosen_actual = Fraction(sum(z == z for z in range(16)), 16)
        self.assertEqual(chosen_actual, 1)
        self.assertGreater(chosen_actual, fixed_marginal)
        data = example()
        data['terms'][0]['opportunities']['conditioning'] = 'fixed-event-marginal'
        self.refused(data)

    def test_first_bad_joint_interface_is_a_declared_alternative(self):
        data = example()
        for term in data['terms']:
            term['opportunities']['conditioning'] = 'first-bad-joint'
        report = budget.evaluate(data)
        self.assertEqual(decode(report['model_arithmetic_sum']), TARGET)
        self.remains_unqualified(report)

    def test_expected_or_observed_count_is_not_an_almost_sure_cap(self):
        for cap_kind in ('expected', 'observed', 'node-log', 'mean-over-runs'):
            with self.subTest(cap_kind=cap_kind):
                data = example()
                data['terms'][0]['opportunities']['cap_kind'] = cap_kind
                self.refused(data)

    def test_whole_lifetime_and_multi_instance_terms_are_not_multiplied_again(self):
        for scope in ('whole-lifetime', 'multi-instance'):
            with self.subTest(scope=scope):
                data = lifetime_example()
                data['terms'][0]['scope'] = scope
                report = budget.evaluate(data)
                self.assertEqual(decode(report['model_arithmetic_sum']), TARGET)
                self.assertEqual(report['term_results'][0]['multiplier'], '1')
                data['terms'][0]['opportunities'] = deepcopy(example()['terms'][0]['opportunities'])
                self.refused(data)

    def test_joint_theorem_is_counted_once_with_all_covered_allocations(self):
        data = lifetime_example()
        first, second = data['terms'][:2]
        first['covers'].extend(second['covers'])
        first['bound'] = ratio(Fraction(2, 1 << 131))
        first['loss_ids'] = ['one-joint-theorem-with-shared-model-replacement']
        del data['terms'][1]
        report = budget.evaluate(data)
        self.assertEqual(len(report['term_results']), 7)
        self.assertEqual(decode(report['model_arithmetic_sum']), TARGET)
        self.assertEqual(decode(report['term_results'][0]['allocation']), Fraction(2, 1 << 131))

    def test_duplicate_event_or_model_replacement_loss_is_ambiguous(self):
        data = lifetime_example()
        data['terms'][1]['covers'].append(EVENTS[0])
        self.refused(data)
        data = lifetime_example()
        data['terms'][1]['loss_ids'] = list(data['terms'][0]['loss_ids'])
        self.refused(data)

    def test_external_model_profile_and_experiment_mismatches_are_refused(self):
        for key, incompatible in (
                ('model', 'classical-ROM'),
                ('profile', 'different-field-extension-FRI-and-recursive-backend'),
                ('experiment_id', 'fresh-instance-game-without-preprocessing')):
            with self.subTest(key=key):
                data = example()
                data['terms'][0][key] = incompatible
                self.refused(data)
        data = example()
        data['experiment']['model'] = 'classical-ROM'
        for term in data['terms']:
            term['model'] = 'classical-ROM'
        self.refused(data)


class UnknownAndQualificationTests(ContractCase):
    def test_unknown_term_is_not_zero_and_partial_sum_is_not_a_global_bound(self):
        data = example()
        make_unknown(data['terms'][0])
        report = budget.evaluate(data)
        self.assertEqual(decode(report['partial_arithmetic_sum']), Fraction(7, 1 << 131))
        self.assertIsNone(report['model_arithmetic_sum'])
        self.assertIsNone(report['target_met_under_declared_bounds'])
        self.assertEqual(report['unknown_terms'], ['signature-term'])
        self.assertIsNone(report['term_results'][0]['declared_lifetime_term'])
        self.remains_unqualified(report)

    def test_unknown_cannot_smuggle_numeric_error_or_missing_obligations(self):
        for key, invalid in (('bound', ratio(0)), ('theorem', example()['terms'][0]['theorem']),
                             ('obligations', [])):
            with self.subTest(key=key):
                data = example()
                make_unknown(data['terms'][0])
                data['terms'][0][key] = invalid
                self.refused(data)

    def test_known_term_requires_numeric_bound_and_theorem_declaration(self):
        for key in ('bound', 'theorem'):
            with self.subTest(key=key):
                data = example()
                data['terms'][0][key] = None
                self.refused(data)

    def test_missing_event_or_term_does_not_improve_the_budget(self):
        for key in ('events', 'terms'):
            with self.subTest(key=key):
                data = example()
                del data[key][0]
                self.refused(data)

    def test_illustrative_terms_cannot_be_laundered_into_research_mode(self):
        data = example()
        # A syntactically valid ID is still a synthetic, unverified declaration.
        data['experiment']['source_revision'] = 'a' * 40
        data['purpose'] = 'research-model'
        self.refused(data)
        for term in data['terms']:
            term['status'] = 'declared-model-bound'
        self.remains_unqualified(budget.evaluate(data))

    def test_arbitrary_self_certification_fields_or_statuses_are_refused(self):
        for field, value in (
                ('pq_128_qualified', True), ('whole_chain_pq_qualified', True),
                ('actual_lifetime_failure_bound', ratio(TARGET)),
                ('theorems_verified', True), ('composition_coverage_proved', True),
                ('assumptions_accepted', True)):
            with self.subTest(field=field):
                data = example()
                data[field] = value
                self.refused(data)
        for status in ('verified', 'independently-certified', 'PQ128'):
            with self.subTest(status=status):
                data = example()
                data['terms'][0]['status'] = status
                self.refused(data)

    def test_unmodeled_implementation_and_custodian_risks_get_no_probability(self):
        for statement in ('All implementations satisfy their specification.',
                          'Independent custodians never all lose their keys.'):
            with self.subTest(statement=statement):
                data = example()
                data['assumptions'].append({'id': 'unmodeled-risk', 'statement': statement,
                                            'status': 'unmet'})
                report = budget.evaluate(data)
                self.assertIs(report['all_declared_assumptions_assumed'], False)
                self.remains_unqualified(report)
                data['assumptions'][-1]['probability'] = ratio(Fraction(1, 1 << 200))
                self.refused(data)

    def test_security_strength_or_asymptotic_labels_do_not_certify_probability(self):
        data = example()
        data['terms'][0]['bound'] = {'security_bits': 128}
        self.refused(data)
        data = example()
        data['terms'][0]['theorem']['reference'] = 'O(poly(q) * 2^(-n/4)); constants are not instantiated'
        # Free-form references are not machine-checked theorems. Even when
        # arithmetic is possible, no applicability or actual bound is certified.
        report = budget.evaluate(data)
        self.remains_unqualified(report)


class LifetimeResourceTests(ContractCase):
    def test_node_observations_cannot_bound_offline_quantum_queries(self):
        for basis in ('native-node-log', 'observed-count', 'protocol-enforced-cap',
                      'signed-query-receipts'):
            with self.subTest(basis=basis):
                data = example()
                data['primitives'][0]['query_budget']['basis'] = basis
                self.refused(data)

    def test_every_lifetime_channel_is_required_including_failures_and_private_search(self):
        for channel in COVERAGE:
            with self.subTest(channel=channel):
                data = example()
                data['primitives'][0]['query_budget']['coverage'].remove(channel)
                self.refused(data)

    def test_unknown_query_cap_stays_unknown_without_default_zero(self):
        data = example()
        query = data['primitives'][0]['query_budget']
        query.update(basis='unknown', maximum=None, assumption_id=None)
        report = budget.evaluate(data)
        self.assertEqual(report['unknown_query_budgets'], ['same-public-oracle'])
        self.remains_unqualified(report)
        query['maximum'] = '0'
        self.refused(data)

    def test_external_query_cap_needs_explicit_known_assumption(self):
        for reference in (None, 'nonexistent-assumption', [], {}):
            with self.subTest(reference=reference):
                data = example()
                data['primitives'][0]['query_budget']['assumption_id'] = reference
                self.refused(data)

    def test_key_epoch_or_domain_change_cannot_reset_fixed_public_primitive(self):
        for key, invalid in (('reset_at_epoch', True), ('fixed_across_epochs', False),
                             ('reset_at_epoch', 0), ('fixed_across_epochs', 1)):
            with self.subTest(key=key, invalid=invalid):
                data = example()
                data['primitives'][0][key] = invalid
                self.refused(data)

    def test_same_public_primitive_cannot_be_split_into_two_budget_identities(self):
        data = example()
        second = deepcopy(data['primitives'][0])
        second['id'] = 'new-epoch-same-oracle'
        data['primitives'].append(second)
        self.refused(data)

    def test_unknown_primitive_and_assumption_references_are_refused(self):
        for field in ('primitive_ids', 'assumption_ids'):
            with self.subTest(field=field):
                data = example()
                data['terms'][0][field] = ['missing-resource']
                self.refused(data)


class StrictInputTests(ContractCase):
    def test_probabilities_require_canonical_exact_decimal_strings(self):
        invalids = (True, False, 1, 0.0, '-1', '+1', '01', '1e-163', ' 1', '1 ',
                    '', 'NaN', 'Infinity', '9' * 1234)
        for value in invalids:
            with self.subTest(value=str(value)[:40]):
                data = example()
                data['terms'][0]['bound']['numerator'] = value
                self.refused(data)

    def test_probability_range_and_zero_denominator_are_refused(self):
        for invalid in ({'numerator': '1', 'denominator': '0'},
                        {'numerator': '2', 'denominator': '1'},
                        {'numerator': '-1', 'denominator': '1'}):
            with self.subTest(invalid=invalid):
                data = example()
                data['terms'][0]['bound'] = invalid
                self.refused(data)

    def test_opportunity_caps_cannot_use_zero_float_bool_or_unbounded_integer(self):
        for invalid in ('0', True, 1.0, '-1', '1e32', '9' * 1234):
            with self.subTest(invalid=str(invalid)[:40]):
                data = example()
                data['terms'][0]['opportunities']['maximum'] = invalid
                self.refused(data)

    def test_duplicate_ids_do_not_silently_replace_prior_entries(self):
        for key in ('assumptions', 'primitives', 'events', 'terms'):
            with self.subTest(key=key):
                data = example()
                data[key].append(deepcopy(data[key][0]))
                self.refused(data)

    def test_strict_json_rejects_duplicates_floats_nonfinite_and_wrong_roots(self):
        for raw in (
                '{"schema":"a","schema":"b"}',
                '{"bound":{"numerator":"1","numerator":"0"}}',
                '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}',
                '{"x":0.0}', '{"x":1e-163}', '{"x":1000000000000000000}',
                '[]', 'null', '"object"', b'\xff'):
            with self.subTest(raw=raw):
                with self.assertRaises(budget.BudgetError):
                    budget.strict_json(raw)

    def test_strict_json_rejects_unencodable_text_and_oversized_input_cleanly(self):
        for raw in ('{"x":"\ud800"}', ' ' * (1024 * 1024 + 1)):
            with self.subTest(kind='unicode' if '\ud800' in raw else 'oversized'):
                with self.assertRaises(budget.BudgetError):
                    budget.strict_json(raw)

    def test_unsafe_source_paths_do_not_become_evidence(self):
        for path in ('../other.json', '/absolute.json', 'a//b', 'a/./b', 'a\\b'):
            with self.subTest(path=path):
                data = example()
                data['events'][0]['source_paths'] = [path]
                self.refused(data)

    def test_revision_aliases_and_illustrative_research_identity_are_refused(self):
        for invalid in ('main', 'HEAD', '12e510b', 'A' * 40, 'g' * 40, '0' * 64):
            with self.subTest(revision=invalid):
                data = example()
                data['experiment']['source_revision'] = invalid
                self.refused(data)
        data = example()
        data['purpose'] = 'research-model'
        for term in data['terms']:
            term['status'] = 'declared-model-bound'
        self.refused(data)  # The illustrative identity is not a source revision.


class ArithmeticResourceLimitTests(ContractCase):
    def test_exact_4096_bit_denominator_is_retained_without_rounding(self):
        data = lifetime_example()
        for term in data['terms']:
            term['bound'] = ratio(0)
        expected = Fraction(1, 1 << 4095)
        data['terms'][0]['bound'] = ratio(expected)
        report = budget.evaluate(data)
        actual = decode(report['model_arithmetic_sum'])
        self.assertEqual(actual, expected)
        self.assertEqual(actual.denominator.bit_length(), 4096)
        self.remains_unqualified(report)

    def test_coprime_denominator_growth_is_refused_not_rounded_down(self):
        data = lifetime_example()
        for term in data['terms']:
            term['bound'] = ratio(0)
        # Each input fits the contract. Their coprime denominator product does
        # not, although the sum is far below the target. No float may erase it.
        left, right = (1 << 2200) - 1, (1 << 2200) + 1
        expected = Fraction(1, left) + Fraction(1, right)
        self.assertGreater(expected.denominator.bit_length(), 4096)
        self.assertLess(expected, TARGET)
        data['terms'][0]['bound'] = ratio(Fraction(1, left))
        data['terms'][1]['bound'] = ratio(Fraction(1, right))
        with self.assertRaisesRegex(budget.BudgetError, 'exact arithmetic limit'):
            budget.evaluate(data)

    def test_multiplication_cannot_overflow_the_exact_result_contract(self):
        data = example()
        numerator, denominator = (1 << 2200) - 1, 1 << 2200
        multiplier = (1 << 2200) + 1
        expected = Fraction(numerator, denominator) * multiplier
        self.assertGreater(expected.numerator.bit_length(), 4096)
        data['terms'][0]['bound'] = ratio(Fraction(numerator, denominator))
        data['terms'][0]['opportunities']['maximum'] = str(multiplier)
        with self.assertRaisesRegex(budget.BudgetError, 'exact arithmetic limit'):
            budget.evaluate(data)


class CheckedInContractTests(ContractCase):
    root = Path(__file__).resolve().parents[2]

    def test_default_research_register_contains_no_known_security_bound(self):
        self.assertEqual(budget.DEFAULT_MANIFEST, MANIFEST)
        self.assertEqual(budget.DEFAULT_SOURCE_LOCK, SOURCE_LOCK)
        data = budget.strict_json((self.root / MANIFEST).read_bytes())
        self.assertEqual(data['purpose'], 'research-model')
        self.assertEqual(len(data['terms']), 8)
        self.assertTrue(all(term['status'] == 'unknown' and term['bound'] is None
                            and term['theorem'] is None for term in data['terms']))
        self.assertTrue(data['assumptions'])
        self.assertTrue(all(row['status'] == 'unmet' for row in data['assumptions']))
        current = current_budget.inspect(self.root)
        report = current['frozen_model']
        self.assertEqual(len(report['unknown_terms']), 8)
        self.assertEqual(len(report['unknown_query_budgets']), 4)
        self.assertIsNone(report['model_arithmetic_sum'])
        self.assertIsNone(report['target_met_under_declared_bounds'])
        self.assertIs(report['source_revision_bound'], False)
        self.assertEqual(report['source_binding_scope'], 'unbound')
        self.assertIsNone(report['source_lock_sha256'])
        self.assertEqual(current['frozen_model_identity']['source_lock_sha256'],
                         hashlib.sha256((self.root / SOURCE_LOCK).read_bytes()).hexdigest())
        correspondence = current['current_source_correspondence']
        self.assertIs(correspondence['source_files_checked'], True)
        self.assertIs(correspondence['source_revision_bound'], False)
        self.assertEqual(correspondence['source_binding_scope'], 'declared-event-paths-only')
        self.assertEqual(set(correspondence['source_files_sha256']), set(report['source_paths']))
        self.assertEqual(len(correspondence['source_files_sha256']), 21)
        self.remains_unqualified(report)
        self.assertEqual(current['status'], 'HOLD')
        self.assertIsNone(current['actual_lifetime_failure_bound'])
        for field in ('whole_chain_pq_qualified', 'pq_128_qualified',
                      'production_activation', 'composition_coverage_proved',
                      'theorem_applicability_verified'):
            self.assertIs(current[field], False, field)

    def test_checked_in_example_reproduces_only_the_illustrative_equality(self):
        example_path = 'config/pon/pq128-lifetime-example-v1.json'
        data = budget.strict_json((self.root / example_path).read_bytes())
        self.assertEqual(data['purpose'], 'arithmetic-example')
        self.assertEqual(data['experiment']['source_revision'], 'illustrative')
        self.assertTrue(all(term['status'] == 'illustrative' for term in data['terms']))
        report = budget.inspect(self.root, example_path)
        self.assertEqual(decode(report['model_arithmetic_sum']), TARGET)
        self.assertIs(report['target_met_under_declared_bounds'], True)
        self.assertIs(report['source_revision_bound'], False)
        self.assertEqual(report['source_binding_scope'], 'unbound')
        self.assertIsNone(report['source_lock_sha256'])
        self.remains_unqualified(report)


class SourceAndCliTests(ContractCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / SOURCE
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b'Synthetic boundary; not project security evidence.\n')
        self.path = self.root / MANIFEST
        self.path.parent.mkdir(parents=True)
        self.write(example())

    def write(self, data):
        self.path.write_text(json.dumps(data), encoding='utf-8')

    def run_cli(self):
        return subprocess.run([sys.executable, str(Path(budget.__file__).resolve()),
                               '--root', str(self.root)], capture_output=True,
                              text=True, timeout=10, check=False)

    def test_inspection_hashes_actual_input_without_certifying_it(self):
        report = budget.inspect(self.root)
        self.assertEqual(report['manifest_sha256'], hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(report['source_files_sha256'],
                         {SOURCE: hashlib.sha256(self.source.read_bytes()).hexdigest()})
        self.remains_unqualified(report)

    def test_missing_or_symlinked_source_is_refused(self):
        self.source.unlink()
        with self.assertRaises(budget.BudgetError):
            budget.inspect(self.root)
        elsewhere = self.root / 'elsewhere.txt'
        elsewhere.write_bytes(b'Unrelated source')
        self.source.symlink_to(elsewhere)
        with self.assertRaises(budget.BudgetError):
            budget.inspect(self.root)

    def test_valid_cli_returns_hold_not_pq_success(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.remains_unqualified(json.loads(result.stdout))

    def test_malformed_reference_cli_returns_structured_refusal_not_traceback(self):
        data = example()
        data['primitives'][0]['query_budget']['assumption_id'] = []
        self.write(data)
        result = self.run_cli()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(json.loads(result.stderr)['status'], 'REFUSE')


class ReviewedSourceLockTests(ContractCase):
    """A reviewed file map binds declared paths, not cryptographic provenance."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / SOURCE
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b'Synthetic owner bytes, not a project implementation.\n')
        self.manifest = self.root / MANIFEST
        self.manifest.parent.mkdir(parents=True)
        self.data = example()
        self.data['purpose'] = 'research-model'
        self.data['experiment']['source_revision'] = 'a' * 40
        for term in self.data['terms']:
            make_unknown(term)
        self.manifest.write_text(json.dumps(self.data), encoding='utf-8')
        self.lock_path = self.root / SOURCE_LOCK
        self.lock = {
            'schema': 'trnm-pq128-source-lock-v1',
            'source_revision': self.data['experiment']['source_revision'],
            'files': {SOURCE: hashlib.sha256(self.source.read_bytes()).hexdigest()},
        }
        self.write_lock()

    def write_lock(self):
        self.lock_path.write_text(json.dumps(self.lock), encoding='utf-8')

    def refuses_inspection(self):
        with self.assertRaises(budget.BudgetError):
            budget.inspect(self.root)

    def test_matching_lock_needs_no_git_history_and_still_grants_no_security_claim(self):
        self.assertFalse((self.root / '.git').exists())
        report = budget.inspect(self.root)
        self.assertIs(report['source_revision_bound'], True)
        self.assertEqual(report['source_binding_scope'], 'declared-event-paths-only')
        self.assertEqual(report['source_lock_sha256'],
                         hashlib.sha256(self.lock_path.read_bytes()).hexdigest())
        self.remains_unqualified(report)

    def test_changed_actual_source_cannot_keep_the_declared_revision_binding(self):
        self.source.write_bytes(b'Changed owner bytes under the old revision declaration.\n')
        self.refuses_inspection()

    def test_manifest_revision_swap_does_not_relabel_locked_bytes(self):
        self.data['experiment']['source_revision'] = 'b' * 40
        self.manifest.write_text(json.dumps(self.data), encoding='utf-8')
        self.refuses_inspection()

    def test_lock_revision_swap_cannot_relabel_the_manifest(self):
        self.lock['source_revision'] = 'b' * 40
        self.write_lock()
        self.refuses_inspection()

    def test_missing_lock_is_not_a_hash_only_fallback(self):
        self.lock_path.unlink()
        self.refuses_inspection()

    def test_omitted_and_extra_lock_paths_are_refused(self):
        original = deepcopy(self.lock)
        del self.lock['files'][SOURCE]
        self.write_lock()
        self.refuses_inspection()
        self.lock = original
        self.lock['files']['test-input/unrequested-owner.txt'] = '0' * 64
        self.write_lock()
        self.refuses_inspection()

    def test_duplicate_json_lock_fields_and_paths_are_refused(self):
        raw = json.dumps(self.lock)
        path_entry = json.dumps(SOURCE) + ': ' + json.dumps(self.lock['files'][SOURCE])
        for altered in (
                raw.replace('"schema":', '"schema":"trnm-pq128-source-lock-v1","schema":', 1),
                raw.replace(path_entry, path_entry + ', ' + path_entry, 1)):
            with self.subTest(raw=altered[:80]):
                self.lock_path.write_text(altered, encoding='utf-8')
                self.refuses_inspection()

    def test_lock_symlink_is_refused_even_when_target_bytes_match(self):
        other = self.root / 'copied-lock.json'
        other.write_bytes(self.lock_path.read_bytes())
        self.lock_path.unlink()
        self.lock_path.symlink_to(other)
        self.refuses_inspection()

    def test_source_symlink_is_refused_even_when_target_hash_matches(self):
        other = self.root / 'copied-source.txt'
        other.write_bytes(self.source.read_bytes())
        self.source.unlink()
        self.source.symlink_to(other)
        self.refuses_inspection()

    def test_oversize_source_lock_is_refused(self):
        self.lock_path.write_bytes(b' ' * (budget.MAX_BYTES + 1))
        self.refuses_inspection()

    def test_lock_schema_fields_and_digest_encoding_are_closed(self):
        original = deepcopy(self.lock)
        for key, value in (('schema', 'trnm-pq128-source-lock-v0'),
                           ('authenticated', True), ('files', [])):
            with self.subTest(field=key):
                self.lock = deepcopy(original)
                self.lock[key] = value
                self.write_lock()
                self.refuses_inspection()
        for value in ('0' * 40, 'A' * 64, 'g' * 64, True, None):
            with self.subTest(digest=value):
                self.lock = deepcopy(original)
                self.lock['files'][SOURCE] = value
                self.write_lock()
                self.refuses_inspection()

    def test_evaluate_without_file_inspection_is_unbound(self):
        report = budget.evaluate(self.data)
        self.assertIs(report['source_revision_bound'], False)
        self.assertEqual(report['source_binding_scope'], 'unbound')
        self.assertIsNone(report['source_lock_sha256'])
        self.remains_unqualified(report)

    def test_arithmetic_example_never_inherits_a_research_source_binding(self):
        for revision in ('illustrative', self.lock['source_revision']):
            with self.subTest(revision=revision):
                data = example()
                data['experiment']['source_revision'] = revision
                self.manifest.write_text(json.dumps(data), encoding='utf-8')
                report = budget.inspect(self.root)
                self.assertIs(report['source_revision_bound'], False)
                self.assertEqual(report['source_binding_scope'], 'unbound')
                self.assertIsNone(report['source_lock_sha256'])
                self.remains_unqualified(report)


if __name__ == '__main__':
    unittest.main()
