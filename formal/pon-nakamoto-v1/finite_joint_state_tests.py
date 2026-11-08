"""Independent exact controls for FJS1; no hardware or physical-state claims."""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction as F
from itertools import combinations, product
import json
from math import comb
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import finite_joint_state_certificate as state


def matrix(rows):
    return tuple(tuple(F(x) for x in row) for row in rows)


def determinant(a):
    """Laplace expansion: independent of the production Schur algorithm."""
    if not a:
        return F(1)
    return sum(((-1) ** j * a[0][j]
                * determinant(tuple(tuple(row[k] for k in range(len(a)) if k != j)
                                    for row in a[1:]))
                for j in range(len(a))), F(0))


def all_principal_minors_nonnegative(a):
    return all(determinant(tuple(tuple(a[i][j] for j in subset) for i in subset)) >= 0
               for k in range(1, len(a) + 1) for subset in combinations(range(len(a)), k))


def trace_product(a, b):
    return sum((a[i][j] * b[j][i] for i in range(len(a)) for j in range(len(a))), F(0))


def partial_trace_second_qubit(rho):
    return tuple(tuple(sum((rho[2 * a + b][2 * c + b] for b in range(2)), F(0))
                       for c in range(2)) for a in range(2))


def build(*, addresses=2, p=F(1, 16), sigma=None, states=None, multiplier=F(1),
          allowance=F(0), excesses=None, registers=None, queries=0, outputs=1, required=1):
    """Independent test encoder; does not use the implementation's example factory."""
    if sigma is None:
        sigma = matrix([[1]])
    dimension = len(sigma)
    if states is None:
        states = [sigma] * (1 << addresses)
    zero = matrix([[0] * dimension for _ in range(dimension)])
    return state.wire({
        "schema": state.CERTIFICATE_SCHEMA,
        "oracle": {"law": state.ORACLE_LAW, "addresses": addresses, "mark_probability": p},
        "advice_registers": registers or [{"name": "all_advice", "dimension": dimension}],
        "reference_state": sigma, "multiplier": multiplier, "excess_allowance": allowance,
        "tables": [{"index": f, "probability": p ** f.bit_count()
                    * (1 - p) ** (addresses - f.bit_count()),
                    "advice_state": states[f],
                    "positive_excess": zero if excesses is None else excesses[f]}
                   for f in range(1 << addresses)],
        "search_contract": {"probability_scope": state.GLOBAL_SCOPE,
                            "oracle_query_interface": state.QUERY_INTERFACE,
                            "bit_queries": queries, "complete_outputs": outputs,
                            "required_distinct_marked": required},
    })


def fvalue(value):
    return F(value["numerator"], value["denominator"])


class ExactPsdTests(unittest.TestCase):
    def test_schur_matches_every_principal_minor_on_729_symmetric_matrices(self):
        for entries in product((-1, 0, 1), repeat=6):
            a, b, c, d, e, f = entries
            value = matrix([[a, b, c], [b, d, e], [c, e, f]])
            expected = all_principal_minors_nonnegative(value)
            try:
                rank = state.psd_rank(value)
                actual = True
                self.assertLessEqual(rank, 3)
            except state.StateCertificateError:
                actual = False
            self.assertEqual(actual, expected, entries)

    def test_singular_gram_matrices_have_exact_ranks(self):
        self.assertEqual(state.psd_rank(matrix([[0, 0], [0, 1]])), 1)
        self.assertEqual(state.psd_rank(matrix([[1, 1], [1, 1]])), 1)
        self.assertEqual(state.psd_rank(matrix([[0, 0], [0, 0]])), 0)
        self.assertEqual(state.psd_rank(matrix([[1, 1, 1], [1, 1, 1], [1, 1, 1]])), 1)
        vectors = ((F(1, 3), F(2, 7)), (F(3, 5), F(-4, 11)), (F(0), F(0)),
                   (F(1, 3), F(2, 7)), (F(-2, 3), F(-4, 7)))
        gram = tuple(tuple(sum((x * y for x, y in zip(left, right)), F(0))
                           for right in vectors) for left in vectors)
        self.assertEqual(state.psd_rank(gram), 2)

    def test_zero_diagonal_nonzero_row_is_refused_at_arbitrary_precision(self):
        for entry in (F(1), F(1, 10 ** 40), F(-1, 10 ** 40)):
            with self.assertRaisesRegex(state.StateCertificateError, "MATRIX_PSD$"):
                state.psd_rank(matrix([[0, entry], [entry, 1]]))

    def test_positive_diagonal_does_not_hide_negative_eigenvalue(self):
        with self.assertRaisesRegex(state.StateCertificateError, "MATRIX_PSD$"):
            state.psd_rank(matrix([[1, 2], [2, 1]]))

    def test_matrix_api_refuses_asymmetry_floats_and_shape(self):
        for invalid in (((F(1), F(1)), (F(0), F(1))), ((F(1),), (F(0), F(1))),
                        ((1.0,),), ((True,),), (), [[F(1)]]):
            with self.assertRaises(state.StateCertificateError):
                state.psd_rank(invalid)

    def test_exact_arithmetic_limit_is_an_explicit_refusal(self):
        with self.assertRaisesRegex(state.StateCertificateError, "EXACT_ARITHMETIC_CHECK_LIMIT"):
            state.psd_rank(((F(1 << (state.MAX_ARITHMETIC_BITS + 1)),),))


class JointStateTests(unittest.TestCase):
    def test_singular_oracle_independent_advice_has_exact_multiplier_one(self):
        plus = matrix([[F(1, 2), F(1, 2)], [F(1, 2), F(1, 2)]])
        report = state.verify_certificate(build(sigma=plus))
        self.assertEqual(fvalue(report["bound"]), F(1, 16))
        self.assertEqual(report["common_reference_state_rank"], 1)
        self.assertTrue(report["exact_domination_without_excess"])
        self.assertTrue(all(row["domination_slack_rank"] == 0
                            for row in report["checked_oracle_blocks"]))

    def test_same_receiver_marginal_does_not_certify_the_joint_oracle_advice_state(self):
        # Both Bell states give I/2 on the receiver; the helper qubit retains
        # exactly the correlation a reduced-state certificate would erase.
        bell_plus = matrix([[F(1, 2), 0, 0, F(1, 2)], [0, 0, 0, 0],
                            [0, 0, 0, 0], [F(1, 2), 0, 0, F(1, 2)]])
        bell_minus = matrix([[F(1, 2), 0, 0, F(-1, 2)], [0, 0, 0, 0],
                             [0, 0, 0, 0], [F(-1, 2), 0, 0, F(1, 2)]])
        marginal = matrix([[F(1, 2), 0], [0, F(1, 2)]])
        self.assertEqual(partial_trace_second_qubit(bell_plus), marginal)
        self.assertEqual(partial_trace_second_qubit(bell_minus), marginal)
        sigma = matrix([[F(1, 2), 0, 0, 0], [0, 0, 0, 0],
                        [0, 0, 0, 0], [0, 0, 0, F(1, 2)]])
        full = build(p=F(1, 2), sigma=sigma,
                     states=[bell_plus if f & 1 else bell_minus for f in range(4)],
                     registers=[{"name": "receiver", "dimension": 2},
                                {"name": "helper", "dimension": 2}])
        with self.assertRaisesRegex(state.StateCertificateError, "JOINT_STATE_DOMINATION_PSD"):
            state.verify_certificate(full)
        full["multiplier"] = state.wire(F(2))
        report = state.verify_certificate(full)
        self.assertEqual(fvalue(report["bound"]), F(3, 4))
        reduced = state.verify_certificate(build(p=F(1, 2), sigma=marginal))
        self.assertEqual(fvalue(reduced["bound"]), F(1, 2))
        self.assertFalse(reduced["actual_register_and_environment_coverage_attested"])
        # A global Bell measurement selects address 0 if f_0=1, else 1.
        measured = sum((F(1, 4) * ((f & 1) != 0 or (f & 2) != 0) for f in range(4)), F(0))
        self.assertEqual(measured, F(3, 4))
        self.assertGreater(measured, fvalue(reduced["bound"]))

    def test_coherent_off_diagonal_advice_is_not_a_classical_diagonal_check(self):
        plus = matrix([[F(1, 2), F(1, 2)], [F(1, 2), F(1, 2)]])
        minus = matrix([[F(1, 2), F(-1, 2)], [F(-1, 2), F(1, 2)]])
        sigma = matrix([[F(1, 2), 0], [0, F(1, 2)]])
        document = build(sigma=sigma, states=[plus if f & 1 else minus for f in range(4)])
        with self.assertRaisesRegex(state.StateCertificateError, "JOINT_STATE_DOMINATION_PSD"):
            state.verify_certificate(document)
        document["multiplier"] = state.wire(F(2))
        report = state.verify_certificate(document)
        probability = F(0)
        for row in document["tables"]:
            rho = matrix([[fvalue(x) for x in values] for values in row["advice_state"]])
            hit = (trace_product(plus, rho) * bool(row["index"] & 1)
                   + trace_product(minus, rho) * bool(row["index"] & 2))
            probability += fvalue(row["probability"]) * hit
        self.assertEqual(probability, F(31, 256))
        self.assertEqual(probability, fvalue(report["bound"]))

    def test_noisy_advice_yields_a_nonvacuous_bound_with_independent_born_replay(self):
        document = state.example_certificates()["noisy-first-winner"]
        report = state.verify_certificate(document)
        success = F(0)
        for row in document["tables"]:
            hit = sum((fvalue(row["advice_state"][i][i]) for i in range(4)
                       if row["index"] & (1 << i)), F(0))
            success += fvalue(row["probability"]) * hit
        self.assertEqual(success, F(43583, 524288))
        self.assertEqual(fvalue(report["bound"]), F(11, 128))
        self.assertLess(success, fvalue(report["bound"]))
        self.assertLess(fvalue(report["bound"]), F(1, 4))
        self.assertGreater(success, F(1, 16))

    def test_complete_truth_table_advice_reaches_the_oracle_existence_limit(self):
        document = state.example_certificates()["full-truth-table-advice"]
        report = state.verify_certificate(document)
        actual = sum((fvalue(row["probability"]) for row in document["tables"]
                      if row["index"] != 0), F(0))
        self.assertEqual(actual, 1 - F(15, 16) ** 4)
        self.assertEqual(actual, fvalue(report["bound"]))
        self.assertGreater(actual, F(1, 16))
        document["multiplier"] = state.wire(F(1))
        with self.assertRaisesRegex(state.StateCertificateError, "JOINT_STATE_DOMINATION_PSD"):
            state.verify_certificate(document)

    def test_positive_excess_pays_for_a_rare_state_outside_reference_support(self):
        document = state.example_certificates()["rare-positive-excess"]
        report = state.verify_certificate(document)
        self.assertEqual(fvalue(report["weighted_positive_excess_trace"]), F(15, 256))
        self.assertEqual(fvalue(report["bound"]), F(31, 256))
        self.assertFalse(report["exact_domination_without_excess"])
        actual = sum((fvalue(row["probability"])
                      for row in document["tables"] if row["index"]), F(0))
        self.assertEqual(actual, fvalue(report["bound"]))
        document["excess_allowance"] = state.wire(F(15, 256) - F(1, 1 << 100))
        with self.assertRaisesRegex(state.StateCertificateError, "POSITIVE_EXCESS_ALLOWANCE_EXCEEDED"):
            state.verify_certificate(document)

    def test_excess_cannot_cancel_its_trace_with_a_negative_direction(self):
        document = state.example_certificates()["rare-positive-excess"]
        document["tables"][2]["positive_excess"] = state.wire(matrix([[-1, 0], [0, 1]]))
        with self.assertRaisesRegex(state.StateCertificateError, "POSITIVE_EXCESS_PSD"):
            state.verify_certificate(document)

    def test_singular_reference_cannot_dominate_orthogonal_state_without_excess(self):
        document = build(sigma=matrix([[1, 0], [0, 0]]),
                         states=[matrix([[0, 0], [0, 1]])] * 4, multiplier=F(1000))
        with self.assertRaisesRegex(state.StateCertificateError, "JOINT_STATE_DOMINATION_PSD"):
            state.verify_certificate(document)

    def test_oracle_dependent_reference_state_has_no_accepted_encoding(self):
        document = build()
        document["tables"][0]["reference_state"] = document["reference_state"]
        with self.assertRaisesRegex(state.StateCertificateError, "ORACLE_TABLE_FIELDS"):
            state.verify_certificate(document)
        document = build()
        document["reference_state"] = {"0": document["reference_state"]}
        with self.assertRaisesRegex(state.StateCertificateError, "REFERENCE_STATE_SHAPE"):
            state.verify_certificate(document)


class CompleteModelTests(unittest.TestCase):
    def test_full_prior_is_checked_not_only_total_mass(self):
        document = build()
        epsilon = F(1, 512)
        document["tables"][0]["probability"] = state.wire(F(225, 256) - epsilon)
        document["tables"][1]["probability"] = state.wire(F(15, 256) + epsilon)
        self.assertEqual(sum((fvalue(row["probability"]) for row in document["tables"]), F(0)), 1)
        with self.assertRaisesRegex(state.StateCertificateError, "COMPLETE_BERNOULLI_PRIOR_MISMATCH"):
            state.verify_certificate(document)

    def test_missing_duplicate_reordered_and_boolean_table_indices_refuse(self):
        mutations = [lambda d: d["tables"].pop(),
                     lambda d: d["tables"].append(deepcopy(d["tables"][0])),
                     lambda d: d["tables"][1].__setitem__("index", 0),
                     lambda d: d["tables"].reverse(),
                     lambda d: d["tables"][0].__setitem__("index", False)]
        for mutation in mutations:
            document = build()
            mutation(document)
            with self.assertRaises(state.StateCertificateError):
                state.verify_certificate(document)

    def test_density_trace_and_matrix_shape_are_not_optional(self):
        for field in ("reference_state", "advice_state"):
            for value in (state.wire(matrix([[0]])), state.wire(matrix([[2]])),
                          state.wire(matrix([[-1]])), [[]], [[1.0]], [[True]],
                          [[{"numerator": 2, "denominator": 2}]]):
                document = build()
                target = document if field == "reference_state" else document["tables"][0]
                target[field] = value
                with self.assertRaises(state.StateCertificateError):
                    state.verify_certificate(document)

    def test_register_names_and_tensor_dimensions_are_explicit(self):
        for registers in ([], [{"name": "a", "dimension": True}],
                          [{"name": "a", "dimension": 2}],
                          [{"name": "a", "dimension": 1}, {"name": "a", "dimension": 1}],
                          [{"name": "a", "dimension": 16}, {"name": "b", "dimension": 16}],
                          [{"name": "a/b", "dimension": 1}]):
            document = build()
            document["advice_registers"] = registers
            with self.assertRaises(state.StateCertificateError):
                state.verify_certificate(document)

    def test_scalar_encodings_and_check_limits_refuse(self):
        mutations = [lambda d: d["oracle"].__setitem__("addresses", True),
                     lambda d: d["oracle"].__setitem__("addresses", 9),
                     lambda d: d["oracle"].__setitem__("mark_probability", state.wire(F(0))),
                     lambda d: d["oracle"].__setitem__("mark_probability", state.wire(F(1))),
                     lambda d: d.__setitem__("multiplier", state.wire(F(1, 2))),
                     lambda d: d.__setitem__("excess_allowance", state.wire(F(-1))),
                     lambda d: d.__setitem__("excess_allowance", state.wire(F(2))),
                     lambda d: d.__setitem__("multiplier", {"numerator": True, "denominator": 1}),
                     lambda d: d.__setitem__("multiplier", {"numerator": 1 << 256, "denominator": 1}),
                     lambda d: d.__setitem__("multiplier", {"numerator": 1, "denominator": 0}),
                     lambda d: d["search_contract"].__setitem__("bit_queries", -1),
                     lambda d: d["search_contract"].__setitem__("bit_queries", 4097),
                     lambda d: d["search_contract"].__setitem__("complete_outputs", 65),
                     lambda d: d["search_contract"].__setitem__("required_distinct_marked", True)]
        for mutation in mutations:
            document = build()
            mutation(document)
            with self.assertRaises(state.StateCertificateError):
                state.verify_certificate(document)

    def test_unknown_namespaces_and_physical_promotion_fields_refuse(self):
        mutations = [lambda d: d.__setitem__("schema", "pon-finite-cq-initial-state-certificate-v2"),
                     lambda d: d.__setitem__("actual_initial_joint_state_attested", True),
                     lambda d: d["oracle"].__setitem__("law", "actual-sha256"),
                     lambda d: d["search_contract"].__setitem__("oracle_query_interface", "SHA256"),
                     lambda d: d["search_contract"].__setitem__("probability_scope", "conditional"),
                     lambda d: d["search_contract"].__setitem__("physical_gate_budget", 100)]
        for mutation in mutations:
            document = build()
            mutation(document)
            with self.assertRaises(state.StateCertificateError):
                state.verify_certificate(document)

    def test_all_physical_and_native_qualifications_remain_false(self):
        for document in state.example_certificates().values():
            report = state.verify_certificate(document)
            for name in state.UNATTESTED:
                self.assertIs(report[name], False)
            self.assertFalse(report["bound_is_conditional_at_selected_start"])
            self.assertFalse(report["oracle_independence_of_actual_advice_claimed"])


class SearchBoundTests(unittest.TestCase):
    def test_zero_query_list_bound_equals_full_finite_law(self):
        p = F(1, 16)
        for addresses in range(1, 6):
            for outputs in range(0, addresses + 2):
                for required in range(0, addresses + 2):
                    slots = min(addresses, outputs)
                    exact = sum((p ** f.bit_count() * (1 - p) ** (addresses - f.bit_count())
                                 for f in range(1 << addresses)
                                 if (f & ((1 << slots) - 1)).bit_count() >= required), F(0))
                    result = state.independent_search_bound(addresses=addresses, p=p,
                        queries=0, outputs=outputs, required=required)
                    self.assertEqual(result["bound"], exact)

    def test_recording_branch_uses_bit_query_cap_and_has_no_virtual_checks(self):
        report = state.verify_certificate(build(addresses=8, p=F(1, 1024),
                                                queries=1, outputs=2, required=2))
        base = report["independent_reference_search_bound"]
        # Independent explicit N=1,k=2 evaluation of the rational triangle term.
        p = F(1, 1024)
        triangle = p ** 2 * (1 + 4 * (1 - p)) ** 2
        self.assertLessEqual(fvalue(base["bound"]), triangle)
        self.assertGreater(fvalue(base["bound"]), 0)
        self.assertLess(fvalue(base["bound"]), fvalue(base["oracle_existence_bound"]))
        self.assertEqual(base["bit_queries"], 1)
        self.assertEqual(base["virtual_verification_queries_added"], 0)
        self.assertEqual(base["oracle_query_interface"], state.QUERY_INTERFACE)
        self.assertFalse(report["actual_sha_or_poseidon_idealization_proved"])

    def test_impossible_output_event_stays_zero_with_positive_excess(self):
        document = state.example_certificates()["rare-positive-excess"]
        document["search_contract"]["complete_outputs"] = 0
        report = state.verify_certificate(document)
        self.assertGreater(fvalue(report["weighted_positive_excess_trace"]), 0)
        self.assertEqual(fvalue(report["bound"]), 0)
        document["search_contract"]["required_distinct_marked"] = 0
        self.assertEqual(fvalue(state.verify_certificate(document)["bound"]), 1)

    def test_more_required_distinct_marks_than_addresses_is_impossible(self):
        report = state.verify_certificate(build(addresses=2, outputs=4, required=3))
        self.assertEqual(fvalue(report["bound"]), 0)

    def test_selected_start_risk_cannot_be_reused_from_global_initial_state(self):
        document = state.example_certificates()["coherent-first-bit"]
        report = state.verify_certificate(document)
        # Conditioning on the plus outcome proves f_0=1; that event has p mass.
        probability_start = sum((fvalue(row["probability"]) for row in document["tables"]
                                 if row["index"] & 1), F(0))
        self.assertEqual(probability_start, F(1, 16))
        conditional_success = probability_start / probability_start
        self.assertGreater(conditional_success, fvalue(report["bound"]))
        document["search_contract"]["probability_scope"] = "conditional-on-plus-outcome"
        with self.assertRaisesRegex(state.StateCertificateError, "GLOBAL_SCOPE_REQUIRED"):
            state.verify_certificate(document)


class ReplayAndEvidenceTests(unittest.TestCase):
    def test_complete_report_recomputation_refuses_changed_bounds_hashes_and_flags(self):
        document = build()
        report = state.verify_certificate(document)
        self.assertEqual(state.recheck_report(document, json.loads(state.canonical(report))), report)
        mutations = [lambda r: r.__setitem__("bound", state.wire(F(0))),
                     lambda r: r.__setitem__("certificate_sha256", "0" * 64),
                     lambda r: r.__setitem__("production_qualified", True),
                     lambda r: r.pop("actual_initial_joint_state_attested"),
                     lambda r: r.__setitem__("oracle_tables_checked", 1),
                     lambda r: r.__setitem__("domination_with_positive_excess_verified_in_declared_model", 1),
                     lambda r: r["independent_reference_search_bound"].__setitem__("bit_queries", 3)]
        for mutation in mutations:
            changed = deepcopy(report)
            mutation(changed)
            with self.assertRaisesRegex(state.StateCertificateError, "REPORT_RECOMPUTATION_MISMATCH"):
                state.recheck_report(document, changed)

    def test_report_binds_the_full_certificate_and_detaches_nested_lists(self):
        document = build()
        report = state.verify_certificate(document)
        document["advice_registers"][0]["name"] = "different_advice"
        self.assertEqual(report["advice_registers"][0]["name"], "all_advice")
        with self.assertRaisesRegex(state.StateCertificateError, "REPORT_RECOMPUTATION_MISMATCH"):
            state.recheck_report(document, report)

    def test_strict_file_parser_refuses_duplicate_keys_nonfinite_and_bad_encoding(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "input.json"
            for encoded in (b'{"a":1,"a":2}', b'{"a": NaN}', b'\xff', b'{bad'):
                path.write_bytes(encoded)
                with self.assertRaises(state.StateCertificateError):
                    state.read_json(path)
            path.write_bytes(b'{"long": "value"}')
            with patch.object(state, "MAX_DOCUMENT_BYTES", 4):
                with self.assertRaisesRegex(state.StateCertificateError, "JSON_FILE"):
                    state.read_json(path)
            link = Path(raw) / "alias.json"
            link.symlink_to(path)
            with self.assertRaisesRegex(state.StateCertificateError, "JSON_FILE"):
                state.read_json(link)

    def test_cli_verifies_recomputes_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            document_path, report_path = base / "input.json", base / "report.json"
            document_path.write_bytes(state.canonical(build()))
            command = [sys.executable, str(Path(state.__file__).resolve()), "--certificate",
                       str(document_path), "--output", str(report_path)]
            run = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout), state.read_json(report_path))
            replay = subprocess.run(command[:4] + ["--report", str(report_path)],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            before = report_path.read_bytes()
            repeated = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(report_path.read_bytes(), before)

    def test_evidence_retains_complete_models_refusals_and_source_bindings(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw) / "attempt"
            summary = state.retain_evidence(directory)
            self.assertEqual(summary["result"], "PASS")
            self.assertEqual(len(summary["examples"]), 5)
            self.assertEqual(len(summary["negative_controls"]), 4)
            self.assertEqual(len(summary["source_bindings"]), 4)
            self.assertTrue(summary["source_files_equal_at_start_and_end"])
            self.assertFalse(summary["loaded_module_execution_attested"])
            self.assertEqual(state.read_json(directory / "source-bindings-start.json"),
                             summary["source_bindings"])
            self.assertEqual(state.read_json(directory / "source-bindings-end.json"),
                             summary["source_bindings"])
            self.assertFalse(summary["actual_quantum_hardware_executed"])
            self.assertFalse(summary["production_qualified"])
            for name in state.example_certificates():
                document = state.read_json(directory / (name + ".certificate.json"))
                report = state.read_json(directory / (name + ".report.json"))
                state.recheck_report(document, report)
            manifest = state.read_json(directory / "manifest.json")
            self.assertEqual(len(manifest["files"]), 17)
            with self.assertRaises(FileExistsError):
                state.retain_evidence(directory)

    def test_actual_source_file_change_between_endpoint_reads_retains_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            copied_sources = []
            for source in state._source_paths():
                copy = root / source.name
                copy.write_bytes(source.read_bytes())
                copied_sources.append(copy)
            original_examples = state.example_certificates

            def change_disk_bytes_then_generate():
                # Change real bytes in a private copy after the first hashes.
                # Neither the digest function nor its returned values is mocked.
                path = copied_sources[0]
                path.write_bytes(path.read_bytes() + b"\n# concurrent source change\n")
                return original_examples()

            directory = root / "source-change-attempt"
            with patch.object(state, "_source_paths", return_value=tuple(copied_sources)):
                with patch.object(state, "example_certificates", side_effect=change_disk_bytes_then_generate):
                    with self.assertRaisesRegex(state.StateCertificateError,
                                                "SOURCE_BINDINGS_CHANGED_DURING_EVIDENCE"):
                        state.retain_evidence(directory)
            before = state.read_json(directory / "source-bindings-start.json")
            after = state.read_json(directory / "source-bindings-end.json")
            self.assertNotEqual(before[0]["sha256"], after[0]["sha256"])
            self.assertEqual(before[1:], after[1:])
            failed = state.read_json(directory / "failed-attempt.json")
            self.assertEqual(failed["result"], "FAIL")
            self.assertEqual(failed["stage"], "source-bindings-end")
            self.assertEqual(failed["error"], "SOURCE_BINDINGS_CHANGED_DURING_EVIDENCE")
            self.assertFalse((directory / "summary.json").exists())
            self.assertFalse((directory / "manifest.json").exists())

    def test_failed_evidence_attempt_is_retained_without_pass_summary(self):
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw) / "failed"
            invalid = build()
            invalid["tables"].pop()
            with patch.object(state, "example_certificates", return_value={"bad-model": invalid}):
                with self.assertRaisesRegex(state.StateCertificateError, "COMPLETE_ORACLE_TABLE_COVERAGE"):
                    state.retain_evidence(directory)
            failure = state.read_json(directory / "failed-attempt.json")
            self.assertEqual(failure["result"], "FAIL")
            self.assertEqual(failure["stage"], "bad-model")
            self.assertTrue((directory / "bad-model.certificate.json").is_file())
            self.assertFalse((directory / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()
