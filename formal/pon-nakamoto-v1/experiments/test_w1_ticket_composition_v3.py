"""Meaningful byte, chronology, exact conditional-law and selection controls."""
from collections import defaultdict
from fractions import Fraction
from itertools import permutations
from pathlib import Path
import hashlib
import struct
import sys
import unittest

import w1_ticket_composition_v3 as model
import w1_multi_instance_cost_v2 as geometry

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import contract_wire
import work_oracle


def header(task: bytes, nonce: int = 0) -> bytes:
    fields = {row["name"]: bytes([index + 1]) * 32 if row["type"] == "hash32" else index + 1
              for index, row in enumerate(contract_wire.SCHEMA["header"])}
    fields["work_task"] = task
    fields["target"] = bytes.fromhex("7f" + "ff" * 31)
    fields["nonce"] = nonce
    return contract_wire.header_encode(fields)


def task_blocks(a=None, b=None):
    a = (0,) * model.CELLS if a is None else a
    b = (0,) * model.CELLS if b is None else b
    return geometry.sha_blocks(geometry.pon_message(
        b"task", model.field_bytes(a), model.field_bytes(b)))


def scripted_noise(observer, c, label):
    words = []
    for counter in range(128):
        result = observer.open_path(geometry.sha_blocks(geometry.noise_message(c, label, counter)))
        words.extend(value for (value,) in struct.iter_unpack("<I", result.to_bytes(32, "big"))
                     if value < model.Q)
        if len(words) >= 512:
            return tuple(words[:512])
    raise AssertionError("script exceeded native noise counter cap")


class ByteAndArithmeticTests(unittest.TestCase):
    def test_universal_key_masks_have_explicit_constant_conflicts(self):
        patterns = model.key_patterns()
        conflicts = model.key_separation()
        self.assertIn(53, conflicts["noise_first"])
        self.assertIn(26, conflicts["noise_last"])
        self.assertIn(63, conflicts["noise_last"])
        self.assertEqual(patterns["noise_first"].values[53], 1)
        self.assertEqual(patterns["ticket_last"].values[53], 0)
        for c in (bytes(32), bytes(range(32)), b"\xff" * 32):
            for label in range(4):
                for counter in range(128):
                    first, last = geometry.sha_blocks(geometry.noise_message(c, label, counter))
                    self.assertTrue(patterns["noise_first"].contains(first))
                    self.assertTrue(patterns["noise_last"].contains(last))
            for t in (bytes(32), c, b"\xff" * 32):
                last = geometry.sha_blocks(geometry.pon_message(b"ticket", c, t))[1]
                self.assertTrue(patterns["ticket_last"].contains(last))
                self.assertFalse(patterns["noise_first"].contains(last))
                self.assertFalse(patterns["noise_last"].contains(last))

    def test_header_target_task_and_padding_are_exact(self):
        raw = header(bytes(range(32)), 2**64 - 1)
        blocks = geometry.sha_blocks(geometry.pon_message(b"challenge", raw))
        parsed = model.parse_header_blocks(blocks)
        self.assertEqual(parsed.encoded, raw)
        self.assertEqual(parsed.task, bytes(range(32)))
        self.assertEqual(parsed.target, 2**255 - 1)
        self.assertEqual(raw[278:310], parsed.task)
        self.assertEqual(raw[118:150], parsed.target.to_bytes(32, "big"))
        mutated = list(blocks)
        last = bytearray(mutated[-1])
        last[23] ^= 1
        mutated[-1] = bytes(last)
        self.assertIsNone(model.parse_header_blocks(tuple(mutated)))
        self.assertIsNone(model.parse_header_blocks(blocks[:-1]))

    def test_task_parser_binds_both_matrices_and_canonical_words(self):
        a = tuple(i % 17 for i in range(model.CELLS))
        b = tuple((3 * i) % 29 for i in range(model.CELLS))
        blocks = task_blocks(a, b)
        self.assertEqual(model.parse_task_blocks(blocks), (a, b))
        raw = bytearray(b"".join(blocks))
        raw[20:24] = model.Q.to_bytes(4, "little")
        self.assertIsNone(model.parse_task_blocks(tuple(bytes(raw[i:i + 64])
                                                       for i in range(0, len(raw), 64))))
        raw = bytearray(b"".join(blocks))
        raw[16] ^= 1
        self.assertIsNone(model.parse_task_blocks(tuple(bytes(raw[i:i + 64])
                                                       for i in range(0, len(raw), 64))))

    def test_trace_ticket_key_overlap_is_arithmetic_realizable_at_fixed_c(self):
        result = model.trace_key_overlap(bytes(range(32)))
        self.assertEqual(result["trace_blocks"][1], result["overlap_block"])
        self.assertTrue(model.key_patterns()["ticket_last"].contains(result["trace_blocks"][1]))
        self.assertEqual(len(result["prefixes"]), 32768)
        parsed = model.parse_trace_blocks(result["trace_blocks"])
        self.assertEqual(parsed, (result["challenge"], result["prefixes"]))
        # Independent scalar relation: this is not a header/task fixed-point search.
        product, trace = work_oracle.evaluate(result["challenge"], result["a"], result["b"])
        self.assertEqual(trace, result["trace_digest"])
        self.assertEqual(product, list(model.matrix_product(
            result["a"], result["b"], 64, 64, 64)))
        self.assertNotEqual(trace, bytes(32))  # overlapping key need not be its own ticket
        self.assertEqual(hashlib.sha256(b"".join(result["trace_blocks"])[:131120]).digest(), trace)


class ChronologyTests(unittest.TestCase):
    def test_full_c_d_t_order_and_canonical_marker_before_ticket_answer(self):
        observer = model.ChronologyControl()
        d = observer.open_path(task_blocks()).to_bytes(32, "big")
        h = header(d)
        c = observer.open_path(geometry.sha_blocks(
            geometry.pon_message(b"challenge", h))).to_bytes(32, "big")
        noise = tuple(scripted_noise(observer, c, label) for label in range(4))
        prefixes = model.canonical_prefixes((0,) * 4096, (0,) * 4096, noise)
        trace_blocks = geometry.sha_blocks(geometry.TRACE_DOMAIN + c + model.field_bytes(prefixes))
        t = observer.open_path(trace_blocks).to_bytes(32, "big")
        captured = model.seal_openings(observer, ((h, t),), maximum_openings=1)
        calls_at_seal = observer.calls
        first, last = geometry.sha_blocks(geometry.pon_message(b"ticket", c, t))
        intermediate = observer.scripted_forward(first, observer.root)
        self.assertEqual(captured.calls, calls_at_seal)
        self.assertEqual(len(captured.parents), len(observer.parents) - 1)
        before = model.extract_candidate(observer, c, t)
        self.assertIsNotNone(before)
        self.assertTrue(before.canonical(noise))
        prior_count = len(observer.table)
        answer = observer.scripted_forward(last, intermediate)
        self.assertFalse(observer.joined)
        self.assertEqual(observer.references[-1].kind, "trace")
        self.assertEqual(observer.references[-1].value, t)
        self.assertEqual(observer.references[-1].query, observer.calls)
        self.assertEqual(len(observer.table), prior_count + 1)
        self.assertEqual(observer.scripted_forward(last, intermediate), answer)
        self.assertEqual(len(observer.table), prior_count + 1)
        kinds = [reference.kind for reference in observer.references]
        self.assertIn("task", kinds)
        self.assertIn("challenge", kinds)
        self.assertIn("trace", kinds)

    def test_seal_registers_all_submissions_before_any_audit_call(self):
        observer = model.ChronologyControl()
        first_t = (1 << 200).to_bytes(32, "big")
        second_t = (1 << 220).to_bytes(32, "big")
        d = (1 << 210).to_bytes(32, "big")
        calls = observer.calls
        captured = model.seal_openings(
            observer, ((header(d, 0), first_t), (header(d, 1), second_t)),
            maximum_openings=2)
        self.assertEqual(observer.calls, calls)
        self.assertEqual(len(observer.references), 4)
        self.assertTrue(all(ref.query == calls for ref in observer.references))
        self.assertTrue({int.from_bytes(first_t, "big"), int.from_bytes(second_t, "big"),
                         int.from_bytes(d, "big")}.issubset(observer.protected))
        with self.assertRaises(TypeError):
            captured.parents[123] = (0, bytes(64))
        # An early audit which tries to create the SECOND opening's path cannot
        # evade its reference by waiting until that second opening is checked.
        observer.forward(b"\x66" * 64, observer.root, int.from_bytes(second_t, "big"))
        self.assertTrue(observer.joined)
        self.assertEqual(captured.entries, 0)

    def test_terminal_marker_rejects_uncaptured_auditor_path_even_without_join(self):
        observer = model.ChronologyControl()
        d = observer.open_path(task_blocks()).to_bytes(32, "big")
        h = header(d)
        c = observer.open_path(geometry.sha_blocks(
            geometry.pon_message(b"challenge", h))).to_bytes(32, "big")
        noise = tuple(scripted_noise(observer, c, label) for label in range(4))
        prefixes = model.canonical_prefixes((0,) * 4096, (0,) * 4096, noise)
        trace_blocks = geometry.sha_blocks(geometry.TRACE_DOMAIN + c + model.field_bytes(prefixes))
        # No new native claim is authorized by an empty sealed list. Completing
        # this diagnostic path later must not turn it into paid captured work.
        captured = model.seal_openings(observer, (), maximum_openings=0)
        captured_size = len(captured.parents)
        t = observer.open_path(trace_blocks).to_bytes(32, "big")
        self.assertFalse(observer.joined)
        self.assertEqual(observer.path_to(int.from_bytes(t, "big"), 2049), trace_blocks)
        self.assertEqual(model.parse_trace_blocks(trace_blocks), (c, prefixes))
        self.assertIsNone(captured.path_to(int.from_bytes(t, "big"), 2049))
        self.assertIsNone(model.extract_candidate(observer, c, t))
        self.assertEqual(len(captured.parents), captured_size)
        self.assertGreater(len(observer.parents), captured_size)

    def test_seal_cannot_be_reset_or_overfilled(self):
        observer = model.ChronologyControl()
        with self.assertRaises(ValueError):
            model.seal_openings(observer, ((header(bytes(32)), bytes(32)),), maximum_openings=0)
        self.assertEqual(observer.references, [])
        capture = model.seal_openings(observer, (), maximum_openings=0)
        observer.scripted_forward(b"\x77" * 64, observer.root)
        with self.assertRaises(ValueError):
            model.seal_openings(observer, (), maximum_openings=0)
        self.assertIs(observer.sealed_capture, capture)
        self.assertEqual(capture.entries, 0)

    def test_late_header_opening_hits_earlier_full_c_reference(self):
        observer = model.ChronologyControl()
        c = (1 << 220).to_bytes(32, "big")
        block = geometry.TRACE_DOMAIN + c + bytes(16)
        observer.scripted_forward(block, observer.root)
        self.assertFalse(observer.joined)
        observer.open_path(geometry.sha_blocks(geometry.pon_message(
            b"challenge", header((1 << 210).to_bytes(32, "big")))), final=int.from_bytes(c, "big"))
        self.assertTrue(observer.joined)

    def test_late_material_opening_hits_header_d_reference(self):
        observer = model.ChronologyControl()
        d = (1 << 220).to_bytes(32, "big")
        observer.open_path(geometry.sha_blocks(geometry.pon_message(b"challenge", header(d))))
        self.assertFalse(observer.joined)
        self.assertTrue(any(ref.kind == "task" and ref.value == d for ref in observer.references))
        observer.open_path(task_blocks(), final=int.from_bytes(d, "big"))
        self.assertTrue(observer.joined)

    def test_late_trace_opening_hits_pre_answer_t_reference(self):
        observer = model.ChronologyControl()
        c, t = (1 << 200).to_bytes(32, "big"), (1 << 220).to_bytes(32, "big")
        first, last = geometry.sha_blocks(geometry.pon_message(b"ticket", c, t))
        middle = observer.scripted_forward(first, observer.root)
        observer.scripted_forward(last, middle)
        self.assertFalse(observer.joined)
        self.assertIsNone(model.extract_candidate(observer, c, t))
        blocks = geometry.sha_blocks(geometry.TRACE_DOMAIN + c + bytes(131072))
        observer.open_path(blocks, final=int.from_bytes(t, "big"))
        self.assertTrue(observer.joined)

    def test_second_ticket_entry_before_first_cannot_later_be_rooted_without_join(self):
        observer = model.ChronologyControl()
        first, last = geometry.sha_blocks(geometry.pon_message(
            b"ticket", (1 << 200).to_bytes(32, "big"), (1 << 220).to_bytes(32, "big")))
        future_middle = 1 << 190
        observer.forward(last, future_middle, 9)
        self.assertFalse(observer.joined)
        self.assertFalse(any(ref.kind == "trace" for ref in observer.references))
        observer.forward(first, observer.root, future_middle)
        self.assertTrue(observer.joined)

    def test_inverse_fixed_point_allowed_until_a_rooted_attachment(self):
        observer = model.ChronologyControl()
        block = b"\x11" * 64
        point = 1 << 180
        self.assertEqual(observer.inverse(block, 0, point), point)
        self.assertFalse(observer.joined)
        observer.forward(b"\x22" * 64, observer.root, point)
        self.assertTrue(observer.joined)

    def test_two_headers_one_challenge_is_explicit_fanout_failure(self):
        observer = model.ChronologyControl()
        d = observer.open_path(task_blocks()).to_bytes(32, "big")
        first = geometry.sha_blocks(geometry.pon_message(b"challenge", header(d, 0)))
        second = geometry.sha_blocks(geometry.pon_message(b"challenge", header(d, 1)))
        self.assertEqual(first[:5], second[:5])  # exact precomputation is allowed
        c = observer.open_path(first)
        observer.open_path(second, final=c)
        self.assertTrue(observer.joined)

    def test_inverse_and_forward_tables_reject_inconsistent_scripts(self):
        observer = model.ChronologyControl()
        block = b"\x44" * 64
        observer.forward(block, 9, 11)
        with self.assertRaises(ValueError):
            observer.forward(block, 8, 11)
        with self.assertRaises(ValueError):
            observer.inverse(block, 12, 9)


class ConditionalLawTests(unittest.TestCase):
    def test_all_small_partial_permutations_match_exact_law_and_envelope(self):
        size = 4
        choices = tuple(permutations(range(size)))
        for h in range(size):
            others = [i for i in range(size) if i != h]
            for used in range(size):
                groups = defaultdict(list)
                for permutation in choices:
                    groups[tuple(permutation[i] for i in others[:used])].append(permutation)
                for outputs, completions in groups.items():
                    for target in range(size):
                        exact = Fraction(sum((h + p[h]) % size <= target for p in completions),
                                         len(completions))
                        self.assertEqual(exact, model.exact_fresh_probability(
                            size, target, h, outputs))
                        lower, upper = model.fresh_probability_bounds(size, target, used)
                        self.assertLessEqual(lower, exact)
                        self.assertLessEqual(exact, upper)

    def test_shared_key_depletion_changes_p_and_can_raise_native_work_mean(self):
        miss_removed = model.exact_fresh_probability(4, 1, 0, (3,))
        hit_removed = model.exact_fresh_probability(4, 1, 0, (0,))
        self.assertEqual(miss_removed, Fraction(2, 3))
        self.assertEqual(hit_removed, Fraction(1, 3))
        self.assertGreater(model.native_weight(4, 1) * miss_removed, 1)
        self.assertEqual(model.native_weight(4, 1) * miss_removed, Fraction(4, 3))
        self.assertEqual(model.exact_fresh_probability(4, 1, 0, iter((3,))), miss_removed)

    def test_adaptive_marked_count_is_dominated_without_future_conditioning(self):
        distribution = model.adaptive_marked_distribution()
        self.assertEqual(sum(distribution.values()), 1)
        upper = model.fresh_probability_bounds(5, 1, 2)[1]
        for threshold in (1, 2):
            observed = sum(probability for wins, probability in distribution.items()
                           if wins >= threshold)
            self.assertLessEqual(observed, model.binomial_tail(2, upper, threshold))

    def test_outcome_selection_and_realized_attempt_conditioning_are_negative_controls(self):
        values = model.selection_countermodels()
        self.assertEqual(values["independent_noise_valid_subset_win_probability"], Fraction(1, 2))
        self.assertEqual(values["overlapping_noise_valid_subset_win_probability"], 1)
        self.assertEqual(values["conditioned_on_one_realized_trial_win_probability"], 1)
        self.assertEqual(values["unconditioned_two_trial_any_win_probability"], Fraction(3, 4))

    def test_retirement_and_prepared_unseen_bank_are_not_double_counted(self):
        length = model.TRACE_BLOCKS
        self.assertEqual(model.fresh_capacity(5 * length, 0, 3), 2)
        self.assertEqual(model.fresh_capacity(3 * length, length - 1, 3), 0)
        self.assertEqual(model.fresh_capacity(3 * length, length, 3), 1)
        with self.assertRaises(ValueError):
            model.fresh_capacity(length - 1, 100 * length, 1)
        # A previously exposed invalid path is not a permitted retired input:
        # the arithmetic API cannot establish this premise from an integer.

    def test_exact_numeric_and_scope_validation(self):
        for arguments in ((4, 4, 0), (4, 1, 4), (4, -1, 0), (4, 1, True)):
            with self.assertRaises(ValueError):
                model.fresh_probability_bounds(*arguments)
        with self.assertRaises(ValueError):
            model.exact_fresh_probability(4, 1, 0, (0, 0))
        with self.assertRaises(ValueError):
            model.native_weight(4, 0)
        self.assertEqual(model.binomial_tail(2, Fraction(1, 2), 0), 1)
        self.assertEqual(model.binomial_tail(2, Fraction(1, 2), 3), 0)


if __name__ == "__main__":
    unittest.main()
