#!/usr/bin/env python3
"""Fixed artifacts, upstream KATs and adverse encodings for the image audit."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('w1_qrom_semantics_audit',
                                            ROOT / 'scripts/w1_qrom_semantics_audit.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def small_elf(segments: list[tuple[int, int, bytes]], entry: int = 0x10000) -> bytes:
    """Construct ELF32 fixtures: (address, memory byte count, file content)."""
    blob = bytearray(52 + 32 * len(segments))
    blob[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<HHIIIIIHHHHHH', blob, 16,
                     2, 243, 1, entry, 52, 0, 0, 52, 32, len(segments), 40, 0, 0)
    for index, (address, memory_bytes, content) in enumerate(segments):
        offset = len(blob)
        blob.extend(content)
        struct.pack_into('<IIIIIIII', blob, 52 + index * 32,
                         1, offset, address, address, len(content), memory_bytes, 5, 4)
    return bytes(blob)


def generated_def(operations: list[str], returned: int) -> str:
    return ('pub const DEF: PolyExtStepDef = PolyExtStepDef { block: &['
            + ''.join('PolyExtStep::' + operation + ',' for operation in operations)
            + f'], ret: {returned}, }};')


class W1SemanticsAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.helper, cls.engine, cls.provenance, cls.archives = AUDIT.load_sources(ROOT)
        cls.binary = (ROOT / AUDIT.GUEST_PATH).read_bytes()
        cls.report = AUDIT.audit(ROOT)

    def test_fixed_r0bf_reconstructs_exact_v2_image_and_memory_root(self) -> None:
        guest = self.report['guest_binary']
        self.assertEqual(guest['image_id'],
                         '7b8fb87437a9f1c308909d6b8e27655a3190ae04d2b11a2fa12ef111941c0dff')
        self.assertEqual(guest['memory_root'],
                         'eaef1e2d046026053790dd77bdafe629eddf1a12c35190385eebf8417c7ae964')
        self.assertEqual(guest['image_id_words'], list(AUDIT.EXPECTED_IMAGE_WORDS))
        self.assertEqual(guest['memory_tree']['loaded_pages'], 208)
        self.assertEqual(guest['memory_tree']['loaded_words'], 51507)

    def test_r0bf_embedded_kernel_matches_complete_locked_release_archive(self) -> None:
        user, kernel, metadata = AUDIT.split_r0bf(self.binary)
        self.assertEqual((len(user), len(kernel), metadata['user_elf_offset']), (343504, 32392, 32))
        self.assertEqual(kernel, self.archives['risc0-zkos-v1compat-2.2.3']['elfs/v1compat.elf'])
        self.assertEqual(AUDIT.sha256(kernel),
                         '7ffd942e4e8babd771094f549ad080cfea8ecb2c05c986e275c011f41979d921')
        self.assertEqual(len(self.provenance['lock_checks']), 3)

    def test_upstream_memory_known_answers_include_nonzero_kernel_image(self) -> None:
        self.assertEqual(AUDIT.digest_hex(AUDIT.page_digest(self.engine, bytes(1024))),
                         AUDIT.ZERO_PAGE_HEX)
        root, _ = AUDIT.memory_root(self.engine, {})
        self.assertEqual(AUDIT.digest_hex(root), AUDIT.ZERO_MEMORY_HEX)
        root, _ = AUDIT.memory_root(self.engine,
                                   {0x10000: 0x1234b337, 0xffff0210: 0x10000, 0xffff0214: 1})
        self.assertEqual(AUDIT.digest_hex(root), AUDIT.KERNEL_KAT_HEX)

    def test_partial_words_and_bss_follow_little_endian_source_loop(self) -> None:
        entry, words, _ = AUDIT.load_elf(small_elf([(0x10000, 12, b'\x01\x02\x03\x04\x05')]),
                                      AUDIT.KERNEL_START)
        self.assertEqual(entry, 0x10000)
        self.assertEqual(words, {0x10000: 0x04030201, 0x10004: 5, 0x10008: 0})
        # The SDK iterates starts of 4-byte words, rather than truncating a final
        # partial memory word.  This narrower audit models that behavior too.
        _, partial, _ = AUDIT.load_elf(small_elf([(0x10000, 5, b'\x01' * 8)]), AUDIT.KERNEL_START)
        self.assertEqual(partial, {0x10000: 0x01010101, 0x10004: 0x01010101})

    def test_later_segments_and_user_memory_override_in_source_order(self) -> None:
        elf = small_elf([(0x10000, 8, b'\x01' * 8), (0x10004, 4, b'\x02' * 4)])
        entry, words, info = AUDIT.load_elf(elf, AUDIT.KERNEL_START)
        self.assertEqual(words[0x10004], 0x02020202)
        self.assertEqual(info['overwritten_segment_words'], 1)
        memory, merge = AUDIT.initial_memory(entry, words, 0xc0000000,
                                             {0x10000: 99, 0x10004: 88, AUDIT.SUSPEND_MODE: 9})
        self.assertEqual(memory[0x10000], entry)
        self.assertEqual(memory[0x10004], 0x02020202)
        self.assertEqual(memory[AUDIT.SUSPEND_PC], 0xc0000000)
        self.assertEqual(memory[AUDIT.SUSPEND_MODE], 1)
        self.assertEqual(merge['user_overwrites_kernel_addresses'], [0x10000, 0x10004])
        self.assertEqual(self.report['guest_binary']['initial_memory_writes']
                         ['user_overwrites_kernel_word_count'], 69)

    def test_r0bf_rejects_bad_magic_version_header_and_lengths(self) -> None:
        variants = []
        for offset in (0, 4, 8, 12, 20):
            changed = bytearray(self.binary)
            changed[offset] ^= 1
            variants.append(bytes(changed))
        for length in (0, len(self.binary), 0xffffffff):
            changed = bytearray(self.binary)
            struct.pack_into('<I', changed, 28, length)
            variants.append(bytes(changed))
        variants.extend((self.binary[:31], self.binary[32:]))
        for variant in variants:
            with self.subTest(prefix=variant[:32].hex()), self.assertRaises(AUDIT.SemanticsAuditError):
                AUDIT.split_r0bf(variant)

    def test_elf_rejects_wrong_class_endian_machine_and_entry(self) -> None:
        baseline = small_elf([(0x10000, 4, b'\x01\0\0\0')])
        changes = ((4, b'\x02'), (5, b'\x02'), (18, struct.pack('<H', 62)),
                   (16, struct.pack('<H', 3)), (24, struct.pack('<I', 0x10001)),
                   (24, struct.pack('<I', AUDIT.KERNEL_START)))
        for offset, data in changes:
            variant = bytearray(baseline)
            variant[offset:offset + len(data)] = data
            with self.subTest(offset=offset, data=data.hex()), self.assertRaises(AUDIT.SemanticsAuditError):
                AUDIT.load_elf(bytes(variant), AUDIT.KERNEL_START)

    def test_elf_rejects_truncated_tables_segments_and_address_overflow(self) -> None:
        baseline = small_elf([(0x10000, 4, b'\x01\0\0\0')])
        variants = [baseline[:51], baseline[:83], baseline[:-1]]
        for offset, value in ((60, 0xfffffffc), (72, 0xffffffff), (52 + 4, 0xfffffff0)):
            changed = bytearray(baseline)
            struct.pack_into('<I', changed, offset, value)
            variants.append(bytes(changed))
        for variant in variants:
            with self.subTest(variant=variant.hex()), self.assertRaises(AUDIT.SemanticsAuditError):
                AUDIT.load_elf(variant, AUDIT.KERNEL_START)

    def test_elf_resource_limit_rejects_unbounded_memory_expansion(self) -> None:
        huge = small_elf([(0x10000, (AUDIT.MAX_LOAD_WORDS + 1) * 4, b'')])
        with self.assertRaisesRegex(AUDIT.SemanticsAuditError, 'loaded-word limit'):
            AUDIT.load_elf(huge, AUDIT.KERNEL_START)

    def test_nonloaded_elf_byte_changes_file_hash_but_preserves_image_inputs(self) -> None:
        counterexample = self.report['unloaded_elf_byte_counterexample']
        changed = bytearray(self.binary)
        changed[counterexample['composite_byte_offset']] ^= 1
        self.assertNotEqual(AUDIT.sha256(bytes(changed)), AUDIT.GUEST_SHA256)
        user, kernel, _ = AUDIT.split_r0bf(self.binary)
        changed_user, changed_kernel, _ = AUDIT.split_r0bf(bytes(changed))
        self.assertEqual(kernel, changed_kernel)
        self.assertEqual(AUDIT.load_elf(user, AUDIT.KERNEL_START)[:2],
                         AUDIT.load_elf(changed_user, AUDIT.KERNEL_START)[:2])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'modified.bin'
            path.write_bytes(changed)
            with self.assertRaisesRegex(AUDIT.SemanticsAuditError, 'SHA-256 mismatch'):
                AUDIT.read_pinned(Path(directory), 'modified.bin', AUDIT.GUEST_SHA256,
                                  AUDIT.MAX_BINARY_BYTES)

    def test_loaded_instruction_byte_changes_recomputed_image(self) -> None:
        changed = bytearray(self.binary)
        # The fixed first executable user segment begins at composite 32+2048.
        changed[2080] ^= 1
        report = AUDIT.recompute_binary(self.engine, bytes(changed))
        self.assertNotEqual(report['memory_root'], self.report['guest_binary']['memory_root'])
        self.assertNotEqual(report['image_id'], self.report['guest_binary']['image_id'])

    def test_page_word_byte_order_and_child_order_are_observable(self) -> None:
        little = struct.pack('<I', 0x12345678) + bytes(1020)
        big = struct.pack('>I', 0x12345678) + bytes(1020)
        self.assertNotEqual(AUDIT.page_digest(self.engine, little), AUDIT.page_digest(self.engine, big))
        left, right = tuple(range(1, 9)), tuple(range(9, 17))
        self.assertNotEqual(AUDIT.memory_pair(self.engine, left, right),
                            AUDIT.memory_pair(self.engine, right, left))

    def test_memory_pair_rejects_malformed_or_noncanonical_field_words(self) -> None:
        for left in ((0,) * 7, (0,) * 9, (AUDIT.P,) + (0,) * 7,
                     (-1,) + (0,) * 7, (False,) + (0,) * 7):
            with self.subTest(left=left), self.assertRaises(AUDIT.SemanticsAuditError):
                AUDIT.memory_pair(self.engine, left, (0,) * 8)
        for page in (bytes(1023), bytes(1025), bytearray(1024)):
            with self.assertRaises(AUDIT.SemanticsAuditError):
                AUDIT.page_digest(self.engine, page)

    def test_shared_poseidon_input_vector_exposes_missing_independence_premise(self) -> None:
        vector = self.report['shared_poseidon_permutation_vector']
        self.assertEqual(vector['identical_permutation_input_normal_words'],
                         [*range(9, 17), *range(1, 9), *([0] * 8)])
        self.assertEqual(vector['memory_output_normal_digest'],
                         '26aef03c2c56af3901843515515a910cb103766734bc58127459504de4c67974')
        self.assertEqual(vector['control_output_montgomery_digest'],
                         '7d8cfe153d59f01c8708c11a6550303dab80484b5f4cdc603e52106b1cbe8427')
        normalized = tuple(word * self.helper.MONTGOMERY_R_INV % AUDIT.P for word in
                           struct.unpack('<8I', bytes.fromhex(vector['control_output_montgomery_digest'])))
        self.assertEqual(AUDIT.digest_hex(normalized), vector['memory_output_normal_digest'])
        # Treating the serialized normal digests as control-tree raw Montgomery
        # digests produces a different permutation input and result.
        wrong = self.engine.hash_pair(vector['memory_right_normal_digest'],
                                      vector['memory_left_normal_digest'])
        self.assertNotEqual(wrong, vector['control_output_montgomery_digest'])
        self.assertIs(vector['independent_oracle_domains_established'], False)

    def test_complete_crate_archive_tamper_rejected_before_member_reads(self) -> None:
        for name in AUDIT.CRATES:
            data = bytearray((ROOT / AUDIT.EVIDENCE / (name + '.crate')).read_bytes())
            data[len(data) // 2] ^= 1
            with self.subTest(crate=name), self.assertRaisesRegex(AUDIT.SemanticsAuditError,
                                                               'archive checksum mismatch'):
                AUDIT.crate_members(bytes(data), name)

    def test_fixed_generated_air_dag_degree_and_register_counts(self) -> None:
        circuits = self.report['generated_air_degree_audit']['circuits']
        for name, counts in {'recursion': (11130, 1229, 643), 'rv32im': (13736, 6466, 790)}.items():
            with self.subTest(circuit=name):
                result = circuits[name]
                self.assertEqual((result['field_registers'], result['mix_registers'], result['tap_count']), counts)
                self.assertEqual(result['return_tot_trace_degree_upper_bound'], 5)
                self.assertEqual(result['return_mul_trace_degree_upper_bound'], 0)
                self.assertEqual(result['division_or_inverse_operations'], 0)
        consequence = self.report['generated_air_degree_audit']['conditional_univariate_consequence']
        self.assertIs(consequence['actual_trace_divisibility_proved'], False)
        self.assertIs(consequence['deep_fri_rational_quotient_and_denominator_events_covered'], False)

    def test_air_conditional_mix_includes_condition_degree(self) -> None:
        # Returned polynomial is y*x^2, not merely x^2 from the inner constraint.
        source = generated_def(['Get(0)', 'Get(1)', 'Mul(0, 0)', 'True',
                                'AndEqz(0, 2)', 'AndCond(0, 1, 1)'], 2)
        result = AUDIT.analyze_poly_ext(source, 2, (1, 1))
        self.assertEqual(result['return_tot_trace_degree_upper_bound'], 3)
        self.assertEqual(result['maximum_field_register_degree_upper_bound'], 2)

    def test_air_public_and_extension_constants_are_fixed_coefficients(self) -> None:
        source = generated_def(['ConstExt(1, 2, 3, 4)', 'GetGlobal(0, 0)', 'Get(0)',
                                'Mul(0, 2)', 'Mul(3, 1)', 'True', 'AndEqz(0, 4)'], 1)
        result = AUDIT.analyze_poly_ext(source, 1, (1, 1))
        self.assertEqual(result['return_tot_trace_degree_upper_bound'], 1)
        self.assertEqual(result['referenced_global_values'], 1)

    def test_air_bound_responds_to_higher_degree_operation_mutation(self) -> None:
        operations = ['Get(0)', 'Mul(0, 0)', 'Mul(1, 0)', 'True', 'AndEqz(0, 2)']
        self.assertEqual(AUDIT.analyze_poly_ext(generated_def(operations, 1), 1, (1, 1))
                         ['return_tot_trace_degree_upper_bound'], 3)
        operations[2] = 'Mul(1, 1)'
        self.assertEqual(AUDIT.analyze_poly_ext(generated_def(operations, 1), 1, (1, 1))
                         ['return_tot_trace_degree_upper_bound'], 4)

    def test_air_returns_selected_constraint_bound_not_unused_field_maximum(self) -> None:
        operations = ['Get(0)', 'Mul(0, 0)', 'Mul(1, 1)', 'Mul(2, 2)',
                      'True', 'AndEqz(0, 0)']
        result = AUDIT.analyze_poly_ext(generated_def(operations, 1), 1, (1, 1))
        self.assertEqual(result['maximum_field_register_degree_upper_bound'], 8)
        self.assertEqual(result['return_tot_trace_degree_upper_bound'], 1)

    def test_air_unknown_operations_forward_refs_and_wrong_input_banks_rejected(self) -> None:
        bad_programs = [
            (['Get(0)', 'Inv(0)', 'True', 'AndEqz(0, 0)'], 1),
            (['Get(0)', 'Mul(0, 1)', 'True', 'AndEqz(0, 0)'], 1),
            (['Get(1)', 'True', 'AndEqz(0, 0)'], 1),
            (['GetGlobal(2, 0)', 'True', 'AndEqz(0, 0)'], 1),
            (['GetGlobal(0, 1)', 'True', 'AndEqz(0, 0)'], 1),
            (['Get(0)', 'True', 'AndCond(0, 0, 1)'], 1),
            (['Get(0)', 'True', 'AndEqz(0, 0)'], 0),
            (['Get(-1)', 'True', 'AndEqz(0, 0)'], 1),
        ]
        for operations, returned in bad_programs:
            with self.subTest(operations=operations), self.assertRaises(AUDIT.SemanticsAuditError):
                AUDIT.analyze_poly_ext(generated_def(operations, returned), 1, (1, 1))

    def test_reconstruction_does_not_promote_compiler_trace_or_qrom_claims(self) -> None:
        qualification = self.report['qualification']
        closed = {'fixed_composite_binary_to_image_id_independently_recomputed',
                  'embedded_kernel_matches_locked_release_binary',
                  'fixed_generated_constraint_dag_degree_bound_recomputed'}
        self.assertEqual({key for key, value in qualification.items() if value is True}, closed)
        self.assertTrue(all(value is False for key, value in qualification.items() if key not in closed))
        self.assertIs(qualification['valid_code_zero_control_digest_excluded'], False)
        self.assertIs(qualification['fresh_receipt_cryptographically_verified'], False)
        self.assertIs(self.report['kernel_release_match']['kernel_source_to_binary_rebuilt'], False)


if __name__ == '__main__':
    unittest.main()
