"""Actual full-relation and adversarial constraint controls, no proof mocks."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from contract_wire import H, header_decode
import w1_specialized_relation as sr
import work_oracle


class LimbControls(unittest.TestCase):
    def test_exact_reductions_include_large_quotient_and_carries(self):
        for terms, positive, negative in [
            ([], [0], []),
            ([(sr.Q - 1, sr.Q - 1)], [], []),
            ([(sr.Q - 1, sr.Q - 1)] * 64, [sr.Q - 1], []),
            ([], [0, 2 * sr.Q], [sr.Q - 1, sr.Q - 1]),
            ([], [sr.Q - 1, 2 * sr.Q], [0, 0]),
        ]:
            row = sr.reduction_row(terms, positive, negative)
            expected = (sum(x * y for x, y in terms) + sum(positive) - sum(negative)) % sr.Q
            self.assertEqual(sr.check_reduction(row, terms, positive, negative), expected)
        row = sr.reduction_row([(sr.Q - 1, sr.Q - 1)] * 64)
        self.assertGreater(row[1], (1 << 32) - 1)
        self.assertLess(sr.COLUMN_RESIDUAL_BOUND, sr.BABY_BEAR)

    def test_wrong_modulus_alias_and_all_carry_positions_reject(self):
        terms = [(sr.Q - 1, sr.Q - 2)] * 64
        row = sr.reduction_row(terms)
        wrong = list(row)
        wrong[0] = sum(x * y for x, y in terms) % sr.BABY_BEAR
        self.assertNotEqual(wrong[0], row[0])
        with self.assertRaises(ValueError):
            sr.check_reduction(wrong, terms)
        for position in range(11):
            changed = list(row)
            changed[position] += 1
            with self.assertRaises(ValueError):
                sr.check_reduction(changed, terms)

    def test_field_quotient_carry_and_python_bool_aliases_reject(self):
        row = sr.reduction_row([(1, 2)])
        for index, bad in [(0, sr.Q), (0, True), (1, -1), (1, 1 << 39),
                           (2, sr.CARRY_BOUND + 1), (2, True)]:
            changed = list(row)
            changed[index] = bad
            with self.assertRaises(ValueError):
                sr.check_reduction(changed, [(1, 2)])
        for term in [(sr.Q, 1), (-1, 1), (True, 2)]:
            with self.assertRaises(ValueError):
                sr.check_reduction(row, [term])


class HashAndAttackControls(unittest.TestCase):
    def test_sha_padding_and_full_compression_match_independent_hashlib(self):
        for length in (0, 1, 55, 56, 63, 64, 65, 127, 131120):
            message = bytes(i % 251 for i in range(length))
            record = sr.sha_record("control", message)
            self.assertEqual(sr.check_sha(record, "control", message), hashlib.sha256(message).digest())
            self.assertEqual(len(record["states"]), (length + 9 + 63) // 64)
        self.assertEqual(len(sr.padded(sr.TRACE_DOMAIN + bytes(32) + bytes(4 * sr.TRACE_WORDS))) // 64,
                         sr.TRACE_BLOCKS)

    def test_sha_intermediate_final_length_and_order_reject(self):
        message = bytes(130)
        original = sr.sha_record("control", message)
        for block in range(len(original["states"])):
            changed = copy.deepcopy(original)
            changed["states"][block][7] ^= 1
            with self.assertRaisesRegex(ValueError, "SHA_COMPRESSION"):
                sr.check_sha(changed, "control", message)
        for changed in [dict(original, name="other"), dict(original, digest="00" * 32),
                        dict(original, states=original["states"][:-1])]:
            with self.assertRaises(ValueError):
                sr.check_sha(changed, "control", message)

    def test_noise_rejection_order_and_exact_last_chunk(self):
        digest = struct.pack("<8I", sr.Q, 5, sr.Q + 1, 8, sr.Q + 4, 0, sr.Q - 1, 10)
        self.assertEqual(sr.accepted_words(digest, 512), [5, 8, 0, sr.Q - 1, 10])
        self.assertEqual(sr.accepted_words(digest, 3), [5, 8, 0])
        self.assertEqual(sr.accepted_words(struct.pack("<8I", *([sr.Q] * 8)), 512), [])

    def test_known_challenge_freivalds_rank_one_forgery_is_not_matrix_proof(self):
        q = sr.Q
        a, b, r = [[1, 2], [3, 4]], [[5, 6], [7, 8]], [9, 10]
        br = [sum(b[i][j] * r[j] for j in range(2)) % q for i in range(2)]
        u = [sum(a[i][j] * br[j] for j in range(2)) % q for i in range(2)]
        v = [pow(r[0], -1, q), 0]
        forged = [[u[i] * v[j] % q for j in range(2)] for i in range(2)]
        actual = [[sum(a[i][k] * b[k][j] for k in range(2)) % q for j in range(2)] for i in range(2)]
        self.assertNotEqual(forged, actual)
        self.assertEqual([sum(forged[i][j] * r[j] for j in range(2)) % q for i in range(2)], u)


class FullSavedW1Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        evidence = root / "evidence/pon-w1-full-v2-20261105"
        data = (evidence / "input.bin").read_bytes()
        cls.header, cls.proof = data[:318], data[318:]
        cls.artifacts = (evidence / "expected-artifacts.bin").read_bytes()
        cls.witness, cls.report = sr.execute(cls.header, cls.proof, cls.artifacts)

    def test_complete_witness_native_bytes_and_all_cost_dimensions(self):
        _, report = sr.execute(self.header, self.proof, self.artifacts, self.witness)
        self.assertTrue(report["complete_mathematical_witness_checked"])
        self.assertFalse(self.report["complete_mathematical_witness_checked"])
        self.assertEqual(report["reduction_rows"], 62464)
        self.assertEqual(report["carry_equations"], 562176)
        self.assertEqual(report["field_multiplications"], 458752)
        self.assertEqual(report["trace_words"], 32768)
        self.assertEqual(report["trace_sha256_blocks"], 2049)
        header = header_decode(self.header)
        ticket, product = work_oracle.verify(H("challenge", self.header), header["work_task"],
                                            header["target"], self.proof)
        self.assertEqual(ticket.hex(), self.witness["statement"]["ticket"])
        self.assertEqual(hashlib.sha256(work_oracle.field_bytes(product)).hexdigest(),
                         self.witness["statement"]["product_sha256"])
        self.assertEqual(H("block", self.header, self.proof[-32:]).hex(), report["work_id"])
        self.assertFalse(report["cryptographic_backend_implemented"])
        self.assertFalse(report["node_admission_authorized"])

    def test_explicit_null_and_nonobject_witnesses_reject(self):
        for witness in (None, False, 0, [], "null"):
            with self.subTest(witness=witness):
                with self.assertRaisesRegex(ValueError, "WITNESS_SCHEMA"):
                    sr.execute(self.header, self.proof, self.artifacts, witness)

    def test_cli_check_null_rejects_without_constructing_a_witness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in (("header.bin", self.header), ("proof.bin", self.proof),
                               ("artifacts.bin", self.artifacts), ("witness.json", b"null\n")):
                (root / name).write_bytes(data)
            result = subprocess.run([
                sys.executable, str(Path(sr.__file__).resolve()), "check",
                "--header", str(root / "header.bin"),
                "--proof", str(root / "proof.bin"),
                "--expected-artifacts", str(root / "artifacts.bin"),
                "--witness", str(root / "witness.json"),
            ], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("WITNESS_SCHEMA", result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual((root / "witness.json").read_bytes(), b"null\n")

    def test_early_middle_and_final_prefix_corruption_reject(self):
        for index in (0, 16384, 32767):
            row = self.witness["arithmetic"]["prefix"][index]
            old = row[0]
            row[0] = (old + 1) % sr.Q
            try:
                with self.assertRaisesRegex(ValueError, "CARRY_EQUATION"):
                    sr.execute(self.header, self.proof, self.artifacts, self.witness)
            finally:
                row[0] = old

    def test_omitted_or_added_prefix_and_unbounded_hash_shape_reject(self):
        for count in (32767, 32769):
            changed = dict(self.witness)
            changed["arithmetic"] = dict(self.witness["arithmetic"])
            changed["arithmetic"]["prefix"] = [[0] * 11] * count
            with self.assertRaisesRegex(ValueError, "GROUP_LENGTH:prefix"):
                sr.execute(self.header, self.proof, self.artifacts, changed)
        changed = dict(self.witness, hashes=[{}] * 521)
        with self.assertRaisesRegex(ValueError, "HASH_COUNT"):
            sr.execute(self.header, self.proof, self.artifacts, changed)

    def test_full_trace_hash_connection_and_result_recovery_reject(self):
        trace = next(row for row in self.witness["hashes"] if row["name"] == "trace")
        old = trace["states"][1024][0]
        trace["states"][1024][0] ^= 1
        try:
            with self.assertRaisesRegex(ValueError, "SHA_COMPRESSION"):
                sr.execute(self.header, self.proof, self.artifacts, self.witness)
        finally:
            trace["states"][1024][0] = old
        row = self.witness["arithmetic"]["recover"][-1]
        old = row[0]
        row[0] = (old + 1) % sr.Q
        try:
            with self.assertRaisesRegex(ValueError, "CARRY_EQUATION"):
                sr.execute(self.header, self.proof, self.artifacts, self.witness)
        finally:
            row[0] = old

    def test_external_statement_material_and_canonicality_reject(self):
        wrong_artifacts = bytes([self.artifacts[0] ^ 1]) + self.artifacts[1:]
        with self.assertRaisesRegex(ValueError, "ARTIFACT_BINDING"):
            sr.execute(self.header, self.proof, wrong_artifacts, self.witness)
        changed_header = bytearray(self.header)
        changed_header[-1] ^= 1
        with self.assertRaises(ValueError):
            sr.execute(bytes(changed_header), self.proof, self.artifacts, self.witness)
        for matrix in range(3):
            changed_proof = bytearray(self.proof)
            start = 4 + 4 * sr.CELLS * matrix
            changed_proof[start:start + 4] = struct.pack("<I", sr.Q)
            with self.assertRaisesRegex(ValueError, "FIELD"):
                sr.execute(self.header, bytes(changed_proof), self.artifacts, self.witness)


if __name__ == "__main__":
    unittest.main()
