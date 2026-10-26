"""Actual ML-DSA-65 model/Cell artifact and evaluator/release signature tests."""
from dataclasses import replace
from pathlib import Path
import subprocess
import tempfile
import unittest

from pq_envelope import Reject, public_key_id
from pq_cell_release import (
    MAX_CELLS, CellBundle, CellRef, content_id, manifest_id, parse_bundle,
    sign_release_fixture, sign_review_fixture, verify_release_research,
)


class PQCellReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="trnm-pq-cell-")
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        cls.keys = {}
        for who in ("release", "eval_a", "eval_b", "eval_c", "attacker"):
            secret, public = root / (who + ".secret"), root / (who + ".public")
            subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65",
                            "-out", str(secret)], check=True, capture_output=True, timeout=15)
            subprocess.run(["openssl", "pkey", "-in", str(secret), "-pubout",
                            "-out", str(public)], check=True, capture_output=True, timeout=15)
            cls.keys[who] = (secret, public.read_bytes())
        cls.net, cls.family, cls.parent = bytes(range(32)), bytes(range(32, 64)), bytes(32)
        cls.base = b"shared immutable encoder weights - development fixture"
        cls.content = {bytes([1])*32: b"cell one head weights v9",
                       bytes([2])*32: b"cell two head weights v9"}
        cls.manifest = CellBundle(
            cls.net, cls.family, cls.parent, 9, content_id(cls.base), len(cls.base),
            tuple(CellRef(i, 9, content_id(b), len(b)) for i, b in sorted(cls.content.items())))
        cls.plan = bytes([0xC3])*48
        cls.reviewer_ids = frozenset(public_key_id(cls.keys[i][1])
                                     for i in ("eval_a", "eval_b", "eval_c"))
        cls.release_id = public_key_id(cls.keys["release"][1])
        cls.eval_frames = {
            who: sign_review_fixture(cls.manifest, cls.plan, public_pem=cls.keys[who][1],
                                     private_key_path=cls.keys[who][0], expires_at=2000, sequence=7)
            for who in ("eval_a", "eval_b", "eval_c")
        }
        cls.two = tuple((cls.keys[i][1], cls.eval_frames[i]) for i in ("eval_a", "eval_b"))
        cls.two_ids = tuple(sorted(public_key_id(pem) for pem, _ in cls.two))
        cls.release_frame = sign_release_fixture(
            cls.manifest, cls.plan, cls.two_ids, public_pem=cls.keys["release"][1],
            private_key_path=cls.keys["release"][0], expires_at=2000, sequence=7)

    def check(self, **changes):
        args = dict(manifest_bytes=self.manifest.encode(), base_weights=self.base,
                    cell_weights=self.content, evaluation_plan_id=self.plan,
                    release_public_pem=self.keys["release"][1], release_frame=self.release_frame,
                    reviewer_frames=self.two, trusted_release_key_id=self.release_id,
                    trusted_reviewer_ids=self.reviewer_ids, expected_network=self.net,
                    expected_family=self.family, expected_parent=self.parent,
                    expected_generation=9, expected_sequence=7, now=1999)
        args.update(changes)
        return verify_release_research(**args)

    def test_real_two_of_three_reviews_and_release_signature(self):
        receipt = self.check()
        self.assertEqual(receipt.manifest_id, manifest_id(self.manifest))
        self.assertEqual(receipt.observed_reviewer_key_ids, self.two_ids)
        self.assertEqual(receipt.content_objects_checked, 3)
        self.assertFalse(hasattr(receipt, "adoption_authorized"))

    def test_model_and_cell_weight_substitution_reject(self):
        with self.assertRaises(Reject):
            self.check(base_weights=self.base[:-1] + b"X")
        for key in self.content:
            altered = dict(self.content)
            altered[key] = altered[key][:-1] + b"X"
            with self.subTest(cell=key.hex()), self.assertRaises(Reject):
                self.check(cell_weights=altered)
        with self.assertRaises(Reject):
            self.check(cell_weights={next(iter(self.content)): b"a"})

    def test_strict_canonical_manifest_mutations_reject(self):
        original = self.manifest.encode()
        for i in range(len(original)):
            corrupted = bytearray(original)
            corrupted[i] ^= 1
            with self.subTest(i=i), self.assertRaises(Reject):
                self.check(manifest_bytes=bytes(corrupted))
        for raw in (original[:-1], original+b"x", b"PCX1"+original[4:],
                    original[:4]+b"\x02"+original[5:],
                    original[:165]+b"\xff"+original[166:]):
            with self.assertRaises(Reject):
                parse_bundle(raw)

    def test_reordered_duplicate_or_too_many_cells_reject(self):
        a, b = self.manifest.cells
        for cells in ((b, a), (a, a), (), tuple([a] * (MAX_CELLS + 1))):
            with self.assertRaises(Reject):
                replace(self.manifest, cells=cells).encode()
        self.assertEqual(parse_bundle(self.manifest.encode()), self.manifest)

    def test_receipt_quorum_duplicate_reviewer_and_untrusted_key_reject(self):
        for frames in (self.two[:1], (self.two[0], self.two[0])):
            with self.assertRaises(Reject):
                self.check(reviewer_frames=frames)
        attacker = self.keys["attacker"]
        forged = sign_review_fixture(self.manifest, self.plan,
                                     public_pem=attacker[1], private_key_path=attacker[0],
                                     expires_at=2000, sequence=7)
        with self.assertRaises(Reject):
            self.check(reviewer_frames=(self.two[0], (attacker[1], forged)))
        with self.assertRaises(Reject):
            self.check(trusted_reviewer_ids=frozenset(self.two_ids))

    def test_release_signature_cannot_omit_or_relabel_reviewers(self):
        changed = bytearray(self.release_frame)
        changed[-1] ^= 1
        with self.assertRaises(Reject):
            self.check(release_frame=bytes(changed))
        third = (self.keys["eval_c"][1], self.eval_frames["eval_c"])
        with self.assertRaises(Reject):
            self.check(reviewer_frames=(self.two[0], third))
        wrong = self.keys["attacker"]
        with self.assertRaises(Reject):
            self.check(release_public_pem=wrong[1])

    def test_evaluation_receipt_signature_and_plan_binding(self):
        modified = bytearray(self.eval_frames["eval_b"])
        modified[-1] ^= 1
        with self.assertRaises(Reject):
            self.check(reviewer_frames=(self.two[0], (self.two[1][0], bytes(modified))))
        with self.assertRaises(Reject):
            self.check(evaluation_plan_id=bytes([0x44])*48)
        with self.assertRaises(Reject):
            self.check(evaluation_plan_id=bytes(48))

    def test_different_network_family_parent_generation_expiry_reject(self):
        for override in (dict(expected_network=bytes(32)),
                         dict(expected_family=bytes(32)),
                         dict(expected_parent=bytes([1])*32),
                         dict(expected_generation=10),
                         dict(expected_generation=True),
                         dict(expected_sequence=8),
                         dict(now=2001)):
            with self.subTest(override=override), self.assertRaises(Reject):
                self.check(**override)

    def test_release_owner_cannot_self_count_as_reviewer(self):
        pub, secret = self.keys["release"][1], self.keys["release"][0]
        new_frame = sign_review_fixture(self.manifest, self.plan,
                                        public_pem=pub, private_key_path=secret,
                                        expires_at=2000, sequence=7)
        with self.assertRaises(Reject):
            self.check(reviewer_frames=(self.two[0], (pub, new_frame)),
                       trusted_reviewer_ids=self.reviewer_ids | {self.release_id})

    def test_field_limits_and_zero_resource_reject(self):
        for value in (b"", "string", bytes(64*1024*1024+1)):
            with self.assertRaises(Reject):
                content_id(value)
        a = self.manifest.cells[0]
        for changed in (dict(cell_id=bytes(32)), dict(generation=True),
                        dict(generation=0), dict(weight_id=bytes(48)),
                        dict(weight_size=-1)):
            with self.assertRaises(Reject):
                replace(a, **changed).encode()
        with self.assertRaises(Reject):
            replace(self.manifest, generation=0).encode()

    def test_no_false_model_adoption_or_independent_evaluator_claim(self):
        observed = self.check()
        self.assertFalse(hasattr(observed, "adoption_authorized"))
        self.assertEqual(observed.content_objects_checked, 1 + len(self.manifest.cells))


if __name__ == "__main__":
    unittest.main()
