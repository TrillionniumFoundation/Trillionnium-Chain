"""Check the mechanically scoped private admission and its public artificial native receipt."""
import copy
from pathlib import Path
import shutil
import tempfile
import unittest

import dev_circuit_evaluation as common
import dev_intake_evaluation as plain


CAPTURE = Path(__file__).resolve().parents[1] / "evidence/cell-released-pair-funded-evaluation-20261123"


class ReleasedEvaluationTests(unittest.TestCase):
    def test_same_release_request_after_reopen(self):
        retained = common.read(CAPTURE / "ADMISSION.json")["intake_release_sha256"]
        observation = common.verify(CAPTURE, expected_release=retained)
        with self.assertRaisesRegex(ValueError, "independently retained release"):
            common.verify(CAPTURE, expected_release="f" * 64)
        self.assertEqual(observation["development_units"], 2000)
        self.assertEqual(observation["checked_evaluation_files"], 12)
        self.assertFalse(common.read(CAPTURE / "CURRENT.json")["actual_consumer_use_verified"])

    def test_wrong_external_reference_or_release_join(self):
        admission = common.read(CAPTURE / "ADMISSION.json")
        release = admission["intake_release"]
        pins = admission["pins"]
        with self.assertRaisesRegex(ValueError, "retained reference"):
            plain.check_release(release, "b" * 64, pins)
        for key in ("candidate_sha256", "study_sha256", "freeze_sha256", "request_sha256"):
            changed = dict(release, **{key: "b" * 64})
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, "retained reference"):
                plain.check_release(changed, common.digest(changed), pins)
        changed = dict(release, scope="owner_intake")
        with self.assertRaisesRegex(ValueError, "retained reference"):
            plain.check_release(changed, admission["intake_release_sha256"], pins)
        changed = dict(release, scope="external_customer")
        with self.assertRaisesRegex(ValueError, "unknown intake scope"):
            plain.check_release(changed, common.digest(changed), pins)
        changed = dict(release, real_human=True)
        with self.assertRaisesRegex(ValueError, "release shape"):
            plain.check_release(changed, common.digest(changed), pins)

    def test_mutated_scope_catalog_or_exact_request_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(CAPTURE, root, dirs_exist_ok=True, ignore=shutil.ignore_patterns("node", "*.sqlite"))
            catalog = root / common.read(root / "SOURCE.json")["catalog"]["path"]
            original = catalog.read_bytes()
            catalog.write_bytes(original + b" ")
            with self.assertRaisesRegex(ValueError, "catalog differs"):
                common.verify(root)
            catalog.write_bytes(original)
            req = root / "PAIRED_INPUT.json"
            req.write_bytes(req.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "original paired request"):
                common.verify(root)
        admission = common.read(CAPTURE / "ADMISSION.json")
        changed = copy.deepcopy(common.read(CAPTURE / "evaluation/RESULT.json"))
        changed["prospective_arrival_authenticated"] = True
        with self.assertRaisesRegex(ValueError, "unqualified paired result"):
            plain.check_plain_result(changed, admission)


class CandidateManifestExposureTests(unittest.TestCase):
    def test_private_inline_commitment_is_verified_without_exporting_training_records(self):
        exposure = dict(schema="hepta.paired-learning.source-exposure.v1", registered_catalogs=[],
                        record_digests=["a" * 64], known_prompt_hashes=["b" * 64],
                        input_ids_sha256=["c" * 64], source_keys=["d" * 64])
        frozen = dict(candidate={"paired_source_exposure": exposure})
        with tempfile.TemporaryDirectory() as name:
            job = Path(name)
            local = job / "FROZEN.json"
            common.record(local, frozen)
            first = common.digest(frozen)
            entry = plain.catalog_snapshot(job, job, first)
            self.assertEqual(entry, {"manifest_exposure_sha256": common.digest(exposure)})
            plain.check_catalog(job, entry, first)
            with self.assertRaisesRegex(ValueError, "exposure commitment differs"):
                plain.check_catalog(job, {"manifest_exposure_sha256": "e" * 64}, first)
            with self.assertRaisesRegex(ValueError, "exposure commitment differs"):
                plain.check_catalog(job, {}, first)
            exposure["known_prompt_hashes"] = ["f" * 64]
            local.write_bytes(common.canonical(frozen))
            with self.assertRaisesRegex(ValueError, "immutable source freeze"):
                plain.check_catalog(job, entry, first)
            with self.assertRaisesRegex(ValueError, "exposure commitment differs"):
                plain.check_catalog(job, entry, common.digest(frozen))

    def test_missing_or_unbound_exposure_refuses(self):
        with tempfile.TemporaryDirectory() as name:
            job = Path(name)
            frozen = {"candidate": {}}
            common.record(job / "FROZEN.json", frozen)
            freeze = common.digest(frozen)
            with self.assertRaisesRegex(ValueError, "missing or ambiguous exposure"):
                plain.catalog_snapshot(job, job, freeze)
            with self.assertRaisesRegex(ValueError, "unbound manifest exposure"):
                plain.check_catalog(job, {"manifest_exposure_sha256": "a" * 64}, freeze)


if __name__ == "__main__":
    unittest.main()
