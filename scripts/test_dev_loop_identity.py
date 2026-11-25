"""Cross-reader vectors and refusal of retargeted or historical loop evidence."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dev_circuit_evaluation import digest, prepare
import dev_intake_evaluation as intake
import dev_loop_identity as loop


class LoopIdentityTests(unittest.TestCase):
    def setUp(self):
        # Deliberately an engineering shape, never a human or execution receipt.
        parent = dict(schema="hepta.experimental-model.v1", family="test-model-family",
                      parent=None, runtime={"threads": 1}, files=[{"sha256": "a" * 64}])
        candidate = dict(parent, parent=digest(parent), files=[{"sha256": "b" * 64}])
        self.frozen = dict(schema="hepta.paired-cold.freeze.v1", parent=parent, candidate=candidate,
                           retention=[{"test": "old"}], timeout_seconds=12)
        self.request = dict(self.frozen, schema="hepta.paired-cold.request.v1", future=[{"test": "unseen"}])
        self.release = dict(schema="hepta.paired-intake.release.v1", scope="engineering_fixture",
                            study_sha256="1" * 64, admission_sha256="2" * 64,
                            freeze_sha256=digest(self.frozen), request_sha256=digest(self.request),
                            candidate_sha256=digest(candidate))
        self.runtime = dict(package_sha256="3" * 64, executable_sha256="4" * 64, python="test-runtime",
                            packages={p: "test-version" for p in loop.PACKAGES},
                            dependency_identity_kind="installed_versions_only", runtime_closure_complete=False)
        self.identity = dict(schema="hepta.paired-learning.loop-identity.v1", release=self.release,
            release_sha256=digest(self.release), family=parent["family"], model_schema=parent["schema"],
            parent_sha256=digest(parent), candidate_sha256=digest(candidate),
            source_exposure_sha256=digest(None), router_sha256=digest(None),
            model_runtime_sha256=digest({a: self.request[a]["runtime"] for a in ("parent", "candidate")}),
            evaluation_sha256=digest({k: self.request[k] for k in ("future", "retention", "timeout_seconds")}),
            native_consent_sha256="5" * 64, implementation=self.runtime)
        self.pin = digest(self.identity)

    def check(self, identity=None, **kwargs):
        return loop.validate(identity or self.identity, self.pin, self.release, self.request, self.frozen, **kwargs)

    def test_matching_reader_and_actual_runtime(self):
        self.assertEqual(self.check(runtime=self.runtime), self.pin)
        self.assertFalse(self.identity["implementation"]["runtime_closure_complete"])

    def test_retargeted_release_is_rejected_even_if_its_own_digest_is_recomputed(self):
        for key in ("study_sha256", "admission_sha256", "freeze_sha256", "candidate_sha256", "request_sha256"):
            with self.subTest(key=key):
                new = copy.deepcopy(self.identity)
                new["release"][key] = "f" * 64
                new["release_sha256"] = digest(new["release"])
                with self.assertRaises(ValueError):
                    loop.validate(new, digest(new), self.release, self.request, self.frozen)

    def test_each_executable_component_must_match_observed_runtime(self):
        for key in ("package_sha256", "executable_sha256", "python", "packages"):
            runtime = copy.deepcopy(self.runtime)
            runtime[key] = {"torch": "different"} if key == "packages" else "different"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "actual source"):
                self.check(runtime=runtime)

    def test_no_namespace_or_claim_upgrade(self):
        for key, value in (("router_sha256", "9" * 64), ("evaluation_sha256", "8" * 64),
                           ("family", "hepta-neuron-q24"), ("source_exposure_sha256", "7" * 64)):
            new = copy.deepcopy(self.identity)
            new[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                loop.validate(new, digest(new), self.release, self.request, self.frozen)
        new = copy.deepcopy(self.identity)
        new["implementation"]["runtime_closure_complete"] = True
        with self.assertRaisesRegex(ValueError, "identity scope"):
            loop.validate(new, digest(new), self.release, self.request, self.frozen)

    def test_v1_study_guard_stays_fixed_and_v2_requires_explicit_study(self):
        pins = {k: self.release[k + "_sha256"] for k in ("request", "candidate", "freeze")}
        with self.assertRaisesRegex(ValueError, "study"):
            intake.check_release(self.release, digest(self.release), pins, self.request["candidate"])
        intake.check_release(self.release, digest(self.release), pins, self.request["candidate"],
                             expected_study=self.release["study_sha256"])

    def test_incomplete_bound_request_refused_before_snapshot_or_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            with self.assertRaisesRegex(ValueError, "both loop identity"):
                prepare(folder, folder, folder, {}, loop_identity=self.identity)
            self.assertEqual(list(folder.iterdir()), [])
            with self.assertRaisesRegex(ValueError, "original intake"):
                prepare(folder, folder, folder, {}, loop_identity=self.identity, expected_loop=self.pin)
            self.assertEqual(list(folder.iterdir()), [])

    def test_historical_paid_evaluation_cannot_acquire_v2_consumer_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / "ADMISSION.json").write_text(json.dumps({"schema": intake.ADMISSION}))
            readback = dict(schema="hepta.paired-learning.loop-readback.v1", loop_sha256=self.pin,
                            loop_identity=self.identity)
            with self.assertRaisesRegex(ValueError, "bound v2"):
                loop.join_readback(folder, readback, digest(readback))

    def test_complete_inputs_with_runtime_mismatch_refuse_before_model_preflight(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job, materials, source = (root / name for name in ("job", "materials", "source"))
            for folder in (job, materials, source / "scripts/cell_experiments", source / "qualification/exposures"):
                folder.mkdir(parents=True)
            (materials / "FROZEN.json").write_text(json.dumps(self.frozen))
            (materials / "paired.json").write_text(json.dumps(self.request))
            (source / "scripts/cell_experiments/paired_cold.py").write_text("# must never execute\n")
            (source / "qualification/exposures/prospective-exposures.json").write_text(
                json.dumps({"freeze_sha256": self.release["freeze_sha256"]}))
            pins = {key: self.release[key + "_sha256"] for key in ("request", "candidate", "freeze")}
            wrong_runtime = dict(self.runtime, executable_sha256="f" * 64)
            with patch.object(loop, "runtime_identity", return_value=wrong_runtime), \
                 patch.object(intake, "preflight") as execute:
                with self.assertRaisesRegex(ValueError, "actual source"):
                    prepare(job, materials, source, pins, intake=self.release,
                            loop_identity=self.identity, expected_loop=self.pin)
            execute.assert_not_called()
            self.assertFalse((job / "ADMISSION.json").exists())
            self.assertFalse((job / "RESERVATION.json").exists())


if __name__ == "__main__":
    unittest.main()
