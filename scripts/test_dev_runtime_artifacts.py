"""Artifact-bound admission controls using real files and synthetic package metadata."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import dev_circuit_evaluation as evaluation
import dev_intake_evaluation as intake
import dev_loop_identity as loop
import dev_runtime_artifacts as artifacts
import test_dev_loop_identity as fixtures


class ArtifactBoundTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime_root = self.root / "installed"
        for name, content in (("pkg/module.py", b"x = 1\n"), ("metadata/RECORD", b"synthetic package inventory\n")):
            path = self.runtime_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.manifest = artifacts.snapshot(self.runtime_root, ["metadata", "pkg"])
        dist = Mock(files=[Path("pkg/module.py"), Path("metadata/RECORD")])
        dist.locate_file.side_effect = lambda path: self.runtime_root / path
        self.package = self.enterContext(patch.object(artifacts.importlib.metadata, "distribution", return_value=dist))
        self.enterContext(patch.object(loop.importlib.metadata, "version", return_value="fixture-version"))
        self.enterContext(patch.dict(os.environ, {"TRNM_DEV_RUNTIME_ARTIFACTS_ROOT": str(self.runtime_root)}))
        self.fixture = fixtures.LoopIdentityTests()
        self.fixture.setUp()
        self.source = self.root / "source"
        source_file = self.source / "scripts/cell_experiments/paired_cold.py"
        source_file.parent.mkdir(parents=True)
        source_file.write_bytes(b"# engineering preflight; no model execution\n")
        self.entries = evaluation.source_files(source_file.parent)
        self.runtime = loop.runtime_identity(self.entries, runtime_artifacts=self.manifest, artifact_root=self.runtime_root)
        self.identity = dict(self.fixture.identity, schema=loop.LOOP_V2, implementation=self.runtime)
        self.pin = evaluation.digest(self.identity)

    def validate(self):
        return loop.validate(self.identity, self.pin, self.fixture.release, self.fixture.request,
                             self.fixture.frozen, runtime=self.runtime)

    def prepare(self):
        job, materials = self.root / "job", self.root / "materials"
        job.mkdir()
        materials.mkdir()
        evaluation.record(materials / "FROZEN.json", self.fixture.frozen)
        evaluation.record(materials / "paired.json", self.fixture.request)
        catalog = self.source / "qualification/exposure"
        catalog.mkdir(parents=True)
        evaluation.record(catalog / "prospective-exposures.json", {"freeze_sha256": self.fixture.release["freeze_sha256"]})
        pins = {key: self.fixture.release[key + "_sha256"] for key in ("request", "candidate", "freeze")}
        evaluation.prepare(job, materials, self.source, pins, intake=self.fixture.release,
                           loop_identity=self.identity, expected_loop=self.pin)
        return job

    def test_matching_artifact_identity_does_not_claim_complete_runtime(self):
        self.assertEqual(self.validate(), self.pin)
        self.assertFalse(self.identity["implementation"]["runtime_closure_complete"])
        self.assertEqual(loop.schemas(self.identity), (loop.ARTIFACT_ADMISSION, loop.ARTIFACT_DELIVERY))
        self.assertIn("dev_runtime_artifacts.py", loop.chain_sources(self.identity))

    def test_prepare_and_live_recheck_use_v3_and_actual_bytes(self):
        with patch.object(intake, "preflight") as preflight:
            job = self.prepare()
        preflight.assert_called_once()
        terms = evaluation.read(job / "ADMISSION.json")
        self.assertEqual(terms["schema"], loop.ARTIFACT_ADMISSION)
        self.assertEqual(loop.check_terms(job, terms, live=True), self.pin)
        (self.runtime_root / "pkg/module.py").write_bytes(b"x = 2\n")
        with self.assertRaisesRegex(ValueError, "bytes or inventory differ"):
            loop.check_terms(job, terms, live=True)
        # Retained comparison still makes no claim to reobserve this environment.
        self.assertEqual(loop.check_terms(job, terms), self.pin)

    def test_extra_unlisted_artifact_refuses_before_model_preflight(self):
        (self.runtime_root / "pkg/extra.py").write_bytes(b"extra")
        with patch.object(intake, "preflight") as preflight:
            with self.assertRaisesRegex(ValueError, "bytes or inventory differ"):
                self.prepare()
        preflight.assert_not_called()
        self.assertFalse((self.root / "job/ADMISSION.json").exists())

    def test_unrelated_copied_material_cannot_substitute_installed_distribution(self):
        self.package.return_value.locate_file.side_effect = lambda path: self.root / path
        for name in ("pkg/module.py", "metadata/RECORD"):
            outside = self.root / name
            outside.parent.mkdir(parents=True, exist_ok=True)
            outside.write_bytes(b"outside")
        with self.assertRaisesRegex(ValueError, "outside runtime material root"):
            loop.observed_runtime(self.entries, self.identity)

    def test_missing_root_namespace_downgrade_and_claim_upgrade_refuse(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "actual runtime material root"):
                loop.observed_runtime(self.entries, self.identity)
        changed = copy.deepcopy(self.identity)
        changed["schema"] = loop.LOOP_V1
        with self.assertRaisesRegex(ValueError, "identity scope"):
            loop.validate(changed, evaluation.digest(changed), self.fixture.release, self.fixture.request, self.fixture.frozen)
        changed = copy.deepcopy(self.identity)
        changed["implementation"]["runtime_closure_complete"] = True
        with self.assertRaisesRegex(ValueError, "identity scope"):
            loop.validate(changed, evaluation.digest(changed), self.fixture.release, self.fixture.request, self.fixture.frozen)

    def test_manifest_rejects_traversal_symlink_size_bool_and_duplicate_path(self):
        for mutate in (lambda m: m["files"][0].update(path="../outside"),
                       lambda m: m["files"][0].update(size=True),
                       lambda m: m["files"].append(m["files"][0])):
            changed = copy.deepcopy(self.manifest)
            mutate(changed)
            with self.assertRaises(ValueError):
                artifacts.validate(changed)
        (self.runtime_root / "pkg/link").symlink_to(self.runtime_root / "pkg/module.py")
        with self.assertRaisesRegex(ValueError, "symlinked"):
            artifacts.snapshot(self.runtime_root, ["metadata", "pkg"])

    def test_parent_replaced_at_leaf_open_never_opens_external_file(self):
        outside = self.root / "outside"
        outside.mkdir()
        external = outside / "module.py"
        external.write_bytes(b"external contents must not be opened")
        external_stat = external.stat()
        external_identity = (external_stat.st_dev, external_stat.st_ino)
        original_open, external_opens, swapped = artifacts.os.open, [], []

        def raced_open(path, flags, *, dir_fd=None):
            if Path(path).name == "module.py" and not swapped:
                package = self.runtime_root / "pkg"
                package.rename(self.runtime_root / "retained-pkg")
                package.symlink_to(outside, target_is_directory=True)
                swapped.append(True)
            descriptor = original_open(path, flags, dir_fd=dir_fd)
            observed = os.fstat(descriptor)
            if (observed.st_dev, observed.st_ino) == external_identity:
                external_opens.append(str(path))
            return descriptor

        with patch.object(artifacts.os, "open", side_effect=raced_open):
            with self.assertRaises((ValueError, OSError)):
                artifacts.snapshot(self.runtime_root, ["metadata", "pkg"])
        self.assertEqual(swapped, [True])
        self.assertEqual(external_opens, [])

    def test_missing_safe_directory_operations_refuses_before_open(self):
        with patch.object(artifacts, "SAFE_DIRECTORY_IO", False), patch.object(artifacts.os, "open") as opened:
            with self.assertRaisesRegex(ValueError, "safe descriptor-relative"):
                artifacts.snapshot(self.runtime_root, ["metadata", "pkg"])
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
