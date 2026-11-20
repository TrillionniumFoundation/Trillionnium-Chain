"""Capture/readback refusals for generated native fixture source provenance.

These controls construct source/receipt fixtures. Actual compiled execution is
covered by TransferNativeTests.test_sha256_full_domain_counter_bounds_and_prewrite_refusal.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hia.tests.native_support import NativeModule, unlinked_path
from hia.tools import qualify, toolchain
from hia.tools import qualify_components_ci as ci
from hia.tests.test_component_partition import complete_report, IDS, LINEAGE, COMPILER
from hia.tools.component_partition import object_hash


class GeneratedFixtureProvenance(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="trnm-generated-provenance-")
        self.base = Path(self.directory.name)
        self.repo = self.base / "repo"
        self.generated = self.base / "generated"
        self.owner = self.repo / "hia/tests/test_owner.py"
        self.entry = self.generated / "src/generated_probe.hepta"
        self.dependency_name = "src/crypto/dependency.hepta"
        self.dependency = self.repo / "hia" / self.dependency_name
        self.canonical_entry = self.repo / "hia/src/canonical.hepta"
        self.fixture_bytes = b"hia-asm.v1 hepta.hia.program.v8 fixture\n"
        self.dependency_bytes = b"hia-asm.v1 hepta.hia.program.v8 dependency\n"
        manifest = {"schema": "trnm.hia.component-includes.v1", "includes": {
            "src/generated_probe.hepta": [{"source": self.dependency_name, "functions": ["helper"]}]}}
        self.generated_bytes = {
            "src/generated_probe.hepta": self.fixture_bytes,
            "components.json": json.dumps(manifest).encode(),
            self.dependency_name: self.dependency_bytes,
        }
        canonical = {"hia/tests/test_owner.py": b"# Bound source of the generated probe.\n",
                     "hia/src/canonical.hepta": b"hia-asm.v1 hepta.hia.program.v8 canonical\n",
                     "hia/" + self.dependency_name: self.dependency_bytes,
                     "hia/components.json": b'{"schema":"trnm.hia.component-includes.v1","includes":{}}\n'}
        for name, raw in canonical.items():
            self.write(self.repo / name, raw)
        for name, raw in self.generated_bytes.items():
            self.write(self.generated / name, raw)
        self.sources = {name: qualify.digest(raw) for name, raw in canonical.items()}
        self.migration = {"backend": "selfhost", "source_sha256": qualify.digest(self.fixture_bytes),
                          "inputs": [{"path": name, "sha256": qualify.digest(raw)}
                                     for name, raw in self.generated_bytes.items()]}
        self.module = SimpleNamespace(source=self.entry, source_root=self.generated,
                                      fixture_owner=self.owner, receipt={"chain_migration": self.migration})
        self.setting = patch.object(qualify, "ROOT", self.repo)
        self.setting.start()

    def tearDown(self):
        self.setting.stop()
        self.directory.cleanup()

    @staticmethod
    def write(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def capture(self, module=None):
        module = self.module if module is None else module
        provenance = qualify.build_provenance(module, self.sources)
        return {**provenance, "chain_migration": copy.deepcopy(module.receipt["chain_migration"]),
                "compiler_sha256": COMPILER["compiler_sha256"]}

    def canonical_module(self):
        names = ["src/canonical.hepta", "components.json", self.dependency_name]
        rows = [{"path": name, "sha256": self.sources["hia/" + name]} for name in names]
        return SimpleNamespace(source=self.canonical_entry, source_root=self.repo / "hia",
                               fixture_owner=None, receipt={"chain_migration": {
                                   "backend": "selfhost", "source_sha256": rows[0]["sha256"],
                                   "inputs": rows}})

    def test_generated_capture_keeps_actual_bytes_and_explicit_owner(self):
        build = self.capture()
        self.assertIsNone(build["source"])
        fixture = build["generated_fixture"]
        self.assertEqual(fixture["owner"], "hia/tests/test_owner.py")
        self.assertEqual(fixture["owner_sha256"], self.sources[fixture["owner"]])
        self.assertEqual(fixture["entry"], "src/generated_probe.hepta")
        self.assertEqual({row["path"]: row["utf8"].encode() for row in fixture["inputs"]}, self.generated_bytes)
        qualify.validate_generated_fixture(build, self.sources)
        qualify.validate_build_provenance(build, self.sources)
        self.assertEqual(json.loads(json.dumps(build)), build)

    def test_capture_refuses_missing_unbound_changed_and_external_owner(self):
        original = self.module.fixture_owner
        self.module.fixture_owner = None
        with self.assertRaisesRegex(ValueError, "bound test owner"):
            self.capture()
        self.module.fixture_owner = original
        owner_sha = self.sources.pop("hia/tests/test_owner.py")
        with self.assertRaises(ValueError):
            self.capture()
        self.sources["hia/tests/test_owner.py"] = owner_sha
        raw = self.owner.read_bytes()
        self.owner.write_bytes(raw + b"# changed after source map\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.capture()
        self.owner.write_bytes(raw)
        outsider = self.base / "unbound_owner.py"
        outsider.write_bytes(raw)
        self.module.fixture_owner = outsider
        with self.assertRaisesRegex(ValueError, "outside"):
            self.capture()

    def test_capture_refuses_input_mutation_and_changed_canonical_dependency(self):
        for name, raw in self.generated_bytes.items():
            path = self.generated / name
            path.write_bytes(raw + b"\nmutation\n")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "changed"):
                self.capture()
            path.write_bytes(raw)
        self.dependency.write_bytes(self.dependency_bytes + b"changed canonical bytes\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.capture()
        self.dependency.write_bytes(self.dependency_bytes)
        # A copied dependency and a coherently changed receipt still cannot
        # replace the bound canonical dependency used by this checkout.
        changed = self.dependency_bytes + b"changed copy\n"
        (self.generated / self.dependency_name).write_bytes(changed)
        self.migration["inputs"][-1]["sha256"] = qualify.digest(changed)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.capture()

    def test_capture_refuses_symlinked_source_owner_dependency_or_root(self):
        paths = [self.entry, self.owner, self.generated / self.dependency_name, self.dependency]
        for index, path in enumerate(paths):
            raw = path.read_bytes()
            backing = self.base / f"backing-{index}"
            backing.write_bytes(raw)
            path.unlink()
            path.symlink_to(backing)
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "Linked"):
                self.capture()
            path.unlink()
            path.write_bytes(raw)
        linked_root = self.base / "linked-root"
        linked_root.symlink_to(self.generated, target_is_directory=True)
        self.module.source_root = linked_root
        self.module.source = linked_root / "src/generated_probe.hepta"
        with self.assertRaisesRegex(ValueError, "Linked"):
            self.capture()

    def test_native_module_does_not_resolve_away_link_or_traversal_before_build(self):
        link = self.generated / "src/linked.hepta"
        link.symlink_to(self.entry)
        with patch.object(toolchain, "HIA_ROOT", self.generated), patch.object(toolchain, "build_native") as compile:
            with self.assertRaisesRegex(ValueError, "Linked"):
                NativeModule(link, fixture_owner=self.owner)
            with self.assertRaisesRegex(ValueError, "Traversing"):
                NativeModule(self.generated / "src/../src/generated_probe.hepta", fixture_owner=self.owner)
            compile.assert_not_called()
        for value in ("./relative.hepta", "src//entry.hepta"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                unlinked_path(value)

    def test_readback_rejects_bad_entry_owner_paths_and_production_shadow(self):
        baseline = self.capture()
        paths = ("", ".", "../entry.hepta", "/tmp/entry.hepta", "src//entry.hepta",
                 "src/./entry.hepta", "src/../../entry.hepta", "src\\entry.hepta",
                 "components.json", "tests/entry.hepta", "src/entry.py", None, False)
        for name in paths:
            wrong = copy.deepcopy(baseline)
            wrong["generated_fixture"]["entry"] = name
            with self.subTest(entry=name), self.assertRaises(ValueError):
                qualify.validate_generated_fixture(wrong, self.sources)
        for owner in ("hia/tests/../owner.py", "hia/tools/owner.py", "hia/tests/owner.rs", "/tmp/owner.py"):
            wrong = copy.deepcopy(baseline)
            wrong["generated_fixture"]["owner"] = owner
            sources = {**self.sources, owner: wrong["generated_fixture"]["owner_sha256"]}
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                qualify.validate_generated_fixture(wrong, sources)
        wrong = copy.deepcopy(baseline)
        wrong["generated_fixture"]["entry"] = "src/canonical.hepta"
        wrong["generated_fixture"]["inputs"][0]["path"] = "src/canonical.hepta"
        wrong["chain_migration"]["inputs"][0]["path"] = "src/canonical.hepta"
        with self.assertRaisesRegex(ValueError, "shadows"):
            qualify.validate_generated_fixture(wrong, self.sources)
        wrong = copy.deepcopy(baseline)
        wrong["source"] = "hia/src/canonical.hepta"
        with self.assertRaises(ValueError):
            qualify.validate_build_provenance(wrong, self.sources)

    def test_readback_refuses_mutated_bytes_roster_receipt_and_dependency(self):
        baseline = self.capture()
        variants = []
        wrong = copy.deepcopy(baseline)
        wrong["generated_fixture"]["inputs"][0]["utf8"] += "changed"
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong["chain_migration"]["source_sha256"] = "0" * 64
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong["chain_migration"]["inputs"][0]["sha256"] = "0" * 64
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong["generated_fixture"]["inputs"].pop()
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong["generated_fixture"]["inputs"].append(copy.deepcopy(wrong["generated_fixture"]["inputs"][0]))
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong["chain_migration"]["inputs"].append(copy.deepcopy(wrong["chain_migration"]["inputs"][0]))
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong["generated_fixture"]["inputs"][-1]["path"] = "src/../../outside.hepta"
        wrong["chain_migration"]["inputs"][-1]["path"] = "src/../../outside.hepta"
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        row = wrong["generated_fixture"]["inputs"][-1]
        row["utf8"] += "altered production function"
        row["sha256"] = qualify.digest(row["utf8"].encode())
        wrong["chain_migration"]["inputs"][-1]["sha256"] = row["sha256"]
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong.pop("source")
        variants.append(wrong)
        for index, wrong in enumerate(variants):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                qualify.validate_build_provenance(wrong, self.sources)

    def test_canonical_builds_bind_complete_receipt_not_only_entry(self):
        module = self.canonical_module()
        build = self.capture(module)
        self.assertEqual(build["source"], "hia/src/canonical.hepta")
        self.assertNotIn("generated_fixture", build)
        qualify.validate_build_provenance(build, self.sources)
        for index in range(len(build["chain_migration"]["inputs"])):
            wrong = copy.deepcopy(build)
            wrong["chain_migration"]["inputs"][index]["sha256"] = "0" * 64
            with self.subTest(input=index), self.assertRaises(ValueError):
                qualify.validate_build_provenance(wrong, self.sources)
        self.dependency.write_bytes(self.dependency_bytes + b"changed\n")
        with self.assertRaisesRegex(ValueError, "changed"):
            self.capture(module)

    def test_component_readback_accepts_bound_fixture_and_rejects_its_mutants(self):
        report = complete_report("general")
        report["source_inputs"] = self.sources
        report["source_set_sha256"] = object_hash(self.sources)
        report["builds"] = [self.capture()]
        self.assertEqual(ci.validate_report(report, "general", LINEAGE, self.sources, IDS, COMPILER),
                         report["test_partition"]["selected_tests"])
        wrong = copy.deepcopy(report)
        wrong["builds"][0]["generated_fixture"]["inputs"][0]["utf8"] += "changed"
        with self.assertRaises(ValueError):
            ci.validate_report(wrong, "general", LINEAGE, self.sources, IDS, COMPILER)
        wrong = copy.deepcopy(report)
        wrong["builds"][0]["generated_fixture"]["owner_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            ci.validate_report(wrong, "general", LINEAGE, self.sources, IDS, COMPILER)

    def direct_fixture(self):
        module = self.canonical_module()
        output = self.base / "actual.so"
        output.write_bytes(b"actual bounded test artifact")
        receipt = {**module.receipt, "ok": True, "artifact_sha256": qualify.digest(output.read_bytes()),
                   "artifact_bytes": output.stat().st_size, "exports": ["f0"],
                   "compiler_sha256": COMPILER["compiler_sha256"]}
        return module, output, receipt

    def test_direct_canonical_build_binds_actual_output_and_full_source_closure(self):
        module, output, receipt = self.direct_fixture()
        record = qualify.direct_native_build_record(module.source, module.source_root,
                                                     output, receipt, self.sources)
        self.assertEqual(record["source"], "hia/src/canonical.hepta")
        self.assertEqual(record["artifact_sha256"], qualify.digest(output.read_bytes()))
        self.assertEqual(record["chain_migration"]["inputs"], receipt["chain_migration"]["inputs"])
        qualify.validate_build_provenance(record, self.sources)
        report = complete_report("oracle")
        report.update(source_inputs=self.sources, source_set_sha256=object_hash(self.sources), builds=[record])
        self.assertEqual(ci.validate_report(report, "oracle", LINEAGE, self.sources, IDS, COMPILER), [IDS[-1]])

    def test_direct_canonical_capture_refuses_changed_output_source_and_receipt(self):
        module, output, receipt = self.direct_fixture()
        def capture(current=receipt):
            return qualify.direct_native_build_record(module.source, module.source_root,
                                                       output, current, self.sources)
        for key, value in (("ok", 1), ("ok", False), ("artifact_sha256", "0" * 64),
                           ("artifact_bytes", True), ("artifact_bytes", output.stat().st_size + 1)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                capture({**receipt, key: value})
        raw = output.read_bytes()
        output.write_bytes(raw + b"changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            capture()
        output.write_bytes(raw)
        dependency = self.dependency.read_bytes()
        self.dependency.write_bytes(dependency + b"changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            capture()
        self.dependency.write_bytes(dependency)
        backing = self.base / "backing.so"
        backing.write_bytes(raw)
        output.unlink()
        output.symlink_to(backing)
        with self.assertRaisesRegex(ValueError, "Linked"):
            capture()


if __name__ == "__main__":
    unittest.main()
