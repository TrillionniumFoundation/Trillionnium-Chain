"""Reject ambiguous or escaping source composition before native compilation."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from hia.tools import toolchain

GOOD = b'''hia-asm.v1 hepta.hia.program.v8 included
fn helper(v0:u32) -> (u32) effects(trap) entry(b0)
block b0(v0:u32)
  ret(v0)
end
'''
ENTRY = b'''hia-asm.v1 hepta.hia.program.v8 entry
fn f0(v0:u32) -> (u32) effects(trap) entry(b0)
block b0(v0:u32)
  v1:u32 = call(v0) {"function":"helper"}
  ret(v1)
end
'''


class CompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        toolchain.pinned_toolchain()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="trnm-hia-composition-")
        self.root = Path(self.directory.name)
        (self.root / "src").mkdir()
        (self.root / "src/entry.hepta").write_bytes(ENTRY)
        (self.root / "src/dependency.hepta").write_bytes(GOOD)
        self.manifest = {"schema": "trnm.hia.component-includes.v1", "includes": {
            "src/entry.hepta": [{"source": "src/dependency.hepta", "functions": ["helper"]}]}}
        self.setting = patch.object(toolchain, "HIA_ROOT", self.root)
        self.setting.start()
        self.save()

    def tearDown(self):
        self.setting.stop()
        self.directory.cleanup()

    def save(self):
        (self.root / "components.json").write_text(json.dumps(self.manifest))

    def compose(self):
        return toolchain.compose_source(self.root / "src/entry.hepta")

    def test_exact_inclusion_then_whole_program_admission(self):
        from hepta.hia_agent_assembly import assemble_program
        wire, inputs = self.compose()
        checked = assemble_program(wire)
        self.assertEqual([fn["name"] for fn in checked.as_dict()["functions"]], ["f0", "helper"])
        self.assertEqual([p.name for p, _ in inputs], ["entry.hepta", "components.json", "dependency.hepta"])
        self.assertTrue(wire.endswith(GOOD[GOOD.index(b"fn helper"):]))

    def test_unknown_duplicate_and_colliding_functions_refused(self):
        for names in (["absent"], ["helper", "helper"], ["f0"]):
            self.manifest["includes"]["src/entry.hepta"][0]["functions"] = names
            self.save()
            with self.assertRaises(ValueError):
                self.compose()

    def test_parent_absolute_alias_and_missing_paths_refused(self):
        for name in ("../outside.hepta", "/tmp/outside.hepta", "src/./dependency.hepta", "src/missing.hepta"):
            self.manifest["includes"]["src/entry.hepta"][0]["source"] = name
            self.save()
            with self.assertRaises(ValueError):
                self.compose()

    def test_symlink_dependency_refused_even_for_identical_bytes(self):
        (self.root / "src/alias.hepta").symlink_to(self.root / "src/dependency.hepta")
        self.manifest["includes"]["src/entry.hepta"][0]["source"] = "src/alias.hepta"
        self.save()
        with self.assertRaises(ValueError):
            self.compose()

    def test_recursive_include_refused(self):
        self.manifest["includes"]["src/dependency.hepta"] = [
            {"source": "src/entry.hepta", "functions": ["f0"]}]
        self.save()
        with self.assertRaises(ValueError):
            self.compose()

    def test_duplicate_manifest_key_and_invalid_dependency_refused(self):
        (self.root / "components.json").write_text('{"schema":"x","schema":"y","includes":{}}')
        with self.assertRaises(ValueError):
            self.compose()
        self.save()
        (self.root / "src/dependency.hepta").write_bytes(GOOD.replace(b"ret(v0)", b"ret(missing)"))
        with self.assertRaises(ValueError):
            self.compose()

    def test_no_implicit_resolution(self):
        from hepta.hia_agent_assembly import assemble_program
        self.manifest["includes"] = {}
        self.save()
        wire, _ = self.compose()
        with self.assertRaises(ValueError):
            assemble_program(wire)

    def test_native_owner_roots_use_the_same_explicit_composition(self):
        from hepta.hia_agent_assembly import assemble_program
        for prefix in ("platform", "storage"):
            with self.subTest(prefix=prefix):
                (self.root / prefix).mkdir()
                entry = self.root / prefix / "entry.hepta"
                entry.write_bytes(ENTRY)
                self.manifest["includes"][prefix + "/entry.hepta"] = [
                    {"source": "src/dependency.hepta", "functions": ["helper"]}]
                self.save()
                wire, inputs = toolchain.compose_source(entry)
                checked = assemble_program(wire)
                self.assertEqual([fn["name"] for fn in checked.as_dict()["functions"]], ["f0", "helper"])
                self.assertEqual(inputs[0][0], entry)
                self.assertEqual(inputs[-1][0], self.root / "src/dependency.hepta")

    def test_source_roots_do_not_admit_other_directories_or_types(self):
        for prefix in ("qualification", "tests", "tools", "src_other", "storage_other", "platform_other"):
            (self.root / prefix).mkdir()
            (self.root / prefix / "dependency.hepta").write_bytes(GOOD)
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                toolchain._source_path(prefix + "/dependency.hepta")
        for value in (None, 1, [], {}, "storage/../src/dependency.hepta", "platform//entry.hepta"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                toolchain._source_path(value)

    def test_native_owner_roots_keep_component_and_parent_symlink_refusal(self):
        (self.root / "storage").mkdir()
        (self.root / "storage/alias.hepta").symlink_to(self.root / "src/dependency.hepta")
        with self.assertRaises(ValueError):
            toolchain._source_path("storage/alias.hepta")
        (self.root / "platform").symlink_to(self.root / "src", target_is_directory=True)
        with self.assertRaises(ValueError):
            toolchain._source_path("platform/dependency.hepta")


if __name__ == "__main__":
    unittest.main()
