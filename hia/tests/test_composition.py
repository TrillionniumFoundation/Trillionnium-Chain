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

    def nested_component(self):
        component = ENTRY.replace(b"fn f0(", b"fn middle(")
        (self.root / "src/component.hepta").write_bytes(component)
        (self.root / "src/entry.hepta").write_bytes(
            ENTRY.replace(b'"function":"helper"', b'"function":"middle"'))
        self.manifest["includes"]["src/component.hepta"] = [
            {"source": "src/dependency.hepta", "functions": ["helper"]}]
        self.manifest["includes"]["src/entry.hepta"] = [
            {"source": "src/component.hepta", "functions": ["middle"]},
            {"source": "src/dependency.hepta", "functions": ["helper"]}]
        self.save()

    def test_component_is_independently_admitted_but_caller_still_names_every_function(self):
        from hepta.hia_agent_assembly import assemble_program
        self.nested_component()
        wire, inputs = self.compose()
        checked = assemble_program(wire)
        self.assertEqual([fn["name"] for fn in checked.as_dict()["functions"]],
                         ["f0", "middle", "helper"])
        self.assertEqual([p.name for p, _ in inputs],
                         ["entry.hepta", "components.json", "component.hepta", "dependency.hepta"])
        self.assertEqual(inputs[-1][1], GOOD)

    def test_nested_admission_does_not_supply_a_missing_caller_callee(self):
        from hepta.hia_agent_assembly import assemble_program
        self.nested_component()
        self.manifest["includes"]["src/entry.hepta"].pop()
        self.save()
        wire, inputs = self.compose()
        self.assertIn(self.root / "src/dependency.hepta", [p for p, _ in inputs])
        self.assertNotIn(b"fn helper(", wire)
        with self.assertRaises(ValueError):
            assemble_program(wire)

    def test_imported_functions_cannot_be_selected_as_component_owned_exports(self):
        self.nested_component()
        self.manifest["includes"]["src/entry.hepta"] = [
            {"source": "src/component.hepta", "functions": ["middle", "helper"]}]
        self.save()
        with self.assertRaisesRegex(ValueError, "Unknown or duplicate"):
            self.compose()

    def test_even_unselected_component_functions_must_pass_original_core(self):
        self.nested_component()
        path = self.root / "src/component.hepta"
        path.write_bytes(path.read_bytes() + GOOD[GOOD.index(b"fn helper("):]
                         .replace(b"fn helper(", b"fn unused(").replace(b"ret(v0)", b"ret(missing)"))
        with self.assertRaises(ValueError):
            self.compose()

    def test_nested_source_cannot_change_its_declared_callee_contract(self):
        self.nested_component()
        (self.root / "src/dependency.hepta").write_bytes(
            GOOD.replace(b"u32", b"u64"))
        with self.assertRaises(ValueError):
            self.compose()

    def test_nested_declarations_keep_path_symlink_and_cycle_refusals(self):
        self.nested_component()
        (self.root / "src/alias.hepta").symlink_to(self.root / "src/dependency.hepta")
        for source in ("src/../src/dependency.hepta", "src/alias.hepta", "src/entry.hepta"):
            with self.subTest(source=source):
                self.manifest["includes"]["src/component.hepta"] = [
                    {"source": source, "functions": ["helper"]}]
                self.save()
                with self.assertRaises(ValueError):
                    self.compose()

    def test_duplicate_symbol_is_not_hidden_by_independent_component_admission(self):
        self.nested_component()
        self.manifest["includes"]["src/entry.hepta"].append(
            {"source": "src/dependency.hepta", "functions": ["helper"]})
        self.save()
        with self.assertRaisesRegex(ValueError, "Unknown or duplicate"):
            self.compose()

    def test_build_rechecks_a_source_used_only_for_dependency_admission(self):
        from hepta.hia_program_native import build_program_machine
        self.nested_component()
        # Middle's unselected function needs helper for independent admission;
        # the caller itself selects an identity function and no helper bytes.
        component = self.root / "src/component.hepta"
        component.write_bytes(component.read_bytes() + GOOD[GOOD.index(b"fn helper("):]
                              .replace(b"fn helper(", b"fn identity("))
        (self.root / "src/entry.hepta").write_bytes(
            ENTRY.replace(b'"function":"helper"', b'"function":"identity"'))
        self.manifest["includes"]["src/entry.hepta"] = [
            {"source": "src/component.hepta", "functions": ["identity"]}]
        self.save()

        def emit_then_change(*args, **kwargs):
            result = build_program_machine(*args, **kwargs)
            (self.root / "src/dependency.hepta").write_bytes(GOOD + b"\n")
            return result

        with patch("hepta.hia_program_native.build_program_machine", side_effect=emit_then_change):
            with self.assertRaisesRegex(ValueError, "changed during build"):
                toolchain.build_native(self.root / "src/entry.hepta",
                    self.root / "candidate.o", backend="direct", kind="object")

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
