#!/usr/bin/env python3
"""Negative controls for analysis completion, coverage and source attribution."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_pinned_codeql_analysis_v1 as reader


def sarif():
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.27.3"}},
        "automationDetails": {"id": "independent-artifact/example/python/code-scanning/"},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": [{
            "level": "none", "descriptor": {"id": "py/diagnostics/successfully-extracted-files"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "scripts/input.py"}}}]}]}],
        "results": []}]}


class AnalysisControls(unittest.TestCase):
    def assess(self, value):
        return reader.assess_sarif(value, "python", ["scripts/input.py"], Path("/source"),
                                   "independent-artifact/example/python/code-scanning")

    def test_complete_observation_never_qualifies_security(self):
        value = self.assess(sarif())
        self.assertTrue(value["extraction_coverage_complete"])
        self.assertEqual(value["finding_count"], 0)
        self.assertFalse(value["official_security_gate_qualified"])
        self.assertFalse(value["production_qualified"])

    def test_success_exit_and_zero_findings_do_not_cover_omitted_file(self):
        value = sarif()
        value["runs"][0]["invocations"][0]["toolExecutionNotifications"] = []
        result = self.assess(value)
        self.assertFalse(result["extraction_coverage_complete"])
        self.assertEqual(result["missing_tracked_inputs"], ["scripts/input.py"])

    def test_retained_warning_is_not_silently_turned_into_coverage(self):
        for level in ("warning", "error"):
            value = sarif()
            value["runs"][0]["invocations"][0]["toolExecutionNotifications"].append(
                {"level": level, "message": {"text": "semantic analyzer unavailable"}})
            with self.subTest(level=level):
                self.assertFalse(self.assess(value)["extraction_coverage_complete"])

    def test_findings_remain_findings_with_complete_extraction(self):
        value = sarif()
        value["runs"][0]["results"] = [{"ruleId": "py/example", "level": "error"}]
        result = self.assess(value)
        self.assertTrue(result["extraction_coverage_complete"])
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings_by_rule"], {"py/example": 1})
        self.assertFalse(result["official_security_gate_qualified"])

    def test_configuration_failure_cannot_hide_behind_successful_execution(self):
        value = sarif()
        value["runs"][0]["invocations"][0]["toolConfigurationNotifications"] = [
            {"level": "error", "message": {"text": "query configuration failed"}}]
        result = self.assess(value)
        self.assertFalse(result["extraction_coverage_complete"])
        self.assertEqual(len(result["error_diagnostics"]), 1)

    def test_unknown_diagnostic_severity_is_not_ignored(self):
        value = sarif()
        value["runs"][0]["invocations"][0]["toolExecutionNotifications"].append(
            {"level": "unexpected", "message": {"text": "unparsed diagnostic"}})
        with self.assertRaisesRegex(ValueError, "unknown diagnostic level"):
            self.assess(value)

    def test_cpp_components_need_actual_generated_extraction(self):
        # Pure association control: the real compilation-context reader is
        # tested independently on retained native artifacts, not fabricated here.
        build = reader.cpp_build
        tracked = [build.SPAWN, build.RETIREMENT, build.WITNESS]
        generated = "/artifacts/build/kernel-owned-original.c"
        mapping = {"generated_path": generated,
                   "components": [{"source": build.SPAWN}, {"source": build.RETIREMENT}]}
        for locations, expected_missing in (
                ([build.WITNESS], [build.SPAWN, build.RETIREMENT]),
                ([generated], [build.WITNESS]),
                ([build.WITNESS, "/different/kernel-owned-original.c"], [build.SPAWN, build.RETIREMENT]),
                ([build.WITNESS, generated], [])):
            value = sarif()
            run = value["runs"][0]
            run["automationDetails"]["id"] = "cpp/example/"
            entry = run["invocations"][0]["toolExecutionNotifications"][0]
            entry["descriptor"]["id"] = "cpp/diagnostics/successfully-extracted-files"
            entry["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": path}}} for path in locations]
            with self.subTest(locations=locations), patch.object(build, "validate_context", return_value=mapping) as validate:
                result = reader.assess_sarif(value, "cpp", tracked, Path("/source"), "cpp/example", {}, Path("/artifacts/build"))
                validate.assert_called_once()
                self.assertEqual(result["missing_tracked_inputs"], sorted(expected_missing))
                self.assertEqual(result["extraction_coverage_complete"], not expected_missing)
                self.assertFalse(result["official_security_gate_qualified"])

    def test_cpp_original_combination_and_path_sensitive_refusal(self):
        build = reader.cpp_build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / build.SPAWN).write_bytes(b"first\n")
            (root / build.RETIREMENT).write_bytes(b"second\n")
            joined, components = build.combined(root)
            self.assertEqual(joined, b"first\n\nsecond\n")
            self.assertEqual(components[1]["byte_start"], 7)
            self.assertEqual(components[1]["line_start"], 3)
            for macro in ("__FILE__", "__BASE_FILE__", "__FILE_NAME__", "__LINE__"):
                (root / build.RETIREMENT).write_text(macro)
                with self.subTest(macro=macro), self.assertRaisesRegex(ValueError, "input identity"):
                    build.combined(root)

    def test_cpp_recipe_owners_are_reviewed_original_bytes(self):
        pins = reader.cpp_build.inputs(reader.ROOT)
        self.assertEqual(set(pins), set(reader.cpp_build.OWNERS)
                         | {reader.cpp_build.SPAWN, reader.cpp_build.RETIREMENT, reader.cpp_build.WITNESS})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.c"
            target = Path(temporary) / "target.c"
            target.write_text("int x;\n")
            path.symlink_to(target)
            with self.assertRaises(OSError):
                reader.cpp_build.raw(path)

    def test_cpp_context_cannot_drop_or_fail_metadata_phase(self):
        # Synthetic schema control only. Real C context/ELF/log observations are
        # produced by the separate compiler owner, not by this mocked fixture.
        build = reader.cpp_build
        root, output, include = Path("/source"), Path("/artifacts/cpp"), Path("/dependency/sqlite3")
        fp = {"bytes": 1, "sha256": "0" * 64}
        recipes = build.commands(root, output, include)
        phase_commands = {"compiler-version": ["/usr/bin/cc", "--version"],
                          "cargo-metadata": ["cargo", "+1.95.0", "metadata", "--locked", "--format-version=1",
                                             "--manifest-path", str(root / "trillionnium/Cargo.toml")], **recipes}
        phases = [{"name": name, "argv": argv, "complete": True, "returncode": 0,
                   "stdout": fp, "stderr": fp} for name, argv in phase_commands.items()]
        context = {"schema": "pon-pinned-codeql-cpp-context-v1", "source_root": str(root),
                   "output": str(output), "complete": True, "inputs_before": {}, "inputs_after": {},
                   "components": [], "generated": fp, "sqlite_dependency": {"include": str(include)},
                   "phases": phases, "outputs": {name: fp for name in recipes},
                   "compilations": {row["name"]: {k: v for k, v in row.items() if k != "name"}
                                    for row in phases if row["name"] in recipes},
                   "runtime_build_qualified": False, "native_code_executed": False}
        with (patch.object(build, "inputs", return_value={}),
              patch.object(build, "combined", return_value=(b"x", [])),
              patch.object(build, "fingerprint", return_value=fp),
              patch.object(build, "raw", side_effect=lambda p, *a: b"{}" if p.name.endswith(".log") else b"x"),
              patch.object(build, "sqlite_dependency", return_value=(include, {}))):
            build.validate_context(context, root, output)
            mutations = [lambda v: v.update(phases=[]),
                         lambda v: v["phases"].reverse(),
                         lambda v: v["phases"][1].update(complete=False),
                         lambda v: v["phases"][1].update(returncode=1),
                         lambda v: v["phases"][1].update(returncode=True),
                         lambda v: v["phases"][1].update(argv=["different-cargo"])]
            for mutate in mutations:
                changed = copy.deepcopy(context)
                mutate(changed)
                with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, "C build phase"):
                    build.validate_context(changed, root, output)

    def test_cpp_source_copy_checks_original_and_copy_again(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / "original", root / "scope/project"
            (source / "nested").mkdir(parents=True)
            (source / "first.c").write_bytes(b"first\n")
            (source / "nested/second.c").write_bytes(b"second\n")
            tracked = ["first.c", "nested/second.c"]
            before = reader.cpp_source_copy(source, destination, tracked, create=True)
            self.assertEqual(before, reader.cpp_source_copy(source, destination, tracked))
            (destination / "first.c").write_bytes(b"other\n")
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                reader.cpp_source_copy(source, destination, tracked)
            (destination / "first.c").write_bytes(b"first\n")
            (destination / "untracked.c").write_text("extra")
            with self.assertRaisesRegex(ValueError, "extra files"):
                reader.cpp_source_copy(source, destination, tracked)

    def test_cpp_copy_rejects_symlinks_and_escaped_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "original"
            source.mkdir()
            (source / "target.c").write_text("int x;\n")
            (source / "link.c").symlink_to(source / "target.c")
            for number, paths in enumerate((["link.c"], ["../outside.c"], ["target.c", "target.c"])):
                with self.subTest(paths=paths), self.assertRaises(ValueError):
                    reader.cpp_source_copy(source, root / f"copy-{number}", paths, create=True)

    def test_cpp_narrow_scope_maps_only_the_bound_project_and_generated_unit(self):
        build = reader.cpp_build
        scope, project, output = Path("/scope"), Path("/scope/project"), Path("/scope/build")
        mapping = {"generated_path": "/scope/build/kernel-owned-original.c",
                   "components": [{"source": build.SPAWN}, {"source": build.RETIREMENT}]}
        value = sarif()
        run = value["runs"][0]
        run["automationDetails"]["id"] = "cpp/scope/"
        run["originalUriBaseIds"] = {"%SRCROOT%": {"uri": "file:///scope/"}}
        entry = run["invocations"][0]["toolExecutionNotifications"][0]
        entry["descriptor"]["id"] = "cpp/diagnostics/successfully-extracted-files"
        entry["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}}
                              for uri in ("project/" + build.WITNESS, "build/kernel-owned-original.c")]
        with patch.object(build, "validate_context", return_value=mapping):
            result = reader.assess_sarif(value, "cpp", [build.SPAWN, build.RETIREMENT, build.WITNESS],
                                        project, "cpp/scope", {}, output, scope)
            self.assertEqual(result["successful_tracked_inputs"], 3)
            self.assertEqual(result["direct_successful_tracked_inputs"], 1)
            self.assertEqual(len(result["composed_successful_tracked_inputs"]), 2)
            run["originalUriBaseIds"]["%SRCROOT%"]["uri"] = "file:///foreign/scope/"
            with self.assertRaisesRegex(ValueError, "base changed"):
                reader.assess_sarif(value, "cpp", [build.SPAWN, build.RETIREMENT, build.WITNESS],
                                    project, "cpp/scope", {}, output, scope)

    def test_foreign_uri_base_cannot_relabel_another_source_tree(self):
        for base in ("%FOREIGN%", "%SRCROOT%"):
            value = sarif()
            run = value["runs"][0]
            location = run["invocations"][0]["toolExecutionNotifications"][0]["locations"][0]
            location["physicalLocation"]["artifactLocation"]["uriBaseId"] = base
            run["originalUriBaseIds"] = {base: {"uri": "file:///different/source/"}}
            with self.subTest(base=base), self.assertRaisesRegex(ValueError, "source base"):
                self.assess(value)
        value = sarif()
        run = value["runs"][0]
        location = run["invocations"][0]["toolExecutionNotifications"][0]["locations"][0]
        location["physicalLocation"]["artifactLocation"]["uriBaseId"] = "%SRCROOT%"
        run["originalUriBaseIds"] = {"%SRCROOT%": {"uri": "file:///source/"}}
        self.assertTrue(self.assess(value)["extraction_coverage_complete"])

    def test_incomplete_or_missing_invocation_is_rejected(self):
        for changed in ([], [{"executionSuccessful": False}], [{"executionSuccessful": 1}]):
            value = sarif()
            value["runs"][0]["invocations"] = changed
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "invocation incomplete"):
                self.assess(value)

    def test_wrong_source_category_tool_and_extra_run_rejected(self):
        mutations = [lambda v: v["runs"][0]["automationDetails"].update(id="other/source/"),
                     lambda v: v["runs"][0]["tool"]["driver"].update(semanticVersion="2.0.0"),
                     lambda v: v["runs"].append(copy.deepcopy(v["runs"][0]))]
        for mutate in mutations:
            value = sarif()
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.assess(value)

    def test_other_source_root_does_not_fill_current_coverage(self):
        value = sarif()
        entry = value["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
        entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "file:///different/scripts/input.py"
        self.assertFalse(self.assess(value)["extraction_coverage_complete"])
        for uri in ("https://example.invalid/source.py", "file://remote/source/scripts/input.py",
                    "../scripts/input.py", "%2e%2e/scripts/input.py"):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                reader.source_uri(uri, Path("/source"))

    def test_duplicate_json_and_nonfinite_rejected(self):
        for raw in ('{"runs":[],"runs":[1]}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                reader.parsed(raw)

    def test_query_output_coverage_and_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pack = root / "qlpacks/codeql/python-queries/1.8.13"
            query = pack / "Security/Test.ql"
            query.parent.mkdir(parents=True)
            query.write_text("select 1\n")
            database = root / "database"
            result = reader.query_bindings([str(query)], pack, database)
            self.assertFalse(result[0]["bqrs_present"])
            bqrs = database / result[0]["bqrs"]
            bqrs.parent.mkdir(parents=True)
            bqrs.write_bytes(b"")
            self.assertFalse(reader.query_bindings([str(query)], pack, database)[0]["bqrs_present"])
            bqrs.write_bytes(b"actual-test-output")
            result = reader.query_bindings([str(query)], pack, database)
            self.assertTrue(result[0]["bqrs_present"])
            with self.assertRaises(ValueError):
                reader.query_bindings([str(query), str(query)], pack, database)
            outside = root / "unselected.ql"
            outside.write_text("select 2\n")
            with self.assertRaises(ValueError):
                reader.query_bindings([str(outside)], pack, database)

    def test_language_inventory_retains_archived_source(self):
        paths = ["evidence/old.rs", "trillionnium/current.rs", "scripts/check.py", ".github/workflows/a.yml",
                 "data.yml", "native/a.c", "native/a.h"]
        self.assertEqual(reader.expected_inputs(paths, "rust"), {"evidence/old.rs", "trillionnium/current.rs"})
        self.assertEqual(reader.expected_inputs(paths, "actions"), {".github/workflows/a.yml"})
        self.assertEqual(reader.expected_inputs(paths, "cpp"), {"native/a.c"})

    def test_missing_tool_retains_failure_and_both_source_observations(self):
        # Only source observation is a test fixture; actual tool resolution fails.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "output"
            argv = ["runner", "--language", "python", "--codeql", str(root / "missing-codeql"),
                    "--output", str(output), "--expected-head", "a" * 40]
            with patch.object(reader.verify_ci_source, "verify", return_value={"unit_source": "unchanged"}), \
                    patch("sys.argv", argv):
                self.assertEqual(reader.main(), 1)
            result = json.loads((output / "result.json").read_text())
            self.assertFalse(result["passed"])
            self.assertFalse(result["analysis_execution_complete"])
            self.assertEqual(result["failure"]["type"], "FileNotFoundError")
            self.assertTrue((output / "source-before.json").is_file())
            self.assertTrue((output / "source-after.json").is_file())


if __name__ == "__main__":
    unittest.main()
