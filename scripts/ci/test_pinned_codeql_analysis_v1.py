#!/usr/bin/env python3
"""Negative controls for analysis completion, coverage and source attribution."""
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
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

    def test_info_semantic_failures_are_located_without_excusing_source_classes(self):
        lines = [
            b"[build-stdout] \x1b[32m INFO\x1b[0m /source/current.rs:1:1: semantic analyzer unavailable (not included as a module): macro expansion will be skipped.",
            b"[build-stdout] WARN /source/evidence/original.rs:2:3: semantic analyzer unavailable (no manifest found): macro expansion will be skipped.",
            b"ERROR failed to load workspace for /source/evidence/Cargo.toml",
        ]
        streams = {"stdout": b"\n".join(lines), "stderr": b""}
        result = reader.semantic_extraction_observations(streams, ["current.rs", "evidence/original.rs"], Path("/source"))
        self.assertEqual(result["diagnostic_line_count"], 3)
        self.assertTrue(result["diagnostic_inventory_complete"])
        self.assertEqual(result["affected_tracked_files"], ["current.rs", "evidence/original.rs"])
        self.assertEqual(result["reason_counts"], {"no manifest found": 1, "not included as a module": 1})
        self.assertEqual(result["unlocated_diagnostic_count"], 1)
        self.assertEqual(result["diagnostics"][1]["source_line"], 2)
        self.assertEqual(result["diagnostics"][1]["source_column"], 3)
        self.assertFalse(result["semantic_coverage_qualified"])
        self.assertFalse(result["official_security_gate_qualified"])

    def test_unmapped_and_unknown_semantic_failure_still_remain_failures(self):
        lines = [
            b"/source/../elsewhere.rs:1:1: semantic analyzer unavailable (unknown future reason): macro expansion will be skipped.",
            b"SEMANTIC ANALYZER UNAVAILABLE without a source location",
        ]
        result = reader.semantic_extraction_observations(
            {"stdout": b"\n".join(lines), "stderr": b""}, ["elsewhere.rs"], Path("/source"))
        self.assertEqual(result["affected_tracked_files"], [])
        self.assertEqual(result["marker_line_counts"]["semantic analyzer unavailable"], 2)
        self.assertIsNone(result["diagnostics"][0]["source_path"])
        self.assertEqual(result["unlocated_diagnostic_count"], 2)
        self.assertEqual(result["reason_counts"], {"unknown future reason": 1})
        self.assertTrue(result["failure_markers"])

    def test_semantic_inventory_bound_never_erases_failure_counts(self):
        raw = b"failed to load workspace\n" * 4
        with patch.object(reader, "SEMANTIC_DIAGNOSTIC_LIMIT", 2):
            result = reader.semantic_extraction_observations({"stdout": raw, "stderr": b""}, [], Path("/source"))
        self.assertEqual(result["diagnostic_line_count"], 4)
        self.assertEqual(result["retained_diagnostic_count"], 2)
        self.assertFalse(result["diagnostic_inventory_complete"])
        self.assertEqual(result["marker_line_counts"], {"failed to load workspace": 4})

    def test_empty_log_inventory_does_not_certify_semantics(self):
        result = reader.semantic_extraction_observations({"stdout": b"", "stderr": b""}, ["current.rs"], Path("/source"))
        self.assertEqual(result["failure_markers"], [])
        self.assertFalse(result["semantic_coverage_qualified"])
        with self.assertRaisesRegex(ValueError, "both retained"):
            reader.semantic_extraction_observations({"stdout": b""}, [], Path("/source"))

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

    def test_actual_phase_construction_keeps_resource_hints_environment_and_deadlines_bound(self):
        # The executor and source observations are explicit fixtures. The real
        # runner constructs commands, records failures and returns nonzero;
        # this does not execute CodeQL or certify any query result.
        for language, expected_ram in (("rust", 8192), ("python", 4096)):
            for failing_phase in ("create", "analyze"):
                with self.subTest(language=language, failing_phase=failing_phase), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    executable = root / "codeql"
                    executable.write_bytes(b"fixture only; never executed")
                    output = root / "output"
                    calls = []
                    def run(argv, _input, **kwargs):
                        calls.append((list(argv), dict(kwargs["env"]), kwargs["timeout"]))
                        command = argv[1:3]
                        stdout = b"fixture toolchain\n"
                        if argv[1:] == ["version", "--format=json"]:
                            stdout = json.dumps({"version": reader.VERSION, "sha": reader.CLI_SHA,
                                                 "configFileFound": False}).encode()
                        elif command == ["resolve", "queries"]:
                            stdout = json.dumps([f"/fixture/{i}.ql" for i in range(reader.QUERY_COUNTS[language])]).encode()
                        elif command == ["resolve", "packs"]:
                            stdout = b"{}"
                        failed = command == ["database", failing_phase]
                        return SimpleNamespace(returncode=99 if failed else 0, stdout=stdout,
                                               stderr=b"synthetic resource failure" if failed else b"")
                    bounded = SimpleNamespace(run_bounded=run, ProcessFailure=RuntimeError)
                    spec = SimpleNamespace(name="_codeql_resource_fixture", loader=SimpleNamespace(exec_module=lambda _: None))
                    argv = ["runner", "--language", language, "--codeql", str(executable),
                            "--output", str(output), "--expected-head", "a" * 40]
                    with patch.object(reader.verify_ci_source, "verify", return_value={"fixture_source": "unchanged"}), \
                            patch.object(reader.importlib.util, "spec_from_file_location", return_value=spec), \
                            patch.object(reader.importlib.util, "module_from_spec", return_value=bounded), \
                            patch.object(reader.subprocess, "check_output", return_value=b"current.rs\0"), \
                            patch.object(reader, "query_bindings", return_value=[]), \
                            patch.object(reader, "host_memory_observation", return_value={"observed": False, "fixture": True}), \
                            patch.dict(reader.os.environ, {"CODEQL_RAM": "1", "CODEQL_THREADS": "99"}), \
                            patch.dict(sys.modules), patch("sys.argv", argv), patch("sys.stdout", io.StringIO()):
                        self.assertEqual(reader.main(), 1)
                    result = json.loads((output / "result.json").read_text())
                    self.assertFalse(result["passed"])
                    self.assertFalse(result["analysis_execution_complete"])
                    self.assertEqual(result["ram_hint_mb"], expected_ram)
                    self.assertEqual(result["resource_hints"]["ram_hint_mb"], expected_ram)
                    self.assertEqual(result["threads_hint"], 2)
                    self.assertEqual(result["phases"][-1]["name"], failing_phase)
                    self.assertEqual(result["phases"][-1]["returncode"], 99)
                    for arguments, environment, budget in calls:
                        self.assertEqual(environment["CODEQL_RAM"], str(expected_ram))
                        self.assertEqual(environment["CODEQL_THREADS"], "2")
                        if arguments[1:3] in (["database", "create"], ["database", "analyze"]):
                            self.assertEqual([a for a in arguments if a.startswith("--ram=")], [f"--ram={expected_ram}"])
                            self.assertEqual([a for a in arguments if a.startswith("--threads=")], ["--threads=2"])
                            self.assertEqual(budget, 1200)
                    for phase in result["phases"]:
                        self.assertEqual(phase["codeql_environment"], {"CODEQL_RAM": str(expected_ram), "CODEQL_THREADS": "2"})
                    if failing_phase == "analyze":
                        # A later evaluator failure must not hide the already
                        # observed extraction context.
                        self.assertTrue((output / "semantic-extraction.json").is_file())
                        self.assertIn("semantic_extraction_observation", result)
                        self.assertIn(f"codeql/{language}-queries@{reader.PACKS[language]}:codeql-suites/{language}-code-scanning.qls",
                                      result["phases"][-1]["argv"])
                        self.assertIn("--no-download", result["phases"][-1]["argv"])

    def test_other_languages_keep_original_resource_profile_and_unknown_is_refused(self):
        for language in ("actions", "python", "cpp"):
            self.assertEqual(reader.resource_hints(language)["ram_hint_mb"], 4096)
            self.assertEqual(reader.resource_hints(language)["threads_hint"], 2)
        with self.assertRaisesRegex(ValueError, "known CodeQL language"):
            reader.resource_hints("unknown")

    def test_memory_observation_is_raw_bound_and_not_a_capacity_certificate(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "meminfo"
            raw = b"MemTotal:       16384000 kB\nMemAvailable:   12000000 kB\n"
            path.write_bytes(raw)
            value = reader.host_memory_observation(8192, path)
            self.assertTrue(value["observed"])
            self.assertEqual(value["physical_memory_bytes"], 16384000 * 1024)
            self.assertEqual(value["available_memory_bytes"], 12000000 * 1024)
            self.assertEqual(value["meminfo"]["sha256"], reader.hashlib.sha256(raw).hexdigest())
            self.assertEqual(value["meminfo"]["raw_utf8"].encode(), raw)
            self.assertTrue(value["hint_below_observed_available_memory"])
            self.assertNotIn("resource_qualified", value)
            path.write_bytes(b"MemTotal: 8388608 kB\nMemAvailable: 1000 kB\n")
            value = reader.host_memory_observation(8192, path)
            self.assertTrue(value["observed"])
            self.assertFalse(value["hint_below_observed_available_memory"])
            path.write_bytes(b"MemTotal: 8388608 kB\nMemAvailable: 0 kB\n")
            value = reader.host_memory_observation(8192, path)
            self.assertTrue(value["observed"])
            self.assertEqual(value["available_memory_bytes"], 0)
            self.assertFalse(value["hint_below_observed_available_memory"])

    def test_missing_or_invalid_memory_stays_unknown_without_positive_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "meminfo"
            for raw in (None, b"", b"MemTotal: 1 kB\nMemAvailable: 2 kB\n",
                        b"MemTotal: 8 kB\nMemTotal: 8 kB\nMemAvailable: 1 kB\n",
                        b"MemTotal: 8 MB\nMemAvailable: 1 kB\n", b"x" * 65537):
                with self.subTest(raw=raw[:100] if raw is not None else None):
                    if raw is not None:
                        path.write_bytes(raw)
                    value = reader.host_memory_observation(8192, path)
                    self.assertFalse(value["observed"])
                    self.assertNotIn("hint_below_observed_available_memory", value)


if __name__ == "__main__":
    unittest.main()
