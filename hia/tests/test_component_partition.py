"""Controls for shard coverage and same-run component result admission."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
import zipfile

from hia.tools import component_partition as part
from hia.tools import qualify_components_ci as ci
from hia.tests import test_sha256_word_evidence as word_fixture

IDS = ["hia.tests.test_example.Example.test_one",
       "hia.tests.test_example.Example.test_two",
       "hia.tests.test_state_root_adversarial.Example.test_maximum",
       "hia.tests.test_transfer.Example.test_signature",
       "hia.tests.test_research_canonical.Example.test_original",
       "hia.tests.test_research_command.Example.test_signature",
       "hia.tests.test_ml_dsa.Example.test_signature",
       "hia.tests.test_oracle.Example.test_original"]
LINEAGE = {"git_head": "a" * 40, "run_id": "42", "attempt": 1}
SOURCES = {"hia/src/fixture.hepta": "d" * 64, "hia/components.json": "f" * 64}
SOURCES.update(word_fixture.fixture()[2])
COMPILER = word_fixture.COMPILER


def fixture_case(identifier):
    class Fixture(unittest.TestCase):
        def id(self):
            return identifier

        def runTest(self):
            self.assertEqual(2 + 2, 4)
    return Fixture()


def complete_report(group):
    selection = part.descriptor(IDS, group)
    selected = selection["selected_tests"]
    return {"schema": "trnm.hia.native-qualification.v1", "status": "PASS",
            "lineage": copy.deepcopy(LINEAGE), "source_commit_observed": LINEAGE["git_head"],
            "working_tree_dirty": False, "source_unchanged_during_tests": True,
            "independent_rust_oracles_required": True,
            "source_inputs": SOURCES, "source_set_sha256": part.object_hash(SOURCES),
            "tests": {"run": len(selected), "failures": [], "errors": [], "skipped": []},
            "test_partition": {**selection, "started_tests": selected,
                               "finished_tests": selected, "all_selected_completed": True},
            "selfhost_compiler_matches_cold_qualified_image": True,
            "retained_compiler_binding_sha256": COMPILER["binding_sha256"],
            "builds": [{"source": "hia/src/fixture.hepta",
                        "chain_migration": {"backend": "selfhost", "source_sha256": "d" * 64,
                                            "inputs": [{"path": "src/fixture.hepta", "sha256": "d" * 64},
                                                       {"path": "components.json", "sha256": "f" * 64}]},
                        "compiler_sha256": COMPILER["compiler_sha256"]}]
                       + (word_fixture.fixture()[1]["builds"] if group == "general" else []),
            "rust_oracles": {key: {"executable_sha256": "e" * 64}
                             for key in ci.qualify.rust_oracle_names(group)},
            "pinned_rust_oracles": {ci.qualify.ML_DSA_ORACLE: "e" * 64} if group == "ml-dsa" else {},
            "pinned_rust_oracles_unchanged": True,
            "whole_chain_native": False, "old_stack_can_be_removed": False,
            "production_activation": False}


def log_for(value):
    count = value["tests"]["run"]
    summary = {"status": "PASS", "tests": count, "skipped": 0,
               "source_set_sha256": value["source_set_sha256"],
               "shared_runner_calls": 7, "wall_seconds": 0.01,
               "shard": value["test_partition"]["group"]}
    return ("Ran " + str(count) + " tests in 0.01s\n\nOK\n"
            + json.dumps(summary, sort_keys=True) + "\n").encode()


class ComponentPartitions(unittest.TestCase):
    def test_finite_worker_cache_and_executor_oracles_bind_exact_original_sources(self):
        sources = ci.qualify.sources()
        for name in (
            "config/hia-migration-v1.json",
            "rust-toolchain.toml",
            "trillionnium/crates/trnm-worker-agent/src/audit_render.rs",
            "trillionnium/crates/trnm-worker-agent/src/audit.rs",
            "trillionnium/crates/trnm-worker-agent/src/main.rs",
            "trillionnium/crates/trnm-data-availability/src/cell/cache_budget.rs",
            "trillionnium/crates/trnm-data-availability/src/cell.rs",
            "trillionnium/crates/trnm-executor/src/env_config.rs",
            "trillionnium/crates/trnm-executor/src/lib.rs",
        ):
            with self.subTest(name=name):
                expected = hashlib.sha256((ci.qualify.ROOT / name).read_bytes()).hexdigest()
                self.assertEqual(sources.get(name), expected)

    def test_all_partitions_execute_every_fixture_exactly_once(self):
        observed = []
        for group in part.GROUPS:
            suite = unittest.TestSuite([unittest.TestSuite(
                fixture_case(identifier) for identifier in IDS)])
            selected, inventory = part.select_suite(suite, group)
            result = unittest.TextTestRunner(stream=io.StringIO(),
                                             resultclass=part.ObservedResult).run(selected)
            value = part.record_completion(inventory, result)
            observed.extend(part.validate_completion(value, IDS, group, result.testsRun))
        self.assertEqual(sorted(observed), sorted(IDS))
        self.assertEqual(len(observed), len(set(observed)))
        self.assertEqual(part.descriptor(IDS, "all")["selected_tests"], sorted(IDS))

    def test_invalid_discovery_never_silently_drops_a_test(self):
        variants = [[], IDS + [IDS[0]], IDS[:-1], [i for i in IDS if "state_root" not in i],
                    [i for i in IDS if "test_transfer" not in i],
                    [i for i in IDS if "test_ml_dsa" not in i],
                    [i for i in IDS if "test_research_" not in i],
                    ["unittest.loader._FailedTest.test_missing"], IDS + ["bad identity"]]
        for identifiers in variants:
            with self.subTest(identifiers=identifiers), self.assertRaises(ValueError):
                part.descriptor(identifiers, "general")
        with self.assertRaises(ValueError):
            part.select_suite(unittest.defaultTestLoader.loadTestsFromName(
                "hia.tests.module_that_does_not_exist"), "general")
        with self.assertRaises(ValueError):
            part.descriptor(IDS, "unregistered-shard")

    def test_oracle_profile_and_preflight_controls_have_one_explicit_partition(self):
        for identifier in ("hia.tests.test_oracle.OracleNativeTests.test_01_original_source_graph_and_retained_roster",
                           "hia.tests.test_oracle_preflight.OraclePreflightTests.test_detached_qualification_reaches_source_admission_without_mutating_git"):
            self.assertEqual(part.group_for(identifier), "oracle")
        self.assertEqual(part.group_for("hia.tests.test_oracle_extra.Example.test_one"), "general")
        self.assertEqual(part.descriptor(IDS, "oracle")["selected_tests"], [IDS[-1]])
        self.assertEqual(set(part.GROUPS), {"general", "crypto-types", "state-root", "oracle", "ml-dsa", "research"})

    def test_complete_research_module_family_has_one_owner(self):
        for module in ("canonical", "external_key", "payload", "command", "future_owner"):
            identifier = "hia.tests.test_research_" + module + ".Example.test_case"
            self.assertEqual(part.group_for(identifier), "research")
        for identifier in ("hia.tests.test_research.Example.test_case",
                           "hia.tests.test_researcher.Example.test_case",
                           "hia.tests.test_example.Research.test_case"):
            self.assertEqual(part.group_for(identifier), "general")
        self.assertEqual(part.descriptor(IDS, "research")["selected_tests"], sorted(IDS[4:6]))
        self.assertEqual(ci.qualify.rust_oracle_names("research"), ci.qualify.RUST_ORACLES)

    def test_actual_discovery_keeps_all_research_methods_and_all_six_groups(self):
        root = Path(__file__).resolve().parents[2]
        suite = unittest.defaultTestLoader.discover(str(root / "hia/tests"),
                    pattern="test_*.py", top_level_dir=str(root))
        identifiers = [case.id() for case in part.flatten(suite)]
        research = sorted(identifier for identifier in identifiers
                          if identifier.split(".")[2].startswith("test_research_"))
        modules = {identifier.split(".")[2] for identifier in research}
        self.assertEqual(modules, {path.stem for path in (root / "hia/tests").glob("test_research_*.py")})
        self.assertTrue(research)
        self.assertEqual(part.descriptor(identifiers, "research")["selected_tests"], research)
        observed = []
        for group in part.GROUPS:
            selected = part.descriptor(identifiers, group)["selected_tests"]
            if group != "research":
                self.assertFalse(set(selected).intersection(research))
            observed.extend(selected)
        self.assertEqual(sorted(observed), sorted(identifiers))
        self.assertEqual(len(observed), len(set(observed)))

    def test_general_discovery_keeps_new_finite_differentials(self):
        root = Path(__file__).resolve().parents[2]
        suite = unittest.defaultTestLoader.discover(str(root / "hia/tests"),
                    pattern="test_*.py", top_level_dir=str(root))
        identifiers = [case.id() for case in part.flatten(suite)]
        general = set(part.descriptor(identifiers, "general")["selected_tests"])
        for identity in (
            "test_cache_capacity.CacheCapacityTests.test_deterministic_full_width_differential",
            "test_executor_env_toggle.ExecutorEnvToggle.test_exact_active_and_retained_environment_and_all_three_callers",
            "test_executor_config_grouped_u64.ExecutorGroupedU64Tests.test_deterministic_differential_corpus",
            "test_executor_config_grouped_u64.ExecutorGroupedU64SourceTests.test_retains_exact_active_bytes_and_refuses_ambiguous_source",
            "test_market_reputation.MarketReputationTests.test_every_u16_tier_including_out_of_range",
            "test_worker_audit_text.WorkerAuditText.test_exact_compiled_rust_original",
            "test_worker_audit_report.WorkerAuditReport.test_exact_original_full_report",
            "test_worker_audit_active_scope.WorkerAuditActiveScope.test_active_markdown_has_seven_typed_columns_beyond_war1",
            "test_worker_audit_active_composition.WorkerAuditActiveComposition.test_native_pieces_reconstruct_active_reports_including_oversized_cell",
        ):
            self.assertIn("hia.tests." + identity, general)

    def test_workflow_wires_six_exact_jobs_with_unchanged_deadlines(self):
        root = Path(__file__).resolve().parents[2]
        text = (root / ".github/workflows/hia-native-migration.yml").read_text().split("jobs:\n", 1)[1]
        headers = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):\n", text))
        jobs = {match[1]: text[match.start():headers[index + 1].start() if index + 1 < len(headers) else len(text)]
                for index, match in enumerate(headers)}
        expected = {group: "native-components" + ("-" + group if group != "general" else "")
                    for group in part.GROUPS}
        for group, name in expected.items():
            job = jobs[name]
            self.assertEqual(re.findall(r"(?m)^    timeout-minutes: ([0-9]+)$", job), ["20"])
            self.assertEqual(job.count("qualify.py --require-rust-oracle --shard " + group + " --output"), 1)
            self.assertNotIn("continue-on-error:", job)
        research = jobs["native-components-research"]
        self.assertIn("cargo fetch --locked --manifest-path trillionnium/Cargo.toml", research)
        self.assertIn("$RUNNER_TEMP/hia-research-dependencies/cargo-fetch.stderr.raw", research)
        self.assertIn("name: Verify candidate sources remained unchanged\n        if: always()", research)
        upload = re.search(r"(?ms)^      - name: Retain success and failure observations\n(.*?)(?=^      - name:|\Z)", research)[1]
        paths = upload.split("          path: |\n", 1)[1].split("          if-no-files-found:", 1)[0]
        self.assertEqual([line.strip() for line in paths.splitlines()], [
            "${{ runner.temp }}/hia-observations/", "${{ runner.temp }}/hia-bootstrap/bootstrap.json",
            "${{ runner.temp }}/original-rust-build.jsonl"])
        self.assertIn("if: always()", upload)
        general = jobs["native-components"]
        self.assertIn("HIA_BENCH_PROFILE_OBSERVATIONS: ${{ runner.temp }}/hia-bench-observations/profile", general)
        self.assertIn("HIA_RECOVERY_ACK_OUTPUT: ${{ runner.temp }}/hia-recovery-ack-observations", general)
        ack = re.search(r"(?ms)^      - name: Retain complete native recovery ACK observations\n(.*?)(?=^      - name:|\Z)", general)[1]
        self.assertIn("if: always()", ack)
        self.assertIn("path: ${{ runner.temp }}/hia-recovery-ack-observations/", ack)
        general_upload = re.search(r"(?ms)^      - name: Retain success and failure observations\n(.*?)(?=^      - name:|\Z)", general)[1]
        self.assertNotIn("hia-recovery-ack-observations", general_upload)
        self.assertNotIn("hia-bench-observations", general_upload)
        reader = jobs["native-components-readback"]
        needs = re.search(r"(?m)^    needs: \[(.*)\]$", reader)[1].split(", ")
        self.assertEqual(set(needs), set(expected.values()))
        self.assertEqual(len(needs), 6)
        for group, producer in expected.items():
            variable = "TRNM_COMPONENT_" + group.upper().replace("-", "_") + "_RESULT"
            self.assertIn(variable + ": ${{ needs." + producer + ".result }}", reader)
            self.assertIn("--" + group + ' "$RUNNER_TEMP/component-' + group + '-download"', reader)
            artifact = "name: hia-components-" + group + "-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_id }}-${{ github.run_attempt }}"
            self.assertIn(artifact, jobs[producer])
            self.assertIn(artifact, reader)

    def test_complete_ml_dsa_and_its_integrity_roster_have_one_explicit_partition(self):
        for identifier in ("hia.tests.test_ml_dsa.MlDsaNativeTests.test_verify",
                           "hia.tests.test_ml_dsa_qualification.MlDsaIntegrity.test_source"):
            self.assertEqual(part.group_for(identifier), "ml-dsa")
        self.assertEqual(part.group_for("hia.tests.test_ml_dsa_poly.PolyTests.test_vectors"), "crypto-types")
        self.assertEqual(part.descriptor(IDS, "ml-dsa")["selected_tests"], [IDS[-2]])
        self.assertEqual(ci.qualify.rust_oracle_names("general"), ci.qualify.RUST_ORACLES)
        for group in ("all", "ml-dsa"):
            self.assertEqual(ci.qualify.rust_oracle_names(group), (*ci.qualify.RUST_ORACLES, ci.qualify.ML_DSA_ORACLE))

    def test_ml_dsa_explicit_pin_reads_actual_binary_and_rejects_missing_or_changed_bytes(self):
        self.assertEqual(ci.qualify.pinned_rust_oracles("general", {}), {})
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "original-reference"
            raw = b"actual private reader fixture, not a cryptographic implementation"
            binary.write_bytes(raw)
            key = ci.qualify.ML_DSA_ORACLE
            env = {key: str(binary), key + "_SHA256": hashlib.sha256(raw).hexdigest()}
            self.assertEqual(ci.qualify.pinned_rust_oracles("ml-dsa", env), {key: env[key + "_SHA256"]})
            for wrong in ({}, {key: str(binary)}, {key + "_SHA256": env[key + "_SHA256"]},
                          {**env, key + "_SHA256": "0" * 64}, {**env, key + "_SHA256": True}):
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    ci.qualify.pinned_rust_oracles("ml-dsa", wrong)
            binary.write_bytes(raw + b"changed")
            with self.assertRaisesRegex(ValueError, "differs"):
                ci.qualify.pinned_rust_oracles("ml-dsa", env)
            binary.unlink()
            target = Path(tmp) / "target"
            target.write_bytes(raw)
            binary.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "Linked"):
                ci.qualify.pinned_rust_oracles("ml-dsa", env)

    def test_actual_start_finish_rosters_cannot_be_inferred_from_count(self):
        baseline = complete_report("general")["test_partition"]
        variants = []
        for key in ("started_tests", "finished_tests"):
            for names in ([], [IDS[0], IDS[0]], [IDS[0], IDS[2]], [False, IDS[1]]):
                wrong = copy.deepcopy(baseline)
                wrong[key] = names
                variants.append(wrong)
        for key, value in (("all_selected_completed", 1), ("selected_sha256", "0" * 64),
                           ("discovered_tests", IDS[:2]), ("group", "all")):
            wrong = copy.deepcopy(baseline)
            wrong[key] = value
            variants.append(wrong)
        for wrong in variants:
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                part.validate_completion(wrong, IDS, "general", 2)
        for count in (True, 2.0, 1, 3):
            with self.subTest(count=count), self.assertRaises(ValueError):
                part.validate_completion(baseline, IDS, "general", count)

    def test_actual_lineage_has_no_partial_or_numeric_coercion(self):
        self.assertIsNone(part.lineage({}))
        self.assertEqual(part.lineage({"TRNM_EXPECTED_SOURCE_SHA": "a" * 40,
                                      "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1"}),
                         LINEAGE)
        for env in ({}, {"GITHUB_RUN_ID": "42"},
                    {"TRNM_EXPECTED_SOURCE_SHA": "a" * 40,
                     "GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "1.0"},
                    {"TRNM_EXPECTED_SOURCE_SHA": "a" * 40,
                     "GITHUB_RUN_ID": "0", "GITHUB_RUN_ATTEMPT": "1"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                part.lineage(env, required=True)
        for field, value in (("attempt", True), ("attempt", 1.0), ("run_id", 42),
                              ("git_head", "A" * 40)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                part.validate_lineage({**LINEAGE, field: value})


class ComponentReadback(unittest.TestCase):
    def validate(self, value):
        return ci.validate_report(value, "general", LINEAGE, SOURCES, IDS, COMPILER)

    def test_report_rejects_source_run_status_skips_and_scope_mutants(self):
        good = complete_report("general")
        self.assertEqual(self.validate(good), IDS[:2])
        variants = []
        for field, value in (("status", "PASS_WITH_SKIPS"), ("working_tree_dirty", 0),
                              ("source_unchanged_during_tests", 1),
                              ("independent_rust_oracles_required", False),
                              ("whole_chain_native", True), ("old_stack_can_be_removed", True),
                              ("production_activation", True), ("builds", []),
                              ("rust_oracles", {}), ("source_inputs", {}),
                              ("retained_compiler_binding_sha256", "0" * 64)):
            variants.append({**copy.deepcopy(good), field: value})
        for field, value in (("attempt", 2), ("run_id", "43"), ("git_head", "f" * 40)):
            wrong = copy.deepcopy(good)
            wrong["lineage"][field] = value
            variants.append(wrong)
        for field, value in (("run", 2.0), ("run", True), ("failures", ["actual failure"]),
                              ("errors", ["actual error"]), ("skipped", ["actual skip"])):
            wrong = copy.deepcopy(good)
            wrong["tests"][field] = value
            variants.append(wrong)
        wrong = copy.deepcopy(good)
        wrong["builds"][0]["compiler_sha256"] = "0" * 64
        variants.append(wrong)
        for wrong in variants:
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                self.validate(wrong)

    def test_every_actual_job_must_succeed_including_the_new_partition(self):
        environ = {"TRNM_COMPONENT_" + group.upper().replace("-", "_") + "_RESULT": "success"
                   for group in part.GROUPS}
        ci.validate_job_results(environ)
        for key in environ:
            for status in (None, "failure", "cancelled", "skipped", True, "PASS"):
                changed = {**environ, key: status}
                with self.subTest(key=key, status=status), self.assertRaises(ValueError):
                    ci.validate_job_results(changed)
            missing = {name: value for name, value in environ.items() if name != key}
            with self.assertRaises(ValueError):
                ci.validate_job_results(missing)

    def test_ml_dsa_cannot_omit_or_substitute_the_actual_original_adapter(self):
        good = complete_report("ml-dsa")
        def validate(value):
            return ci.validate_report(value, "ml-dsa", LINEAGE, SOURCES, IDS, COMPILER)
        self.assertEqual(validate(good), [IDS[-2]])
        variants = []
        wrong = copy.deepcopy(good)
        del wrong["rust_oracles"][ci.qualify.ML_DSA_ORACLE]
        variants.append(wrong)
        for key, value in (("pinned_rust_oracles", {}), ("pinned_rust_oracles_unchanged", False),
                           ("pinned_rust_oracles_unchanged", 1),
                           ("pinned_rust_oracles", {ci.qualify.ML_DSA_ORACLE: "0" * 64})):
            variants.append({**copy.deepcopy(good), key: value})
        for wrong in variants:
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                validate(wrong)

    def test_duplicate_and_nonfinite_json_are_refused(self):
        for raw in ('{"a":1,"a":2}', '{"nested":{"x":1,"x":1}}',
                    '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                ci.decode(raw)

    def test_complete_raw_summary_cannot_be_missing_changed_or_skipped(self):
        value = complete_report("general")
        raw = log_for(value)
        ci.verify_log(raw, value)
        variants = [b"", raw.replace(b"Ran 2 tests", b"Ran 1 tests"),
                    raw.replace(b"\nOK\n", b"\nOK (skipped=1)\n"),
                    raw.replace(b"\nOK\n", b"\nFAILED (errors=1)\n"),
                    raw.replace(b'"tests": 2', b'"tests": 2.0'),
                    raw.replace(b'"skipped": 0', b'"skipped": false'),
                    raw.replace(b'"shard": "general"', b'"shard": "state-root"'),
                    raw + raw.splitlines()[-1] + b"\n"]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                ci.verify_log(changed, value)

    def make_bundle(self, root, group):
        directory = root / group
        value = complete_report(group)
        source = {"kind": "head", "candidate": "a" * 40, "tested_commit": "a" * 40,
                  "tested_tree": "f" * 40, "tracked_worktree_verified": True,
                  "tests_executed_by_identity_check": False,
                  "tracked_entries": 3, "tracked_bytes": 99}
        files = {
            "hia-observations/source.json": json.dumps(source).encode(),
            "hia-observations/source-after.json": json.dumps(source).encode(),
            "hia-observations/qualification.json": json.dumps(value).encode(),
            "hia-observations/qualification.log": log_for(value),
            "hia-bootstrap/bootstrap.json": json.dumps({
                "status": "PASS", "compiler_sha256": COMPILER["compiler_sha256"],
                "compiler": "/tmp/fixture-compiler"}).encode(),
            "original-rust-build.jsonl": b'{"fixture":true}\n',
        }
        if group == "general":
            captures = word_fixture.fixture()[0]
            files["hia-observations/qualification.log"] = (
                captures.pop("hia-observations/qualification.log") + log_for(value))
            files.update(captures)
        for name, raw in files.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return directory

    def test_all_complete_artifacts_cover_full_roster_and_keep_scope_finite(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundles = {group: self.make_bundle(Path(tmp), group) for group in part.GROUPS}
            result = ci.verify_all(bundles, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            self.assertIs(result["complete_disjoint_coverage"], True)
            self.assertEqual(result["tests"], len(IDS))
            self.assertIs(result["actual_runtime_reexecuted"], False)
            self.assertIs(result["old_stack_can_be_removed"], False)
            with self.assertRaises(ValueError):
                ci.verify_all({"general": bundles["general"]}, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            for missing in part.GROUPS:
                with self.subTest(missing=missing), self.assertRaises(ValueError):
                    ci.verify_all({key: value for key, value in bundles.items() if key != missing},
                                  LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            with self.assertRaises(ValueError):
                ci.verify_all({**bundles, "crypto-types": bundles["general"]},
                              LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)

    def test_six_downloaded_zip_fixtures_reject_missing_overlapping_or_failed_research(self):
        # Real ZIP/regular-file transport around explicit semantic reader
        # fixtures. This is not evidence of actual component native execution.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            originals = {group: self.make_bundle(root / "producer", group) for group in part.GROUPS}
            bundles = {}
            for group, directory in originals.items():
                archive = root / (group + ".zip")
                with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as stream:
                    for path in sorted(directory.rglob("*")):
                        if path.is_file():
                            stream.write(path, path.relative_to(directory).as_posix())
                destination = root / "download" / group
                with zipfile.ZipFile(archive) as stream:
                    self.assertEqual(set(stream.namelist()), ci.artifact_files(group))
                    stream.extractall(destination)
                bundles[group] = destination
            result = ci.verify_all(bundles, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            self.assertEqual(set(result["partitions"]), set(part.GROUPS))
            with self.assertRaisesRegex(ValueError, "Exactly all component partitions"):
                ci.verify_all({group: value for group, value in bundles.items() if group != "research"},
                              LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            path = bundles["research"] / "hia-observations/qualification.json"
            baseline = path.read_bytes()
            good = json.loads(baseline)
            variants = []
            for names in ([IDS[0], IDS[5]], [IDS[4], IDS[4]], [IDS[4]]):
                wrong = copy.deepcopy(good)
                wrong["test_partition"].update(selected_tests=names, selected_sha256=part.object_hash(names),
                                                started_tests=names, finished_tests=names)
                wrong["tests"]["run"] = len(names)
                variants.append((wrong, "Discovered or selected component roster differs"))
            wrong = copy.deepcopy(good)
            wrong["status"] = "FAIL"
            variants.append((wrong, "Component execution did not finish"))
            wrong = copy.deepcopy(good)
            wrong["tests"]["failures"] = [[IDS[4], "retained actual failure"]]
            variants.append((wrong, "Failed or skipped component tests"))
            for value, reason in variants:
                path.write_text(json.dumps(value))
                with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                    ci.verify_all(bundles, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
                path.write_bytes(baseline)

    def test_coherent_wrong_producer_trees_cannot_replace_consumer_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundles = {group: self.make_bundle(Path(tmp), group) for group in part.GROUPS}
            ci.verify_all(bundles, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)
            for directory in bundles.values():
                for name in ("source.json", "source-after.json"):
                    path = directory / "hia-observations" / name
                    value = json.loads(path.read_text())
                    value["tested_tree"] = "0" * 40
                    path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "actual consumer Git tree"):
                ci.verify_all(bundles, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40)

    def test_artifact_bytes_roster_and_source_fences_are_independently_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = self.make_bundle(Path(tmp), "general")
            def verify():
                return ci.read_bundle(directory, "general", LINEAGE, SOURCES, IDS, COMPILER)
            verify()
            extra = directory / "unbound"
            extra.write_bytes(b"x")
            with self.assertRaises(ValueError):
                verify()
            extra.unlink()
            extra.mkdir()
            with self.assertRaisesRegex(ValueError, "extra directories"):
                verify()
            extra.rmdir()
            path = directory / "hia-observations/source-after.json"
            original = path.read_bytes()
            value = json.loads(original)
            value["tested_tree"] = "0" * 40
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                verify()
            path.write_bytes(original)
            path.unlink()
            path.symlink_to(directory / "hia-observations/source.json")
            with self.assertRaises(ValueError):
                verify()


if __name__ == "__main__":
    unittest.main()
