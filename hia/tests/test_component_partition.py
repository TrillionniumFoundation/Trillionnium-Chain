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
BENCH_IDS = [
    "hia.tests.test_bench_main.NativeBenchMain.test_ordinary_classic_footprint_desc_exact_bounded_process",
    "hia.tests.test_bench_main.NativeBenchMain.test_ordinary_classic_footprint_desc_default_direct_process",
]
SPLIT_IDS = IDS + BENCH_IDS
GENERAL_IDS = SPLIT_IDS + [
    "hia.tests.test_control_guard.Example.test_a",
    "hia.tests.test_sha256_words.Example.test_c",
]
SETTLEMENT_IDS = GENERAL_IDS + [
    "hia.tests.test_settlement_held_variable_stream_replay.Example.test_actual_original",
    "hia.tests.test_settlement_held_variable_stream_replay.Example.test_companion",
    "hia.tests.test_settlement_read_only_uri.Example.test_original_uri",
]
STATE_IMPORT_IDS = SETTLEMENT_IDS + [
    "hia.tests.test_state_import_checkpoint_context.Example.test_original_context",
    "hia.tests.test_state_import_sqlite_update_write.Example.test_original_update",
]
PLAN_FIXTURES = {part.LEGACY_PLAN: IDS, part.SPLIT_PLAN: SPLIT_IDS,
                 part.GENERAL_PLAN: GENERAL_IDS, part.SETTLEMENT_PLAN: SETTLEMENT_IDS,
                 part.STATE_IMPORT_PLAN: STATE_IMPORT_IDS}
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


def complete_report(group, plan=part.LEGACY_PLAN):
    selection = part.descriptor(PLAN_FIXTURES[plan], group, plan)
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
                       + (word_fixture.fixture()[1]["builds"] if group in part.SHA_WORD_GROUPS else []),
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

    def test_live_bench_executes_each_id_exactly_once_without_source_fallback(self):
        observed = []
        for group in part.SPLIT_GROUPS:
            suite = unittest.TestSuite(fixture_case(i) for i in SPLIT_IDS)
            selected, inventory = part.select_suite(suite, group, part.SPLIT_PLAN)
            result = unittest.TextTestRunner(stream=io.StringIO(),
                                             resultclass=part.ObservedResult).run(selected)
            completion = part.record_completion(inventory, result)
            observed.extend(part.validate_completion(
                completion, SPLIT_IDS, group, result.testsRun, part.SPLIT_PLAN))
            self.assertEqual(inventory["schema"], part.SPLIT_SCHEMA)
        self.assertEqual(sorted(observed), sorted(SPLIT_IDS))
        self.assertEqual(len(observed), len(set(observed)))
        self.assertEqual(part.descriptor(SPLIT_IDS, "bench", part.SPLIT_PLAN)["selected_tests"],
                         sorted(BENCH_IDS))
        self.assertEqual(part.descriptor(SPLIT_IDS, "all", part.LEGACY_PLAN)["discovered_sha256"],
                         part.descriptor(SPLIT_IDS, "all", part.SPLIT_PLAN)["discovered_sha256"])
        with self.assertRaisesRegex(ValueError, "differs from tracked source"):
            part.source_bound_plan(Path(__file__).resolve().parents[2], part.LEGACY_PLAN)

    def test_live_discovery_preserves_legacy_inventory_and_all_bench_modules(self):
        root = Path(__file__).resolve().parents[2]
        suite = unittest.defaultTestLoader.discover(str(root / "hia/tests"),
                    pattern="test_*.py", top_level_dir=str(root))
        ids = [case.id() for case in part.flatten(suite)]
        old = {g: part.descriptor(ids, g, part.LEGACY_PLAN)["selected_tests"] for g in part.GROUPS}
        new = {g: part.descriptor(ids, g, part.SPLIT_PLAN)["selected_tests"] for g in part.SPLIT_GROUPS}
        self.assertEqual(sorted(old["general"]), sorted(new["general"] + new["bench"]))
        self.assertEqual(sorted(ids), sorted(i for names in new.values() for i in names))
        self.assertEqual(set(new["bench"]), {i for i in ids if i.split(".")[2].startswith("test_bench_")})
        self.assertEqual({i.split(".")[2] for i in new["bench"]},
                         {p.stem for p in (root / "hia/tests").glob("test_bench_*.py")})
        for group in set(part.GROUPS)-{"general"}:
            self.assertEqual(old[group], new[group])
        self.assertTrue(set(BENCH_IDS) <= set(new["bench"]))

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

    def test_workflow_wires_ten_exact_jobs_with_unchanged_deadlines(self):
        root = Path(__file__).resolve().parents[2]
        text = (root / ".github/workflows/hia-native-migration.yml").read_text().split("jobs:\n", 1)[1]
        headers = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):\n", text))
        jobs = {match[1]: text[match.start():headers[index + 1].start() if index + 1 < len(headers) else len(text)]
                for index, match in enumerate(headers)}
        expected = {group: "native-components" + ("-" + group if group != "general-a" else "")
                    for group in part.STATE_IMPORT_GROUPS}
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
        general_b = jobs["native-components-general-b"]
        general_c = jobs["native-components-general-c"]
        settlement = jobs["native-components-general-settlement"]
        state_import = jobs["native-components-general-state-import"]
        bench = jobs["native-components-bench"]
        for shard in (general, general_b, general_c, settlement, state_import):
            self.assertNotIn("HIA_BENCH_PROFILE_OBSERVATIONS:", shard)
            self.assertNotIn("hia-bench-${{", shard)
            self.assertNotIn("archive_ci_evidence.py", shard)
            self.assertIn("cargo fetch --locked --manifest-path trillionnium/Cargo.toml", shard)
        for shard in (general, general_b):
            self.assertIn("prepare_original_m06_m09_oracles", shard)
            self.assertNotIn("TRNM_HIA_SHA256_WORDS_ARTIFACT_DIR", shard)
        self.assertNotIn("prepare_original_m06_m09_oracles", general_c)
        self.assertIn("TRNM_HIA_SHA256_WORDS_ARTIFACT_DIR", general_c)
        self.assertIn("TRNM_HIA_TASK_METADATA_ARTIFACT_DIR", general_c)
        self.assertNotIn("TRNM_HIA_SHA256_WORDS_ARTIFACT_DIR", settlement)
        self.assertNotIn("TRNM_HIA_TASK_METADATA_ARTIFACT_DIR", settlement)
        self.assertNotIn("hia-task-metadata-boundaries", settlement)
        self.assertNotIn("prepare_original_m06_m09_oracles", settlement)
        c_base = general_c.split("      - name: Execute every assigned native HIA", 1)[0]
        settlement_base = settlement.split("      - name: Execute every assigned native HIA", 1)[0]
        self.assertEqual(c_base.replace("  native-components-general-c:",
                                        "  native-components-general-settlement:", 1), settlement_base)
        # Same untouched original setup, gates and evidence contract as the
        # established Settlement split apart from the shard/artifact name.
        self.assertEqual(settlement.replace("general-settlement", "general-state-import"), state_import)
        self.assertIn("HIA_CONTROL_GUARD_OUTPUT", general)
        for variable in ("HIA_CONTROL_PLANE_OUTPUT", "TRNM_HIA_ESCROW_OUTPUT",
                         "TRNM_HIA_GOVERNANCE_OUTPUT", "HIA_PEER_LEASE_OUTPUT"):
            self.assertIn(variable, general_b)
            self.assertNotIn(variable, general)
            self.assertNotIn(variable, general_c)
        self.assertIn("HIA_BENCH_PROFILE_OBSERVATIONS: ${{ runner.temp }}/hia-bench-observations/profile", bench)
        self.assertIn('hia-bench-${{ env.TRNM_EXPECTED_SOURCE_SHA }}-${{ github.run_id }}-${{ github.run_attempt }}', bench)
        self.assertIn("archive_ci_evidence.py", bench)
        self.assertNotIn("TRNM_HIA_SHA256_WORDS_ARTIFACT_DIR", bench)
        self.assertIn("HIA_RECOVERY_ACK_OUTPUT: ${{ runner.temp }}/hia-recovery-ack-observations", general_b)
        ack = re.search(r"(?ms)^      - name: Retain complete native recovery ACK observations\n(.*?)(?=^      - name:|\Z)", general_b)[1]
        self.assertIn("if: always()", ack)
        self.assertIn("path: ${{ runner.temp }}/hia-recovery-ack-observations/", ack)
        general_upload = re.search(r"(?ms)^      - name: Retain success and failure observations\n(.*?)(?=^      - name:|\Z)", general)[1]
        self.assertNotIn("hia-recovery-ack-observations", general_upload)
        self.assertNotIn("hia-bench-observations", general_upload)
        reader = jobs["native-components-readback"]
        needs = re.search(r"(?m)^    needs: \[(.*)\]$", reader)[1].split(", ")
        self.assertEqual(set(needs), set(expected.values()))
        self.assertEqual(len(needs), 11)
        self.assertIn(" --partition-plan split-general-state-import-v1 ", reader)
        self.assertEqual(part.source_plan(root), part.STATE_IMPORT_PLAN)
        for historical in (part.SPLIT_PLAN, part.GENERAL_PLAN, part.SETTLEMENT_PLAN):
            with self.assertRaisesRegex(ValueError, "differs from tracked source"):
                part.source_bound_plan(root, historical)
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

    def make_bundle(self, root, group, plan=part.LEGACY_PLAN):
        directory = root / group
        value = complete_report(group, plan)
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
        if group in part.SHA_WORD_GROUPS:
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

    def test_live_readback_rejects_legacy_or_mixed_source_even_with_six_good_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = {g:self.make_bundle(root / "legacy",g) for g in part.GROUPS}
            live = {g:self.make_bundle(root / "live",g,part.SPLIT_PLAN) for g in part.SPLIT_GROUPS}
            result = ci.verify_all(live, LINEAGE, SOURCES, SPLIT_IDS, COMPILER, "f" * 40, part.SPLIT_PLAN)
            self.assertEqual(result["schema"], ci.SPLIT_SCHEMA)
            self.assertEqual(result["tests"],len(SPLIT_IDS))
            self.assertEqual(ci.verify_all(legacy, LINEAGE, SOURCES, IDS, COMPILER, "f" * 40,
                                           part.LEGACY_PLAN)["schema"], ci.SCHEMA)
            for bad in (legacy, {**live, "state-root": legacy["state-root"]},
                        {**live, "bench": live["general"]}):
                with self.assertRaises(ValueError):
                    ci.verify_all(bad, LINEAGE, SOURCES, SPLIT_IDS, COMPILER, "f" * 40, part.SPLIT_PLAN)
            env = {"TRNM_COMPONENT_" + g.upper().replace("-","_") + "_RESULT":"success" for g in part.GROUPS}
            with self.assertRaisesRegex(ValueError, "must succeed: bench"):
                ci.validate_job_results(env, part.SPLIT_PLAN)
            for result in ("cancelled", "skipped", "failure"):
                with self.assertRaisesRegex(ValueError, "must succeed: bench"):
                    ci.validate_job_results({**env,"TRNM_COMPONENT_BENCH_RESULT":result},part.SPLIT_PLAN)
            ci.validate_job_results({**env,"TRNM_COMPONENT_BENCH_RESULT":"success"},part.SPLIT_PLAN)
            for name, value in (("lineage", {**LINEAGE,"attempt":2}),
                                ("tests", {"run":2,"failures":[],"errors":[],"skipped":[BENCH_IDS[0]]})):
                bad = complete_report("bench", part.SPLIT_PLAN)
                bad[name]=value
                with self.assertRaises(ValueError):
                    ci.validate_report(bad, "bench", LINEAGE, SOURCES, SPLIT_IDS, COMPILER, part.SPLIT_PLAN)

    def test_live_general_splits_whole_modules_and_unchanged_non_general_ids(self):
        root = Path(__file__).resolve().parents[2]
        suite = unittest.defaultTestLoader.discover(str(root / "hia/tests"),
                    pattern="test_*.py", top_level_dir=str(root))
        ids = [case.id() for case in part.flatten(suite)]
        old = {g: part.descriptor(ids, g, part.SPLIT_PLAN)["selected_tests"]
               for g in part.SPLIT_GROUPS}
        current = {g: part.descriptor(ids, g, part.GENERAL_PLAN)["selected_tests"]
                   for g in part.GENERAL_GROUPS}
        self.assertEqual(sorted(old["general"]),
                         sorted(i for g in part.GENERAL_SHARDS for i in current[g]))
        self.assertEqual(sorted(ids), sorted(i for selected in current.values() for i in selected))
        for group in set(part.SPLIT_GROUPS) - {"general"}:
            self.assertEqual(old[group], current[group])
        for group, modules in {
            "general-a": ("test_control_guard", "test_cell_release_snapshot_content_equality"),
            "general-b": ("test_control_plane", "test_escrow", "test_governance", "test_peer_lease",
                          "test_peer_payload_ack", "test_integer_model_sealed_descriptor",
                          "test_release_file_descriptor"),
            "general-c": ("test_sha256_words", "test_task_metadata_initializer",
                          "test_release_pq_bundle_checkpoint", "test_worker_audit_sealed_query"),
        }.items():
            for module in modules:
                self.assertIn(module, {i.split(".")[2] for i in current[group]})
        for module in {i.split(".")[2] for i in ids}:
            self.assertEqual(len({part.group_for(i, part.GENERAL_PLAN)
                                  for i in ids if i.split(".")[2] == module}), 1)

    def test_nine_way_readback_requires_actual_lane_and_word_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = part.GENERAL_PLAN
            bundles = {g: self.make_bundle(root / "current", g, plan) for g in part.GENERAL_GROUPS}
            result = ci.verify_all(bundles, LINEAGE, SOURCES, GENERAL_IDS, COMPILER, "f" * 40, plan)
            self.assertEqual(result["schema"], ci.GENERAL_SCHEMA)
            self.assertEqual(result["tests"], len(GENERAL_IDS))
            word_evidence = "sha256_word_evidence"
            self.assertIsNone(result["partitions"]["general-a"][word_evidence])
            self.assertIsNone(result["partitions"]["general-b"][word_evidence])
            self.assertIsNotNone(result["partitions"]["general-c"][word_evidence])
            old_general = self.make_bundle(root / "historical", "general", part.SPLIT_PLAN)
            for bad in ({g: d for g, d in bundles.items() if g != "general-c"},
                        {**bundles, "general-c": old_general},
                        {**bundles, "general-b": bundles["general-a"]},
                        {**bundles, "general": old_general}):
                with self.assertRaises(ValueError):
                    ci.verify_all(bad, LINEAGE, SOURCES, GENERAL_IDS, COMPILER, "f" * 40, plan)
            env = {"TRNM_COMPONENT_" + g.upper().replace("-", "_") + "_RESULT": "success"
                   for g in part.GENERAL_GROUPS}
            ci.validate_job_results(env, plan)
            for result in ("cancelled", "skipped", "failure"):
                with self.assertRaisesRegex(ValueError, "must succeed: general-b"):
                    ci.validate_job_results({**env, "TRNM_COMPONENT_GENERAL_B_RESULT": result}, plan)

    def test_settlement_split_reassigns_only_whole_costed_c_modules(self):
        root = Path(__file__).resolve().parents[2]
        raw_suite = unittest.defaultTestLoader.discover(str(root / "hia/tests"),
                    pattern="test_*.py", top_level_dir=str(root))
        ids = [case.id() for case in part.flatten(raw_suite)]
        old = {g: part.descriptor(ids, g, part.GENERAL_PLAN)["selected_tests"] for g in part.GENERAL_GROUPS}
        plan = part.SETTLEMENT_PLAN
        new = {g: part.descriptor(ids, g, plan)["selected_tests"] for g in part.SETTLEMENT_GROUPS}
        moved = new["general-settlement"]
        # The historical plan's tracked cutoff still governs new Settlement
        # modules. Read the actual old C inventory, not the launch-day roster.
        expected_settlement = sorted(x for x in old["general-c"]
                                     if x.split(".")[2].startswith("test_settlement_")
                                     and x.split(".")[2] <= "test_settlement_held_variable_stream_replay")
        self.assertEqual(moved, expected_settlement)
        self.assertTrue({
            "test_settlement_checksum_journal_read", "test_settlement_command_journal_read",
            "test_settlement_execution_context", "test_settlement_execution_journal_read",
            "test_settlement_first_native_replay", "test_settlement_held_first_replay",
            "test_settlement_held_same_block_replay", "test_settlement_held_state_shape",
            "test_settlement_held_variable_first_replay", "test_settlement_held_variable_pair_replay",
            "test_settlement_held_variable_settle_replay", "test_settlement_held_variable_stream_replay"}
            <= {x.split(".")[2] for x in moved})
        self.assertEqual(sorted(ids), sorted(i for selected in new.values() for i in selected))
        self.assertEqual(sorted(old["general-c"]), sorted(new["general-c"] + moved))
        self.assertFalse(set(new["general-c"]) & set(moved))
        for group in set(old) - {"general-c"}:
            self.assertEqual(old[group], new[group])
        for module in {i.split(".")[2] for i in ids}:
            self.assertEqual(len({part.group_for(i, plan) for i in ids if i.split(".")[2] == module}), 1)
        c_modules = {x.split(".")[2] for x in new["general-c"]}
        self.assertTrue({"test_sha256_word_evidence", "test_task_metadata_initializer",
                         "test_settlement_read_only_uri"} <= c_modules)
        from hia.tools import qualify
        self.assertEqual(qualify.rust_oracle_names("general-c"), qualify.rust_oracle_names("general-settlement"))
        live = part.STATE_IMPORT_PLAN
        final = {g: part.descriptor(ids, g, live)["selected_tests"] for g in part.STATE_IMPORT_GROUPS}
        picked = final["general-state-import"]
        self.assertTrue(picked)
        self.assertEqual(picked, sorted(x for x in ids if x.split(".")[2].startswith("test_state_import_")))
        self.assertEqual(sorted(ids), sorted(x for group in final.values() for x in group))
        self.assertEqual(sorted(final["general-c"] + picked), new["general-c"])
        for group in set(new) - {"general-c"}:
            self.assertEqual(new[group], final[group])
        for module in {i.split(".")[2] for i in ids}:
            self.assertEqual(len({part.group_for(i, live) for i in ids if i.split(".")[2] == module}), 1)
        final_c = {x.split(".")[2] for x in final["general-c"]}
        self.assertTrue({"test_sha256_word_evidence", "test_task_metadata_initializer",
                         "test_settlement_read_only_uri"} <= final_c)
        self.assertEqual(qualify.rust_oracle_names("general-c"), qualify.rust_oracle_names("general-state-import"))

    def test_ten_way_readback_refuses_missing_duplicate_stale_and_nine_way_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = part.SETTLEMENT_PLAN
            bundles = {g: self.make_bundle(root / "current", g, plan) for g in part.SETTLEMENT_GROUPS}
            def verify(inputs):
                return ci.verify_all(inputs, LINEAGE, SOURCES, SETTLEMENT_IDS, COMPILER, "f" * 40, plan)
            result = verify(bundles)
            self.assertEqual((result["schema"], result["tests"]), (ci.SETTLEMENT_SCHEMA, len(SETTLEMENT_IDS)))
            self.assertIsNotNone(result["partitions"]["general-c"]["sha256_word_evidence"])
            self.assertIsNone(result["partitions"]["general-settlement"]["sha256_word_evidence"])
            old = self.make_bundle(root / "old-partition", "general-c", part.GENERAL_PLAN)
            stale = self.make_bundle(root / "stale", "general-settlement", plan)
            path = stale / "hia-observations/qualification.json"
            value = json.loads(path.read_text())
            value["lineage"]["attempt"] += 1
            path.write_text(json.dumps(value))
            repeated = self.make_bundle(root / "repeated", "general-settlement", plan)
            path = repeated / "hia-observations/qualification.json"
            value = json.loads(path.read_text())
            actual = value["test_partition"]["finished_tests"]
            self.assertEqual(len(actual), 2)
            actual[1] = actual[0]
            path.write_text(json.dumps(value))
            for inputs in ({g: p for g, p in bundles.items() if g != "general-settlement"},
                           {**bundles, "general-settlement": bundles["general-c"]},
                           {**bundles, "general-c": old},
                           {**bundles, "general-settlement": old}):
                with self.assertRaises(ValueError):
                    verify(inputs)
            with self.assertRaisesRegex(ValueError, "Different component head, run or attempt"):
                verify({**bundles, "general-settlement": stale})
            with self.assertRaisesRegex(ValueError, "Missing, repeated or unassigned actual component execution"):
                verify({**bundles, "general-settlement": repeated})
            env = {"TRNM_COMPONENT_" + g.upper().replace("-", "_") + "_RESULT": "success"
                   for g in part.SETTLEMENT_GROUPS}
            ci.validate_job_results(env, plan)
            key = "TRNM_COMPONENT_GENERAL_SETTLEMENT_RESULT"
            for bad in ("cancelled", "skipped", "failure", ""):
                with self.assertRaisesRegex(ValueError, "must succeed: general-settlement"):
                    ci.validate_job_results({**env, key: bad}, plan)
            with self.assertRaisesRegex(ValueError, "must succeed: general-settlement"):
                ci.validate_job_results({k: v for k, v in env.items() if k != key}, plan)

        self._assert_eleven_way_hard_negatives()

    def _assert_eleven_way_hard_negatives(self):
        # Extend the historical owner test; keep its stable discovered test
        # identity and the same roster size for the CI migration itself.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = part.STATE_IMPORT_PLAN
            active = "general-state-import"
            bundles = {g: self.make_bundle(root / "current", g, plan) for g in part.STATE_IMPORT_GROUPS}
            def read(inputs):
                return ci.verify_all(inputs, LINEAGE, SOURCES, STATE_IMPORT_IDS, COMPILER, "f" * 40, plan)
            result = read(bundles)
            self.assertEqual((result["schema"], result["tests"]), (ci.STATE_IMPORT_SCHEMA, len(STATE_IMPORT_IDS)))
            self.assertIsNotNone(result["partitions"]["general-c"]["sha256_word_evidence"])
            self.assertIsNone(result["partitions"][active]["sha256_word_evidence"])
            old = self.make_bundle(root / "ten-partition", "general-c", part.SETTLEMENT_PLAN)
            for inputs in ({g: p for g, p in bundles.items() if g != active},
                           {**bundles, active: bundles["general-c"]},
                           {**bundles, "general-c": old},
                           {**bundles, active: old}):
                with self.assertRaises(ValueError):
                    read(inputs)
            for control in ("next-attempt", "different-head", "duplicate-completion"):
                bad = self.make_bundle(root / control, active, plan)
                path = bad / "hia-observations/qualification.json"
                value = json.loads(path.read_text())
                reason = "Different component head, run or attempt"
                if control == "next-attempt":
                    value["lineage"]["attempt"] += 1
                elif control == "different-head":
                    value["lineage"]["git_head"] = "c" * 40
                else:
                    completed = value["test_partition"]["finished_tests"]
                    self.assertEqual(len(completed), 2)
                    completed[1] = completed[0]
                    reason = "Missing, repeated or unassigned actual component execution"
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, reason):
                    read({**bundles, active: bad})
            env = {"TRNM_COMPONENT_" + g.upper().replace("-", "_") + "_RESULT": "success"
                   for g in part.STATE_IMPORT_GROUPS}
            ci.validate_job_results(env, plan)
            key = "TRNM_COMPONENT_GENERAL_STATE_IMPORT_RESULT"
            for bad in ("cancelled", "skipped", "failure", ""):
                with self.assertRaisesRegex(ValueError, "must succeed: general-state-import"):
                    ci.validate_job_results({**env, key: bad}, plan)
            with self.assertRaisesRegex(ValueError, "must succeed: general-state-import"):
                ci.validate_job_results({k: v for k, v in env.items() if k != key}, plan)

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
