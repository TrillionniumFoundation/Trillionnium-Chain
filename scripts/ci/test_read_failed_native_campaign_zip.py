"""Offline evidence-reader controls; these fixtures run no native workloads."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import read_failed_native_campaign_zip as reader


HEAD = "1" * 40
TREE = "2" * 40
RUN = 123
BINARY = "/fixture/target/release/deps/public_v3_multiprocess"
COMMAND = ["/fixture/cargo", "+1.95.0", "test", "--locked", "--offline", "--release",
           "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--test",
           "public_v3_multiprocess"]


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixtures():
    source = {"schema": "trnm-ci-source-v1", "kind": "head", "tested_commit": HEAD,
              "tested_tree": TREE, "candidate": HEAD, "tracked_worktree_verified": True,
              "base": None, "prospective_merge": None, "tests_executed_by_identity_check": False,
              "tracked_entries": 1, "tracked_bytes": 1}
    source_names = ["source-before.json", "source-before-build.json", "source-before-campaigns.json",
                    "source-after-native.json", "source-after.json"]
    source_names += [f"run-{n}-source-after.json" for n in range(1, 4)]
    files = {name: encoded(source) for name in source_names}
    files["public_v3_multiprocess.bin"] = b"fixture data only; never executable"
    files["hardware.json"] = encoded({"machine": "x86_64", "cpu_models": ["fixture only"]})
    files["run-native-campaign.py"] = b"fixture bytes, not an executable runner"
    resource = {"schema": "trnm.resource-observation.v1", "cgroup": "/fixture",
                "nice": 10, "cpu_affinity": [0, 1, 2, 3], "limits": [
                    {"path": "/sys/fs/cgroup/fixture", "cpu.max": "400000 100000", "memory.max": "17179869184"},
                    {"path": "/sys/fs/cgroup", "cpu.max": "max 100000", "memory.max": "max"}]}
    resource_names = ["resource-before-build.json", "resource-after-native.json"]
    resource_names += [f"run-{n}-resource-{when}.json" for n in range(1, 4) for when in ("before", "after")]
    files.update({name: encoded(resource) for name in resource_names})
    attempts = []
    for n in range(1, 4):
        phases, readback = [], []
        for i, mode in enumerate(reader.MODES):
            rounds = []
            for r in range(2 if i == 0 else 1):
                confirmed = i == 0 and r == 0
                rounds.append({"round": r, "started_ns": 1, "ended_ns": 20,
                               "confirmed_inside_pressure_window": confirmed,
                               "observation": {"confirmed": True, "depth": 6,
                                               "finalized": False,
                                               "execution_authority": False} if confirmed else None})
            phases.append({"mode": mode, "duration_seconds": 30,
                           "attacker_processes_requested": reader.ATTACKERS[i],
                           "attacker_processes_ready": reader.ATTACKERS[i],
                           "state_backend": "authenticated-v1",
                           "confirmations": rounds, "finite_phase_criteria_met": False,
                           "all_signed_rounds_confirmed_in_window": False,
                           "submissions": [], "history": [], "children": [],
                           "receiver_observation": {"schema": "public-v3-local-request-resource-observation-v2",
                               "cpu_intervals_are_nested_not_additive": True,
                               "submit_phase_cpu_excludes_scoped_workers": True, "records": []},
                           "observer_complete": True, "service_outcome": {}, "final_meter": {},
                           "verifier_errors": [], "receiver_client_state_equal": False,
                           "genuine_budget_depletion_observed": False,
                           "actor_reports_successful_without_cap_or_kill": False,
                           "whole_parent_phase_cpu_ns": None, "whole_parent_phase_wall_ns": None,
                           "receiver_and_verifier_setup_cpu_ns": None,
                           "receiver_and_verifier_setup_wall_ns": None})
        raw = {"schema": "native-public-v3-separate-process-campaign-v2",
               "state_backend": "authenticated-v1", "preparation": {
                   "actual_signed_seed_transfers": 1024, "seed_blocks": 4, "business_blocks": 21,
                   "cpu_ns": 1, "wall_ns": 1},
               "phases": phases, "finite_experiment_criteria_met": False, "economics_complete": True,
               "best_observed_cold_legal_method": "fixture only"}
        raw.update({key: False for key in ("cryptographic_hardness_qualified", "work_profile_qualified",
                   "independent_operators", "wan_qualified", "production_candidate", "release_ready")})
        raw_name = f"run-{n}-raw/report.json"
        files[raw_name] = encoded(raw)
        # This fixture deliberately preserves the historical v3 derivation.
        readback = reader.original.phase_reader.analyze_for_retained_schema(
            raw, "pon-public-v3-multiprocess-phase-derivation-v3")
        readback["input"] = {"sha256": digest(files[raw_name]), "bytes": len(files[raw_name]),
                             "report": f"/fixture/pon-native-campaign-{RUN}-1/{raw_name}"}
        files[f"run-{n}-phase-readback.json"] = encoded(readback)
        step = {"returncode": 101, "complete_success": False, "name": f"run-{n}",
                "command": COMMAND + [reader.original.SELECTOR, "--", "--exact", "--ignored",
                                       "--nocapture", "--test-threads=1"],
                "cwd": "/fixture/source", "error": None, "outer_stage_timeout_seconds": 600,
                "elapsed_ns": 1_000_000, "elapsed_seconds": 0.001}
        for stream in ("stdout", "stderr"):
            name = f"run-{n}.{stream}.log"
            files[name] = (f"Running tests/public_v3_multiprocess.rs ({BINARY})\n".encode()
                           if stream == "stderr" else b"fixture failed native observation")
            step.update({stream: name, f"{stream}_sha256": digest(files[name]),
                         f"{stream}_bytes": len(files[name]), f"{stream}_truncated": False})
        attempt = {"number": n, "complete_success": False, "original_criteria_met": False,
                   "report_directory": f"run-{n}-raw", "report_sha256": digest(files[raw_name]),
                   "step": step, "phase_startup_errors": [], "report_validation_failure": None}
        files[f"run-{n}-result.json"] = encoded(attempt)
        files[f"run-{n}.step.json"] = encoded(step)
        attempts.append(attempt)
    profile = {"debug_assertions": False, "debuginfo": 0, "opt_level": "3",
               "overflow_checks": False, "test": True}
    build = {"returncode": 0, "complete_success": True, "name": "build",
             "command": COMMAND + ["--no-run", "--message-format=json"],
             "cwd": "/fixture/source", "error": None, "outer_stage_timeout_seconds": 1800,
             "elapsed_ns": 1_000_000, "elapsed_seconds": 0.001}
    compiler = {"reason": "compiler-artifact", "target": {"name": "public_v3_multiprocess"},
                "profile": profile, "executable": BINARY}
    for stream in ("stdout", "stderr"):
        name = f"build.{stream}.log"
        files[name] = encoded(compiler) + b"\n" if stream == "stdout" else b"fixture only\n"
        build.update({stream: name, f"{stream}_sha256": digest(files[name]),
                      f"{stream}_bytes": len(files[name]), f"{stream}_truncated": False})
    files["build.step.json"] = encoded(build)
    binary = {"retained": "public_v3_multiprocess.bin", "bytes": len(files["public_v3_multiprocess.bin"]),
              "sha256_before": digest(files["public_v3_multiprocess.bin"]),
              "sha256_after": digest(files["public_v3_multiprocess.bin"]),
              "build_artifact": BINARY, "actual_compiler_artifact_profile": profile,
              "build_separate_from_measured_campaign": True}
    files["binary-before.json"] = encoded({**binary, "sha256_after": None})
    files["results.json"] = encoded({
        "schema": "pon-original-native-campaign-ci-v1", "expected_head": HEAD, "expected_tree": TREE,
        "original_inputs": deepcopy(reader.ORIGINAL_INPUTS), "planned_complete_runs": 3,
        "source_kind": "head", "toolchain": "1.95.0", "build_timeout_seconds": 1800,
        "original_campaign_outer_timeout_seconds": 600,
        "expected_resources": {"cpu_max": "400000 100000", "memory_max": "17179869184", "nice": 10},
        "state_backend": "authenticated-v1", "profile": "release", "attempts": attempts,
        "complete_success": False, "failure": "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED",
        "finalization_failures": [], "binary": binary, "build": build,
        "source_after": source, "runner_sha256": digest(files["run-native-campaign.py"])} )
    return files


def repin_report(files, n, mutate):
    name = f"run-{n}-raw/report.json"
    report = json.loads(files[name])
    mutate(report)
    files[name] = encoded(report)
    sha = digest(files[name])
    result_name = f"run-{n}-result.json"
    result = json.loads(files[result_name])
    result["report_sha256"] = sha
    files[result_name] = encoded(result)
    results = json.loads(files["results.json"])
    results["attempts"][n - 1] = result
    files["results.json"] = encoded(results)
    name = f"run-{n}-phase-readback.json"
    readback = json.loads(files[name])
    readback["input"].update(sha256=sha, bytes=len(files[f"run-{n}-raw/report.json"]))
    files[name] = encoded(readback)


def v4_fixtures():
    files = fixtures()
    for number in range(1, 4):
        def scheduled_clocks(report):
            for phase in report["phases"]:
                for row in phase["confirmations"]:
                    scheduled = (1_000_000_000, 5_000_000_000, 9_000_000_000)[row["round"]]
                    row.update(started_ns=scheduled, ended_ns=scheduled + 10_000_000)
        repin_report(files, number, scheduled_clocks)
        raw = json.loads(files[f"run-{number}-raw/report.json"])
        name = f"run-{number}-phase-readback.json"
        original_input = json.loads(files[name])["input"]
        value = reader.original.phase_reader.analyze_for_retained_schema(
            raw, "pon-public-v3-multiprocess-phase-derivation-v4")
        value["input"] = original_input
        files[name] = encoded(value)
    return files


class ArtifactReadbackControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, files=None, mutate_manifest=None, extra=None):
        files = fixtures() if files is None else files
        manifest = {"files": [{"path": name, "bytes": len(data), "sha256": digest(data)}
                              for name, data in files.items()], "scope": "fixture only"}
        if mutate_manifest:
            mutate_manifest(manifest)
        target = self.root / "artifact.zip"
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as out:
            for name, data in files.items():
                out.writestr(name, data)
            out.writestr("artifact-files.json", encoded(manifest))
            if extra:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    out.writestr(*extra)
        return target, digest(target.read_bytes())

    def read(self, path, sha, **kwargs):
        return reader.summarize(path, sha, kwargs.get("head", HEAD), kwargs.get("tree", TREE),
                                kwargs.get("run", RUN), 456)

    def test_valid_failed_campaign_preserves_missing_rounds_and_no_authority(self):
        report = self.read(*self.archive())
        self.assertTrue(report["evidence_read_success"])
        self.assertFalse(report["native_campaign_complete_success"])
        self.assertFalse(report["qualification_granted"])
        self.assertEqual(report["totals"], {
            "scheduled_confirmation_rounds": 27, "observed_confirmation_rounds": 12,
            "confirmed_rounds": 3, "unobserved_scheduled_rounds": 15})
        self.assertEqual([a["native_process_returncode"] for a in report["attempts"]], [101] * 3)
        self.assertEqual([a["original_positive_step_reader_refusal"] for a in report["attempts"]],
                         ["original step did not complete successfully inside its budget"] * 3)

    def test_current_v4_derivation_retains_failed_campaign_scope(self):
        files = v4_fixtures()
        value = json.loads(files["run-1-phase-readback.json"])
        cohort = value["phases"][0]["honest_business_completion"]
        # The old partial confirmation fixture has no complete identity/work
        # evidence. Its native flag remains separate from v4 readback evidence.
        self.assertEqual(cohort["native_reported_in_window_rounds"], 1)
        self.assertEqual(cohort["readback_confirmed_in_window_rounds"], 0)
        self.assertEqual(cohort["completion_fraction"], {"numerator": 0, "denominator": 3})
        self.assertFalse(cohort["all_scheduled_rounds_latency_ns"]["complete_observation"])
        report = self.read(*self.archive(files))
        self.assertTrue(report["evidence_read_success"])
        self.assertFalse(report["native_campaign_complete_success"])
        self.assertFalse(report["qualification_granted"])
        self.assertEqual(report["totals"], {
            "scheduled_confirmation_rounds": 27, "observed_confirmation_rounds": 12,
            "confirmed_rounds": 3, "unobserved_scheduled_rounds": 15})

    def test_v4_readback_cannot_omit_change_or_relabel_business_cohort(self):
        mutations = (
            ("missing", lambda value: value["phases"][0].pop("honest_business_completion"),
             "ORIGINAL_PHASE_DERIVATION_MISMATCH"),
            ("changed", lambda value: value["phases"][0]["honest_business_completion"][
                "completion_fraction"].update(numerator=3), "ORIGINAL_PHASE_DERIVATION_MISMATCH"),
            ("relabeled", lambda value: value.update(
                schema="pon-public-v3-multiprocess-phase-derivation-v3"),
             "ORIGINAL_PHASE_DERIVATION_MISMATCH"),
            ("unknown", lambda value: value.update(
                schema="pon-public-v3-multiprocess-phase-derivation-v5"),
             "ORIGINAL_READBACK_INPUT_MISMATCH"),
        )
        for name, mutate, refusal in mutations:
            with self.subTest(name=name):
                files = v4_fixtures()
                value = json.loads(files["run-1-phase-readback.json"])
                mutate(value)
                files["run-1-phase-readback.json"] = encoded(value)
                with self.assertRaisesRegex(reader.EvidenceError, refusal):
                    self.read(*self.archive(files))

    def test_archive_identity_required(self):
        path, _ = self.archive()
        with self.assertRaisesRegex(reader.EvidenceError, "ARCHIVE_SHA256_MISMATCH"):
            self.read(path, "0" * 64)

    def test_inner_manifest_hash_survives_a_rehashed_archive(self):
        path, sha = self.archive(mutate_manifest=lambda m: m["files"][0].update(sha256="0" * 64))
        with self.assertRaisesRegex(reader.EvidenceError, "MEMBER_SHA256_MISMATCH"):
            self.read(path, sha)

    def test_manifest_must_cover_every_regular_member(self):
        with self.assertRaisesRegex(reader.EvidenceError, "MANIFEST_MEMBER_SET_MISMATCH"):
            self.read(*self.archive(mutate_manifest=lambda m: m["files"].pop()))

    def test_duplicate_zip_member_is_refused(self):
        with self.assertRaisesRegex(reader.EvidenceError, "DUPLICATE_ZIP_MEMBER"):
            self.read(*self.archive(extra=("results.json", b"{}")))

    def test_archive_paths_are_never_extracted(self):
        with self.assertRaisesRegex(ValueError, "artifact path escapes root"):
            self.read(*self.archive(extra=("../outside", b"must not be written")))
        self.assertFalse((self.root.parent / "outside").exists())

    def test_duplicate_json_keys_cannot_override_native_verdict(self):
        files = fixtures()
        files["results.json"] = files["results.json"][:-1] + b', "complete_success": true}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.read(*self.archive(files))

    def test_nonfinite_json_is_refused(self):
        files = fixtures()
        files["hardware.json"] = b'{"cpu": NaN}'
        with self.assertRaisesRegex(ValueError, "nonfinite JSON"):
            self.read(*self.archive(files))

    def test_source_after_does_not_inherit_another_commit(self):
        files = fixtures()
        source = json.loads(files["source-after.json"])
        source["tested_commit"] = "3" * 40
        files["source-after.json"] = encoded(source)
        with self.assertRaisesRegex(ValueError, "measured source head/tree mismatch"):
            self.read(*self.archive(files))

    def test_workflow_run_identity_must_match_original_report_path(self):
        with self.assertRaisesRegex(reader.EvidenceError, "ORIGINAL_WORKFLOW_RUN_ID_MISMATCH"):
            self.read(*self.archive(), run=999)

    def test_bool_is_not_an_original_actor_count(self):
        files = fixtures()
        value = json.loads(files["results.json"])
        value["original_inputs"]["attacker_processes"][0] = False
        files["results.json"] = encoded(value)
        with self.assertRaisesRegex(reader.EvidenceError, "ORIGINAL_CAMPAIGN_CONTRACT_CHANGED"):
            self.read(*self.archive(files))

    def test_missing_phase_cannot_be_filled_with_zero_observations(self):
        files = fixtures()
        repin_report(files, 2, lambda r: r["phases"].pop())
        with self.assertRaisesRegex(ValueError, "all three original phases required"):
            self.read(*self.archive(files))

    def test_claimed_confirmation_requires_actual_confirmed_observation(self):
        files = fixtures()
        repin_report(files, 1, lambda r: r["phases"][0]["confirmations"][0]["observation"].update(confirmed=False))
        # The retained phase validator now refuses this inconsistency before
        # the later diagnostic summary; keep the exact earlier refusal.
        with self.assertRaisesRegex(ValueError, "^confirmed round requires the original six-depth observation$"):
            self.read(*self.archive(files))

    def test_existing_reader_count_disagreement_is_refused(self):
        files = fixtures()
        value = json.loads(files["run-1-phase-readback.json"])
        value["phases"][0]["confirmed_rounds"] = 2
        files["run-1-phase-readback.json"] = encoded(value)
        with self.assertRaisesRegex(reader.EvidenceError, "ORIGINAL_PHASE_DERIVATION_MISMATCH"):
            self.read(*self.archive(files))

    def test_campaign_success_cannot_relabel_failed_attempts(self):
        files = fixtures()
        value = json.loads(files["results.json"])
        value["complete_success"] = True
        files["results.json"] = encoded(value)
        with self.assertRaisesRegex(reader.EvidenceError, "CONFLICTING_CAMPAIGN_SUCCESS"):
            self.read(*self.archive(files))

    def test_unknown_import_is_not_zero_cost_or_success(self):
        value = reader.history_row(0, {"status": "error", "error": "PUBLIC_REQUEST_DEADLINE"})
        self.assertFalse(value["client_import_available"])
        self.assertIsNone(value["client_import"])
        self.assertIsNone(value["calling_process_cpu_ns"])

    def test_counter_regression_is_not_silently_clamped(self):
        before = {"stages": [{"stage": "activation", "totals": {"cpu_ns": 12}}]}
        after = {"stages": [{"stage": "activation", "totals": {"cpu_ns": 11}}]}
        with self.assertRaisesRegex(reader.EvidenceError, "STAGE_COUNTER_REGRESSION"):
            reader.stage_deltas(before, after)

    def test_hash_stream_stops_at_finite_declared_bound(self):
        with self.assertRaisesRegex(reader.EvidenceError, "STREAM_BYTE_LIMIT"):
            reader.sha_stream(io.BytesIO(b"past declared bound"), 3)

    def test_original_resource_validator_cannot_be_bypassed_by_failure_diagnostics(self):
        files = fixtures()
        value = json.loads(files["resource-before-build.json"])
        value["limits"][0]["cpu.max"] = "25000 100000"
        files["resource-before-build.json"] = encoded(value)
        with self.assertRaisesRegex(ValueError, "ACTUAL_400_PERCENT_16_GIB_REQUIRED"):
            self.read(*self.archive(files))

    def test_cli_never_overwrites_an_existing_result(self):
        path, sha = self.archive()
        output = self.root / "existing.json"
        output.write_bytes(b"original observation")
        code = reader.main([str(path), "--archive-sha256", sha, "--expected-head", HEAD,
                            "--expected-tree", TREE, "--run-id", str(RUN), "--artifact-id", "456",
                            "--output", str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(output.read_bytes(), b"original observation")


class CheckpointAttributionTests(unittest.TestCase):
    """Synthetic observer controls only; no original campaign is executed."""
    def observation(self, *, unknown=False, clock_unknown=False, failures=0):
        def empty():
            row = {key: 0 for key in reader.HOST_CHECKPOINT_COUNTERS}
            row.update({key: None for key in reader.HOST_CHECKPOINT_TIMES})
            return dict(row, phase="checkpoint", last_error_code=None)
        buckets = [{"owner_phase": name, "calls": empty()} for name in reader.HOST_CHECKPOINT_PHASES]
        row = buckets[-1 if unknown else 3]["calls"]
        row.update(calls_started=1, calls_completed=1, calls_accepted=1,
                   first_started_ns=10, last_ended_ns=20, wall_ns=10,
                   thread_cpu_ns=None if clock_unknown else 5,
                   cpu_clock_unknown_calls=1 if clock_unknown else 0)
        return {
            "measurement_failures": failures,
            "host_checks": [empty(), empty(), dict(row), empty()],
            "host_checkpoint_attribution": {
                "schema": "pon-local-history-host-phase-attribution-v1",
                "buckets": buckets,
                "all_checkpoint_calls_attributed": failures == 0 and not unknown,
                "has_consensus_authority": False,
                "scope": reader.HOST_CHECKPOINT_SCOPE,
            },
        }

    def test_old_artifacts_are_absent_without_retrospective_counts(self):
        actual = reader.checkpoint_attribution({})
        self.assertEqual(actual["availability"], "absent")
        self.assertNotIn("checkpoint_calls", actual)

    def test_known_buckets_preserve_original_measurements(self):
        value = self.observation()
        actual = reader.checkpoint_attribution(value)
        self.assertEqual(actual["raw"], value["host_checkpoint_attribution"])
        self.assertTrue(actual["derived_all_checkpoint_calls_attributed"])
        self.assertFalse(actual["qualification_granted"])

    def test_native_and_host_observations_remain_separate_without_promoting_unknown(self):
        value = self.observation()
        native = {"schema": "pon-local-history-import-native-attribution-v1",
                  "page": None, "packets": []}
        value["native_attribution"] = native
        row = {"client_import": {"native_import_observation": value}}
        result = reader.history_row(0, row)["client_import"]
        self.assertEqual(result["host_checkpoint_attribution"]["raw"],
                         value["host_checkpoint_attribution"])
        self.assertEqual(result["native_attribution"]["raw"], native)
        self.assertIsNone(result["native_attribution"]["raw"]["page"])
        self.assertFalse(result["native_attribution"]["validation_performed"])
        self.assertFalse(result["native_attribution"]["qualification_granted"])
        value["native_attribution"] = None
        unknown = reader.history_row(0, row)["client_import"]["native_attribution"]
        self.assertEqual(unknown["availability"], "unknown")
        self.assertIsNone(unknown["raw"])
        del value["native_attribution"]
        absent = reader.history_row(0, row)["client_import"]["native_attribution"]
        self.assertEqual(absent["availability"], "absent")
        self.assertIsNone(absent["raw"])

    def test_unknown_owner_and_observer_failure_cannot_claim_all_attributed(self):
        for changes in ({"unknown": True}, {"failures": 1}):
            value = self.observation(**changes)
            actual = reader.checkpoint_attribution(value)
            self.assertFalse(actual["derived_all_checkpoint_calls_attributed"])
            value["host_checkpoint_attribution"]["all_checkpoint_calls_attributed"] = True
            with self.assertRaises(ValueError):
                reader.checkpoint_attribution(value)

    def test_unknown_cpu_remains_null_even_when_calls_are_classified(self):
        actual = reader.checkpoint_attribution(self.observation(clock_unknown=True))
        self.assertTrue(actual["derived_all_checkpoint_calls_attributed"])
        self.assertIsNone(actual["raw"]["buckets"][3]["calls"]["thread_cpu_ns"])
        self.assertEqual(actual["raw"]["buckets"][3]["calls"]["cpu_clock_unknown_calls"], 1)

    def test_bucket_order_and_counter_type_are_not_advisory(self):
        for modify in (
            lambda value: value["host_checkpoint_attribution"]["buckets"].reverse(),
            lambda value: value["host_checkpoint_attribution"]["buckets"][3]["calls"].update(calls_started=True),
        ):
            value = self.observation()
            modify(value)
            with self.assertRaises(ValueError):
                reader.checkpoint_attribution(value)

    def test_known_clock_totals_must_conserve_and_unknown_cannot_be_zero(self):
        for modify in (
            lambda value: value["host_checks"][2].update(thread_cpu_ns=6),
            lambda value: value["host_checkpoint_attribution"]["buckets"][3]["calls"].update(thread_cpu_ns=0, cpu_clock_unknown_calls=1),
        ):
            value = self.observation()
            modify(value)
            with self.assertRaises(ValueError):
                reader.checkpoint_attribution(value)

    def test_zero_calls_can_be_fully_classified_without_qualification(self):
        value = self.observation()
        empty = dict(value["host_checkpoint_attribution"]["buckets"][0]["calls"])
        value["host_checkpoint_attribution"]["buckets"][3]["calls"] = dict(empty)
        value["host_checks"][2] = dict(empty)
        actual = reader.checkpoint_attribution(value)
        self.assertEqual(actual["checkpoint_calls"], 0)
        self.assertTrue(actual["derived_all_checkpoint_calls_attributed"])
        self.assertFalse(actual["qualification_granted"])


if __name__ == "__main__":
    unittest.main()
