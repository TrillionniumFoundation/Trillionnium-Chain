#!/usr/bin/env python3
"""Synthetic readback and finite-budget refusal controls; no native qualification."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import read_history_verifier_lifeline_v1 as reader
from run_history_verifier_lifeline_v1 import capture_inventory, remaining_timeout

BINARY = "ab" * 32
HEAD, TREE = "11" * 20, "22" * 20
OUTER = "/system.slice/lifeline-fixture.service"


def put(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def parent(cpu, tasks):
    return {
        "path": reader.PARENT, "device": 1, "inode": 77, "uid": 0, "mode": 0o40755,
        "boot_id": "12345678-1234-1234-1234-123456789abc", **reader.LIMITS,
        "pids.current": tasks, "memory.current": 4096,
        "cpu.stat": {key: cpu for key in reader.COUNTERS},
    }


def fixture(root, stage):
    root.mkdir()
    (root / "verifier").mkdir()
    owner = {"pid": 101, "uid": 1001, "gid": 1001}
    unit = "trnm-campaign-verifier-101-700.service"
    cgroup = "/trnmponpublic.slice/" + unit
    genesis, network, parameters, tip = ("01" * 32, "02" * 32, "03" * 32, "04" * 32)
    common_state = {"LoadState": "loaded", "ControlGroup": cgroup,
                    "CPUUsageNSec": "1000", "MemoryPeak": "4096"}
    values = {
        "control.json": {"schema": "native-history-owner-death-control-v1", "stage": stage,
                         "binary_sha256": BINARY, "state_backend": "authenticated-v1",
                         "genesis": genesis, "network": network, "parameters": parameters},
        "verifier/job.json": {"kind": "history-verifier", "backend": "authenticated-v1",
                              "seed": [], "parent": reader.PARENT, "binary_sha256": BINARY,
                              "owner_death_control": stage, "controller_observation": owner},
        "verifier/launch.json": {"schema": "native-history-verifier-launch-v1",
                                "unit": unit, "controller_pid": 101, "launcher_pid": 102,
                                "binary_sha256": BINARY, "parent": reader.PARENT,
                                "original_outer_cgroup": OUTER, "parent_before_spawn": parent(1, 0),
                                "controller_capability_prequeued": True,
                                "owner_death_control": stage, "collect_on_exit": False},
        "verifier/owner-death-boundary.json": {
            "schema": "native-history-owner-death-boundary-v1", "stage": stage,
            "pid": 103, "cgroup": cgroup, "binary_sha256": BINARY,
            "controller_observation": copy.deepcopy(owner), "parent": parent(3, 3), "facts": {}},
        "before-owner-death.json": {"controller_pid": 101, "actor_pid": 103, "binary_sha256": BINARY},
        "result.json": {
            "schema": "native-history-owner-death-result-v1", "stage": stage,
            "binary_sha256": BINARY, "controller_pid": 101, "actor_pid": 103,
            "controller_signal": 9, "unit": unit,
            "before": {**common_state, "MainPID": "103", "ActiveState": "active",
                       "SubState": "running", "ExecMainCode": "0", "ExecMainStatus": "0"},
            "after": {**common_state, "MainPID": "0", "ActiveState": "failed",
                      "SubState": "failed", "ExecMainCode": "1", "ExecMainStatus": "137"},
            "parent_before_death": parent(4, 3), "parent_after_death": parent(5, 0),
            "death_to_empty_ns": 1_000_000, "maximum_death_to_empty_ns": reader.DEATH_NS,
            "administrative_stop_before_observation": False,
            "clean_completion_report_exists": False, "completed_control": True,
            "original_campaign_qualified": False,
        },
        "cleanup.json": {"schema": "native-history-owner-death-cleanup-v1", "unit": unit,
                         "assertions_completed_before_cleanup": True,
                         "killed_owned_controller_during_cleanup": False,
                         "commands": [{"action": "reset-failed", "exit_success": True,
                                       "stdout": "", "stderr": ""}]},
    }
    facts = values["verifier/owner-death-boundary.json"]["facts"]
    if stage == reader.CASES[0][0]:
        facts.update(actual_native_open_returned=True, active=[[1] * 32, 0, {}])
    else:
        values["verifier/ready.json"] = {
            "pid": 103, "cgroup": cgroup, "calling_thread_cgroup": "0::" + cgroup,
            "binary_sha256": BINARY, "public_host_kernel_checked": True,
            "wrong_parent_refused": True, "parent": parent(2, 3), "setup_process_cpu_ns": 10,
            "controller_lifeline": {
                "schema": "native-history-controller-lifeline-v1",
                "capability": "anonymous-unix-stream+prequeued-self-pidfd",
                "controller": copy.deepcopy(owner), "armed_before_node_open": True,
                "watch_until_process_exit": True},
        }
        if stage == reader.CASES[1][0]:
            values["original-packet.json"] = {"id": tip, "after": genesis, "wire": "aabb"}
            values["verifier/request-000.json"] = {
                "sequence": 0, "operation": "import", "source": "127.0.0.1:1",
                "tip": [4] * 32, "after": [1] * 32, "clock": 1, "epoch": 1,
                "page": {"schema": "pon-native-history-v1", "network": network,
                         "parameters": parameters, "genesis": genesis, "tip": tip,
                         "after": genesis, "next": tip, "packets": ["aabb"], "complete": True},
            }
            facts.update(actual_strict_public_import_returned=True, returned_value=[4] * 32,
                         active=[[4] * 32, 1, {}], sequence=0)
        else:
            values["verifier/request-000.json"] = {"sequence": 0, "operation": "finish"}
            values["verifier/response-000.json"] = {
                "sequence": 0, "binary_sha256": BINARY, "error": None,
                "value": {"closing_original_node": True},
                "measurement": {"sequence": 0, "process_id": 103,
                                "thread_cpu_observation_available": True,
                                "process_cpu_ns": 10, "thread_cpu_ns": 5, "process_wall_ns": 20},
            }
            facts.update(actual_node_close_returned=True, actual_runner_returned=True,
                         clean_node_close=True, entry_schema="native-public-history-verifier-entry-v2")
    (root / "controller.log").write_text("synthetic shape only; no actual process was run\n")
    (root / "verifier/actor.log").write_text("synthetic shape only; no Node was run\n")
    sync(root, values)
    return values


def sync(root, values):
    """Recompute summaries and transport hashes, so semantic substitutions still face the reader."""
    job_sha = put(root / "verifier/job.json", values["verifier/job.json"])
    boundary = values["verifier/owner-death-boundary.json"]
    launch = values["verifier/launch.json"]
    launch["job_sha256"] = boundary["job_sha256"] = job_sha
    if "verifier/request-000.json" in values:
        request_sha = put(root / "verifier/request-000.json", values["verifier/request-000.json"])
        if values["result.json"]["stage"] == reader.CASES[1][0]:
            boundary["facts"]["request_sha256"] = request_sha
        if "verifier/response-000.json" in values:
            values["verifier/response-000.json"]["request_sha256"] = request_sha
    before, result = values["before-owner-death.json"], values["result.json"]
    before.update(launch=copy.deepcopy(launch), boundary=copy.deepcopy(boundary),
                  actual_systemd_unit=copy.deepcopy(result["before"]),
                  parent=copy.deepcopy(result["parent_before_death"]))
    result["actual_boundary"] = copy.deepcopy(boundary)
    for name, value in values.items():
        put(root / name, value)


def source():
    return {"schema": "trnm-ci-source-v1", "kind": "head", "tested_commit": HEAD,
            "tested_tree": TREE, "candidate": HEAD, "base": None, "prospective_merge": None,
            "tracked_worktree_verified": True, "tests_executed_by_identity_check": False,
            "tracked_entries": 123, "tracked_bytes": 456}


def build_fixture(root):
    root.mkdir()
    binary = root / "public_v3_multiprocess.bin"
    binary.write_bytes(b"\x7fELFsynthetic reader fixture; never executed")
    binary.chmod(0o700)
    profile = {"opt_level": "3", "debug_assertions": False, "test": True}
    artifact = {"reason": "compiler-artifact", "target": {"name": "public_v3_multiprocess"},
                "profile": profile, "executable": "/separate-target/public_v3_multiprocess-123"}
    record = {"retained": binary.name, "sha256_before": reader.hash_file(binary),
              "sha256_after": None, "bytes": binary.stat().st_size,
              "build_artifact": artifact["executable"], "actual_compiler_artifact_profile": profile,
              "build_separate_from_measured_campaign": True}
    (root / "build.stdout.log").write_text(json.dumps(artifact) + "\n")
    (root / "build.stderr.log").write_text("")
    step = {"name": "build", "returncode": 0, "error": None, "complete_success": True,
            "stdout_truncated": False, "stderr_truncated": False,
            "outer_stage_timeout_seconds": 1800, "elapsed_ns": 5,
            "stdout": "build.stdout.log", "stderr": "build.stderr.log"}
    for channel in ("stdout", "stderr"):
        path = root / step[channel]
        step[channel + "_bytes"] = path.stat().st_size
        step[channel + "_sha256"] = reader.hash_file(path)
    put(root / "binary-before.json", record)
    put(root / "build.step.json", step)
    put(root / "source-before-build.json", source())
    put(root / "source-before-campaigns.json", source())
    final = copy.deepcopy(record)
    final["sha256_after"] = final["sha256_before"]
    put(root / "results.json", {"schema": "pon-original-native-campaign-ci-v1",
                               "expected_head": HEAD, "expected_tree": TREE,
                               "profile": "release", "toolchain": "1.95.0",
                               "binary": final, "source_after": source(),
                               "complete_success": False})  # A separate failed campaign is retained.


def native_log(selectors, ignored=()):
    rows = [f"test {name} ... ok" for name in selectors]
    rows += [f"test {name} ... ignored, actual parent-driven helper" for name in ignored]
    return "\n".join(rows) + (
        f"\ntest result: ok. {len(selectors)} passed; 0 failed; {len(ignored)} ignored; "
        "0 measured; 9 filtered out; finished in 0.01s\n")


class LifelineReaderControls(unittest.TestCase):
    def test_all_three_distinct_native_boundary_shapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            for number, (stage, _) in enumerate(reader.CASES):
                root = Path(temporary) / str(number)
                fixture(root, stage)
                observed = reader.validate_case(root, stage, BINARY, OUTER)
                self.assertTrue(observed["complete"])
                self.assertFalse(observed["original_campaign_qualified"])
                self.assertFalse(observed["production_qualified"])

    def test_semantic_replacements_survive_rehash_but_are_refused(self):
        changes = [
            ("stage", lambda v: v["control.json"].update(stage="different")),
            ("summary_success", lambda v: v["result.json"].update(completed_control=False)),
            ("false_original_pass", lambda v: v["result.json"].update(original_campaign_qualified=True)),
            ("wrong_elf", lambda v: v["verifier/launch.json"].update(binary_sha256="cc" * 32)),
            ("wrong_owner", lambda v: v["verifier/job.json"]["controller_observation"].update(pid=999)),
            ("bool_uid", lambda v: v["verifier/job.json"]["controller_observation"].update(uid=True)),
            ("wrong_actor", lambda v: v["result.json"].update(actor_pid=999)),
            ("wrong_cgroup", lambda v: v["verifier/owner-death-boundary.json"].update(cgroup="/other")),
            ("wrong_outer", lambda v: v["verifier/launch.json"].update(original_outer_cgroup="/other")),
            ("wrong_unit", lambda v: v["result.json"].update(unit="unowned.service")),
            ("capability_not_prequeued", lambda v: v["verifier/launch.json"].update(controller_capability_prequeued=False)),
            ("premature_collect", lambda v: v["verifier/launch.json"].update(collect_on_exit=True)),
            ("wrong_backend", lambda v: v["control.json"].update(state_backend="legacy-v2")),
            ("hidden_seed", lambda v: v["verifier/job.json"].update(seed=["00"])),
            ("no_sigkill", lambda v: v["result.json"].update(controller_signal=15)),
            ("late_exit", lambda v: v["result.json"].update(death_to_empty_ns=reader.DEATH_NS)),
            ("increased_deadline", lambda v: v["result.json"].update(maximum_death_to_empty_ns=reader.DEATH_NS + 1)),
            ("admin_kill", lambda v: v["result.json"].update(administrative_stop_before_observation=True)),
            ("fake_clean", lambda v: v["result.json"].update(clean_completion_report_exists=True)),
            ("cleanup_kill_exit", lambda v: v["result.json"]["after"].update(ExecMainCode="2")),
            ("panic_exit", lambda v: v["result.json"]["after"].update(ExecMainStatus="101")),
            ("hidden_active", lambda v: v["result.json"]["after"].update(MainPID="103")),
            ("unit_disappeared", lambda v: v["result.json"]["after"].update(LoadState="not-found")),
            ("live_helper", lambda v: v["result.json"]["parent_after_death"].update({"pids.current": 1})),
            ("nonempty_initial", lambda v: v["verifier/launch.json"]["parent_before_spawn"].update({"pids.current": 1})),
            ("changed_fixed_parent", lambda v: v["verifier/owner-death-boundary.json"]["parent"].update(inode=78)),
            ("looser_cpu", lambda v: v["result.json"]["parent_after_death"].update({"cpu.max": "400000 100000"})),
            ("rewound_cpu", lambda v: v["result.json"]["parent_after_death"]["cpu.stat"].update(usage_usec=0)),
            ("early_cleanup", lambda v: v["cleanup.json"].update(assertions_completed_before_cleanup=False)),
            ("cleanup_owns_death", lambda v: v["cleanup.json"].update(killed_owned_controller_during_cleanup=True)),
            ("cleanup_other_unit", lambda v: v["cleanup.json"].update(unit="other.service")),
            ("cleanup_failure", lambda v: v["cleanup.json"]["commands"][0].update(exit_success=False)),
            ("cleanup_stop_pass", lambda v: v["cleanup.json"]["commands"][0].update(action="stop")),
        ]
        per_stage = [
            [("fake_open", lambda v: v["verifier/owner-death-boundary.json"]["facts"].update(actual_native_open_returned=False)),
             ("wrong_genesis", lambda v: v["control.json"].update(genesis="99" * 32)),
             ("wrong_active", lambda v: v["verifier/owner-death-boundary.json"]["facts"].update(active=[[9] * 32, 0, {}]))],
            [("fake_import", lambda v: v["verifier/owner-death-boundary.json"]["facts"].update(actual_strict_public_import_returned=False)),
             ("wrong_packet", lambda v: v["original-packet.json"].update(wire="ccdd")),
             ("wrong_page_context", lambda v: v["verifier/request-000.json"]["page"].update(parameters="99" * 32)),
             ("wrong_cursor", lambda v: v["verifier/request-000.json"].update(after=[9] * 32)),
             ("fake_import_tip", lambda v: v["verifier/owner-death-boundary.json"]["facts"].update(returned_value=[9] * 32)),
             ("downgraded_watch", lambda v: v["verifier/ready.json"]["controller_lifeline"].update(capability="numeric-pid"))],
            [("fake_close", lambda v: v["verifier/owner-death-boundary.json"]["facts"].update(actual_node_close_returned=False)),
             ("fake_return", lambda v: v["verifier/owner-death-boundary.json"]["facts"].update(actual_runner_returned=False)),
             ("no_watch_tail", lambda v: v["verifier/ready.json"]["controller_lifeline"].update(watch_until_process_exit=False)),
             ("wrong_finish", lambda v: v["verifier/request-000.json"].update(operation="snapshot")),
             ("failed_finish", lambda v: v["verifier/response-000.json"].update(error="actual failure")),
             ("wrong_measurement", lambda v: v["verifier/response-000.json"]["measurement"].update(process_id=999))],
        ]
        with tempfile.TemporaryDirectory() as temporary:
            counter = 0
            for index, (stage, _) in enumerate(reader.CASES):
                for label, change in [*changes, *per_stage[index]]:
                    with self.subTest(stage=stage, vector=label):
                        root = Path(temporary) / str(counter)
                        counter += 1
                        values = fixture(root, stage)
                        change(values)
                        sync(root, values)
                        with self.assertRaises((ValueError, KeyError, TypeError)):
                            reader.validate_case(root, stage, BINARY, OUTER)
        self.assertEqual(counter, 114)

    def test_missing_swapped_duplicate_or_post_boundary_bytes_refused(self):
        variants = ("missing_boundary", "wrong_job_hash", "duplicate_key", "symlink",
                    "false_report", "pending_report", "extra_response", "extra_request")
        with tempfile.TemporaryDirectory() as temporary:
            for index, mode in enumerate(variants):
                with self.subTest(vector=mode):
                    root = Path(temporary) / str(index)
                    stage = reader.CASES[1][0]
                    fixture(root, stage)
                    if mode == "missing_boundary":
                        (root / "verifier/owner-death-boundary.json").unlink()
                    elif mode == "wrong_job_hash":
                        with (root / "verifier/job.json").open("a") as stream:
                            stream.write(" ")
                    elif mode == "duplicate_key":
                        path = root / "result.json"
                        path.write_text(path.read_text()[:-1] + ',"completed_control":true}')
                    elif mode == "symlink":
                        path = root / "result.json"
                        path.rename(root / "real-result.json")
                        path.symlink_to("real-result.json")
                    else:
                        name = {"false_report": "report.json", "pending_report": "report.pending",
                                "extra_response": "response-000.json",
                                "extra_request": "request-001.json"}[mode]
                        put(root / "verifier" / name, {"invented": True})
                    with self.assertRaises((ValueError, KeyError, TypeError, OSError)):
                        reader.validate_case(root, stage, BINARY, OUTER)

    def test_exact_method_roster_and_native_terminal(self):
        methods = [reader.SMALL_PREFIX + name for name in reader.SMALL_METHODS]
        helper = reader.SMALL_PREFIX + "helper_entry"
        listed = "\n".join(name + ": test" for name in [*methods, helper])
        reader.validate_roster(listed, helper + ": test\n")
        valid = native_log(methods, [helper])
        reader.test_terminal(valid, methods, [helper])
        for bad in (listed.replace(methods[0] + ": test", ""), listed + "\nextra: test"):
            with self.assertRaises(ValueError):
                reader.validate_roster(bad, helper + ": test\n")
        for bad in (valid.replace("6 passed", "5 passed"), valid.replace("1 ignored", "0 ignored"),
                    valid.replace(methods[0], "other"), valid + valid,
                    "test unexpected ... FAILED\n" + valid,
                    valid.replace("0 failed", "1 failed")):
            with self.assertRaises(ValueError):
                reader.test_terminal(bad, methods, [helper])

    def test_original_release_source_and_raw_build_are_required(self):
        changes = (
            ("source", "source-before-build.json", lambda v: v.update(tested_commit="33" * 20)),
            ("hidden_source", "source-before-campaigns.json", lambda v: v.update(tracked_worktree_verified=False)),
            ("profile", "binary-before.json", lambda v: v["actual_compiler_artifact_profile"].update(opt_level="0")),
            ("debug", "binary-before.json", lambda v: v["actual_compiler_artifact_profile"].update(debug_assertions=True)),
            ("binary", "binary-before.json", lambda v: v.update(sha256_before="ff" * 32)),
            ("failed_build", "build.step.json", lambda v: v.update(returncode=1)),
            ("truncated_build", "build.step.json", lambda v: v.update(stdout_truncated=True)),
            ("stale_final", "results.json", lambda v: v.update(expected_tree="44" * 20)),
            ("stale_binary", "results.json", lambda v: v["binary"].update(sha256_after="ff" * 32)),
        )
        with tempfile.TemporaryDirectory() as temporary:
            positive = Path(temporary) / "positive"
            build_fixture(positive)
            binary, _ = reader.baseline_binary(positive, HEAD, TREE)
            self.assertEqual(binary.name, "public_v3_multiprocess.bin")
            for label, filename, change in changes:
                with self.subTest(vector=label):
                    root = Path(temporary) / label
                    build_fixture(root)
                    value, _ = reader.read(root / filename)
                    change(value)
                    put(root / filename, value)
                    with self.assertRaises((ValueError, KeyError, TypeError)):
                        reader.baseline_binary(root, HEAD, TREE)
            (positive / "build.stdout.log").write_text("{}\n")
            with self.assertRaises(ValueError):
                reader.baseline_binary(positive, HEAD, TREE)

    def test_graph_campaign_build_keeps_exact_profile_and_strict_lifeline_separate(self):
        fields = {
            "schema": "pon-history-graph-resource-fence-campaign-ci-v1",
            "history_resource_profile": "history-account-graph-resource-fence-v1",
            "native_selector": "separate_process_graph_resource_fence_v1_work_and_signed_confirmation_campaign",
            "strict_profile_result_is_separate": True,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "graph"
            build_fixture(root)
            original, _ = reader.read(root / "results.json")
            graph = {**original, **fields}
            put(root / "results.json", graph)
            reader.baseline_binary(root, HEAD, TREE)
            # An independently failed campaign stays failed after its actual
            # binary is admitted solely for fresh owner-death controls.
            self.assertIs(reader.read(root / "results.json")[0]["complete_success"], False)
            for key in fields:
                for missing in (False, True):
                    with self.subTest(field=key, missing=missing):
                        changed = copy.deepcopy(graph)
                        if missing:
                            del changed[key]
                        else:
                            changed[key] = (1 if key == "strict_profile_result_is_separate" else "other")
                        put(root / "results.json", changed)
                        with self.assertRaises((ValueError, KeyError, TypeError)):
                            reader.baseline_binary(root, HEAD, TREE)
            for key in ("expected_head", "expected_tree"):
                changed = {**graph, key: "33" * 20}
                put(root / "results.json", changed)
                with self.assertRaises(ValueError):
                    reader.baseline_binary(root, HEAD, TREE)
            for key in ("sha256_before", "sha256_after"):
                changed = copy.deepcopy(graph)
                changed["binary"][key] = "ff" * 32
                put(root / "results.json", changed)
                with self.assertRaises(ValueError):
                    reader.baseline_binary(root, HEAD, TREE)
            # Relabelling an N8 run with the original strict schema cannot pass.
            put(root / "results.json", {**graph, "schema": original["schema"]})
            with self.assertRaises(ValueError):
                reader.baseline_binary(root, HEAD, TREE)

    def test_deadline_and_final_inventory_cannot_skip_failed_artifacts(self):
        self.assertEqual(remaining_timeout(600, 180, now=0), 180)
        self.assertEqual(remaining_timeout(600, 180, now=550), 50)
        self.assertEqual(remaining_timeout(600, 60, now=599.5), 0.5)
        for now in (600, 601):
            with self.assertRaises(TimeoutError):
                remaining_timeout(600, 180, now=now)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "failed-child.log"
            path.write_bytes(b"retained original failure\n")
            self.assertEqual(capture_inventory(root), [
                {"path": path.name, "bytes": path.stat().st_size, "sha256": reader.hash_file(path)}])
            (root / "foreign.log").symlink_to(path)
            with self.assertRaises(ValueError):
                capture_inventory(root)

    def test_all_small_modes_and_no_late_thread_effect_required(self):
        modes = ("normal", "eof", "owner-death", "already-dead", "unexpected-data",
                 "regular-file-right", "missing-right", "ordinary-stdin", "multiple-rights",
                 "truncated-rights", "wrong-preface", "named-socket")
        methods = [reader.SMALL_PREFIX + name for name in reader.SMALL_METHODS]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {}
            for index, mode in enumerate(modes):
                path = root / f"history-lifeline-{mode}-100-999-{index}"
                path.mkdir()
                paths[mode] = path
                text = "synthetic control shape only"
                if mode == "named-socket":
                    text += " named or abstract owner listener refused"
                    (path / "actual-named-socket").write_text("synthetic socket observation")
                if mode in ("multiple-rights", "truncated-rights", "wrong-preface"):
                    text += " one exact prequeued pidfd capability required"
                (path / ("normal.log" if mode == "normal" else "watch.log")).write_text(text)
                if mode in ("normal", "eof", "owner-death", "unexpected-data"):
                    put(path / "entered-scope", {"peer_pid": 101, "peer_uid": 1001, "peer_gid": 1001})
                if mode in ("eof", "owner-death", "unexpected-data"):
                    (path / "watch-ready").write_text("synthetic")
                    (path / "termination-trigger").write_text("synthetic")
                if mode in ("owner-death", "already-dead"):
                    (path / "controller-ready").write_text("prequeued-self-pidfd\n")
            (paths["normal"] / "normal-return").write_text("watcher remains armed until actual OS exit\n")
            log = native_log(methods, [reader.SMALL_PREFIX + "helper_entry"])
            reader.validate_small(root, log)
            (paths["owner-death"] / "late-worker-side-effect").write_text("actual leak would fail")
            with self.assertRaises(ValueError):
                reader.validate_small(root, log)


if __name__ == "__main__":
    unittest.main(verbosity=2)
